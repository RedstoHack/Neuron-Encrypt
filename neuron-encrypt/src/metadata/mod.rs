//! Metadata scrubbing — remove privacy-relevant metadata (EXIF, GPS, XMP,
//! ID3, document properties) from media files, on every platform, from this
//! one Rust module.
//!
//! Design constraints inherited from the crypto module:
//! - Atomic writes: output goes to a `.tmp` file first, then is hard-linked
//!   (unix) or renamed over the destination. The source is never touched
//!   unless the caller explicitly asks for in-place replacement.
//! - Cancellation: checked before work starts and again before persisting.
//! - Fail closed: any structural surprise aborts with `MalformedFile` /
//!   `UnsupportedMediaFormat` and leaves no partial output behind.
//!
//! Coverage is per-format by nature: encryption treats files as opaque
//! bytes, but scrubbing must understand container structure to excise
//! metadata without corrupting the payload. Unknown formats are rejected
//! loudly instead of being copied silently.

#[cfg(test)]
pub(crate) mod brutal;
pub mod documents;
pub mod images;
pub mod media;
#[cfg(test)]
pub(crate) mod tests;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::crypto::{persist_temp_file, tmp_path, ProgressReporter};
use crate::error::{CryptoError, CryptoResult};

/// Media formats with a dedicated metadata scrubber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFormat {
    Jpeg,
    Png,
    WebP,
    Gif,
    Bmp,
    Tiff,
    Heif,
    Pdf,
    Ooxml,
    Mp3,
    Aac,
    Flac,
    Ogg,
    Opus,
    Wav,
    Aiff,
    Mp4,
    MobileMp4,
}

impl MediaFormat {
    pub fn name(&self) -> &'static str {
        match self {
            MediaFormat::Jpeg => "JPEG",
            MediaFormat::Png => "PNG",
            MediaFormat::WebP => "WebP",
            MediaFormat::Gif => "GIF",
            MediaFormat::Bmp => "BMP",
            MediaFormat::Tiff => "TIFF",
            MediaFormat::Heif => "HEIF/HEIC",
            MediaFormat::Pdf => "PDF",
            MediaFormat::Ooxml => "Office document",
            MediaFormat::Mp3 => "MP3",
            MediaFormat::Aac => "AAC",
            MediaFormat::Flac => "FLAC",
            MediaFormat::Ogg => "OGG",
            MediaFormat::Opus => "Opus",
            MediaFormat::Wav => "WAV",
            MediaFormat::Aiff => "AIFF",
            MediaFormat::Mp4 => "MP4/MOV",
            MediaFormat::MobileMp4 => "3GP/3G2",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            MediaFormat::Jpeg => "jpg",
            MediaFormat::Png => "png",
            MediaFormat::WebP => "webp",
            MediaFormat::Gif => "gif",
            MediaFormat::Bmp => "bmp",
            MediaFormat::Tiff => "tiff",
            MediaFormat::Heif => "heic",
            MediaFormat::Pdf => "pdf",
            // OOXML containers keep their original extension; detection does
            // not distinguish docx/xlsx/pptx and must not guess one.
            MediaFormat::Ooxml => "",
            MediaFormat::Mp3 => "mp3",
            MediaFormat::Aac => "aac",
            MediaFormat::Flac => "flac",
            MediaFormat::Ogg => "ogg",
            MediaFormat::Opus => "opus",
            MediaFormat::Wav => "wav",
            MediaFormat::Aiff => "aiff",
            MediaFormat::Mp4 => "mp4",
            MediaFormat::MobileMp4 => "3gp",
        }
    }
}

/// Result of a successful scrub.
#[derive(Debug, Clone)]
pub struct ScrubReport {
    pub format: MediaFormat,
    /// Human-readable categories of metadata that were found and removed.
    pub removed: Vec<String>,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

/// How to place the scrubbed output relative to the source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubOutput {
    /// Write `<name>.clean.<ext>` next to the source (or an explicit path).
    /// The original is never modified.
    CleanedCopy,
    /// Atomically replace the source file with the scrubbed version.
    InPlace,
}

const SCRUB_READ_HEADER_LEN: usize = 64;
/// In-memory rewrite cap for format families that need whole-file parsing.
/// Media containers (audio/video) go through streaming rewriters instead.
///
/// The image/PDF/OOXML scrubbers hold **two** full-size buffers at once
/// (source bytes plus the rebuilt output), so peak allocation is roughly 2x
/// the file size. Desktop can afford the 1 GiB ceiling; Android cannot, and an
/// oversized file there is killed by `lmkd` before any of our error handling
/// runs. Mobile therefore gets a much tighter ceiling so oversized inputs fail
/// loudly (and cheaply) instead of taking the process - and the foreground
/// service notification - down with them.
#[cfg(target_os = "android")]
const IN_MEMORY_SCRUB_CAP: u64 = 64 * 1024 * 1024; // 64 MiB
#[cfg(not(target_os = "android"))]
const IN_MEMORY_SCRUB_CAP: u64 = 1_073_741_824; // 1 GiB

/// Sniff the media format from leading magic bytes. Returns `None` for
/// anything without a dedicated scrubber — callers must surface that as a
/// loud error, never as a silent pass-through copy.
pub fn detect_media_format(header: &[u8]) -> Option<MediaFormat> {
    if header.len() < 12 {
        return None;
    }

    if header.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(MediaFormat::Jpeg);
    }
    if header.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(MediaFormat::Png);
    }
    if header.starts_with(b"GIF87a") || header.starts_with(b"GIF89a") {
        return Some(MediaFormat::Gif);
    }
    if header.starts_with(b"BM") && header.len() >= 14 {
        return Some(MediaFormat::Bmp);
    }
    if header.starts_with(b"II*\0") || header.starts_with(b"MM\0*") {
        return Some(MediaFormat::Tiff);
    }
    if header.starts_with(b"II+\0") || header.starts_with(b"MM\0+") {
        // BigTIFF has no scrubber; report unsupported rather than TIFF.
        return None;
    }
    if header.starts_with(b"RIFF") {
        if &header[8..12] == b"WEBP" {
            return Some(MediaFormat::WebP);
        }
        if &header[8..12] == b"WAVE" {
            return Some(MediaFormat::Wav);
        }
        return None;
    }
    if header.starts_with(b"fLaC") {
        return Some(MediaFormat::Flac);
    }
    if header.starts_with(b"OggS") {
        // Opus and Vorbis share the Ogg container and are told apart by the
        // first packet's codec id, which appears in the bytes right after the
        // page header. Both are scrubbed by the same lofty path, but the
        // reported format (and default output extension) must match the file.
        if find_subslice(header, b"OpusHead").is_some() {
            return Some(MediaFormat::Opus);
        }
        return Some(MediaFormat::Ogg);
    }
    // AIFF/AIFC: "FORM" <be32 size> "AIFF" | "AIFC". Big-endian chunked
    // container handled by lofty's IFF reader.
    if header.starts_with(b"FORM")
        && header.len() >= 12
        && (&header[8..12] == b"AIFF" || &header[8..12] == b"AIFC")
    {
        return Some(MediaFormat::Aiff);
    }
    if header.starts_with(b"%PDF-") {
        return Some(MediaFormat::Pdf);
    }
    if header.starts_with(b"PK\x03\x04") {
        // An OOXML package carries [Content_Types].xml; plain zips do not.
        let window = &header[..header.len().min(4096).min(header.len())];
        if find_subslice(window, b"[Content_Types].xml").is_some() {
            return Some(MediaFormat::Ooxml);
        }
        return None;
    }
    if header.starts_with(b"ID3") {
        return Some(MediaFormat::Mp3);
    }
    // MPEG audio (MP1/2/3) and raw AAC share the 11-bit frame sync. They are
    // told apart by the layer bits: MPEG reserves 00 (reserved), so a real
    // MPEG frame always carries a non-zero layer, while ADTS AAC uses 00.
    if header[0] == 0xFF && (header[1] & 0xE0) == 0xE0 {
        let layer = (header[1] >> 1) & 0x03;
        if layer == 0x00 {
            return Some(MediaFormat::Aac);
        }
        return Some(MediaFormat::Mp3);
    }
    // ADIF is the other raw AAC variant lofty reads.
    if header.starts_with(b"ADIF") {
        return Some(MediaFormat::Aac);
    }
    // ISO-BMFF family: box size at 0..4, "ftyp" at 4..8, brand at 8..12.
    if &header[4..8] == b"ftyp" {
        let brand = &header[8..12];
        // Only brands that are unambiguously ISO-BMFF *and* handled by the
        // lofty-based media scrubber. HEIF/HEIC brands are matched separately
        // below and rejected (no structural scrubber yet), so they must stay
        // out of this list.
        const MP4_BRANDS: [&[u8; 4]; 17] = [
            b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4A ", b"M4V ", b"qt  ", b"dash",
            b"MSNV",
            // Newer ISO base-media file format versions (modern phone cameras).
            b"iso5", b"iso6", b"iso7", b"iso8", b"iso9", b"isoa", b"isob",
        ];
        if MP4_BRANDS.iter().any(|b| *b == brand) {
            return Some(MediaFormat::Mp4);
        }
        // 3GPP / 3GPP2 mobile video (the default on many Android phones) and
        // the Apple book/podcast variants. Scrubbed by the same lofty path as
        // MP4; reported separately so the output keeps the right extension.
        const MOBILE_MP4_BRANDS: [&[u8; 4]; 12] = [
            b"3gp4", b"3gp5", b"3gp6", b"3gp7", b"3gp8", b"3ge6", b"3gg6", b"3g2a", b"M4B ",
            b"M4P ", b"mqv ", b"3g2b",
        ];
        if MOBILE_MP4_BRANDS.iter().any(|b| *b == brand) {
            return Some(MediaFormat::MobileMp4);
        }
        const HEIF_BRANDS: [&[u8; 4]; 6] = [b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"];
        if HEIF_BRANDS.iter().any(|b| *b == brand) {
            return Some(MediaFormat::Heif);
        }
        return None;
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_header(path: &Path) -> CryptoResult<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut header = vec![0u8; SCRUB_READ_HEADER_LEN];
    let mut filled = 0;
    while filled < header.len() {
        match file.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    header.truncate(filled);
    Ok(header)
}

/// Default destination for [`ScrubOutput::CleanedCopy`]: `photo.jpg` becomes
/// `photo.clean.jpg` next to the source.
pub fn default_scrub_output_name(src: &Path) -> String {
    let stem = src
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let ext = src
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    if ext.is_empty() {
        format!("{stem}.clean")
    } else {
        format!("{stem}.clean.{ext}")
    }
}

fn open_scratch_file(tmp: &Path) -> CryptoResult<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)
            .map_err(Into::into)
    }
    #[cfg(not(unix))]
    {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
            .map_err(Into::into)
    }
}

fn validate_scrub_output(tmp: &Path, format: MediaFormat) -> CryptoResult<()> {
    let header = read_header(tmp)?;
    let redetected = detect_media_format(&header);
    if redetected != Some(format) {
        // BMP scrubs to itself, so this holds for every supported format.
        return Err(CryptoError::ScrubFailed(format!(
            "post-write validation failed: output no longer detected as {}",
            format.name()
        )));
    }
    Ok(())
}

/// Persist the scrubbed scratch file at `dest`, replacing an existing file in a
/// single step when necessary.
///
/// In-place scrubbing (`dest == src`) must never leave a window where the
/// original has been deleted but the replacement is not yet in place: the old
/// remove-then-link sequence lost *both* copies when the second step failed
/// (for example on filesystems without hard-link support such as exFAT, FAT,
/// or SMB/NFS shares, where `persist_temp_file` then removes the scratch file
/// as part of its own failure handling) and also on a crash between the two
/// steps. `fs::rename` replaces the destination atomically on unix (`rename(2)`)
/// and on windows (`MoveFileEx` with `MOVEFILE_REPLACE_EXISTING`), so the
/// original is either fully there or fully replaced.
///
/// A *new* destination still goes through [`persist_temp_file`] so its
/// create-new guarantee is preserved (validated earlier but re-checked here).
fn persist_scratched(tmp: &Path, dest: &Path) -> CryptoResult<()> {
    match fs::symlink_metadata(dest) {
        Ok(_) => {
            // A read-only destination cannot be replaced by rename on windows
            // (access denied), so clear the flag for the swap and put it back
            // on the replacement - the attribute the user chose survives.
            #[cfg(windows)]
            {
                let meta = fs::symlink_metadata(dest)?;
                if meta.permissions().readonly() {
                    let mut cleared = meta.permissions();
                    // Windows-specific: clear read-only for the atomic swap.
                    // This is a no-op on Unix, so the clippy warning is a false
                    // positive for this platform-guarded code.
                    #[allow(clippy::permissions_set_readonly_false)]
                    cleared.set_readonly(false);
                    fs::set_permissions(dest, cleared)?;
                    let mut readonly = fs::metadata(tmp)?.permissions();
                    // Windows-specific: restore the read-only attribute on the
                    // replacement file after the atomic swap.
                    #[allow(clippy::permissions_set_readonly_false)]
                    readonly.set_readonly(true);
                    fs::set_permissions(tmp, readonly)?;
                }
            }
            match fs::rename(tmp, dest) {
                Ok(()) => Ok(()),
                Err(error) => {
                    let _ = fs::remove_file(tmp);
                    Err(error.into())
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => persist_temp_file(tmp, dest),
        Err(error) => {
            let _ = fs::remove_file(tmp);
            Err(error.into())
        }
    }
}

/// Remove all known metadata from the file at `src`.
///
/// - [`ScrubOutput::CleanedCopy`] writes `photo.clean.jpg`-style output
///   beside the source (or at the explicit `dest`) and never modifies the
///   original. With `wipe_original`, the original is then securely wiped
///   (best-effort on flash storage).
/// - [`ScrubOutput::InPlace`] atomically replaces the source file.
///
/// `overwrite` only affects [`ScrubOutput::CleanedCopy`]: when false an
/// existing `dest` is rejected with [`CryptoError::FileAlreadyExists`], when
/// true it is replaced atomically by [`persist_scratched`]. The existing file
/// is never deleted up front, so a failure part-way through leaves it intact.
///
/// Unknown/corrupt inputs fail loudly and leave no output behind.
#[allow(clippy::too_many_arguments)]
pub fn scrub_file(
    src: &Path,
    dest: Option<&Path>,
    mode: ScrubOutput,
    overwrite: bool,
    wipe_original: bool,
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<ScrubReport> {
    if !src.is_file() {
        return Err(CryptoError::NotAFile(src.to_path_buf()));
    }

    if let Some(flag) = cancel_flag {
        if flag.load(Ordering::SeqCst) {
            return Err(CryptoError::Cancelled);
        }
    }

    let header = read_header(src)?;
    let format = detect_media_format(&header).ok_or(CryptoError::UnsupportedMediaFormat(
        "no dedicated metadata scrubber for this file type",
    ))?;

    let source_len = fs::metadata(src)?.len();

    let dest: PathBuf = match mode {
        ScrubOutput::CleanedCopy => {
            let explicit = dest.map(Path::to_path_buf);
            let candidate =
                explicit.unwrap_or_else(|| src.with_file_name(default_scrub_output_name(src)));
            crate::crypto::validate_destination_path_public(src, &candidate, overwrite)?
        }
        ScrubOutput::InPlace => {
            // Resolve symlinks so an in-place scrub rewrites the *target* file
            // and leaves the link intact, instead of replacing the link itself
            // with a regular file.
            fs::canonicalize(src)?
        }
    };

    reporter.report(
        0.05,
        &format!("Detected {} — removing metadata...", format.name()),
    );

    let tmp = tmp_path(&dest);
    let write_result = (|| -> CryptoResult<Vec<String>> {
        let mut out = open_scratch_file(&tmp)?;

        let removed = match format {
            MediaFormat::Heif => {
                drop(out);
                let _ = fs::remove_file(&tmp);
                return Err(CryptoError::UnsupportedMediaFormat(
                    "HEIC/HEIF structural scrubbing is not supported yet; \
                     convert to JPEG/PNG first",
                ));
            }
            MediaFormat::Bmp => {
                // BMP carries no standard embedded metadata; a validated no-op
                // copy is the correct behaviour. Streamed rather than read into
                // memory so a large BMP is bounded by the chunk buffer instead
                // of the in-memory scrub cap.
                copy_streaming(src, &mut out, cancel_flag)?;
                out.sync_all()?;
                drop(out);
                Vec::new()
            }
            MediaFormat::Jpeg
            | MediaFormat::Png
            | MediaFormat::WebP
            | MediaFormat::Gif
            | MediaFormat::Tiff => {
                let data = read_all_capped(src, source_len)?;
                let (cleaned, removed) = images::scrub_image(format, &data)?;
                out.write_all(&cleaned)?;
                out.sync_all()?;
                drop(out);
                removed
            }
            MediaFormat::Pdf | MediaFormat::Ooxml => {
                let data = read_all_capped(src, source_len)?;
                let (cleaned, removed) = documents::scrub_document(format, &data)?;
                out.write_all(&cleaned)?;
                out.sync_all()?;
                drop(out);
                removed
            }
            MediaFormat::Mp3
            | MediaFormat::Aac
            | MediaFormat::Flac
            | MediaFormat::Ogg
            | MediaFormat::Opus
            | MediaFormat::Wav
            | MediaFormat::Aiff
            | MediaFormat::Mp4
            | MediaFormat::MobileMp4 => {
                drop(out);
                let removed = media::scrub_media_file(src, &tmp)?;
                if let Ok(f) = fs::File::open(&tmp) {
                    let _ = f.sync_all();
                }
                removed
            }
        };

        reporter.report(0.95, "Validating scrubbed output...");
        validate_scrub_output(&tmp, format)?;

        Ok(removed)
    })();

    let removed = match write_result {
        Ok(removed) => removed,
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
    };

    if let Some(flag) = cancel_flag {
        if flag.load(Ordering::SeqCst) {
            let _ = fs::remove_file(&tmp);
            return Err(CryptoError::Cancelled);
        }
    }

    // In-place replacement: keep the original file's permission bits, so a
    // world-readable photo does not silently become 0600 merely because the
    // scratch file is created private. Only the classic permission bits are
    // copied; setuid/setgid/sticky are dropped, as any in-place editor would.
    #[cfg(unix)]
    if mode == ScrubOutput::InPlace {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&dest) {
            let bits = meta.permissions().mode() & 0o777;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(bits));
        }
    }

    persist_scratched(&tmp, &dest)?;

    if wipe_original && mode == ScrubOutput::CleanedCopy {
        crate::crypto::secure_wipe(src)?;
    }

    let bytes_after = fs::metadata(&dest)?.len();
    reporter.report(1.00, "Metadata removed.");

    Ok(ScrubReport {
        format,
        removed,
        bytes_before: source_len,
        bytes_after,
    })
}

fn read_all_capped(path: &Path, len: u64) -> CryptoResult<Vec<u8>> {
    if len > IN_MEMORY_SCRUB_CAP {
        return Err(CryptoError::FileTooLarge {
            size_gb: len as f64 / 1_000_000_000.0,
            max_gb: IN_MEMORY_SCRUB_CAP as f64 / 1_000_000_000.0,
        });
    }
    fs::read(path).map_err(Into::into)
}

/// Chunked copy used by no-op scrub paths (BMP). Keeps peak memory flat and
/// honours the caller's cancellation flag at chunk boundaries.
fn copy_streaming(
    src: &Path,
    dest: &mut fs::File,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<()> {
    use std::io::Read;
    const CHUNK: usize = 1024 * 1024;
    let mut input = fs::File::open(src)?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        if let Some(flag) = cancel_flag {
            if flag.load(Ordering::SeqCst) {
                return Err(CryptoError::Cancelled);
            }
        }
        let read = input.read(&mut buf)?;
        if read == 0 {
            break;
        }
        dest.write_all(&buf[..read])?;
    }
    Ok(())
}
