//! Metadata scrubber test suite.
//!
//! Fixture files are constructed programmatically (no binary test assets)
//! so every format exercises the real parser paths.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::documents;
use super::images;
use super::{default_scrub_output_name, detect_media_format, scrub_file, MediaFormat, ScrubOutput};
use crate::crypto::ProgressReporter;
use crate::error::CryptoError;

struct NullReporter;
impl ProgressReporter for NullReporter {
    fn report(&self, _progress: f32, _message: &str) {}
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "neuron-scrub-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_file(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(data).unwrap();
    path
}

const EVIL_CAMERA: &[u8] = b"EVIL-CAM";
const EVIL_CAMERA_STR: &str = "EVIL-CAM";

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ===========================================================================
// Fixture builders
// ===========================================================================

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Minimal TIFF payload with one IFD0 tag (used inside JPEG APP1).
fn tiny_exif_tiff() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"II*\0");
    out.extend_from_slice(&8u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&271u16.to_le_bytes()); // Make
    out.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    out.extend_from_slice(&(EVIL_CAMERA.len() as u32).to_le_bytes());
    let ext_off = 8 + 2 + 12 + 4;
    out.extend_from_slice(&(ext_off as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // next IFD = 0
    out.extend_from_slice(EVIL_CAMERA);
    out
}

fn jpeg_fixture(with_metadata: bool) -> Vec<u8> {
    let mut out = vec![0xFF, 0xD8];
    if with_metadata {
        let exif_payload = {
            let mut p = b"Exif\0\0".to_vec();
            p.extend_from_slice(&tiny_exif_tiff());
            p
        };
        out.extend_from_slice(&[0xFF, 0xE1]);
        out.extend_from_slice(&((exif_payload.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&exif_payload);

        let xmp = b"http://ns.adobe.com/xap/1.0/\0<evil/>";
        out.extend_from_slice(&[0xFF, 0xE1]);
        out.extend_from_slice(&((xmp.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(xmp);

        let iptc = b"Photoshop 3.0\08BIM";
        out.extend_from_slice(&[0xFF, 0xED]);
        out.extend_from_slice(&((iptc.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(iptc);

        out.extend_from_slice(&[0xFF, 0xFE]);
        out.extend_from_slice(&((b"secret comment".len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(b"secret comment");
    }

    let dqt = [0x00u8, 0x10, 0x10, 0x10];
    out.extend_from_slice(&[0xFF, 0xDB]);
    out.extend_from_slice(&((dqt.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&dqt);

    let sof = [0x00u8, 0x08, 0x00, 0x02, 0x00, 0x02, 0x01, 0x11, 0x00];
    out.extend_from_slice(&[0xFF, 0xC0]);
    out.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&sof);

    out.extend_from_slice(&[0xFF, 0xDA]); // SOS
    out.extend_from_slice(&[0x00, 0x04, 0x01, 0x00]);
    out.extend_from_slice(&[0x12, 0x34, 0x56, 0xAB, 0xCD]); // entropy bytes
    out.extend_from_slice(&[0xFF, 0xD9]); // EOI
    out
}

fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(data.len() + 12);
    c.extend_from_slice(&(data.len() as u32).to_be_bytes());
    c.extend_from_slice(kind);
    c.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(data.len() + 4);
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    c.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    c
}

fn png_fixture(with_metadata: bool) -> Vec<u8> {
    let ihdr: [u8; 13] = [0, 2, 0, 2, 8, 2, 0, 0, 0]; // 2x2 RGB
    let idat = [0xABu8; 12];

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(png_chunk(b"IHDR", &ihdr));
    if with_metadata {
        out.extend(png_chunk(b"tEXt", b"Comment\x00hide me"));
        out.extend(png_chunk(b"iTXt", b"XML:com.adobe.xmp\x00\x00\x00\x00\x00<x/>"));
        out.extend(png_chunk(b"eXIf", &tiny_exif_tiff()));
        out.extend(png_chunk(b"tIME", &[2026, 1, 1, 0, 0, 0]));
        out.extend(png_chunk(b"zTXt", b"key\x00\x00compressed"));
    }
    out.extend(png_chunk(b"IDAT", &idat));
    out.extend(png_chunk(b"IEND", &[]));
    out
}

fn webp_fixture(with_metadata: bool) -> Vec<u8> {
    let vp8l = [0x2Bu8, 0x14, 0x00, 0x00, 0x00];
    let mut body = Vec::new();
    body.extend(png_chunk(b"VP8L", &vp8l));
    if with_metadata {
        body.extend(png_chunk(b"EXIF", &tiny_exif_tiff()));
        body.extend(png_chunk(b"XMP ", b"<odd>")); // odd length → pad byte
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
    out.extend_from_slice(b"WEBP");
    out.extend_from_slice(&body);
    out
}

fn gif_fixture(with_metadata: bool) -> Vec<u8> {
    let mut out = b"GIF89a".to_vec();
    out.extend_from_slice(&[0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]); // LSD 2x2, no GCT

    if with_metadata {
        out.extend_from_slice(&[0x21, 0xFE, 0x05]); // comment ext
        out.extend_from_slice(b"EVIL!");
        out.push(0x00);
        out.extend_from_slice(&[0x21, 0xFF, 0x0B]); // application ext
        out.extend_from_slice(b"XMP DataXMP");
        out.extend_from_slice(&[0x02, 0xAA, 0xBB, 0x00]);
    }

    out.extend_from_slice(&[0x2C, 0, 0, 0, 0, 0x02, 0x00, 0x02, 0x00, 0x00]); // image 2x2
    out.push(0x02); // LZW min code size
    out.extend_from_slice(&[0x04, 0x44, 0x44, 0x44, 0x44]);
    out.push(0x00); // block terminator
    out.push(0x3B); // trailer
    out
}

/// Classic little-endian TIFF with externals, strip data, and an EXIF sub-IFD.
fn tiff_fixture() -> Vec<u8> {
    const H: u16 = 4;

    // Source entries (tag order): 254, 256, 257, 258, 259, 262, 271, 273,
    // 277, 278, 279, 282, 283, 296, 306, 34665.
    let n_entries = 16usize;
    let header_len = 8usize;
    let ifd_len = 2 + n_entries * 12 + 4;

    let bits_off = header_len + ifd_len; // 3 × SHORT = 6 bytes
    let make_off = bits_off + 6;
    let date_off = make_off + EVIL_CAMERA.len(); // 8
    let rat_off = date_off + 20; // "2026:01:01 00:00:00\0"
    let exif_ifd_off = rat_off + 16; // two RATIONALs
    let strip_off = exif_ifd_off + 2 + 12 + 4; // minimal EXIF sub-IFD

    let mut out = Vec::new();
    out.extend_from_slice(b"II*\0");
    out.extend_from_slice(&(header_len as u32).to_le_bytes());

    out.extend_from_slice(&(n_entries as u16).to_le_bytes());
    {
        let mut entry = |out: &mut Vec<u8>, tag: u16, typ: u16, count: u32, value: [u8; 4]| {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&typ.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&value);
        };
        let short_val = |v: u16| -> [u8; 4] {
            let mut b = [0u8; 4];
            b[..2].copy_from_slice(&v.to_le_bytes());
            b
        };

        entry(&mut out, 254, 4, 1, 0u32.to_le_bytes()); // NewSubfileType
        entry(&mut out, 256, 3, 1, short_val(4)); // ImageWidth
        entry(&mut out, 257, 3, 1, short_val(H)); // ImageLength
        entry(&mut out, 258, 3, 3, (bits_off as u32).to_le_bytes()); // BitsPerSample
        entry(&mut out, 259, 3, 1, short_val(1)); // Compression = none
        entry(&mut out, 262, 3, 1, short_val(2)); // Photometric = RGB
        entry(&mut out, 271, 2, EVIL_CAMERA.len() as u32, (make_off as u32).to_le_bytes());
        entry(&mut out, 273, 4, 1, (strip_off as u32).to_le_bytes()); // StripOffsets
        entry(&mut out, 277, 3, 1, short_val(3)); // SamplesPerPixel
        entry(&mut out, 278, 3, 1, short_val(H)); // RowsPerStrip
        entry(&mut out, 279, 4, 1, (48u32).to_le_bytes()); // StripByteCounts
        entry(&mut out, 282, 5, 1, (rat_off as u32).to_le_bytes()); // XResolution
        entry(&mut out, 283, 5, 1, ((rat_off + 8) as u32).to_le_bytes()); // YResolution
        entry(&mut out, 296, 3, 1, short_val(2)); // ResolutionUnit = inch
        entry(&mut out, 306, 2, 20, (date_off as u32).to_le_bytes()); // DateTime
        entry(&mut out, 34665, 4, 1, (exif_ifd_off as u32).to_le_bytes()); // ExifIFD
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // next IFD

    assert_eq!(out.len(), bits_off);
    out.extend_from_slice(&8u16.to_le_bytes()); // BitsPerSample [8,8,8]
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    assert_eq!(out.len(), make_off);
    out.extend_from_slice(EVIL_CAMERA);
    assert_eq!(out.len(), date_off);
    out.extend_from_slice(b"2026:01:01 00:00:00\0");
    assert_eq!(out.len(), rat_off);
    out.extend_from_slice(&[72, 0, 0, 0, 1, 0, 0, 0]); // 72/1 dpi
    out.extend_from_slice(&[72, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(out.len(), exif_ifd_off);
    out.extend_from_slice(&1u16.to_le_bytes()); // sub-IFD: DateTimeOriginal
    out.extend_from_slice(&36868u16.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&20u32.to_le_bytes());
    out.extend_from_slice(&(date_off as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(out.len(), strip_off);

    for i in 0..48u8 {
        out.push(i.wrapping_mul(5)); // 4×4 RGB pixels
    }
    out
}

fn wav_fixture() -> Vec<u8> {
    let fmt: [u8; 16] = [
        1, 0, 1, 0, 0x40, 0x1F, 0x00, 0x00, 0x40, 0x1F, 0x00, 0x00, 1, 0, 8, 0,
    ];
    let pcm = [0x55u8; 8];
    let mut list_body = b"INFO".to_vec();
    let inam = b"SECRET SONG";
    list_body.extend_from_slice(b"INAM");
    list_body.extend_from_slice(&(inam.len() as u32).to_le_bytes());
    list_body.extend_from_slice(inam);

    let mut chunks = Vec::new();
    chunks.extend_from_slice(b"fmt ");
    chunks.extend_from_slice(&(fmt.len() as u32).to_le_bytes());
    chunks.extend_from_slice(&fmt);
    chunks.extend_from_slice(b"LIST");
    chunks.extend_from_slice(&(list_body.len() as u32).to_le_bytes());
    chunks.extend_from_slice(&list_body);
    chunks.extend_from_slice(b"data");
    chunks.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
    chunks.extend_from_slice(&pcm);

    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&((chunks.len() + 4) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(&chunks);
    out
}

fn flac_vorbis_comment_block(last: bool) -> Vec<u8> {
    let vendor = b"testvendor";
    let mut body = Vec::new();
    body.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    body.extend_from_slice(vendor);
    body.extend_from_slice(&2u32.to_le_bytes()); // two comments
    for c in [&b"ARTIST=Evil Singer"[..], &b"TITLE=Secret Track"[..]] {
        body.extend_from_slice(&(c.len() as u32).to_le_bytes());
        body.extend_from_slice(c);
    }

    let mut block = Vec::new();
    block.push(if last { 0x84 } else { 0x04 }); // type 4 = VORBIS_COMMENT
    block.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte len
    block.extend_from_slice(&body);
    block
}

fn flac_fixture() -> Vec<u8> {
    let streaminfo = [0u8; 34];
    let mut out = b"fLaC".to_vec();
    out.push(0x00); // STREAMINFO, not last
    out.extend_from_slice(&(streaminfo.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&streaminfo);
    out.extend(flac_vorbis_comment_block(true));
    out
}

fn mp3_fixture() -> Vec<u8> {
    let frame_data = b"TALB\x00\x00\x00\x0A\x00\x00EVILALBUM!";
    let syncsafe = |mut s: u32| -> [u8; 4] {
        let mut out = [0u8; 4];
        for b in out.iter_mut().rev() {
            *b = (s & 0x7F) as u8;
            s >>= 7;
        }
        out
    };

    let mut out = b"ID3".to_vec();
    out.extend_from_slice(&[0x03, 0x00, 0x00]); // v2.3, no flags
    out.extend_from_slice(&syncsafe(frame_data.len() as u32));
    out.extend_from_slice(frame_data);

    out.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x64]); // MPEG-1 Layer III frame
    out.extend_from_slice(&vec![0x00u8; 200]);
    out
}

fn docx_fixture() -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"#;

    let rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"#;

    let buf = std::io::Cursor::new(Vec::new());
    let mut zw = ZipWriter::new(buf);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zw.start_file("[Content_Types].xml", opts.clone()).unwrap();
    zw.write_all(content_types.as_bytes()).unwrap();
    zw.start_file("_rels/.rels", opts.clone()).unwrap();
    zw.write_all(rels.as_bytes()).unwrap();
    zw.start_file("docProps/core.xml", opts.clone()).unwrap();
    zw.write_all(b"<cp:coreProperties><dc:creator>Sneaky Author</dc:creator></cp:coreProperties>")
        .unwrap();
    zw.start_file("word/document.xml", opts).unwrap();
    zw.write_all(b"<w:document><w:body><w:p>hello</w:p></w:body></w:document>")
        .unwrap();
    zw.finish().unwrap().into_inner()
}

// ===========================================================================
// Detection tests
// ===========================================================================

#[test]
fn detects_all_supported_formats_by_magic() {
    let cases: Vec<(Vec<u8>, MediaFormat)> = vec![
        (jpeg_fixture(false), MediaFormat::Jpeg),
        (png_fixture(false), MediaFormat::Png),
        (webp_fixture(false), MediaFormat::WebP),
        (gif_fixture(false), MediaFormat::Gif),
        (tiff_fixture(), MediaFormat::Tiff),
        (wav_fixture(), MediaFormat::Wav),
        (flac_fixture(), MediaFormat::Flac),
        (mp3_fixture(), MediaFormat::Mp3),
        (b"%PDF-1.7 trailing".to_vec(), MediaFormat::Pdf),
        (b"\xFF\xFB\x90\x64raw-frame-no-id3".to_vec(), MediaFormat::Mp3),
    ];
    for (data, expected) in cases {
        assert_eq!(
            detect_media_format(&data),
            Some(expected),
            "detection failed for {}",
            expected.name()
        );
    }
}

#[test]
fn detects_mp4_and_heif_brands() {
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypisom\x00\x00\x02\x00isomiso2avc1mp41");
    assert_eq!(detect_media_format(&mp4), Some(MediaFormat::Mp4));

    let mut heic = vec![0, 0, 0, 0x20];
    heic.extend_from_slice(b"ftypheic\x00\x00\x00\x00heicmif1heicmif1");
    assert_eq!(detect_media_format(&heic), Some(MediaFormat::Heif));
}

#[test]
fn rejects_unknown_and_lookalike_formats() {
    assert_eq!(detect_media_format(b"II+\0\x08\x00\x00\x00\x00\x00\x00\x00"), None); // BigTIFF
    assert_eq!(detect_media_format(b"PK\x03\x04no-content-types-here...."), None);
    let ooxml_head: Vec<u8> = b"PK\x03\x04some-local-header-data-before-[Content_Types].xml".to_vec();
    assert_eq!(detect_media_format(&ooxml_head), Some(MediaFormat::Ooxml));
    assert_eq!(detect_media_format(b"garbage garbage!"), None);
    assert_eq!(detect_media_format(b"VAULTX04\x00\x00\x00"), None);
    assert_eq!(detect_media_format(b"short"), None);
}

// ===========================================================================
// Per-format scrub tests (in-memory scrubbers)
// ===========================================================================

#[test]
fn scrubs_jpeg_segments_and_keeps_payload() {
    let src = jpeg_fixture(true);
    let (out, removed) = images::scrub_image(MediaFormat::Jpeg, &src).unwrap();

    let joined = String::from_utf8_lossy(&out);
    assert!(!joined.contains("Exif"), "EXIF survived");
    assert!(!joined.contains(EVIL_CAMERA_STR), "camera survived");
    assert!(!joined.contains("secret comment"), "comment survived");
    assert!(!joined.contains("ns.adobe.com"), "XMP survived");
    assert!(!joined.contains("Photoshop"), "IPTC survived");

    assert!(out.starts_with(&[0xFF, 0xD8]));
    assert!(out.windows(2).any(|w| w == [0xFF, 0xDB]));
    assert!(out.windows(2).any(|w| w == [0xFF, 0xC0]));
    assert!(out.ends_with(&[0xFF, 0xD9]));

    assert!(removed.iter().any(|r| r.contains("EXIF")));
    assert!(removed.iter().any(|r| r.contains("XMP")));
    assert!(removed.iter().any(|r| r.contains("IPTC")));
    assert!(removed.iter().any(|r| r.contains("Comment")));
    assert!(out.len() < src.len());
}

#[test]
fn scrubs_png_chunks_verbatim_elsewhere() {
    let src = png_fixture(true);
    let (out, removed) = images::scrub_image(MediaFormat::Png, &src).unwrap();

    assert!(find(&out, b"hide me").is_none(), "tEXt survived");
    assert!(find(&out, b"<x/>").is_none(), "iTXt survived");
    assert!(find(&out, b"eXIf").is_none(), "eXIf survived");
    assert!(find(&out, b"tIME").is_none(), "tIME survived");
    assert!(find(&out, b"zTXt").is_none(), "zTXt survived");

    // IHDR and IDAT byte-identical (verbatim copy incl. CRC).
    let src_idat = find(&src, b"IDAT").unwrap();
    let out_idat = find(&out, b"IDAT").unwrap();
    assert_eq!(
        &src[src_idat - 4..src_idat + 16],
        &out[out_idat - 4..out_idat + 16]
    );
    assert!(find(&out, b"IHDR").is_some());
    assert!(out.ends_with(png_chunk(b"IEND", &[])));

    assert_eq!(removed.len(), 3, "{removed:?}"); // text, exif, time
}

#[test]
fn scrubs_webp_chunks_and_fixes_riff_size() {
    let src = webp_fixture(true);
    let (out, removed) = images::scrub_image(MediaFormat::WebP, &src).unwrap();

    assert!(find(&out, b"EXIF").is_none());
    assert!(find(&out, b"XMP ").is_none());
    assert!(find(&out, b"VP8L").is_some());

    let riff_size = u32::from_le_bytes([out[4], out[5], out[6], out[7]]) as usize;
    assert_eq!(riff_size + 8, out.len(), "RIFF size not rewritten");

    assert!(removed.iter().any(|r| r.contains("EXIF")));
    assert!(removed.iter().any(|r| r.contains("XMP")));
}

#[test]
fn scrubs_gif_blocks_and_keeps_image_data() {
    let src = gif_fixture(true);
    let (out, removed) = images::scrub_image(MediaFormat::Gif, &src).unwrap();

    assert!(find(&out, b"EVIL!").is_none());
    assert!(find(&out, b"XMP DataXMP").is_none());
    assert!(find(&out, &[0x2C]).is_some(), "image descriptor lost");

    // Image data block and trailer survive untouched (last 18 bytes).
    assert_eq!(&out[out.len() - 18..], &src[src.len() - 18..]);
    assert_eq!(removed.len(), 2, "{removed:?}");

    let (out2, removed2) = images::scrub_image(MediaFormat::Gif, &out).unwrap();
    assert_eq!(out, out2);
    assert!(removed2.is_empty());
}

#[test]
fn bmp_is_a_validated_noop() {
    let src = b"BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00pixeldata!".to_vec();
    let (out, removed) = images::scrub_image(MediaFormat::Bmp, &src).unwrap();
    assert_eq!(out, src);
    assert!(removed.is_empty());
}

#[test]
fn tiff_rebuild_preserves_pixels_and_drops_metadata() {
    let src = tiff_fixture();
    let (out, removed) = images::scrub_image(MediaFormat::Tiff, &src).unwrap();

    assert!(find(&out, EVIL_CAMERA).is_none(), "Make survived");
    assert!(find(&out, b"2026:01:01").is_none(), "DateTime survived");

    assert!(removed.iter().any(|r| r.contains("Camera")), "{removed:?}");
    assert!(removed.iter().any(|r| r.contains("Authorship")), "{removed:?}");
    assert!(removed.iter().any(|r| r.contains("EXIF")), "{removed:?}");

    let entries = parse_tiff_entries(&out);
    let tags: HashSet<u16> = entries.iter().map(|e| e.0).collect();
    for expected in [254u16, 256, 257, 258, 259, 262, 273, 277, 278, 279, 282, 283, 296] {
        assert!(tags.contains(&expected), "lost essential tag {expected}");
    }
    assert!(!tags.contains(&271) && !tags.contains(&306) && !tags.contains(&34665));

    let bps = entries.iter().find(|e| e.0 == 258).unwrap();
    assert_eq!(bps.3, &[8, 0, 8, 0, 8, 0]);

    let strip = entries.iter().find(|e| e.0 == 273).unwrap();
    let new_off = u32::from_le_bytes([strip.3[0], strip.3[1], strip.3[2], strip.3[3]]) as usize;
    let original_pixels = &src[src.len() - 48..];
    assert_eq!(&out[new_off..new_off + 48], original_pixels, "pixels corrupted");

    assert!(out.len() <= src.len());
    assert_eq!(detect_media_format(&out), Some(MediaFormat::Tiff));

    let (out2, removed2) = images::scrub_image(MediaFormat::Tiff, &out).unwrap();
    assert!(removed2.is_empty(), "{removed2:?}");
    assert_eq!(parse_tiff_entries(&out2).len(), entries.len());
}

#[test]
fn tiff_wrong_endianness_fails_closed() {
    let mut be = tiff_fixture();
    be[0] = b'M';
    be[1] = b'M';
    // Offsets/values remain little-endian → parser must bail, not guess.
    let err = images::scrub_image(MediaFormat::Tiff, &be).unwrap_err();
    assert!(matches!(err, CryptoError::MalformedFile(_)));
}

#[test]
fn tiff_corrupt_entries_never_panic() {
    let mut src = tiff_fixture();
    src[16] = 0xFF; // corrupt first entry type byte
    let result = images::scrub_image(MediaFormat::Tiff, &src);
    match result {
        Ok((out, _)) => {
            // If it rebuilt at all, only whitelist tags may remain.
            for (tag, _, _, _) in parse_tiff_entries(&out) {
                assert!(![271u16, 306, 34665].contains(&tag));
            }
        }
        Err(CryptoError::MalformedFile(_)) => {} // fail-closed is fine
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

// ===========================================================================
// Document scrub tests
// ===========================================================================

#[test]
fn pdf_info_and_xmp_are_removed() {
    use lopdf::{dictionary, Document, Object};

    let mut doc = Document::new();
    let info_id = doc.add_object(dictionary! {
        "Author" => "Sneaky Author",
        "Producer" => "Evil Producer",
    });
    let pages_id = doc.add_object(dictionary! {
        "Type" => "Pages",
        "Kids" => Vec::<Object>::new(),
        "Count" => 0,
    });
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => Object::Reference(pages_id),
    });
    let meta_stream = lopdf::Stream::new(
        dictionary! {"Type" => "Metadata", "Subtype" => "XML"},
        b"<x:xmpmeta>secret-author@example</x:xmpmeta>".to_vec(),
    );
    let meta_id = doc.add_object(Object::Stream(meta_stream));
    doc.trailer.set("Root", Object::Reference(catalog_id));
    doc.trailer.set("Info", Object::Reference(info_id));
    doc.get_object_mut(catalog_id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Metadata", Object::Reference(meta_id));

    let mut src = Vec::new();
    doc.save_to(&mut src).unwrap();

    let (out, removed) = documents::scrub_document(MediaFormat::Pdf, &src).unwrap();

    let reparsed = Document::load_mem(&out).unwrap();
    assert!(reparsed.trailer.get(b"Info").is_err(), "Info ref survived");
    let dump = String::from_utf8_lossy(&out);
    assert!(!dump.contains("Sneaky Author"), "author string survived");
    assert!(!dump.contains("Evil Producer"), "producer string survived");
    assert!(!dump.contains("secret-author@example"), "XMP survived");

    assert!(removed.iter().any(|r| r.contains("Document info")));
    assert!(removed.iter().any(|r| r.contains("XMP")));
}

#[test]
fn docx_props_removed_and_package_stays_consistent() {
    use std::io::Read as _;
    use zip::ZipArchive;

    let src = docx_fixture();
    let (out, removed) = documents::scrub_document(MediaFormat::Ooxml, &src).unwrap();

    let reader = std::io::Cursor::new(&out);
    let mut ar = ZipArchive::new(reader).unwrap();
    let names: HashSet<String> = (0..ar.len())
        .map(|i| ar.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(!names.contains("docProps/core.xml"));
    assert!(names.contains("word/document.xml"));

    let mut ct = String::new();
    ar.by_name("[Content_Types].xml")
        .unwrap()
        .read_to_string(&mut ct)
        .unwrap();
    assert!(!ct.contains("/docProps"), "content-types override survived");
    assert!(ct.contains("/word/document.xml"));

    let mut rels = String::new();
    ar.by_name("_rels/.rels").unwrap().read_to_string(&mut rels).unwrap();
    assert!(!rels.contains("docProps"), ".rels reference survived");
    assert!(rels.contains("word/document.xml"));

    let mut document = Vec::new();
    ar.by_name("word/document.xml")
        .unwrap()
        .read_to_end(&mut document)
        .unwrap();
    assert!(find(&document, b"hello").is_some(), "payload damaged");
    assert!(find(&out, b"Sneaky Author").is_none(), "author survived");

    assert!(removed.iter().any(|r| r.contains("Core properties")));
}

// ===========================================================================
// Media scrub tests (lofty-backed, file-based)
// ===========================================================================

#[test]
fn mp3_tags_removed_sync_frame_kept() {
    let dir = tmp_dir("mp3");
    let src_path = write_file(&dir, "song.mp3", &mp3_fixture());

    let dest = dir.join("scratch.mp3");
    std::fs::File::create(&dest).unwrap();
    let removed = super::media::scrub_media_file(&src_path, &dest).unwrap();

    let out = std::fs::read(&dest).unwrap();
    assert!(removed.iter().any(|r| r.contains("ID3v2")), "{removed:?}");
    assert!(!out.starts_with(b"ID3"), "ID3v2 survived");
    assert!(find(&out, b"EVILALBUM").is_none());
    assert!(out.starts_with(&[0xFF, 0xFB]), "mpeg frame lost");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wav_riff_info_removed_pcm_kept() {
    let dir = tmp_dir("wav");
    let src_path = write_file(&dir, "clip.wav", &wav_fixture());

    let dest = dir.join("scratch.wav");
    std::fs::File::create(&dest).unwrap();
    let removed = super::media::scrub_media_file(&src_path, &dest).unwrap();

    let out = std::fs::read(&dest).unwrap();
    assert!(removed.iter().any(|r| r.contains("RIFF INFO")), "{removed:?}");
    assert!(find(&out, b"INAM").is_none(), "INAM survived");
    assert!(find(&out, b"SECRET").is_none());
    assert!(find(&out, b"data").is_some(), "data chunk lost");
    assert!(find(&out, b"fmt ").is_some(), "fmt chunk lost");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn flac_comments_removed_streaminfo_kept() {
    let dir = tmp_dir("flac");
    let src_path = write_file(&dir, "track.flac", &flac_fixture());

    let dest = dir.join("scratch.flac");
    std::fs::File::create(&dest).unwrap();
    let removed = super::media::scrub_media_file(&src_path, &dest).unwrap();

    let out = std::fs::read(&dest).unwrap();
    assert!(removed.iter().any(|r| r.contains("Vorbis")), "{removed:?}");
    assert!(out.starts_with(b"fLaC"));
    assert!(find(&out, b"Evil Singer").is_none(), "artist survived");
    assert!(find(&out, b"Secret Track").is_none(), "title survived");

    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// End-to-end orchestration tests (scrub_file)
// ===========================================================================

#[test]
fn cleaned_copy_default_naming_and_original_untouched() {
    let dir = tmp_dir("copy-default");
    let src = write_file(&dir, "photo.jpg", &jpeg_fixture(true));
    let original = std::fs::read(&src).unwrap();

    let report =
        scrub_file(&src, None, ScrubOutput::CleanedCopy, false, &NullReporter, None).unwrap();

    assert_eq!(report.format, MediaFormat::Jpeg);
    assert!(!report.removed.is_empty());
    assert!(report.bytes_after < report.bytes_before);

    assert!(dir.join("photo.clean.jpg").exists());
    let cleaned = std::fs::read(dir.join("photo.clean.jpg")).unwrap();
    assert!(find(&cleaned, EVIL_CAMERA).is_none());
    assert_eq!(std::fs::read(&src).unwrap(), original, "original modified");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn explicit_dest_conflict_respected() {
    let dir = tmp_dir("conflict");
    let src = write_file(&dir, "a.png", &png_fixture(true));
    let existing_dest = write_file(&dir, "b.png", b"precious");

    let err = scrub_file(
        &src,
        Some(&existing_dest),
        ScrubOutput::CleanedCopy,
        false,
        &NullReporter,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, CryptoError::FileAlreadyExists(_)));
    assert_eq!(std::fs::read(&existing_dest).unwrap(), b"precious");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unsupported_formats_fail_loudly_without_output() {
    let dir = tmp_dir("unsupported");

    for (name, data) in [
        ("plain.zip", b"PK\x03\x04not-an-office-doc".to_vec()),
        ("vault.vx2", b"VAULTX04encrypted-bytes".to_vec()),
        ("blob.bin", b"\x00\x01\x02random-garbage".to_vec()),
    ] {
        let src = write_file(&dir, name, &data);
        let err =
            scrub_file(&src, None, ScrubOutput::CleanedCopy, false, &NullReporter, None).unwrap_err();
        assert!(
            matches!(err, CryptoError::UnsupportedMediaFormat(_)),
            "{name}: {err:?}"
        );
    }

    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 3, "stray outputs left");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn truncated_files_fail_cleanly() {
    let dir = tmp_dir("truncated");

    let png_trunc = &png_fixture(true)[..14];
    let src = write_file(&dir, "cut.png", png_trunc);
    let err = scrub_file(&src, None, ScrubOutput::InPlace, false, &NullReporter, None).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::MalformedFile(_) | CryptoError::UnsupportedMediaFormat(_)
    ));

    let jpg_trunc = &jpeg_fixture(true)[..6];
    let src = write_file(&dir, "cut.jpg", jpg_trunc);
    let err = scrub_file(&src, None, ScrubOutput::InPlace, false, &NullReporter, None).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::MalformedFile(_) | CryptoError::UnsupportedMediaFormat(_)
    ));

    let litter: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(litter.is_empty(), "tmp litter: {litter:?}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cancel_flag_prevents_work_and_output() {
    let dir = tmp_dir("cancel");
    let src = write_file(&dir, "pic.jpg", &jpeg_fixture(true));

    let flag = Arc::new(AtomicBool::new(true));
    let err = scrub_file(
        &src,
        None,
        ScrubOutput::CleanedCopy,
        false,
        &NullReporter,
        Some(&flag),
    )
    .unwrap_err();
    assert!(matches!(err, CryptoError::Cancelled));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "output despite cancel");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn in_place_replaces_source_atomically() {
    let dir = tmp_dir("inplace");
    let src = write_file(&dir, "pic.jpg", &jpeg_fixture(true));
    let original = std::fs::read(&src).unwrap();

    let report = scrub_file(&src, None, ScrubOutput::InPlace, false, &NullReporter, None).unwrap();
    assert_eq!(report.format, MediaFormat::Jpeg);

    let out = std::fs::read(&src).unwrap();
    assert!(out.len() < original.len());
    assert!(find(&out, EVIL_CAMERA).is_none());
    assert!(out.ends_with(&[0xFF, 0xD9]));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wipe_original_removes_source_in_copy_mode() {
    let dir = tmp_dir("wipe");
    let src = write_file(&dir, "gone.jpg", &jpeg_fixture(true));

    scrub_file(&src, None, ScrubOutput::CleanedCopy, true, &NullReporter, None).unwrap();
    assert!(!src.exists(), "original survived wipe_original");
    assert!(dir.join("gone.clean.jpg").exists());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn idempotence_across_formats() {
    for (name, data, format) in [
        ("idem.jpg", jpeg_fixture(true), MediaFormat::Jpeg),
        ("idem.png", png_fixture(true), MediaFormat::Png),
        ("idem.webp", webp_fixture(true), MediaFormat::WebP),
        ("idem.gif", gif_fixture(true), MediaFormat::Gif),
        ("idem.tiff", tiff_fixture(), MediaFormat::Tiff),
    ] {
        let dir = tmp_dir(&format!("idem-{name}"));
        let src = write_file(&dir, name, &data);
        scrub_file(&src, None, ScrubOutput::InPlace, false, &NullReporter, None).unwrap();
        let once = std::fs::read(&src).unwrap();

        let report =
            scrub_file(&src, None, ScrubOutput::InPlace, false, &NullReporter, None).unwrap();
        assert_eq!(report.format, format);
        assert!(
            report.removed.is_empty(),
            "{name}: second pass removed {:?}",
            report.removed
        );
        assert_eq!(once, std::fs::read(&src).unwrap(), "{name}: mutated on second pass");

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn missing_source_errors() {
    let dir = tmp_dir("missing");
    let err = scrub_file(
        &dir.join("nope.jpg"),
        None,
        ScrubOutput::CleanedCopy,
        false,
        &NullReporter,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, CryptoError::NotAFile(_)));
    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// Test-only helpers
// ===========================================================================

type TiffEntryTuple = (u16, u16, u32, Vec<u8>);

/// Independent minimal TIFF reader for verifying rebuilt files.
fn parse_tiff_entries(data: &[u8]) -> Vec<TiffEntryTuple> {
    assert_eq!(&data[0..4], b"II*\0");
    let rd16 = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
    let rd32 = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);

    let ifd = rd32(4) as usize;
    let count = rd16(ifd) as usize;
    let mut entries = Vec::new();
    for i in 0..count {
        let base = ifd + 2 + i * 12;
        let tag = rd16(base);
        let typ = rd16(base + 2);
        let cnt = rd32(base + 4);
        let unit = [0u32, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8][typ as usize] as usize;
        let total = unit * cnt as usize;
        let raw = if total <= 4 {
            data[base + 8..base + 8 + total].to_vec()
        } else {
            let off = rd32(base + 8) as usize;
            data[off..off + total].to_vec()
        };
        entries.push((tag, typ, cnt, raw));
    }
    entries
}
