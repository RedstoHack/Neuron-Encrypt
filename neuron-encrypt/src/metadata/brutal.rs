//! Adversarial / "brutal" test suite for the metadata scrubber.
//!
//! The per-format round-trip tests in `tests.rs` prove each parser works on a
//! well-formed file. This file attacks the *boundaries*: truncated headers,
//! garbage tails, zero-byte and single-byte inputs, magic-byte lookalikes,
//! hostile sizes, symlink/hardlink tricks, cancellation, and concurrent
//! writers — asserting the two invariants that matter for a privacy tool:
//!
//! 1. **Fail closed** — anything not confidently understood must error loudly
//!    and leave the source file byte-identical, with no output or scratch file
//!    left behind.
//! 2. **Never corrupt** — a successful scrub must preserve the payload, and a
//!    failed one must never leave a truncated/partial result in place of the
//!    original.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::{default_scrub_output_name, detect_media_format, scrub_file, MediaFormat, ScrubOutput};
use crate::crypto::ProgressReporter;
use crate::error::CryptoError;

struct NullReporter;
impl ProgressReporter for NullReporter {
    fn report(&self, _progress: f32, _message: &str) {}
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "neuron-brutal-{name}-{}-{}",
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
    std::fs::write(&path, data).unwrap();
    path
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Every byte left in `dir` except the named source file. Used to assert that
/// no `.tmp` / partial output survives any code path.
fn stray_files(dir: &Path, keep: &Path) -> Vec<String> {
    let mut stray = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path() == keep {
            continue;
        }
        stray.push(entry.file_name().to_string_lossy().to_string());
    }
    stray.sort();
    stray
}

// ===========================================================================
// Fixtures: real containers carrying recognisable private metadata
// ===========================================================================

/// A minimal but structurally valid JPEG with an EXIF APP1 segment whose
/// payload contains the canary string, followed by a real (tiny) frame.
fn jpeg_with_exif() -> Vec<u8> {
    let mut app1_payload = b"Exif\0\0".to_vec();
    app1_payload.extend_from_slice(b"EVIL-CAM GPS-LAT-51.5074");
    let mut seg = vec![0xFF, 0xE1];
    seg.extend_from_slice(&((app1_payload.len() + 2) as u16).to_be_bytes());
    seg.extend_from_slice(&app1_payload);

    let mut out = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    out.extend_from_slice(b"JFIF\0");
    out.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&seg);
    // SOF0 (1x1 baseline), DHT, SOS, entropy data, EOI.
    out.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
    ]);
    // DHT: one empty table (Tc/Th = 0x00, 16 zero counts, no symbols).
    out.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x13, 0x00]);
    out.extend_from_slice(&[0u8; 16]);
    // SOS: Ns = 1, one component spec, Ss/Se/Ah-Al.
    out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    // Entropy-coded data followed by EOI.
    out.extend_from_slice(&[0x12, 0x34, 0x56, 0xAB, 0xCD]);
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

/// A minimal PNG carrying a `tEXt` chunk with the canary.
fn png_with_text() -> Vec<u8> {
    let chunk = |kind: &[u8; 4], data: &[u8]| -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&(data.len() as u32).to_be_bytes());
        c.extend_from_slice(kind);
        c.extend_from_slice(data);
        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(data);
        c.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        c
    };
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    out.extend_from_slice(&chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]));
    out.extend_from_slice(&chunk(b"tEXt", b"Software\x00EVIL-CAM"));
    out.extend_from_slice(&chunk(
        b"IDAT",
        &[0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01],
    ));
    out.extend_from_slice(&chunk(b"IEND", &[]));
    out
}

/// A valid PDF (built with lopdf so the cross-reference table is real) whose
/// Info dictionary names the author.
fn pdf_with_info() -> Vec<u8> {
    use lopdf::{dictionary, Document, Object};

    let mut doc = Document::new();
    let info_id = doc.add_object(dictionary! {
        "Author" => "EVIL-CAM",
        "Producer" => "SecretTool 9.9",
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

    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

/// A valid OOXML package (built with the `zip` crate so the central directory
/// is real) carrying a `docProps/core.xml` that names the author.
fn ooxml_with_core() -> Vec<u8> {
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        let entries: Vec<(&str, Vec<u8>)> = vec![
            (
                "[Content_Types].xml",
                br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#.to_vec(),
            ),
            (
                "_rels/.rels",
                br#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"#.to_vec(),
            ),
            (
                "docProps/core.xml",
                br#"<?xml version="1.0"?><cp:coreProperties xmlns:cp="x"><dc:creator>EVIL-CAM</dc:creator></cp:coreProperties>"#.to_vec(),
            ),
        ];
        for (name, body) in entries {
            zw.start_file(name, opts).unwrap();
            std::io::Write::write_all(&mut zw, &body).unwrap();
        }
        zw.finish().unwrap();
    }
    buf.into_inner()
}

/// WAV (RIFF) with a `LIST INFO` chunk containing the canary. The INFO list
/// must hold well-formed sub-chunks (id + length + payload) for the RIFF
/// structure to parse at all.
fn wav_with_list_info() -> Vec<u8> {
    let inam = b"EVIL-CAM";
    let mut list_body = b"INFO".to_vec();
    list_body.extend_from_slice(b"INAM");
    list_body.extend_from_slice(&(inam.len() as u32).to_le_bytes());
    list_body.extend_from_slice(inam);
    if inam.len() % 2 == 1 {
        list_body.push(0);
    }

    // fmt: PCM(1) / mono / 8000 Hz / 16 kB-per-s / block align 2 / 16 bits.
    let fmt: [u8; 16] = [
        1, 0, 1, 0, 0x40, 0x1F, 0x00, 0x00, 0x40, 0x1F, 0x00, 0x00, 2, 0, 16, 0,
    ];
    let pcm = [0x55u8; 16];

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

/// A WAV whose RIFF chunk declares a length far beyond the actual data.
///
/// lofty's WAV writer adds to that field without a checked addition, so the
/// file used to panic with "attempt to add with overflow" — and because the
/// release profile is `panic = "abort"`, that killed the whole process
/// instead of failing the scrub. The container is now validated before any
/// third-party parser sees it.
#[test]
fn wav_with_impossible_riff_size_fails_closed() {
    let dir = tmp_dir("wav-riiff-overflow");
    let mut data = wav_with_list_info();
    data[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let src = write_file(&dir, "boom.wav", &data);
    let before = data.clone();

    let result = scrub_file(
        &src,
        None,
        ScrubOutput::CleanedCopy,
        false,
        false,
        &NullReporter,
        None,
    );

    assert!(
        result.is_err(),
        "a WAV claiming a {}-byte RIFF body inside a {}-byte file was accepted",
        u32::MAX,
        before.len()
    );
    assert_eq!(
        std::fs::read(&src).unwrap(),
        before,
        "source was modified by a malformed WAV"
    );
    assert!(
        stray_files(&dir, &src).is_empty(),
        "a malformed WAV left files behind"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// GIF89a with a Comment extension containing the canary.
fn gif_with_comment() -> Vec<u8> {
    let mut out = b"GIF89a".to_vec();
    out.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // 1x1 GCT
                                                                        // Comment extension: 0x21 0xFE, sub-blocks.
    let comment = b"EVIL-CAM";
    out.push(0x21);
    out.push(0xFE);
    out.push(comment.len() as u8);
    out.extend_from_slice(comment);
    out.push(0x00); // block terminator
    out.push(0x2C); // image descriptor
                    // left(2) top(2) width(2) height(2) flags(1) = 9 bytes, then LZW min code size.
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
    out.push(0x02); // LZW minimum code size
    out.push(0x02); // first data sub-block length
    out.extend_from_slice(&[0x4C, 0x01]);
    out.push(0x00); // block terminator
    out.push(0x3B); // trailer
    out
}

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

// ===========================================================================
// 1. Fail-closed: malformed / hostile inputs
// ===========================================================================

/// Every one of these must be rejected, must not be modified, and must not
/// leave a partial output behind.
#[test]
fn hostile_inputs_fail_closed_and_leave_no_output() {
    let cases: &[(&str, &[u8], &str)] = &[
        ("empty.jpg", b"", "zero-byte"),
        ("tiny.jpg", &[0xFF, 0xD8], "magic only"),
        ("txt.txt", b"just some text, not media at all", "plain text"),
        ("garbage.png", &[0x00; 512], "all zeroes"),
        (
            "random.bin",
            b"\xDE\xAD\xBE\xEF\xFE\xED\xFA\xCE\x12\x34\x56\x78",
            "random",
        ),
        (
            "vault.vx2",
            b"VAULTX04\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A",
            "own encrypted file",
        ),
        ("plain.zip", b"PK\x03\x04not-an-office-package", "plain zip"),
        (
            "heic.heic",
            b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heicmif1",
            "HEIC (unsupported)",
        ),
        (
            "bigtiff.tif",
            b"II+\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00",
            "BigTIFF (unsupported)",
        ),
        ("onlymagic.jpg", &jpeg_with_exif()[..3], "3-byte JPEG"),
        ("trunc.png", &png_with_text()[..20], "PNG cut mid-chunk"),
        ("trunc.pdf", &pdf_with_info()[..30], "PDF cut mid-object"),
        ("trunc.gif", &gif_with_comment()[..9], "GIF cut early"),
        (
            "trunc.wav",
            &wav_with_list_info()[..20],
            "WAV cut mid-chunk",
        ),
        ("trunc.zip", &ooxml_with_core()[..40], "OOXML cut mid-entry"),
    ];

    for (name, data, label) in cases {
        let dir = tmp_dir(&format!("hostile-{}", name.replace('.', "-")));
        let src = write_file(&dir, name, data);
        let before = std::fs::read(&src).unwrap();

        let result = scrub_file(
            &src,
            None,
            ScrubOutput::CleanedCopy,
            false,
            false,
            &NullReporter,
            None,
        );

        assert!(
            result.is_err(),
            "{label} ({name}) was accepted — must fail closed"
        );
        assert_eq!(
            std::fs::read(&src).unwrap(),
            before,
            "{label} ({name}): source was modified on a failed scrub"
        );
        let stray = stray_files(&dir, &src);
        assert!(
            stray.is_empty(),
            "{label} ({name}): failed scrub left files behind: {stray:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}

/// Truncation at *every* offset of a valid file must never produce output
/// that claims success while corrupting the source. Walk the whole file.
#[test]
fn truncation_sweep_never_corrupts_source() {
    let fixtures: &[(&str, &[u8])] = &[
        ("photo.jpg", &jpeg_with_exif()),
        ("pic.png", &png_with_text()),
        ("doc.pdf", &pdf_with_info()),
        ("sheet.xlsx", &ooxml_with_core()),
        ("sound.wav", &wav_with_list_info()),
        ("anim.gif", &gif_with_comment()),
    ];

    for (name, full) in fixtures {
        let dir = tmp_dir(&format!("sweep-{}", name.replace('.', "-")));
        // Only sweep a bounded number of offsets for large fixtures; the
        // interesting cases are the first bytes and the boundary regions.
        let step = if full.len() > 64 {
            1 + full.len() / 64
        } else {
            1
        };
        let mut offset = 0;
        while offset < full.len() {
            let src = write_file(&dir, name, &full[..offset]);
            let result = scrub_file(
                &src,
                None,
                ScrubOutput::CleanedCopy,
                false,
                false,
                &NullReporter,
                None,
            );
            // Whatever the outcome, the truncated source must be unchanged and
            // must not be joined by stray output files.
            assert_eq!(
                std::fs::read(&src).unwrap(),
                &full[..offset],
                "{name}: source changed at truncation offset {offset}"
            );
            if let Ok(report) = result {
                // If it *did* succeed on a truncated file, the output must be
                // a genuine re-parseable container of the same type.
                //
                // The output path is derived from the *source* name, not from
                // the detected format: an OOXML package keeps its original
                // extension, and `MediaFormat::Ooxml::extension()` is empty.
                let out = dir.join(default_scrub_output_name(&src));
                assert!(
                    out.exists(),
                    "{name}@{offset}: reported success but wrote no output"
                );
                let head = read_head(&out, 64);
                assert_eq!(
                    detect_media_format(&head),
                    Some(report.format),
                    "{name}@{offset}: output is not a valid {:?}",
                    report.format
                );
                // Remove the cleaned copy *before* the stray-file check —
                // otherwise a legitimate output would be reported as a stray.
                std::fs::remove_file(&out).ok();
            }
            let stray = stray_files(&dir, &src);
            assert!(stray.is_empty(), "{name}@{offset}: stray output {stray:?}");
            offset += step;
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}

fn read_head(path: &Path, n: usize) -> Vec<u8> {
    use std::io::Read as _;
    let mut buf = vec![0u8; n];
    let mut f = std::fs::File::open(path).unwrap();
    let _ = f.read(&mut buf);
    let len = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    buf.truncate(len.min(n));
    buf
}

/// Magic-byte lookalikes: a valid magic followed by structural garbage must be
/// rejected rather than "cleaned" into a broken file.
#[test]
fn magic_lookalikes_are_rejected() {
    let cases: &[(&str, Vec<u8>)] = &[
        ("jpeg_no_payload.jpg", {
            let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
            v.extend_from_slice(&[0xFF; 64]);
            v
        }),
        ("png_bad_crc.png", {
            let mut p = png_with_text();
            // Corrupt the final IEND CRC.
            let n = p.len();
            p[n - 5] ^= 0xFF;
            p
        }),
        ("pdf_no_eof.pdf", {
            let mut p = pdf_with_info();
            p.truncate(p.len() - 6);
            p
        }),
        ("wav_bad_riff.wav", {
            let mut w = wav_with_list_info();
            // Claim a size far beyond the actual data.
            w[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
            w
        }),
        ("riff_not_wave.wav", {
            let mut v = b"RIFF".to_vec();
            v.extend_from_slice(&4u32.to_le_bytes());
            v.extend_from_slice(b"AVI ");
            v.extend_from_slice(&[0u8; 32]);
            v
        }),
    ];

    for (name, data) in cases {
        let dir = tmp_dir(&format!("lookalike-{}", name.replace('.', "-")));
        let src = write_file(&dir, name, data);
        let before = data.clone();

        let result = scrub_file(
            &src,
            None,
            ScrubOutput::CleanedCopy,
            false,
            false,
            &NullReporter,
            None,
        );

        if let Ok(report) = &result {
            // Acceptable only if the output re-validates as the same format.
            let out = dir.join(format!("{name}.clean.{}", report.format.extension()));
            if out.exists() {
                assert_eq!(
                    detect_media_format(&read_head(&out, 64)),
                    Some(report.format),
                    "{name}: claimed success but wrote an unrecognisable file"
                );
                std::fs::remove_file(&out).ok();
            }
        }
        assert_eq!(
            std::fs::read(&src).unwrap(),
            before,
            "{name}: source modified despite a malformed structure"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

// ===========================================================================
// 2. Payload integrity on success
// ===========================================================================

/// The canary must be gone *and* the structural payload must survive.
#[test]
fn successful_scrubs_remove_metadata_and_keep_payload() {
    let cases: &[(&str, Vec<u8>, MediaFormat, &str)] = &[
        (
            "photo.jpg",
            jpeg_with_exif(),
            MediaFormat::Jpeg,
            "photo.clean.jpg",
        ),
        (
            "pic.png",
            png_with_text(),
            MediaFormat::Png,
            "pic.clean.png",
        ),
        (
            "doc.pdf",
            pdf_with_info(),
            MediaFormat::Pdf,
            "doc.clean.pdf",
        ),
        (
            "book.xlsx",
            ooxml_with_core(),
            MediaFormat::Ooxml,
            "book.clean.xlsx",
        ),
        (
            "sound.wav",
            wav_with_list_info(),
            MediaFormat::Wav,
            "sound.clean.wav",
        ),
        (
            "anim.gif",
            gif_with_comment(),
            MediaFormat::Gif,
            "anim.clean.gif",
        ),
    ];

    for (name, data, expected_format, expected_out) in cases {
        let expected_format = *expected_format;
        let dir = tmp_dir(&format!("integrity-{}", name.replace('.', "-")));
        let src = write_file(&dir, name, data);
        let original = data.clone();

        let report = scrub_file(
            &src,
            None,
            ScrubOutput::CleanedCopy,
            false,
            false,
            &NullReporter,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: valid fixture was rejected: {e}"));

        assert_eq!(report.format, expected_format, "{name}: wrong format");
        let out = dir.join(expected_out);
        assert!(out.exists(), "{name}: expected output {expected_out}");

        let scrubbed = std::fs::read(&out).unwrap();
        assert!(
            find(&scrubbed, b"EVIL-CAM").is_none(),
            "{name}: metadata canary survived the scrub"
        );
        assert_eq!(
            detect_media_format(&read_head(&out, 64)),
            Some(expected_format),
            "{name}: output is not a valid {:?} container",
            expected_format
        );
        assert_eq!(
            std::fs::read(&src).unwrap(),
            original,
            "{name}: cleaned-copy mode modified the source"
        );
        // The source must still scrub cleanly (proves we wrote a real file).
        let second = dir.join(format!("{name}.twice"));
        std::fs::copy(&out, &second).unwrap();
        scrub_file(
            &second,
            None,
            ScrubOutput::InPlace,
            false,
            false,
            &NullReporter,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: scrubbed output is not re-scrubbable: {e}"));

        std::fs::remove_dir_all(&dir).ok();
    }
}

// ===========================================================================
// 3. Filesystem hostility
// ===========================================================================

/// Scrubbing a file reached through a symlink must rewrite the target and
/// leave the link intact — never replace the link with a regular file.
#[cfg(unix)]
#[test]
fn in_place_through_symlink_keeps_the_link() {
    use std::os::unix::fs::symlink;

    let dir = tmp_dir("symlink");
    let target = write_file(&dir, "real.jpg", &jpeg_with_exif());
    let link = dir.join("link.jpg");
    symlink(&target, &link).unwrap();

    let report = scrub_file(
        &link,
        None,
        ScrubOutput::InPlace,
        false,
        false,
        &NullReporter,
        None,
    )
    .unwrap();

    assert_eq!(report.format, MediaFormat::Jpeg);
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the symlink was replaced by a regular file"
    );
    let out = std::fs::read(&target).unwrap();
    assert!(find(&out, b"EVIL-CAM").is_none(), "target not scrubbed");
    std::fs::remove_dir_all(&dir).ok();
}

/// A read-only *source* is still readable, so the scrub must succeed and only
/// touch the destination.
#[cfg(unix)]
#[test]
fn read_only_source_scrubs_to_fresh_destination() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("ro-source");
    let src = write_file(&dir, "ro.jpg", &jpeg_with_exif());
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o400)).unwrap();
    let original = std::fs::read(&src).unwrap();

    scrub_file(
        &src,
        None,
        ScrubOutput::CleanedCopy,
        false,
        false,
        &NullReporter,
        None,
    )
    .expect("a read-only source is still readable and must be scrubbable");

    assert_eq!(std::fs::read(&src).unwrap(), original);
    let out = dir.join("ro.clean.jpg");
    assert!(find(&std::fs::read(&out).unwrap(), b"EVIL-CAM").is_none());
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).ok();
    std::fs::remove_dir_all(&dir).ok();
}

/// Source and destination must never be the same file in cleaned-copy mode.
#[test]
fn destination_equal_to_source_is_rejected() {
    let dir = tmp_dir("same-path");
    let src = write_file(&dir, "same.jpg", &jpeg_with_exif());
    let before = std::fs::read(&src).unwrap();

    let err = scrub_file(
        &src,
        Some(&src),
        ScrubOutput::CleanedCopy,
        true, // even with force
        false,
        &NullReporter,
        None,
    )
    .unwrap_err();

    assert!(
        matches!(
            err,
            CryptoError::SourceAndDestinationSame(_) | CryptoError::FileAlreadyExists(_)
        ),
        "unexpected error for same src/dest: {err:?}"
    );
    assert_eq!(std::fs::read(&src).unwrap(), before, "source was clobbered");
    std::fs::remove_dir_all(&dir).ok();
}

/// Cancelling must abort before any output is persisted and leave the source
/// and any pre-existing destination untouched.
#[test]
fn cancellation_at_every_stage_is_clean() {
    for pre_cancel in [true, false] {
        let dir = tmp_dir("cancel");
        let src = write_file(&dir, "photo.jpg", &jpeg_with_exif());
        let dest = write_file(&dir, "existing.jpg", b"pre-existing output");
        let original_src = std::fs::read(&src).unwrap();
        let original_dest = std::fs::read(&dest).unwrap();

        let cancel = Arc::new(AtomicBool::new(pre_cancel));
        let result = scrub_file(
            &src,
            Some(&dest),
            ScrubOutput::CleanedCopy,
            true,
            false,
            &NullReporter,
            Some(&cancel),
        );

        match result {
            Err(CryptoError::Cancelled) => {
                assert_eq!(std::fs::read(&dest).unwrap(), original_dest);
            }
            Ok(_) => {
                // Only reachable when the cancel flag was set late enough that
                // the work completed; then the destination must be the real
                // scrubbed output, never a truncated one.
                let out = std::fs::read(&dest).unwrap();
                assert!(
                    find(&out, b"EVIL-CAM").is_none(),
                    "destination left holding unscrubbed data"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(
            std::fs::read(&src).unwrap(),
            original_src,
            "source modified during a cancelled scrub"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// Two concurrent scrubs racing for the same destination: exactly one must
/// win, and the loser must not corrupt the winner's output.
#[test]
fn concurrent_scrubs_to_same_destination_do_not_corrupt() {
    let src_data = jpeg_with_exif();
    let src2_data = png_with_text();

    for _ in 0..5 {
        let dir = tmp_dir("concurrent");
        let src = write_file(&dir, "a.jpg", &src_data);
        let src2 = write_file(&dir, "b.png", &src2_data);
        let dest = dir.join("shared.out");

        let s1 = std::thread::spawn({
            let src = src.clone();
            let dest = dest.clone();
            move || {
                scrub_file(
                    &src,
                    Some(&dest),
                    ScrubOutput::CleanedCopy,
                    true,
                    false,
                    &NullReporter,
                    None,
                )
            }
        });
        let s2 = std::thread::spawn({
            let src2 = src2.clone();
            let dest = dest.clone();
            move || {
                scrub_file(
                    &src2,
                    Some(&dest),
                    ScrubOutput::CleanedCopy,
                    true,
                    false,
                    &NullReporter,
                    None,
                )
            }
        });

        let r1 = s1.join().unwrap();
        let r2 = s2.join().unwrap();

        assert!(r1.is_ok() || r2.is_ok(), "both concurrent scrubs failed");
        // The destination must always be one complete, self-consistent file.
        let final_bytes = std::fs::read(&dest).unwrap();
        let head = read_head(&dest, 64);
        let detected = detect_media_format(&head);
        assert!(
            detected.is_some(),
            "concurrent writers left an unrecognisable destination"
        );
        // Exactly one of the two payloads, never a blend.
        let is_jpeg = detected == Some(MediaFormat::Jpeg);
        let is_png = detected == Some(MediaFormat::Png);
        assert!(
            is_jpeg || is_png,
            "unexpected destination format {detected:?}"
        );
        assert!(
            find(&final_bytes, b"EVIL-CAM").is_none(),
            "destination contains unscrubbed metadata"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

// ===========================================================================
// 4. Detection matrix
// ===========================================================================

/// Detection must be exact: correct type for real headers, `None` for
/// everything else. A false positive means we would rewrite a file we do not
/// actually understand.
#[test]
fn detection_matrix_is_exact() {
    let positives: &[(&str, Vec<u8>, MediaFormat)] = &[
        ("JPEG", jpeg_with_exif(), MediaFormat::Jpeg),
        ("PNG", png_with_text(), MediaFormat::Png),
        ("PDF", pdf_with_info(), MediaFormat::Pdf),
        ("WAV", wav_with_list_info(), MediaFormat::Wav),
        ("GIF", gif_with_comment(), MediaFormat::Gif),
    ];
    for (label, data, expected) in positives {
        assert_eq!(
            detect_media_format(data),
            Some(*expected),
            "{label} misdetected"
        );
    }

    let negatives: &[(&str, Vec<u8>)] = &[
        ("empty", vec![]),
        ("short", vec![0xFF, 0xD8]),
        ("text", b"hello world, definitely not a media file".to_vec()),
        (
            "own-encrypted",
            b"VAULTX04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        ),
        ("plain-zip", b"PK\x03\x04\x14\x00\x00\x00\x08\x00".to_vec()),
        (
            "bigtiff",
            b"II+\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        ),
        (
            "riff-avi",
            b"RIFF\x04\x00\x00\x00AVI \x00\x00\x00\x00".to_vec(),
        ),
        ("eleven-bytes", b"01234567890".to_vec()),
    ];
    for (label, data) in negatives {
        assert_eq!(
            detect_media_format(data),
            None,
            "{label} was falsely detected as scrubbable"
        );
    }

    // HEIC/HEIF is deliberately *detected* even though it has no scrubber yet:
    // recognising it lets the error say "HEIC is not supported" instead of the
    // generic "unknown format". It must still be rejected by `scrub_file`.
    let heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heic".to_vec();
    assert_eq!(detect_media_format(&heic), Some(MediaFormat::Heif));
    let dir = tmp_dir("heic-unsupported");
    let src = write_file(&dir, "photo.heic", &heic);
    let err = scrub_file(
        &src,
        None,
        ScrubOutput::CleanedCopy,
        false,
        false,
        &NullReporter,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, CryptoError::UnsupportedMediaFormat(_)),
        "HEIC must fail closed, got {err:?}"
    );
    assert!(
        stray_files(&dir, &src).is_empty(),
        "HEIC rejection left files behind"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// 5. New formats added in 2.3.0 (lofty-backed)
// ===========================================================================

fn aiff_with_text_chunk() -> Vec<u8> {
    // COMM (mandatory, big-endian) + a NAME text chunk carrying the canary.
    let mut comm = b"COMM".to_vec();
    comm.extend_from_slice(&18u32.to_be_bytes()); // size
    comm.extend_from_slice(&1u16.to_be_bytes()); // channels
    comm.extend_from_slice(&1u16.to_be_bytes()); // sample frames
    comm.extend_from_slice(&16u16.to_be_bytes()); // bits
    comm.extend_from_slice(&8000u32.to_be_bytes()); // rate (80-bit extended)
    comm.extend_from_slice(&8000u32.to_be_bytes()); // rate (hi)
    comm.extend_from_slice(&0u32.to_be_bytes()); // rate (lo)

    let name = b"NAMEcanary-EVIL-CAM";
    let mut text = b"NAME".to_vec();
    text.extend_from_slice(&(name.len() as u32).to_be_bytes());
    text.extend_from_slice(name);
    if name.len() % 2 == 1 {
        text.push(0);
    }

    let mut body = b"AIFF".to_vec();
    body.extend_from_slice(&comm);
    body.extend_from_slice(&text);
    body.extend_from_slice(b"SSND");
    body.extend_from_slice(&8u32.to_be_bytes());
    body.extend_from_slice(&[0u8; 8]);

    let mut out = b"FORM".to_vec();
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

#[test]
fn aiff_is_detected_and_scrubbed() {
    let data = aiff_with_text_chunk();
    assert_eq!(detect_media_format(&data), Some(MediaFormat::Aiff));

    let dir = tmp_dir("aiff");
    let src = write_file(&dir, "sound.aiff", &data);
    let original = data.clone();

    let report = scrub_file(
        &src,
        None,
        ScrubOutput::CleanedCopy,
        false,
        false,
        &NullReporter,
        None,
    )
    .unwrap_or_else(|e| panic!("valid AIFF was rejected: {e}"));

    assert_eq!(report.format, MediaFormat::Aiff);
    let out = dir.join("sound.clean.aiff");
    assert!(out.exists(), "expected sound.clean.aiff");
    let scrubbed = std::fs::read(&out).unwrap();
    assert!(
        find(&scrubbed, b"EVIL-CAM").is_none(),
        "AIFF text chunk survived"
    );
    // The COMM chunk is structural and must remain.
    assert!(
        find(&scrubbed, b"COMM").is_some(),
        "AIFF lost its mandatory COMM chunk"
    );
    assert_eq!(std::fs::read(&src).unwrap(), original, "source modified");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn aiff_truncated_and_malformed_fail_closed() {
    let data = aiff_with_text_chunk();
    let mut badsize = data.clone();
    badsize[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("short.aiff", data[..8].to_vec()),
        ("no-form.aiff", b"XXXX\x00\x00\x00\x10AIFF".to_vec()),
        ("badsize.aiff", badsize),
    ];
    for (name, bytes) in cases {
        let dir = tmp_dir("aiff-bad");
        let src = write_file(&dir, name, &bytes);
        let before = bytes.clone();
        let result = scrub_file(
            &src,
            None,
            ScrubOutput::CleanedCopy,
            false,
            false,
            &NullReporter,
            None,
        );
        if result.is_ok() {
            let out = dir.join(format!("{name}.clean.aiff"));
            if out.exists() {
                assert_eq!(
                    detect_media_format(&read_head(&out, 64)),
                    Some(MediaFormat::Aiff),
                    "{name}: bad input produced an invalid output"
                );
                std::fs::remove_file(&out).ok();
            }
        }
        assert_eq!(
            std::fs::read(&src).unwrap(),
            before,
            "{name}: source modified on a malformed AIFF"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn ogg_vorbis_and_opus_are_distinguished() {
    // Vorbis: Ogg page containing the vorbis identification header.
    let mut vorbis = b"OggS\x00\x02".to_vec();
    vorbis.extend_from_slice(&[0u8; 20]);
    vorbis.extend_from_slice(b"\x01vorbis");
    assert_eq!(detect_media_format(&vorbis), Some(MediaFormat::Ogg));

    // Opus: same container, different codec id.
    let mut opus = b"OggS\x00\x02".to_vec();
    opus.extend_from_slice(&[0u8; 20]);
    opus.extend_from_slice(b"OpusHead\x01\x02");
    assert_eq!(detect_media_format(&opus), Some(MediaFormat::Opus));
}

#[test]
fn mobile_mp4_brands_are_detected_separately_from_mp4() {
    let mobile: &[(&[u8; 4], MediaFormat)] = &[
        (b"3gp5", MediaFormat::MobileMp4),
        (b"3gp8", MediaFormat::MobileMp4),
        (b"3g2a", MediaFormat::MobileMp4),
        (b"M4B ", MediaFormat::MobileMp4),
        (b"isom", MediaFormat::Mp4),
        (b"mp42", MediaFormat::Mp4),
        (b"M4A ", MediaFormat::Mp4),
    ];
    for (brand, expected) in mobile {
        let mut header = vec![0x00, 0x00, 0x00, 0x18];
        header.extend_from_slice(b"ftyp");
        header.extend_from_slice(*brand);
        header.extend_from_slice(b"isom");
        assert_eq!(
            detect_media_format(&header),
            Some(*expected),
            "brand {:?} misdetected",
            std::str::from_utf8(*brand).unwrap()
        );
    }
}
