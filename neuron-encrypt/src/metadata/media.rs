//! Audio/video container scrubbers via lofty: MP3 (ID3v1/v2, APE),
//! FLAC, OGG (Vorbis comments), WAV (RIFF INFO), MP4/MOV (ilst/iTunes).
//!
//! lofty rewrites containers correctly, including MP4 chunk-offset (stco)
//! patching when tag atoms are removed — hand-rolling that safely is out of
//! scope here.

use std::path::Path;

use lofty::config::WriteOptions;
use lofty::prelude::*;
use lofty::probe::Probe;
use lofty::tag::{Tag, TagType};

use crate::error::{CryptoError, CryptoResult};

fn tag_type_name(tt: TagType) -> &'static str {
    match tt {
        TagType::VorbisComments => "Vorbis comments",
        TagType::Id3v2 => "ID3v2",
        TagType::Id3v1 => "ID3v1",
        TagType::Ape => "APE tags",
        TagType::Mp4Ilst => "iTunes/MP4 metadata",
        TagType::RiffInfo => "RIFF INFO",
        TagType::AiffText => "AIFF text chunks",
        _ => "Container tags",
    }
}

/// Validate the outer RIFF container before handing the file to lofty.
///
/// A RIFF chunk declares its own length in the four bytes at offset 4. When
/// that length does not match the file, the container is inconsistent — and
/// lofty's WAV writer does `size + n` on that field without a checked
/// addition, so a file claiming `u32::MAX` makes it panic with "attempt to
/// add with overflow". The release profile is `panic = "abort"`, so that
/// panic kills the whole process instead of surfacing as an error.
///
/// Catching it here keeps the module's fail-closed promise: a structurally
/// impossible container is rejected, the source is left untouched, and no
/// third-party parser ever sees it.
fn validate_riff_container(src: &Path, format: super::MediaFormat) -> CryptoResult<()> {
    if format != super::MediaFormat::Wav {
        return Ok(());
    }

    let mut header = [0u8; 12];
    {
        use std::io::Read;
        let mut file = std::fs::File::open(src)?;
        let mut filled = 0;
        while filled < header.len() {
            match file.read(&mut header[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        if filled < 12 {
            return Err(CryptoError::MalformedFile(
                "WAV header is truncated".to_string(),
            ));
        }
    }

    if &header[0..4] != b"RIFF" {
        return Err(CryptoError::MalformedFile(
            "WAV does not start with a RIFF chunk".to_string(),
        ));
    }

    let declared = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;
    let file_len = std::fs::metadata(src)?.len();

    // `ckSize` counts everything after the size field itself.
    let expected = declared.saturating_add(8);
    if expected > file_len {
        return Err(CryptoError::MalformedFile(format!(
            "WAV RIFF size {declared} exceeds the file ({file_len} bytes)"
        )));
    }

    Ok(())
}

/// Strip every tag from the media file at `src`, writing the clean file to
/// `dest`.
///
/// Lofty's save becomes a no-op when no tags are registered on the file, so
/// tag *removal* is expressed as replacing each existing tag with an empty
/// one — the writer then rebuilds (or drops) the container's tag blocks with
/// zero items. This also patches MP4 chunk-offset tables correctly.
pub fn scrub_media_file(
    src: &Path,
    dest: &Path,
    format: super::MediaFormat,
) -> CryptoResult<Vec<String>> {
    validate_riff_container(src, format)?;

    // Copy source into the scratch destination; lofty then rewrites it.
    std::fs::copy(src, dest)?;

    let probe = Probe::open(dest)
        .map_err(|e| CryptoError::MalformedFile(format!("media open failed: {e}")))?
        .guess_file_type()
        .map_err(|e| CryptoError::MalformedFile(format!("media probe failed: {e}")))?;

    let mut tagged = probe
        .read()
        .map_err(|e| CryptoError::MalformedFile(format!("media parse failed: {e}")))?;

    let tag_types: Vec<TagType> = tagged.tags().iter().map(|t| t.tag_type()).collect();
    if tag_types.is_empty() {
        return Ok(Vec::new());
    }

    for tt in &tag_types {
        tagged.remove(*tt);
        tagged.insert_tag(Tag::new(*tt));
    }

    tagged
        .save_to_path(dest, WriteOptions::new())
        .map_err(|e| CryptoError::ScrubFailed(format!("media rewrite failed: {e}")))?;

    Ok(tag_types
        .iter()
        .map(|tt| tag_type_name(*tt).to_string())
        .collect())
}
