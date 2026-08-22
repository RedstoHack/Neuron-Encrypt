//! Audio/video container scrubbers via lofty: MP3 (ID3v1/v2, APE),
//! FLAC, OGG (Vorbis comments), WAV (RIFF INFO), MP4/MOV (ilst/iTunes).
//!
//! lofty rewrites containers correctly, including MP4 chunk-offset (stco)
//! patching when tag atoms are removed — hand-rolling that safely is out of
//! scope here.

use std::path::Path;

use lofty::config::WriteOptions;
use lofty::file::TagType;
use lofty::prelude::*;
use lofty::probe::Probe;

use crate::error::{CryptoError, CryptoResult};

fn tag_type_name(tt: TagType) -> &'static str {
    match tt {
        TagType::VorbisComments => "Vorbis comments",
        TagType::Id3v2 => "ID3v2",
        TagType::Id3v1 => "ID3v1",
        TagType::Ape => "APE tags",
        TagType::Ilst => "iTunes/MP4 metadata",
        TagType::RiffInfo => "RIFF INFO",
        TagType::Matroska => "Matroska tags",
        _ => "Container tags",
    }
}

/// Strip every tag from the media file at `src`, writing the clean file to
/// `dest` (which must already exist as an empty scratch file created by the
/// orchestrator — lofty rewrites in place, so the caller copies first).
pub fn scrub_media_file(src: &Path, dest: &Path) -> CryptoResult<Vec<String>> {
    // Copy source into the scratch destination; lofty then rewrites it.
    std::fs::copy(src, dest)?;

    let mut tagged = Probe::open(dest)
        .and_then(|probe| probe.guess_file_type())
        .and_then(|probe| probe.read())
        .map_err(|e| CryptoError::MalformedFile(format!("media parse failed: {e}")))?;

    let removed: Vec<String> = tagged
        .tags()
        .iter()
        .map(|t| tag_type_name(t.tag_type()).to_string())
        .collect();

    if removed.is_empty() {
        return Ok(removed);
    }

    tagged.clear();

    tagged
        .save_to_path(dest, WriteOptions::new())
        .map_err(|e| CryptoError::ScrubFailed(format!("media rewrite failed: {e}")))?;

    Ok(removed)
}
