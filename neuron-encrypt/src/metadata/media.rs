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

/// Strip every tag from the media file at `src`, writing the clean file to
/// `dest`.
///
/// Lofty's save becomes a no-op when no tags are registered on the file, so
/// tag *removal* is expressed as replacing each existing tag with an empty
/// one — the writer then rebuilds (or drops) the container's tag blocks with
/// zero items. This also patches MP4 chunk-offset tables correctly.
pub fn scrub_media_file(src: &Path, dest: &Path) -> CryptoResult<Vec<String>> {
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
