//! Image scrubbers: JPEG, PNG, WebP, GIF, TIFF (hand-rolled parsers),
//! BMP (validated no-op).
//!
//! Everything here follows one rule: copy the container verbatim and drop
//! only metadata elements. Kept chunks/segments are byte-for-byte identical
//! to the source, so no checksums ever need recomputing and the decoder-
//! relevant payload cannot be altered.

use super::MediaFormat;
use crate::error::{CryptoError, CryptoResult};

/// Remove all known metadata from an in-memory image.
/// Returns the cleaned bytes plus categories of what was removed.
pub fn scrub_image(format: MediaFormat, data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    match format {
        MediaFormat::Jpeg => scrub_jpeg(data),
        MediaFormat::Png => scrub_png(data),
        MediaFormat::WebP => scrub_webp(data),
        MediaFormat::Gif => scrub_gif(data),
        MediaFormat::Tiff => scrub_tiff(data),
        MediaFormat::Bmp => Ok((data.to_vec(), Vec::new())),
        other => Err(CryptoError::UnsupportedMediaFormat(other.name())),
    }
}

// ---------------------------------------------------------------------------
// JPEG
// ---------------------------------------------------------------------------

const JPEG_SOS: u8 = 0xDA;
const JPEG_COM: u8 = 0xFE;

fn scrub_jpeg(data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    if data.len() < 4 || !data.starts_with(&[0xFF, 0xD8]) {
        return Err(CryptoError::MalformedFile("bad JPEG SOI".to_string()));
    }

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..2]); // SOI

    let mut removed = Vec::new();
    let mut pos = 2usize;

    loop {
        // Find next marker (fill bytes 0xFF may repeat).
        if pos < data.len() && data[pos] != 0xFF {
            return Err(CryptoError::MalformedFile(format!(
                "stray byte 0x{:02X} at {pos} before marker",
                data[pos]
            )));
        }
        if pos >= data.len() {
            return Err(CryptoError::MalformedFile(
                "JPEG ended without SOS/trailer".to_string(),
            ));
        }
        while pos < data.len() && data[pos] == 0xFF {
            pos += 1;
        }
        if pos >= data.len() {
            return Err(CryptoError::MalformedFile(
                "truncated JPEG marker".to_string(),
            ));
        }
        let marker_start = pos - 1; // include the leading 0xFF when copying
        let marker = data[pos];
        pos += 1;

        match marker {
            // Standalone markers without length field.
            0xD8 | 0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&data[marker_start..pos]);
            }
            // End of image — done.
            0xD9 => {
                out.extend_from_slice(&data[marker_start..pos]);
                break;
            }
            // Start of scan: everything after is entropy-coded data.
            JPEG_SOS => {
                let seg_end = marker_len(data, pos)?;
                out.extend_from_slice(&data[marker_start..seg_end.min(data.len())]);

                // Copy the remainder blindly (scan data may contain 0xFFxx
                // lookalikes that must not be parsed as markers).
                out.extend_from_slice(&data[seg_end.min(data.len())..]);
                return Ok((out, dedup(removed)));
            }
            _ => {
                let seg_end = marker_len(data, pos)?;
                let payload = &data[pos + 2..seg_end.min(data.len())];

                let mut drop_reason: Option<&'static str> = None;
                match marker {
                    JPEG_COM => drop_reason = Some("Comment segments"),
                    0xED => drop_reason = Some("IPTC (APP13)"), // Photoshop/IPTC
                    0xE1 => {
                        if payload.starts_with(b"Exif\0\0") {
                            drop_reason = Some(RemovedCategory::EXIF);
                        } else if payload.starts_with(b"http://ns.adobe.com/xap/") {
                            drop_reason = Some(RemovedCategory::XMP);
                        } else {
                            // Unknown APP1 (e.g. audio metadata) — privacy-first drop.
                            drop_reason = Some("APP1 metadata");
                        }
                    }
                    0xE2 => {
                        if payload.starts_with(b"ICC_PROFILE\0") {
                            drop_reason = Some("ICC profile (APP2)");
                        }
                    }
                    _ => {}
                }

                match drop_reason {
                    Some(reason) => removed.push(reason.to_string()),
                    None => out.extend_from_slice(&data[marker_start..seg_end.min(data.len())]),
                }
                pos = seg_end;
            }
        }
    }

    Ok((out, dedup(removed)))
}

fn marker_len(data: &[u8], payload_start: usize) -> CryptoResult<usize> {
    if payload_start + 2 > data.len() {
        return Err(CryptoError::MalformedFile(
            "truncated JPEG segment header".to_string(),
        ));
    }
    let len = u16::from_be_bytes([data[payload_start], data[payload_start + 1]]) as usize;
    if len < 2 {
        return Err(CryptoError::MalformedFile(
            "degenerate JPEG segment length".to_string(),
        ));
    }
    let end = payload_start + len;
    if end > data.len() {
        return Err(CryptoError::MalformedFile(
            "JPEG segment overruns file".to_string(),
        ));
    }
    Ok(end)
}

// ---------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

fn scrub_png(data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    const META_CHUNKS: [&[u8; 4]; 5] = [b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"];

    if !data.starts_with(&PNG_SIGNATURE) || data.len() < 16 {
        return Err(CryptoError::MalformedFile("bad PNG signature".to_string()));
    }

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&PNG_SIGNATURE);

    let mut removed = Vec::new();
    let mut pos = 8usize;

    while pos + 12 <= data.len() {
        let len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let kind = [data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]];
        let end = pos + 12 + len;
        if end > data.len() {
            return Err(CryptoError::MalformedFile(
                "PNG chunk overruns file".to_string(),
            ));
        }

        if META_CHUNKS.iter().any(|t| **t == kind) {
            match &kind {
                b"eXIf" => removed.push(RemovedCategory::EXIF.to_string()),
                b"tIME" => removed.push("Timestamp chunk (tIME)".to_string()),
                _ => removed.push("Text chunks (tEXt/zTXt/iTXt)".to_string()),
            }
        } else {
            out.extend_from_slice(&data[pos..end]);
        }
        pos = end;

        if &kind == b"IEND" {
            break;
        }
    }

    if pos != data.len() {
        return Err(CryptoError::MalformedFile(
            "trailing bytes after PNG IEND".to_string(),
        ));
    }

    Ok((out, dedup(removed)))
}

// ---------------------------------------------------------------------------
// WebP (RIFF container)
// ---------------------------------------------------------------------------

fn scrub_webp(data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    if data.len() < 15 || &data[0..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return Err(CryptoError::MalformedFile(
            "bad WebP RIFF header".to_string(),
        ));
    }

    let mut body = Vec::with_capacity(data.len());
    let mut removed = Vec::new();
    let mut pos = 12usize;

    while pos + 8 <= data.len() {
        let kind = &data[pos..pos + 4];
        let len = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
            as usize;
        let end = pos + 8 + len;
        if end > data.len() {
            return Err(CryptoError::MalformedFile(
                "WebP chunk overruns file".to_string(),
            ));
        }

        if kind == b"EXIF" || kind == b"XMP " {
            if kind == b"EXIF" {
                removed.push(RemovedCategory::EXIF.to_string());
            } else {
                removed.push(RemovedCategory::XMP.to_string());
            }
        } else {
            body.extend_from_slice(&data[pos..end]);
            if len % 2 == 1 {
                // Preserve the mandatory odd-length pad byte.
                body.push(*data.get(end).unwrap_or(&0));
            }
        }
        pos = end + (len % 2);
    }

    if pos != data.len() {
        return Err(CryptoError::MalformedFile(
            "trailing bytes after WebP chunks".to_string(),
        ));
    }

    let mut out = Vec::with_capacity(body.len() + 8);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(body.len() as u32 + 4).to_le_bytes());
    out.extend_from_slice(b"WEBP");
    out.extend_from_slice(&body);

    Ok((out, dedup(removed)))
}

// ---------------------------------------------------------------------------
// GIF
// ---------------------------------------------------------------------------

const GIF_TRAILER: u8 = 0x3B;
const GIF_IMAGE_DESCRIPTOR: u8 = 0x2C;
const GIF_EXTENSION: u8 = 0x21;

fn gif_skip_sub_blocks(data: &[u8], pos: &mut usize) -> CryptoResult<()> {
    loop {
        let len = *data.get(*pos).ok_or_else(|| {
            CryptoError::MalformedFile("GIF truncated inside sub-blocks".to_string())
        })?;
        *pos += 1 + len as usize;
        if len == 0 {
            return Ok(());
        }
        if *pos > data.len() {
            return Err(CryptoError::MalformedFile(
                "GIF sub-block overruns file".to_string(),
            ));
        }
    }
}

fn scrub_gif(data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    if data.len() < 14 {
        return Err(CryptoError::MalformedFile("GIF too short".to_string()));
    }

    let gct_flag = data[10] & 0x80 != 0;
    let gct_size = if gct_flag {
        3 * (1usize << ((data[10] & 0x07) as usize + 1))
    } else {
        0
    };
    let mut pos = 13 + gct_size;
    if pos > data.len() {
        return Err(CryptoError::MalformedFile(
            "GIF global color table overruns file".to_string(),
        ));
    }

    let mut out = Vec::with_capacity(data.len());
    let mut removed = Vec::new();
    out.extend_from_slice(&data[..pos]);

    while pos < data.len() {
        match data[pos] {
            GIF_TRAILER => {
                out.push(GIF_TRAILER);
                pos += 1;
                break;
            }
            GIF_EXTENSION => {
                let label = *data.get(pos + 1).ok_or_else(|| {
                    CryptoError::MalformedFile("GIF truncated extension label".to_string())
                })?;
                let mut block_end = pos + 2;
                gif_skip_sub_blocks(data, &mut block_end)?;

                match label {
                    0xFE => removed.push("Comment extensions".to_string()),
                    0xFF => removed.push("Application extensions (incl. XMP)".to_string()),
                    0x01 => removed.push("Plain-text extensions".to_string()),
                    _ => out.extend_from_slice(&data[pos..block_end]),
                }
                pos = block_end;
            }
            GIF_IMAGE_DESCRIPTOR => {
                let flags = *data.get(pos + 9).ok_or_else(|| {
                    CryptoError::MalformedFile("GIF truncated image descriptor".to_string())
                })?;
                let lct_size = if flags & 0x80 != 0 {
                    3 * (1usize << ((flags & 0x07) as usize + 1))
                } else {
                    0
                };
                let mut block_end = pos + 10 + lct_size + 1; // + LZW min code size
                gif_skip_sub_blocks(data, &mut block_end)?;
                out.extend_from_slice(&data[pos..block_end]);
                pos = block_end;
            }
            other => {
                return Err(CryptoError::MalformedFile(format!(
                    "unexpected GIF block 0x{other:02X} at offset {pos}"
                )));
            }
        }
    }

    if data.last() == Some(&GIF_TRAILER) && pos == data.len() {
        // Trailer consumed exactly once.
    } else if pos == data.len() - 1 && data[data.len() - 1] == GIF_TRAILER {
        out.push(GIF_TRAILER);
    }

    Ok((out, dedup(removed)))
}

// ---------------------------------------------------------------------------
// TIFF — whitelist IFD rebuild with strip/tile relocation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct TiffEntry {
    tag: u16,
    typ: u16,
    count: u32,
    /// Raw 4-byte value field (inline value or absolute offset).
    value: [u8; 4],
}

const TYPE_SIZES: [u64; 13] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8];

/// Tags required to keep a TIFF decodable. Anything not listed is treated as
/// metadata and dropped (privacy-first whitelist).
const TIFF_KEEP_TAGS: [u16; 27] = [
    254, 255, // NewSubfileType, SubfileType
    256, 257, // ImageWidth, ImageLength
    258, // BitsPerSample
    259, // Compression
    262, // PhotometricInterpretation
    266, // FillOrder
    273, // StripOffsets
    277, 278, 279, // SamplesPerPixel, RowsPerStrip, StripByteCounts
    282, 283, 296, // X/YResolution, ResolutionUnit
    284, // PlanarConfiguration
    317, // Predictor
    320, // ColorMap
    322, 323, 324, 325, // TileWidth/Length/Offsets/ByteCounts
    338, 339, // ExtraSamples, SampleFormat
    347, // JPEGTables
    530, 531, // YCbCrSubSampling, YCbCrPositioning
];

fn tiff_tag_category(tag: u16) -> &'static str {
    match tag {
        271 | 272 => "Camera make/model",
        305 | 306 | 315 | 316 | 33432 => "Authorship info (software/artist/dates/copyright)",
        269 | 270 | 285 => "Descriptions and titles",
        34853 => "GPS data",
        34665 => "EXIF sub-IFD (dates/settings/thumbnails)",
        700 => "XMP metadata",
        33723 => "IPTC metadata",
        34377 | 34675 => "Photoshop/ICC blocks",
        18246 | 18249 => "Ratings and labels",
        _ => "Other non-essential tags",
    }
}

struct TiffCtx {
    le: bool,
}

impl TiffCtx {
    fn u16_at(&self, d: &[u8], o: usize) -> CryptoResult<u16> {
        if o + 2 > d.len() {
            return Err(CryptoError::MalformedFile(
                "TIFF read out of range".to_string(),
            ));
        }
        Ok(if self.le {
            u16::from_le_bytes([d[o], d[o + 1]])
        } else {
            u16::from_be_bytes([d[o], d[o + 1]])
        })
    }
    fn u32_at(&self, d: &[u8], o: usize) -> CryptoResult<u32> {
        if o + 4 > d.len() {
            return Err(CryptoError::MalformedFile(
                "TIFF read out of range".to_string(),
            ));
        }
        Ok(if self.le {
            u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
        } else {
            u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
        })
    }
    fn entry_offset(&self, e: &TiffEntry) -> u32 {
        if self.le {
            u32::from_le_bytes(e.value)
        } else {
            u32::from_be_bytes(e.value)
        }
    }
    fn put_u16(&self, out: &mut Vec<u8>, v: u16) {
        if self.le {
            out.extend_from_slice(&v.to_le_bytes());
        } else {
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
    fn put_u32(&self, out: &mut Vec<u8>, v: u32) {
        if self.le {
            out.extend_from_slice(&v.to_le_bytes());
        } else {
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
    fn set_u32(&self, buf: &mut [u8], pos: usize, v: u32) {
        let b = if self.le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        buf[pos..pos + 4].copy_from_slice(&b);
    }
}

fn tiff_value_span(
    ctx: &TiffCtx,
    data: &[u8],
    e: &TiffEntry,
) -> CryptoResult<Option<(usize, usize)>> {
    let unit = TYPE_SIZES.get(e.typ as usize).copied().unwrap_or(1).max(1);
    let total = unit.saturating_mul(e.count as u64);
    if total <= 4 {
        return Ok(None); // inline
    }
    if e.typ == 0 || e.typ > 12 {
        return Err(CryptoError::MalformedFile(format!(
            "unknown TIFF type {} in tag {}",
            e.typ, e.tag
        )));
    }
    let off = ctx.entry_offset(e) as usize;
    let end = off
        .checked_add(total as usize)
        .ok_or_else(|| CryptoError::MalformedFile("TIFF value span overflow".to_string()))?;
    if end > data.len() {
        return Err(CryptoError::MalformedFile(
            "TIFF external value out of range".to_string(),
        ));
    }
    Ok(Some((off, end)))
}

/// One contiguous byte range relocated into the rebuilt file.
struct RelocRange {
    old: usize,
    len: usize,
    new: usize,
}

impl RelocRange {
    fn translate(&self, abs_old: usize) -> Option<usize> {
        if abs_old >= self.old && abs_old < self.old + self.len {
            Some(self.new + (abs_old - self.old))
        } else {
            None
        }
    }
}

fn scrub_tiff(data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    if data.len() < 8 {
        return Err(CryptoError::MalformedFile("TIFF too short".to_string()));
    }
    let le = match &data[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => unreachable!("detect_media_format guarantees II/MM"),
    };
    let ctx = TiffCtx { le };

    // ---- Parse the full IFD chain --------------------------------------
    let mut chain = Vec::new();
    let mut cursor = ctx.u32_at(data, 4)?;
    let mut seen = std::collections::HashSet::new();
    while cursor != 0 {
        if !seen.insert(cursor) || chain.len() >= 64 {
            return Err(CryptoError::MalformedFile(
                "TIFF IFD chain loops or is too deep".to_string(),
            ));
        }
        let start = cursor as usize;
        if start + 2 > data.len() {
            return Err(CryptoError::MalformedFile(
                "TIFF IFD offset out of range".to_string(),
            ));
        }
        let count = ctx.u16_at(data, start)? as usize;
        if count == 0 || count > 4096 {
            return Err(CryptoError::MalformedFile(
                "implausible TIFF IFD entry count".to_string(),
            ));
        }
        let table_end = start + 2 + count * 12 + 4;
        if table_end > data.len() {
            return Err(CryptoError::MalformedFile(
                "TIFF IFD table exceeds bounds".to_string(),
            ));
        }
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let base = start + 2 + i * 12;
            entries.push(TiffEntry {
                tag: ctx.u16_at(data, base)?,
                typ: ctx.u16_at(data, base + 2)?,
                count: ctx.u32_at(data, base + 4)?,
                value: [
                    data[base + 8],
                    data[base + 9],
                    data[base + 10],
                    data[base + 11],
                ],
            });
        }
        cursor = ctx.u32_at(data, start + 2 + count * 12)?;
        chain.push(entries);
    }
    if chain.is_empty() {
        return Err(CryptoError::MalformedFile(
            "TIFF contains no IFD".to_string(),
        ));
    }

    // ---- Filter entries -------------------------------------------------
    let mut removed = Vec::new();
    let mut kept_pages: Vec<Vec<TiffEntry>> = Vec::with_capacity(chain.len());
    for page in &chain {
        let mut filtered: Vec<TiffEntry> = Vec::new();
        for e in page {
            if TIFF_KEEP_TAGS.contains(&e.tag) {
                filtered.push(*e);
            } else {
                removed.push(tiff_tag_category(e.tag).to_string());
            }
        }
        filtered.sort_by_key(|e| e.tag);
        kept_pages.push(filtered);
    }

    // ---- Plan relocation --------------------------------------------------
    // Externals: out-of-line values of kept entries.
    let mut externals: Vec<(usize, usize)> = Vec::new();
    for page in &kept_pages {
        for e in page {
            if let Some(span) = tiff_value_span(&ctx, data, e)? {
                externals.push(span);
            }
        }
    }

    // Data blocks: (StripOffsets[i], StripByteCounts[i]) pairs — or tiles.
    struct OffsetsCounts<'a> {
        offsets: &'a TiffEntry,
        counts: &'a TiffEntry,
        typ_u32: bool,
    }
    let mut blocks_spec: Vec<OffsetsCounts> = Vec::new();
    for page in &kept_pages {
        for (off_tag, cnt_tag) in [(273u16, 279u16), (324u16, 325u16)] {
            if let (Some(o), Some(c)) = (
                page.iter().find(|e| e.tag == off_tag),
                page.iter().find(|e| e.tag == cnt_tag),
            ) {
                if o.typ != c.typ || !(o.typ == 4 || o.typ == 3) || o.count != c.count {
                    return Err(CryptoError::MalformedFile(
                        "mismatched TIFF offsets/counts entries".to_string(),
                    ));
                }
                blocks_spec.push(OffsetsCounts {
                    offsets: o,
                    counts: c,
                    typ_u32: o.typ == 4,
                });
            }
        }
    }

    let unit_of =
        |e: &TiffEntry| TYPE_SIZES.get(e.typ as usize).copied().unwrap_or(1).max(1) as usize;
    let mut data_ranges: Vec<(usize, usize)> = Vec::new(); // absolute (old_off, len)
    for spec in &blocks_spec {
        let n = spec.offsets.count as usize;
        let u = unit_of(spec.offsets);

        let read_one = |arr_abs: usize, i: usize| -> CryptoResult<u64> {
            let p = arr_abs + i * u;
            if spec.typ_u32 {
                Ok(ctx.u32_at(data, p)? as u64)
            } else {
                Ok(ctx.u16_at(data, p)? as u64)
            }
        };

        let offs_arr = if u * n <= 4 {
            None
        } else {
            Some(ctx.entry_offset(spec.offsets) as usize)
        };
        let cnts_arr = if u * n <= 4 {
            None
        } else {
            Some(ctx.entry_offset(spec.counts) as usize)
        };

        let inline_val = |e: &TiffEntry| -> CryptoResult<u64> {
            if spec.typ_u32 {
                Ok(ctx.entry_offset(e) as u64)
            } else {
                Ok(u16::from_le_bytes([e.value[0], e.value[1]]) as u64)
            }
        };
        let inline_cnt = |e: &TiffEntry| -> CryptoResult<u64> {
            Ok(u16::from_le_bytes([e.value[0], e.value[1]]) as u64)
        };

        for i in 0..n {
            let off = match offs_arr {
                Some(a) => read_one(a, i)?,
                None if i == 0 => inline_val(spec.offsets)?,
                None => continue,
            };
            let len = match cnts_arr {
                Some(a) => read_one(a, i)?,
                None if i == 0 => inline_cnt(spec.counts)?,
                None => continue,
            };
            if off == 0 || len == 0 {
                continue;
            }
            let end = off.checked_add(len).ok_or_else(|| {
                CryptoError::MalformedFile("TIFF strip range overflow".to_string())
            })?;
            if end > data.len() as u64 {
                return Err(CryptoError::MalformedFile(
                    "TIFF strip data out of range".to_string(),
                ));
            }
            data_ranges.push((off as usize, len as usize));
        }
    }

    externals.sort_unstable();
    externals.dedup();
    data_ranges.sort_unstable();
    data_ranges.dedup();

    // Merge overlapping ranges (defensive; well-formed files do not overlap).
    let merge = |ranges: &[(usize, usize)]| -> Vec<(usize, usize)> {
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for &(s, e) in ranges {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        merged
    };
    let externals_merged = merge(&externals);
    // data_ranges holds (offset, length); merge expects (start, end) spans.
    let data_spans: Vec<(usize, usize)> = data_ranges.iter().map(|(o, l)| (*o, o + l)).collect();
    let data_merged = merge(&data_spans);

    // ---- Assign new layout ------------------------------------------------
    let header_len = 8usize;
    let mut cursor_new = header_len;
    let mut table_positions = Vec::with_capacity(kept_pages.len());
    for page in &kept_pages {
        table_positions.push(cursor_new);
        cursor_new += 2 + page.len() * 12 + 4;
    }

    let mut reloc_ext: Vec<RelocRange> = Vec::with_capacity(externals_merged.len());
    for (s, e) in &externals_merged {
        reloc_ext.push(RelocRange {
            old: *s,
            len: e - s,
            new: cursor_new,
        });
        cursor_new += e - s;
    }
    let mut reloc_data: Vec<RelocRange> = Vec::with_capacity(data_merged.len());
    for (s, e) in &data_merged {
        reloc_data.push(RelocRange {
            old: *s,
            len: e - s,
            new: cursor_new,
        });
        cursor_new += e - s;
    }

    let translate_ext = |abs: usize| -> CryptoResult<usize> {
        reloc_ext
            .iter()
            .find_map(|r| r.translate(abs))
            .ok_or_else(|| CryptoError::MalformedFile("unmapped TIFF external value".to_string()))
    };
    let translate_data = |abs: usize| -> CryptoResult<usize> {
        reloc_data
            .iter()
            .find_map(|r| r.translate(abs))
            .ok_or_else(|| {
                CryptoError::MalformedFile("unmapped TIFF strip/tile offset".to_string())
            })
    };

    // ---- Serialize ----------------------------------------------------------
    let mut out = vec![0u8; cursor_new];
    out[..2].copy_from_slice(if le { b"II" } else { b"MM" });
    out[2] = b'*';
    out[3] = 0;
    ctx.set_u32(&mut out, 4, table_positions[0] as u32);

    for (pi, page) in kept_pages.iter().enumerate() {
        let table_pos = table_positions[pi];
        ctx.set_u32(
            &mut out,
            table_pos + 2 + page.len() * 12,
            table_positions.get(pi + 1).copied().unwrap_or(0) as u32,
        );

        let mut scratch = Vec::with_capacity(page.len() * 12 + 6);
        ctx.put_u16(&mut scratch, page.len() as u16);
        for e in page {
            ctx.put_u16(&mut scratch, e.tag);
            ctx.put_u16(&mut scratch, e.typ);
            ctx.put_u32(&mut scratch, e.count);

            let unit = TYPE_SIZES.get(e.typ as usize).copied().unwrap_or(1).max(1);
            let total = unit.saturating_mul(e.count as u64);

            if total <= 4 {
                let mut v = e.value;
                if (e.tag == 273 || e.tag == 324) && total > 0 {
                    // Inline single offset — remap through the data map.
                    let old = if e.typ == 4 {
                        ctx.entry_offset(e) as usize
                    } else {
                        ctx.u16_at(&e.value, 0)? as usize
                    };
                    if old != 0 {
                        let new = translate_data(old)?;
                        v = if e.typ == 4 {
                            if le {
                                (new as u32).to_le_bytes()
                            } else {
                                (new as u32).to_be_bytes()
                            }
                        } else {
                            let mut b = [0u8; 4];
                            let pair = if le {
                                (new as u16).to_le_bytes()
                            } else {
                                (new as u16).to_be_bytes()
                            };
                            b[..2].copy_from_slice(&pair);
                            b
                        };
                    }
                }
                scratch.extend_from_slice(&v);
            } else {
                let old_abs = ctx.entry_offset(e) as usize;
                let new_abs = translate_ext(old_abs)?;
                ctx.put_u32(&mut scratch, new_abs as u32);
            }
        }
        let end = table_pos + scratch.len();
        out[table_pos..end].copy_from_slice(&scratch);
    }

    // Copy relocated byte ranges.
    for r in reloc_ext.iter().chain(reloc_data.iter()) {
        out[r.new..r.new + r.len].copy_from_slice(&data[r.old..r.old + r.len]);
    }

    // ---- Patch offset arrays inside relocated external values -------------
    for spec in &blocks_spec {
        let n = spec.offsets.count as usize;
        let u = unit_of(spec.offsets);
        let offs_arr_old = if u * n <= 4 {
            None
        } else {
            Some(ctx.entry_offset(spec.offsets) as usize)
        };
        if let Some(old_arr) = offs_arr_old {
            let new_arr = translate_ext(old_arr)?;
            for i in 0..n {
                let p_old = old_arr + i * u;
                let old = if spec.typ_u32 {
                    ctx.u32_at(data, p_old)? as usize
                } else {
                    ctx.u16_at(data, p_old)? as usize
                };
                if old == 0 {
                    continue;
                }
                let new = translate_data(old)?;
                let p_new = new_arr + i * u;
                if spec.typ_u32 {
                    ctx.set_u32(&mut out, p_new, new as u32);
                } else {
                    let b = if le {
                        (new as u16).to_le_bytes()
                    } else {
                        (new as u16).to_be_bytes()
                    };
                    out[p_new..p_new + 2].copy_from_slice(&b);
                }
            }
        }
    }

    Ok((out, dedup(removed)))
}

// ---------------------------------------------------------------------------

mod removed_labels {
    pub const EXIF: &str = "EXIF metadata";
    pub const XMP: &str = "XMP metadata";
}
use removed_labels as RemovedCategory;

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|i| seen.insert(i.clone()))
        .collect()
}
