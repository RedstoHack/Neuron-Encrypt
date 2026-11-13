//! Document scrubbers: PDF (lopdf) and Office Open XML (zip).

use zip::result::ZipError;

use super::MediaFormat;
use crate::error::{CryptoError, CryptoResult};

/// Remove all known metadata from an in-memory document.
pub fn scrub_document(format: MediaFormat, data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    match format {
        MediaFormat::Pdf => scrub_pdf(data),
        MediaFormat::Ooxml => scrub_ooxml(data),
        other => Err(CryptoError::UnsupportedMediaFormat(other.name())),
    }
}

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

const PDF_INFO_KEYS: [&[u8]; 10] = [
    b"Title",
    b"Author",
    b"Subject",
    b"Keywords",
    b"Creator",
    b"Producer",
    b"CreationDate",
    b"ModDate",
    b"Trapped",
    b"Company",
];

fn scrub_pdf(data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    use lopdf::{Document, Object};

    let mut doc = Document::load_mem(data)
        .map_err(|e| CryptoError::MalformedFile(format!("PDF parse failed: {e}")))?;

    let mut removed = Vec::new();

    // 1. Trailer /Info dictionary — authorship and dates.
    let has_info = doc.trailer.get(b"Info").is_ok();
    let info_id = doc
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|o| o.as_reference().ok());
    if let Some(id) = info_id {
        if let Ok(dict) = doc.get_object(id).and_then(Object::as_dict) {
            let present: Vec<u8> = PDF_INFO_KEYS
                .iter()
                .filter(|k| dict.has(k))
                .flat_map(|k| k.iter().copied())
                .collect();
            if !present.is_empty() {
                removed.push("Document info (title/author/dates/producer)".to_string());
            }
        }
        if doc.delete_object(id).is_none() {
            return Err(CryptoError::ScrubFailed("PDF Info object not found".to_string()));
        }
    }
    if has_info {
        let _ = doc.trailer.remove(b"Info");
    }

    // 2. Catalog /Metadata stream — XMP packet.
    let catalog_id = doc
        .trailer
        .get(b"Root")
        .ok()
        .and_then(|o| o.as_reference().ok());
    if let Some(catalog_id) = catalog_id {
        let metadata_ref = doc
            .get_object(catalog_id)
            .ok()
            .and_then(|o| o.as_dict().ok())
            .and_then(|d| d.get(b"Metadata").ok())
            .and_then(|o| o.as_reference().ok());
        if let Some(meta_id) = metadata_ref {
            // delete_object strips every reference to meta_id across the
            // document graph (including the catalog entry) and drops the
            // object itself.
            if doc.delete_object(meta_id).is_none() {
                return Err(CryptoError::ScrubFailed("PDF XMP object not found".to_string()));
            }
            removed.push("XMP metadata stream".to_string());
        }
    }

    // Clean out any objects orphaned by the removals above.
    let _ = doc.prune_objects();

    // Dropping the Info object can orphan private data referenced nowhere
    // else; a full save re-serializes only reachable objects.
    let mut out = std::io::Cursor::new(Vec::with_capacity(data.len()));
    doc.save_to(&mut out)
        .map_err(|e| CryptoError::ScrubFailed(format!("PDF write failed: {e}")))?;
    Ok((out.into_inner(), dedup(removed)))
}

// ---------------------------------------------------------------------------
// Office Open XML (docx / xlsx / pptx)
// ---------------------------------------------------------------------------

const OOXML_DROP_PARTS: [&str; 4] = [
    "docProps/core.xml",
    "docProps/app.xml",
    "docProps/custom.xml",
    "docProps/thumbnail",
];

/// Maximum expansion ratio tolerated between an archive member's compressed and
/// uncompressed size.
///
/// A zip member's declared uncompressed size lives in the archive header and is
/// never checked by the format: the writer may claim any size it likes. Real
/// OOXML packages expand far less than this (XML compresses roughly 10:1), so
/// 100:1 leaves a wide margin for legitimate content while stopping a small
/// archive from claiming gigabytes.
const MAX_ZIP_EXPANSION_RATIO: u64 = 100;

/// Slack added to the ratio allowance so that tiny members (an empty file, a
/// short XML part) are never rejected by the ratio rule alone.
const ZIP_RATIO_SLACK: u64 = 64 * 1024;

/// Largest uncompressed size a single archive member may have.
///
/// Bounded by the platform in-memory scrub cap so a hostile member cannot make
/// the process allocate more than the module already accepts for the whole
/// file (64 MiB on Android, 1 GiB on desktop).
fn zip_member_limit(compressed_size: u64) -> u64 {
    let ratio_limit = compressed_size
        .saturating_mul(MAX_ZIP_EXPANSION_RATIO)
        .saturating_add(ZIP_RATIO_SLACK);
    ratio_limit.min(super::IN_MEMORY_SCRUB_CAP)
}

/// Reject an archive member whose declared uncompressed size exceeds `limit`.
fn check_zip_member_size(name: &str, declared: u64, compressed: u64) -> CryptoResult<()> {
    let limit = zip_member_limit(compressed);
    if declared > limit {
        return Err(CryptoError::MalformedFile(format!(
            "OOXML entry {name} declares {declared} uncompressed bytes (limit {limit}) — refused"
        )));
    }
    Ok(())
}

fn scrub_ooxml(data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    use std::io::{Read, Write};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipArchive, ZipWriter};

    let reader = std::io::Cursor::new(data);
    let mut archive = ZipArchive::new(reader)
        .map_err(|e| CryptoError::MalformedFile(format!("OOXML parse failed: {e}")))?;

    let buf = std::io::Cursor::new(Vec::with_capacity(data.len() + 4096));
    let mut writer = ZipWriter::new(buf);
    let mut removed: Vec<String> = Vec::new();
    // If any docProps part is dropped, the two index parts must be patched
    // so the package does not keep dangling references (single-quoted or
    // namespaced attributes included).
    let has_dropped_part = archive.file_names().any(is_dropped_part);

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| CryptoError::MalformedFile(format!("OOXML entry {i} unreadable: {e}")))?;
        let name = file.name().to_string();

        if is_dropped_part(&name) {
            removed.push(category_for_part(&name));
            continue;
        }

        // Read the full entry, then patch the two index parts that reference
        // docProps so the package stays valid after their removal.
        //
        // The declared uncompressed size is attacker-controlled, so it is
        // validated against the expansion ratio and the in-memory cap *before*
        // any allocation, and the read itself is bounded by the same limit —
        // the declared size can also lie about how much data follows.
        let declared = file.size();
        let compressed = file.compressed_size();
        check_zip_member_size(&name, declared, compressed)?;

        let limit = zip_member_limit(compressed);
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(CryptoError::from)?;
        if bytes.len() as u64 > limit {
            return Err(CryptoError::MalformedFile(format!(
                "OOXML entry {name} decompressed past its declared size — refused"
            )));
        }

        let patched = match name.as_str() {
            "[Content_Types].xml" => remove_xml_elements(&bytes, b"Override", &|elem| {
                find_attr(elem, b"PartName").starts_with(b"/docProps")
            }),
            "_rels/.rels" => remove_xml_elements(&bytes, b"Relationship", &|elem| {
                find_attr(elem, b"Target").starts_with(b"docProps")
            }),
            _ => None,
        };
        if has_dropped_part
            && matches!(name.as_str(), "[Content_Types].xml" | "_rels/.rels")
            && find_subslice(patched.as_deref().unwrap_or(&bytes), b"docProps").is_some()
        {
            return Err(CryptoError::ScrubFailed(format!(
                "OOXML index '{name}' still references a removed docProps part"
            )));
        }
        let bytes = patched.unwrap_or(bytes);

        if file.is_dir() {
            writer
                .add_directory(name.as_str(), SimpleFileOptions::default())
                .map_err(map_zip_write(e_name(&name)))?;
            continue;
        }

        let method = file.compression();
        let method = if method == CompressionMethod::Stored || method == CompressionMethod::Deflated
        {
            method
        } else {
            CompressionMethod::Deflated
        };
        let options = SimpleFileOptions::default()
            .compression_method(method)
            .large_file(file.compressed_size() > 0xFFFF_FFFF);

        writer
            .start_file(name.as_str(), options)
            .map_err(map_zip_write(e_name(&name)))?;
        writer.write_all(&bytes).map_err(CryptoError::from)?;
    }

    let inner = writer
        .finish()
        .map_err(map_zip_write("closing OOXML package".to_string()))?
        .into_inner();
    Ok((inner, dedup(removed)))
}

fn e_name(name: &str) -> String {
    format!("rewrite of '{name}' failed")
}

fn map_zip_write(context: String) -> impl Fn(ZipError) -> CryptoError {
    move |e: ZipError| CryptoError::ScrubFailed(format!("{context}: {e}"))
}

fn is_dropped_part(name: &str) -> bool {
    OOXML_DROP_PARTS
        .iter()
        .any(|p| name == *p || name.starts_with(&format!("{p}.")))
}

fn category_for_part(name: &str) -> String {
    if name.starts_with("docProps/core") {
        "Core properties (author/title/dates)".to_string()
    } else if name.starts_with("docProps/app") {
        "Application properties".to_string()
    } else if name.starts_with("docProps/custom") {
        "Custom properties".to_string()
    } else {
        "Embedded thumbnail".to_string()
    }
}

/// Remove self-closing elements whose *local* tag name equals local_name
/// (namespace prefixes such as ct:Override are accepted) and whose content
/// satisfies matches. Returns None when nothing matched.
fn remove_xml_elements(
    xml: &[u8],
    local_name: &[u8],
    matches: &dyn Fn(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(xml.len());
    let mut changed = false;
    let mut pos = 0usize;

    while pos < xml.len() {
        let Some(rel) = find_subslice(&xml[pos..], b"<") else {
            out.extend_from_slice(&xml[pos..]);
            break;
        };
        let start = pos + rel;
        let after = start + 1;
        if after >= xml.len() {
            out.extend_from_slice(&xml[pos..]);
            break;
        }
        // Copy comments, processing instructions and close tags verbatim.
        if xml[after] == b'!' {
            if let Some(rel_end) = find_subslice(&xml[after..], b"-->") {
                let end = after + rel_end + 3;
                out.extend_from_slice(&xml[pos..end]);
                pos = end;
            } else {
                out.extend_from_slice(&xml[pos..]);
                break;
            }
            continue;
        }
        if xml[after] == b'?' {
            if let Some(rel_end) = find_subslice(&xml[after..], b"?>") {
                let end = after + rel_end + 2;
                out.extend_from_slice(&xml[pos..end]);
                pos = end;
            } else {
                out.extend_from_slice(&xml[pos..]);
                break;
            }
            continue;
        }
        if xml[after] == b'/' {
            if let Some(rel_end) = find_subslice(&xml[after..], b">") {
                let end = after + rel_end + 1;
                out.extend_from_slice(&xml[pos..end]);
                pos = end;
            } else {
                out.extend_from_slice(&xml[pos..]);
                break;
            }
            continue;
        }

        // Tag name up to whitespace, '/', or '>'.
        let name_start = after;
        let mut name_end = name_start;
        while name_end < xml.len()
            && !matches!(xml[name_end], b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>')
        {
            name_end += 1;
        }
        let raw_name = &xml[name_start..name_end];
        let local = raw_name
            .split(|b| *b == b':')
            .next_back()
            .unwrap_or(raw_name);

        // Find the end of the start tag, ignoring '>' inside quoted values.
        let mut scan = name_end;
        let mut quote: Option<u8> = None;
        let mut tag_end = None;
        while scan < xml.len() {
            let b = xml[scan];
            match quote {
                Some(q) => {
                    if b == q {
                        quote = None;
                    }
                }
                None => {
                    if b == b'"' || b == b'\'' {
                        quote = Some(b);
                    } else if b == b'>' {
                        tag_end = Some(scan);
                        break;
                    }
                }
            }
            scan += 1;
        }
        let Some(tag_end) = tag_end else {
            out.extend_from_slice(&xml[pos..]);
            return if changed { Some(out) } else { None };
        };

        let element = &xml[start..=tag_end];
        let self_closing = xml[start..tag_end]
            .iter()
            .rev()
            .find(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .map(|b| *b == b'/')
            .unwrap_or(false);

        if local == local_name && self_closing && matches(element) {
            changed = true;
        } else {
            out.extend_from_slice(&xml[pos..=tag_end]);
        }
        pos = tag_end + 1;
    }

    if changed { Some(out) } else { None }
}

/// Return the value of attr in element, accepting either quote style.
fn find_attr(element: &[u8], attr: &[u8]) -> Vec<u8> {
    for quote in [b'"', b'\''] {
        let needle: Vec<u8> = [attr, b"=", &[quote]].concat();
        if let Some(start) = find_subslice(element, &needle) {
            let vstart = start + needle.len();
            if let Some(rel) = find_subslice(&element[vstart..], &[quote]) {
                return element[vstart..vstart + rel].to_vec();
            }
        }
    }
    Vec::new()
}


fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|i| seen.insert(i.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_attr_accepts_both_quote_styles() {
        assert_eq!(
            find_attr(br#"<Override PartName="/docProps/core.xml"/>"#, b"PartName"),
            b"/docProps/core.xml".to_vec()
        );
        assert_eq!(
            find_attr(b"<Override PartName='/docProps/core.xml'/>", b"PartName"),
            b"/docProps/core.xml".to_vec()
        );
        assert!(find_attr(b"<Override/>", b"PartName").is_empty());
    }

    #[test]
    fn remove_xml_elements_matches_prefixed_local_name() {
        let xml = br#"<Types><Override PartName="/docProps/core.xml"/><ct:Override PartName="/docProps/app.xml"/><Default Extension="xml"/></Types>"#;
        let out = remove_xml_elements(xml, b"Override", &|e| {
            find_attr(e, b"PartName").starts_with(b"/docProps")
        })
        .expect("elements should be removed");
        assert!(!out.windows(8).any(|w| w == b"docProps".as_slice()));
        assert!(out.windows(7).any(|w| w == b"Default".as_slice()));
    }
}
