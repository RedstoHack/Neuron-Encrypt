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
        let _ = doc.delete_object(id);
        let _ = doc.trailer.remove(b"Info");
    }

    // 2. Catalog /Metadata stream — XMP packet.
    let catalog_id = doc.trailer.get(b"Root").ok().and_then(|o| o.as_reference().ok());
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
            let _ = doc.delete_object(meta_id);
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

fn scrub_ooxml(data: &[u8]) -> CryptoResult<(Vec<u8>, Vec<String>)> {
    use std::io::{Read, Write};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipArchive, ZipWriter};

    let reader = std::io::Cursor::new(data);
    let mut archive =
        ZipArchive::new(reader).map_err(|e| CryptoError::MalformedFile(format!("OOXML parse failed: {e}")))?;

    let buf = std::io::Cursor::new(Vec::with_capacity(data.len() + 4096));
    let mut writer = ZipWriter::new(buf);
    let mut removed: Vec<String> = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| {
            CryptoError::MalformedFile(format!("OOXML entry {i} unreadable: {e}"))
        })?;
        let name = file.name().to_string();

        if is_dropped_part(&name) {
            removed.push(category_for_part(&name));
            continue;
        }

        // Read the full entry, then patch the two index parts that reference
        // docProps so the package stays valid after their removal.
        let mut bytes = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut bytes)
            .map_err(CryptoError::from)?;

        let patched = match name.as_str() {
            "[Content_Types].xml" => remove_xml_elements(
                &bytes,
                b"<Override",
                &|elem| find_attr(elem, b"PartName").starts_with(b"/docProps"),
            ),
            "_rels/.rels" => remove_xml_elements(
                &bytes,
                b"<Relationship",
                &|elem| find_attr(elem, b"Target").starts_with(b"docProps"),
            ),
            _ => None,
        };
        let bytes = patched.unwrap_or_else(|| bytes);

        if file.is_dir() {
            writer
                .add_directory(name.as_str(), SimpleFileOptions::default())
                .map_err(map_zip_write(e_name(&name)))?;
            continue;
        }

        let method = file.compression();
        let method = if method == CompressionMethod::Stored || method == CompressionMethod::Deflated {
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

/// Remove `<prefix .../>` elements whose content satisfies `matches`.
/// Returns `None` when nothing matched (input returned unchanged).
fn remove_xml_elements(
    xml: &[u8],
    prefix: &[u8],
    matches: &dyn Fn(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(xml.len());
    let mut changed = false;
    let mut pos = 0usize;

    while pos < xml.len() {
        match find_subslice(&xml[pos..], prefix) {
            Some(rel) => {
                let start = pos + rel;
                out.extend_from_slice(&xml[pos..start]);
                let end_rel = find_subslice(&xml[start..], b"/>").map(|r| r + 2);
                let elem_end = match end_rel {
                    Some(end) => start + end,
                    None => {
                        // Malformed fragment — copy rest verbatim.
                        out.extend_from_slice(&xml[start..]);
                        return if changed { Some(out) } else { None };
                    }
                };
                let element = &xml[start..elem_end];
                if matches(element) {
                    changed = true;
                } else {
                    out.extend_from_slice(element);
                }
                pos = elem_end;
            }
            None => {
                out.extend_from_slice(&xml[pos..]);
                break;
            }
        }
    }

    if changed {
        Some(out)
    } else {
        None
    }
}

fn find_attr(element: &[u8], attr: &[u8]) -> Vec<u8> {
    let needle: Vec<u8> = [attr, "=\"".as_bytes()].concat();
    match find_subslice(element, &needle) {
        Some(start) => {
            let vstart = start + needle.len();
            let vend = find_subslice(&element[vstart..], b"\"").map(|r| vstart + r).unwrap_or(vstart);
            element[vstart..vend].to_vec()
        }
        None => Vec::new(),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items.into_iter().filter(|i| seen.insert(i.clone())).collect()
}
