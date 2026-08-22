# Plan: Metadata Scrubbing Feature (v2.2.0)

Add standalone metadata removal ("scrub") to all surfaces: Rust core → Windows/macOS/Linux GUI, CLI, and Android app.

## Locked decisions

| Decision | Choice |
|---|---|
| Format coverage | Dedicated scrubbers: JPEG, PNG, WebP, TIFF, GIF, BMP (no-op success), PDF, Office OOXML (docx/xlsx/pptx), MP3, FLAC, OGG, WAV, MP4/MOV, HEIC/HEIF (best-effort). **Unknown formats → explicit `UnsupportedFormat` error**, never a silent copy. |
| Output semantics | Default: atomically-written cleaned copy `<name>.clean.<ext>`. Optional in-place mode: atomic tmp+rename over original, then optional `secure_wipe()` of the displaced original (existing crypto.rs helper). |
| Batch | Android BatchScreen + desktop GUI batch get scrub. CLI stays single-file (consistent with existing limitation). |
| Encrypt tie-in | Out of scope. Standalone scrub only; "scrub-before-encrypt" is a future phase. |
| Filesystem timestamps | Out of scope v1 (follows from error-on-unknown choice). |
| Streaming/stdin | Out of scope v1 — scrub requires seeking (same rationale as encrypt). |

## Why not "any format"

Encryption treats files as opaque bytes; scrubbing must parse container structure to locate and excise metadata without corruption. Coverage is inherently per-format — hence the broad fixed list above with loud failure on anything unrecognized.

## Architecture

New module tree in the shared core so every platform gets it from one codebase (mirrors how `crypto.rs` serves GUI/CLI/JNI):

```
neuron-encrypt/src/
├── metadata/mod.rs      # detect_format() magic-byte sniffing, orchestration, ScrubReport
├── metadata/images.rs   # JPEG/PNG/WebP via img-parts, GIF hand-rolled, TIFF via kamadak-exif
├── metadata/documents.rs# PDF via lopdf, OOXML via zip
├── metadata/media.rs    # MP3/FLAC/OGG/WAV/MP4/HEIC via lofty (+ mp4-box walk for HEIC meta)
└── metadata/tests.rs    # fixtures + round-trip tests
```

### New dependencies (core Cargo.toml, behind `metadata` feature, default-on)

- `img-parts` — JPEG APP-segment / PNG chunk / WebP RIFF rebuild (handles CRCs)
- `kamadak-exif` — TIFF IFD enumerate + rebuild without metadata tags
- `lofty` — tag-block removal across MP3 (ID3v1/v2/APEv2), FLAC, OGG, WAV LIST/INFO, MP4 ilst
- `lopdf` — PDF Info dictionary + XMP metadata stream deletion
- `zip` — OOXML: remove `docProps/core.xml`, `app.xml`, `custom.xml` and fix `[Content_Types].xml` + `docProps/_rels` so packages stay valid
- GIF/BMP: hand-rolled (~100 lines), no crate needed

JNI crate opts in via `features = ["metadata"]` on the path-dep (it already uses `default-features = false`). Move `deny.toml` from `.cargo/deny.toml` next to `Cargo.toml` in this change so advisory checks actually cover the new deps.

### Core API (crypto.rs conventions reused)

```rust
pub enum MediaFormat { /* Jpeg, Png, ... */ }
pub struct RemovedItem { pub category: String, /* "EXIF", "GPS", "XMP", "ID3v2"... */ }
pub struct ScrubReport { pub format: MediaFormat, pub removed: Vec<RemovedItem>,
                         pub bytes_before: u64, pub bytes_after: u64 }

pub fn scrub_file(src: &Path, dest: Option<&Path>, in_place: bool,
                  wipe_original: bool, reporter: &dyn ProgressReporter,
                  cancel_flag: Option<&Arc<AtomicBool>>) -> CryptoResult<ScrubReport>;
pub fn detect_media_format(header: &[u8]) -> Option<MediaFormat>;  // None => caller errors
```

Reuse wholesale: `ThrottledReporter`, cancel-flag polling at chunk boundaries + pre-persist check, `tmp_path`/`persist_temp_file` atomic writes (unix mode 0600, create_new), `validate_destination_path` (add `allow_same_as_src: bool` param for in-place), `secure_wipe`. Progress convention: detect 0–0.05, rewrite 0.05–0.95, validate 0.95–1.0.

**Safety rails for untrusted-parser input:** cap input size at existing `MAX_FILE_SIZE`; after rewriting, re-open and sanity-validate the output (magic + container parse) *before* `persist_temp_file`; delete tmp on any error/cancel. All scrubbers must be panic-safe (no unwraps on attacker-influenced paths — mirror `unwrap_or_else(|e| e.into_inner())` lock style).

## Surface changes

### CLI (`src/bin/cli.rs`)
- New subcommand: `scrub -i <path> [-o <path>] [--in-place] [--wipe-original] [--json] [-q] [--no-progress] [-F]`
  - No `-i -` (requires seeking → BadInput, same message pattern as stdin encrypt)
  - Exit codes: 0 ok, 1 I/O, 2 bad input / unsupported format, 3 unused-for-scrub (reserved)
  - `--json`: extend result with `"operation": "scrub"`, `"format": "jpeg"`, `"removed": ["EXIF","GPS"]`, `"bytes_before"/"bytes_after"`
  - Default output name via `default_scrub_output_name(path)` (`photo.clean.jpg`)
  - Unknown format → exit 2 with clear "unsupported format, file left unmodified" message
  - Update the FAQ-documented limitations block accordingly

### Desktop GUI (`src/gui.rs`)
- Extend `Mode::{Encrypt, Decrypt}` with `Mode::Scrub`; new AppFlow states reuse Configure/Processing/Success screens with scrub-specific copy (no password row; show detected-format badge + removed-items list on Success instead of SHA-256 details)
- File drop / picker: when magic bytes match a media format (not VAULTX), preselect Scrub
- In-place toggle + confirm dialog; wipe-original checkbox appears only with in-place (mirrors Android wipe UX)
- Batch: add operation selector (Encrypt | Decrypt | Scrub); scrub rows skip passphrase validation and render per-file `removed` summary in BatchDone

### Android
- JNI (`android/neuron-encrypt-jni/src/lib.rs`): `nativeScrub(inputFd, outputFd, sourceSize, listener, cancelFlag) -> jint` — same dup-not-detach fd handling, `DurableFile`, `CancelableReader`, `catch_unwind`, `map_error` (no wrong-password branch). Return code 2 = unsupported format.
- Kotlin: `NeuronEncryptNative.nativeScrub`, `CryptoOps.scrub()` (zero-password plumbing omitted; fd open/close pattern identical), foreground-service reuse unchanged
- `SingleFileScreen`: operation segmented button Encrypt/Decrypt/Scrub; hides password field + strength meter when scrubbing; success card lists removed categories; unsupported-format banner
- `BatchScreen`: same toggle; per-file status shows format + removed count
- ProGuard: no new reflective surface beyond existing keeps

## Tests & validation

1. **Unit tests** (`metadata/tests.rs`, run in CI via existing `cargo test --lib --release`): per-format round-trip — build a fixture with known metadata (construct in-test: JPEG+EXIF via img-parts, PDF via lopdf, docx via zip, ID3 via lofty), scrub, assert (a) metadata gone, (b) container still parses, (c) primary payload intact (image dimensions equal, PDF page count equal, audio duration equal), (d) CRCs valid
2. Negative tests: truncated headers, garbage after magic, zero-byte file, VAULTX file fed to scrub → `UnsupportedFormat`
3. Fuzz targets (`fuzz/`, local-only, not wired to CI): one harness per parser family; document in CONTRIBUTING section of README
4. Gates per repo convention: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (both crates), `cargo test --lib --release`, `cargo audit`/`cargo deny`
5. Manual matrix: one sample file per format through GUI (Linux), CLI `--json`, and Android emulator; batch of mixed formats incl. one unsupported file asserting it reports error and other files still succeed

## Release chores (version → 2.2.0)

- Bump version in `neuron-encrypt/Cargo.toml`, `android/neuron-encrypt-jni/Cargo.toml`, `app/build.gradle.kts` (versionName 2.2.0, versionCode 6), NSIS `VERSION` define, docs/index.html badge
- CHANGELOG.md entry; RELEASE_NOTES_2.2.0.md; fastlane `changelogs/6.txt`
- F-Droid `metadata/com.neuronencrypt.app.yml`: add Build entry for code 6 (subdir android, fdroidRelease flavor, existing prebuild script) **and backfill missing Build entries for codes 4/5** (currently stale at 2.1.0/code 3); update CurrentVersion fields
- README: new "Metadata scrubbing" section (format table + what's removed per format), download-table blurb, threat-model note that scrubbing is content-level, distinct from encryption
- docs/index.html: features grid card + FAQ entry ("What metadata is removed?")

## Ordered task list

1. Move `deny.toml` beside `Cargo.toml`; add deps + `metadata` feature to core Cargo.toml; wire JNI feature opt-in
2. `metadata/mod.rs`: `MediaFormat`, `detect_media_format`, `ScrubReport`, error variants (`UnsupportedFormat`, `NoMetadataFound` reuse path), orchestration skeleton
3. Implement scrubbers in order: JPEG/PNG/WebP → GIF/BMP → audio containers (lofty) → MP4/HEIC → PDF → OOXML → TIFF last (hardest)
4. `scrub_file` orchestration: atomic tmp write, cancel checks, post-write validation, in-place + wipe-original paths
5. Unit tests + negative tests + fuzz scaffolding
6. CLI subcommand + JSON schema + completions refresh
7. Desktop GUI Mode::Scrub + screens + batch selector
8. Android JNI export → CryptoOps → screens → batch
9. Full validation pass (gates above, manual matrix)
10. Release chores (versions, changelog, fastlane/F-Droid, README/docs)

Tasks 3–8 can proceed incrementally behind the feature flag; ship order within task 3 chosen so the most common formats land first.

## Risks & mitigations

- **Parser vulns on hostile files** → audited crates only, fuzz harnesses, no unwraps, size caps; JNI `catch_unwind` already isolates panics
- **Corrupted output** → mandatory re-parse validation before atomic rename; failures never touch the original
- **APK size growth** (lofty+lopdf+zip ≈ low-MB range) → feature-gated; acceptable vs. value; revisit if >10% APK delta
- **HEIC variance** → strictly best-effort: if box layout isn't recognized, return `UnsupportedFormat` rather than risk a broken file
- **BMP/GIF edge cases** → BMP is a documented no-op success ("no removable metadata"); GIF only strips comment/application extensions, never touches image data

## Explicitly out of scope (future phases)

- "Scrub before encrypt" combined flow (needs its own failure-mode UX)
- Stdin/streaming scrub
- Filesystem-timestamp normalization (universal fallback mode)
- Office legacy binary formats (.doc/.xls/.ppt), RAW camera formats (CR2/NEF/ARW)
