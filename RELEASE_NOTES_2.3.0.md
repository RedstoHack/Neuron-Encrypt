# Neuron Encrypt 2.3.0

**Released:** 2026-10-01
**Android versionCode:** 7

Metadata scrubbing gains four new audio/video formats, and a set of
file-corruption bugs found by the new adversarial test suite is fixed.

---

## New scrub formats

All four are handled by the tag writer that was already a dependency, so they
are pure detection changes with no new runtime cost:

| Format | What is removed |
|---|---|
| **M4A / AAC** | Title, artist, album, year, comments, cover art, encoder tags |
| **Opus** | Vorbis comments (artist, location, encoder) |
| **AIFF / AIFC** | `NAME`/`AUTH` text chunks, comments, ID3 |
| **3GP / 3G2** | Title, artist, creation & recording time, GPS, device tags |

Previously M4A worked only incidentally (it shares the MP4 container) and
3GP brands were detected but reported as MP4, so a cleaned `.3gp` was written
with a `.mp4` extension. Raw AAC was also misdetected as MP3, which meant it
could not be scrubbed at all.

**Not added, deliberately:** HEIC/HEIF and AVIF. These carry GPS and device
data in ISO-BMFF item boxes whose absolute offsets point into the media
payload; the available Rust crates either cannot write the container back or
say so explicitly. Guessing at that rewrite risks silently corrupting
someone's photo, so HEIC continues to be rejected with a clear message
instead. Camera RAW is skipped for the same reason.

## Bug fixes

### Dependency advisory: webbrowser 1.2.1

A transitive dependency of `eframe` (so of the desktop GUI) mishandled the
Unix `BROWSER` environment variable, allowing argument injection when a URL is
opened. Bumped to 1.2.4. Caught by the new `cargo audit` step in CI — the
release could not have shipped without it.

### Corrupt files from truncated images

A PNG cut off at a chunk boundary was reported as **successfully scrubbed**,
and `--in-place` replaced the original with a header-only stub containing no
image data. The chunk loop could exhaust the file without ever reaching the
`IEND` marker, and the "no trailing bytes" check then passed. WebP had the
same flaw (a file with no `VP8`/`VP8L`/`VP8X` chunk was accepted) and so did
GIF (no image descriptor, or no trailer). All three now fail closed with a
specific error, and the source file is left untouched.

This class of bug is what the new `metadata/brutal.rs` suite hunts: it
truncates every supported container at each byte offset and asserts the source
is never modified and no partial output is left behind.

### Android: the notification that would not go away

After a finished operation, an ongoing notification sometimes stayed in the
shade and **could not be swiped away** — it survived until the app was
force-stopped from Settings.

Progress updates are posted directly through `NotificationManagerCompat` under
the same id as the foreground notification, but teardown only called
`stopForeground(REMOVE)`, which removes the notification the *service* attached
and not one posted behind its back. A final progress tick landing after teardown
therefore re-created an ongoing notification belonging to no service.

Now the notification is cancelled by id on every teardown path (`stop`,
`onDestroy`, `onTaskRemoved`), progress ticks are ignored once the operation
is no longer in flight, and starting a new operation clears any entry left
behind by a killed run.

### Android: batch runs finished silently

A multi-file batch posted no completion notice, so a backgrounded user never
learned it had finished. It now reports counted totals (succeeded / skipped /
failed / cancelled).

### CLI: `--force` deleted the destination before starting

The core was hardened in 2.2.0 to replace an existing output with a single
atomic rename, but the CLI still deleted the target up front — so any later
failure (full disk, wrong passphrase, Ctrl-C, unsupported format) destroyed the
user's existing file. Both CLI paths now rely on the atomic replace.

## Also in this release

- **A "Supported formats" screen in the Android app**, so you can check whether
  your file type is scrubbable before picking it, with an explanation of what
  is removed and why HEIC/RAW/archives are rejected.
- **CI quality gate.** Every push and merge request now runs `cargo fmt`,
  `clippy -D warnings` and the test suite before anything can ship.
- **One release pipeline.** Pushing a `vX.Y.Z` tag builds Linux, Windows and
  Android in parallel and attaches the APK, the Windows EXE, the archives and
  all checksums to a single GitLab release. The macOS job is removed — it
  needed a self-hosted runner that does not exist, so it only ever sat pending.
- **F-Droid metadata corrected.** Builds for version codes 4–7 added and
  `CurrentVersion` fixed from the long-stale 2.1.0/3.
- **An AppImage for Linux**, alongside the tar.gz.

## Verification

- `cargo test --lib --release`: **86/86 pass** (63 at 2.2.0)
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`: clean
- `cargo audit`: clean
