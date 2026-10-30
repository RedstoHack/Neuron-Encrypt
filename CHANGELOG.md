# Changelog

All notable changes to Neuron Encrypt are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] — 2026-10-01

### Added
- **Metadata scrubbing for M4A/AAC, Opus, AIFF and 3GP/3G2.** All four are handled by the `lofty` tag writer that was already a dependency, so they cost only detection changes: ADTS/ADIF AAC is now told apart from MPEG audio by the frame layer bits (previously any `0xFF 0xEx` frame was assumed MP3), Opus is distinguished from Ogg Vorbis by the `OpusHead` codec id, AIFF/AIFC is recognised by its `FORM`+`AIFF` container, and the 3GPP/3GPP2 and Apple `M4B`/`M4P` brands are reported as their own format so the cleaned copy keeps a matching extension instead of being written as `.mp4`.
- **A "Supported formats" screen in the Android app**, listing every scrubbable format and what is removed from it, plus the formats that are deliberately rejected (HEIC/HEIF, camera RAW, archives) and why. Reachable from the home screen so a user can check support *before* picking a file rather than only from an error message.
- **Adversarial test suite for the scrubber** (`metadata/brutal.rs`): 14 tests covering zero-byte/truncated/garbage inputs, magic-byte lookalikes, a byte-by-byte truncation sweep of every supported container, payload-integrity assertions, symlink and read-only handling, cancellation, and concurrent scrubs racing for one destination.

### Fixed
- **Dependency advisory: `webbrowser` 1.2.1 (RUSTSEC-2026-0257).** A transitive dependency of `eframe` (and therefore of the desktop GUI) mishandled the Unix `BROWSER` environment variable, allowing argument injection when a URL is opened. Bumped to 1.2.4 in both lockfiles. Caught by the new CI quality gate, which runs `cargo audit` — the release could not have been cut without fixing it.
- **A truncated PNG was reported as successfully scrubbed and replaced the original with a corrupt stub.** The chunk loop could run out of data rather than reach `IEND`; when the file happened to end exactly on a chunk boundary, `pos == data.len()` passed the trailing-bytes check and the scrub "succeeded" — producing a header-only file with no image data. Under `--in-place` this destroyed the user's photo. The scrubber now requires an `IEND` chunk.
- **Same class of bug in WebP and GIF.** WebP accepted a file with no `VP8`/`VP8L`/`VP8X` chunk (i.e. no image at all), and GIF accepted a file containing no image descriptor or no trailer. Both now fail closed with a specific error.
- **Android: the ongoing notification survived completion and could not be dismissed.** Progress ticks are posted directly through `NotificationManagerCompat` under the same id as the foreground notification, but teardown only called `stopForeground(REMOVE)` — which removes the notification the *service* attached, not one posted behind its back. A tick that landed after teardown therefore re-created an ongoing notification belonging to no service, which the user could not swipe away and which survived until the app was force-stopped. `stop()`/`onDestroy()`/`onTaskRemoved` now cancel the notification by id, `updateProgress()` ignores ticks once the operation is no longer in flight, and `start()` clears any stale entry left by a killed run.
- **Android: batch runs left no completion notice.** A multi-file batch finished silently for a backgrounded user; it now posts a counted summary.
- **`--force` still deleted the destination up front at the CLI layer**, leaving the data-loss window that the core had just been hardened against. Neither CLI path deletes up front any more: `encrypt`/`decrypt` rely on the core's atomic replace, and `scrub` threads `--force` into `metadata::scrub_file` as a new `overwrite` argument.

### Changed
- **Version bump** 2.2.0 → 2.3.0 (core + JNI crates, Android `versionName`), Android `versionCode` 6 → 7.
- The NSIS installer takes its version from a `!define`, so releases no longer need a manual edit.
- F-Droid metadata brought up to date: builds added for version codes 4–7 and `CurrentVersion` corrected from the long-stale 2.1.0/3.
- CI: a `quality` gate job (fmt, clippy `-D warnings`, tests) now runs on every push and merge request, and releases are produced by a single tag-triggered pipeline that builds Linux, Windows and Android in parallel and attaches every artifact (APK, EXE, archives, checksums) to the GitLab release. The macOS job is removed — it required a self-hosted runner that does not exist, so it only ever sat pending.

### Test Results
- `cargo test --lib --release`: 86/86 pass (was 63; +3 from the truncation fixes, +14 adversarial, +6 from the new formats).
- `cargo fmt --check` and `cargo clippy --all-targets --all-features -D warnings`: clean.
- Android `:app:compileStandardDebugKotlin` and `:app:compileFdroidDebugKotlin`: clean.

## [Unreleased]

### Security
- **The CLI published a SHA-256 of the *plaintext* on every encryption.** `neuron-encrypt-cli encrypt` printed `SHA-256 (original): <digest>` and put the same value in the `--json` document. A digest of the plaintext is a confirmation-attack oracle: anyone holding a candidate of the original file could confirm it against the published value without knowing the passphrase. The digest now always identifies the **encrypted container** — the `.vx2` written on encrypt, and the `.vx2` read on decrypt — in both the CLI and the desktop GUI (single-file and batch). The GUI had already been hardened for the encrypt direction (audit finding P2-4); the CLI and the GUI's decrypt direction had not. The human-readable label is now `SHA-256 (encrypted file)`.
- **`--json` corrupted piped output.** `emit_json` wrote to stdout, which is also where `-o -` streams the ciphertext/plaintext, so `neuron-encrypt-cli encrypt -i f -o - --json` appended a JSON document to the binary stream. The JSON document now goes to stderr whenever the payload owns stdout, so stdout always carries exactly one stream.
- **The piped decrypt path wrote plaintext to a world-readable temporary file.** The scratch file was created without a mode, so the default umask produced `0644` for the duration of the write — unlike every core path, which creates its scratch files `0600`. The CLI now sets `0600` on unix.
- **A malformed WAV could kill the process.** A WAV whose RIFF chunk declares a length larger than the file (`u32::MAX` was enough) made lofty's WAV writer overflow an unchecked addition and panic. The release profile used `panic = "abort"`, so the panic aborted the whole application — in the Windows GUI, which has no console, that is a silent death with no message. The RIFF container is now validated before any third-party parser sees it, the scrubber catches a panic from a container parser and turns it into an ordinary "malformed file" error, and the release profile no longer aborts on panic.
- **Temp files are unlinked but never overwritten.** `secure_wipe` was only ever used for the original of a scrub; every failure and cancellation path removed the scratch file without overwriting it first, so plaintext could survive in filesystem free space. Documented as a known limitation rather than silently changed, because the fix has to work on flash storage where it cannot be guaranteed.
- **The installers could install an unverified binary.** `install.sh` piped `grep <name> SHA256SUMS` into `sha256sum --check`, and `sha256sum` exits **0** when it has nothing to check — so a checksum file that did not mention the binary at all was reported as `Checksum OK.`. The installer now fails when no matching entry exists, compares the digests directly (the old form also resolved the file name in the checksum line against the *current* directory, not the download directory, so it could not have worked), and says `Checksum verified.` only when a comparison actually happened.
- **`install.ps1` could corrupt the user's `PATH`.** It read the user `PATH` through `GetEnvironmentVariable`, which expands `%SystemRoot%`-style references, and wrote it back with `SetEnvironmentVariable` — which stores the value as `REG_SZ`, so every expansion became a literal. An empty user `PATH` also produced a leading `;`, and on Windows an empty `PATH` entry means "current directory". The installer now reads the unexpanded registry value and writes it back as `REG_EXPAND_SZ`, dropping empty segments.
- **A TLS-interception CA was committed to the repository.** `new-root.pem` was a Cloudflare "proxy-everything" Intercept CA (issued 2026-08-23, valid until 2026-09-22) referenced by no script in the tree, next to documentation telling operators to add an intercept CA to the build truststore. A machine that trusts such a CA accepts forged certificates for every HTTPS endpoint it talks to. Removed, and `*.pem` / `*.crt` are now ignored.
- **The Android release APK was never signed, but the release advertised a signed one.** `android/app/build.gradle.kts` had no `signingConfigs` block at all, so `standardRelease` was built unsigned while `.gitlab-ci.yml` listed `neuron-encrypt-<version>-android-signed.apk` as an expected release asset — an asset that could never exist. The build now defines a release signing config driven by `UPLOAD_KEYSTORE_PATH` / `UPLOAD_KEYSTORE_PASSWORD` / `UPLOAD_KEY_ALIAS` / `UPLOAD_KEY_PASSWORD`, the GitLab pipeline materialises the keystore from the base64 secret, and a missing keystore is reported loudly instead of silently producing an unsigned APK.
- **Android: R8 broke the scrub report in release builds.** The native side calls `ScrubReportListener.onScrubReport` *by name* through JNI, but the ProGuard rules only kept `ProgressListener` — so in minified release builds the callback was renamed, the native call failed, and the result was discarded. The scrub report never reached the UI, and the completion notification showed no detail. The listener is now kept, and a failed delivery clears the pending JNI exception instead of leaking it.

### Fixed
- **The test suite did not compile on Windows.** `metadata/brutal.rs` used `std::os::unix::fs::{symlink, PermissionsExt}` without a `cfg(unix)` gate, and the module was declared with a bare `#[cfg(test)]`, so `cargo test` failed to build on Windows and took the whole 48-test suite with it. CI only runs on Linux, so this was invisible there.
- **`cargo test` could not run on Windows at all.** `neuron-encrypt/.cargo/config.toml` was committed to the repository and set `runner = "wine64"` for `x86_64-pc-windows-gnu`, so every test binary was launched through Wine. The file was listed in `.gitignore`, but that has no effect on an already-tracked file. It is now untracked (the CI job that needs a MinGW linker writes its own copy).
- **A JPEG with no image data was reported as successfully scrubbed.** The parser returned as soon as it saw an SOS marker and treated reaching EOI as success, so a header-only stub (`FF D8` + APP0 + `FF D9`) was accepted — and under `--in-place` that replaced a real photo with a file no decoder can render. A JPEG now has to contain a scan. The canonical test fixture had no SOS marker either, so the whole suite was asserting success on an image-less JPEG; the fixture now carries a real DHT, SOS and entropy data.
- **A PNG with no image data was reported as successfully scrubbed.** The parser checked for `IEND` but not for `IHDR` or `IDAT`, so a 20-byte file consisting of the signature plus a lone `IEND` was accepted. Both chunks are now required.
- **A PNG chunk length could overflow on 32-bit targets.** `pos + 12 + len` with an attacker-controlled `u32` length wraps on a 32-bit `usize`, which slips past the bounds check and panics on the slice. The addition is now checked. (The 32-bit Android ABIs are affected.)
- **The TIFF scrubber could panic through the public API.** `scrub_image` is `pub`, and the `unreachable!` that asserted the byte-order mark was only guaranteed by the internal call path — a library consumer calling `scrub_image(MediaFormat::Tiff, ...)` with other bytes aborted the process. It is now an ordinary `MalformedFile` error.
- **The WebP RIFF size could overflow.** The chunk size was computed as `body.len() as u32 + 4`, which wraps for a body at or above 4 GiB. The conversion is now checked.
- **A zip bomb could exhaust memory in the OOXML scrubber.** The reader trusted the *declared* uncompressed size of each archive member — a value the archive author controls and the format never checks — and pre-allocated that much memory from it. A few-kilobyte archive could claim 4 GiB. The declared size is now validated against both an expansion-ratio limit and the platform in-memory cap *before* any allocation, and the read itself is bounded by the same limit. This also defeated the 64 MiB Android cap, which only bounded the compressed input.
- **Legal Office documents were rejected as unsupported.** The format sniffer looked for `[Content_Types].xml` in the first 64 bytes of the file, but the sniff buffer was 64 bytes long, so a package whose first entry carried an extra field was never recognised. The window is now 4 KiB, in the core and in the Android pre-flight alike.
- **The `--completions` command could never run.** The subcommand was mandatory, so clap rejected `neuron-encrypt-cli --completions bash` during parsing, before the flag was ever looked at. The subcommand is now optional and the documented command works.
- **The CLI reported some failures twice.** `validate_output_path` printed the JSON document and the error message itself and then returned the error, which the caller reported again. The function now only returns the error.
- **The GUI could un-cancel a running operation.** Starting a new operation, picking a different file, or resetting the session *cleared* the cancellation flag. If a worker was still running it saw the flag go from `true` back to `false`, carried on, and wrote its output while the UI had already returned to the start screen. Each operation now gets a fresh flag, and the previous one is set to `true` so the running worker stops.
- **The GUI hid the result of an operation that had already succeeded.** The cancel flag was checked when the result arrived, so a cancel that landed after the operation had written its output wiped the session — the user was never told the file existed or where it was. Successes and failures are now always reported; a real cancellation is a separate message that says nothing was written.
- **The GUI showed a button whose label contradicted its action.** The primary button's label followed the file extension while the action followed the selected mode, so picking a non-`.vx2` file and switching the mode to DECRYPT showed an `ENCRYPT` button that decrypted the file. Both now follow the mode.
- **The GUI's passphrase meter left copies of the passphrase in memory.** The strength estimator ran on every repaint and allocated a lowercased copy and a `Vec<char>` of the passphrase — plain heap allocations that were never overwritten, sixty times a second while typing. The copies are now wrapped in `Zeroizing`.
- **The GUI's scrubbing button ignored the passphrase rules.** The button was always enabled in scrub mode and the passphrase-length check applied to it. The check is now skipped for scrub, which needs no passphrase.
- **`cargo build --no-default-features` failed.** The `neuron-encrypt-cli` binary uses the core's `metadata` module but did not declare `required-features`, so a metadata-less build failed with an unresolved import instead of simply skipping the binary.
- **The Android build was not reproducible.** `android/build-rust.sh` was the only Rust build in the repository that did not pass `--locked`, so the JNI dependency graph could drift from the reviewed lockfile at build time.
- **The two CI systems disagreed about whether the code was secure.** The GitHub workflow ran `cargo audit --deny warnings` and the GitLab pipeline ran `cargo audit` with no threshold. The `paste` "unmaintained" advisory (RUSTSEC-2024-0436, reached through `lofty`, and deferred on purpose in `docs/SECURITY_DEFER.md`) is a warning, not a vulnerability — so the GitHub gate failed on every push while the GitLab gate, which publishes the release, passed. Both now use the same policy, and the GitLab pipeline additionally runs `cargo deny check` (the license policy in `deny.toml` was previously only enforced by GitHub, never by the pipeline that publishes the release) and audits the Android JNI crate's separate lockfile (which no pipeline had ever audited).
- **The build toolchain was whatever "stable" happened to be.** `rust-toolchain.toml` said `stable`, the GitHub desktop workflow pinned `1.88.0`, and both Android workflows used `stable`. Because Rust's toolchain-file discovery walks up from the crate directory, the `rust:1.88-slim` CI image resolved "stable" to the current release channel rather than to 1.88 — so the "1.88" pipelines were not necessarily building with 1.88. The toolchain is now pinned to `1.89.0` everywhere — 1.89, not 1.88, because `lofty 0.25.1` in the lockfile requires rustc 1.89 and a 1.88 pin cannot resolve `Cargo.lock`.
- **`--force` still deleted the destination up front at the CLI layer**, leaving the data-loss window that the core had just been hardened against. The core now replaces an existing output with a single atomic `rename` only after the new content is complete, but `validate_output_path` deleted the target during validation and the scrub path deleted it again before starting — so any later failure (full disk, wrong passphrase, Ctrl-C, unsupported format) destroyed the user's existing file. Neither CLI path deletes up front any more: `encrypt`/`decrypt` rely on the core's atomic replace, and `scrub` threads `--force` into `metadata::scrub_file` as a new `overwrite` argument so the same atomic replace applies. Covered by new regression tests asserting an existing destination survives a failed, a cancelled, and a successful forced overwrite.
- **Android: notification permission was never requested.** `POST_NOTIFICATIONS` was declared in the manifest but not asked for at runtime, so on Android 13+ the foreground-service notification was dropped silently and long operations ran invisibly in the background (where they are reaped more aggressively). The home screen now requests it once after onboarding and shows a banner with a settings shortcut when denied.
- **Android: progress updates re-armed the foreground-service start timeout.** Every throttled tick called `startForegroundService()` while the service's `ACTION_UPDATE` branch never called `startForeground()` — which the platform treats as a fatal error (`ForegroundServiceDidNotStartInTimeException`) and which could resurrect a stopped service with no notification. Updates now post in-process via `CryptoService.updateProgress()` (no service start per tick), and every `onStartCommand` branch enters the foreground state.
- **Android: the ongoing notification could get stuck.** `ACTION_STOP` was unreachable (`stopService()` does not deliver intents) and the service had no `onTaskRemoved`, so swiping the app out of Recents left a permanent "Removing metadata…" entry. `onDestroy` now removes the notification, `onTaskRemoved` stops an idle service, and an in-flight flag keeps a *running* operation from being torn down.
- **Android: leaving a screen mid-operation abandoned the write.** The service was stopped while the un-interruptible native call kept running, so the process could be killed mid-write with no foreground protection. Navigating away now latches the cancel flag, the native dispatch runs under `NonCancellable`, and the service stops only after the call returns.
- **Android: scrub failed with a generic "Storage I/O failed" on large files.** The free-space check ran *after* the input had already been staged and used `f_bsize` instead of `f_frsize`. Space is now verified against the fd's reported size *before* anything is written, and failures surface as actionable messages ("Not enough free storage — scrubbing needs about twice the file size…").
- **Android: large images/PDFs could get the process killed by the OS.** Image/PDF/OOXML scrubbing holds two full-size buffers, so oversized inputs were killed by `lmkd` (taking the notification with them). Android caps in-memory scrubbing at 64 MiB (desktop stays at 1 GiB) with a clear "too large to scrub on this device" error, and BMP "no-op" copies are streamed instead of buffered.
- **Android: scrub errors were mis-reported.** The UI keyed off native return codes while the JNI always throws `NeuronEncryptException`, so its code-based messages (e.g. "Unsupported format — skipped") were unreachable. The screens now handle the exception and show the native reason.
- **Android: scrubbed/decrypted outputs were created as `*/*`.** Providers recorded them as `application/octet-stream`, so cleaned photos stayed invisible to gallery/media apps. Outputs are now created with a MIME derived from the destination name.

### Changed
- **The release profile no longer aborts on panic.** `panic = "abort"` is removed from the core crate. A panic in a container parser now unwinds into the scrubber, which reports it as a malformed file instead of taking the process down; and because the unwind runs the `Drop` impls, the `Zeroizing` guards wipe the passphrase and plaintext buffers that an abort would have left in RAM. The Android JNI crate never set `panic = "abort"` either, so its `catch_unwind` wrappers work as its own comments describe.
- **The metadata scrubber catches panics from container parsers.** `lofty`, `lopdf` and `zip` parse attacker-controlled bytes; a panic inside one of them is now turned into the ordinary "malformed file" error that the module's fail-closed contract promises.
- **The `install.sh` checksum comparison was rewritten.** It now fails when the checksum file has no entry for the binary, compares the digests directly instead of relying on `sha256sum --check` resolving a path against the current directory, and reports `Checksum verified.` only after a real comparison. It also says plainly that no Linux `aarch64` build is published instead of failing later with an opaque 404.
- **The toolchain is pinned to 1.89.0** in `rust-toolchain.toml` and in the desktop and Android workflows, so local builds, the CI images and the GitHub Actions all use the same compiler. (1.89, not 1.88: the lockfile's `lofty 0.25.1` requires rustc 1.89.)
- **Stale and unverified artifacts were removed from the repository.** `audit_output.json` was a `cargo audit` snapshot more than four months old that no job regenerated; `release/v2.2.0/` held four prebuilt binaries of unknown provenance that no CI job produced and that nothing distinguished from an official release. Both are now ignored, and the artifacts are published only through the package registry and the release page.
- **Android: scrub pre-flight.** Files are sniffed against the core's magic-byte table (`nativeScrubFormatName`) when picked: unsupported formats (unknown types, plain zips, BigTIFF, HEIC/HEIF) disable the Scrub tab with an explanation, and batch mode skips them without creating then deleting output documents.
- **Android: scrub results are surfaced.** The native `ScrubReport` (format + removed categories) now reaches the UI through `ScrubReportListener` — shown on the success screen, in the batch list, and in a new dismissible completion notification.
- **Scrub coverage: mobile video containers.** The MP4/MOV detector now accepts the 3GPP/3GPP2 brands (`3gp4`…`3gp8`, `3ge6`, `3gg6`, `3g2a`), newer ISO base-media versions (`iso5`…`isob`) and `M4B`/`M4P`/`mqv`, so the video formats phone cameras actually produce scrub through the existing lofty path instead of being rejected. HEIC/HEIF remains explicitly unsupported (fail-closed) until structural scrubbing lands.

### Removed
- **`new-root.pem`** — a Cloudflare TLS-interception CA committed at the repository root.
- **`audit_output.json`** — a stale `cargo audit` snapshot.
- **`release/v2.2.0/`** — prebuilt binaries of unknown provenance.
- **`neuron-encrypt/.cargo/config.toml`** — a local build configuration that forced every test binary through Wine.

## [2.2.0] — 2026-08-23

### Added
- **Metadata scrubbing** (new `metadata` module in the core crate, default-on; the JNI crate opts in via feature flag): remove privacy-relevant metadata from files on every platform from one Rust codebase.
  - **Dedicated scrubbers**: JPEG (APP1 Exif/XMP, APP13 IPTC, COM comments, ICC profiles), PNG (tEXt/zTXt/iTXt/eXIf/tIME chunks; kept chunks copied verbatim so no CRC recomputation), WebP (EXIF/XMP RIFF chunks with size fixup and pad-byte handling), GIF (comment/application/plain-text extensions), TIFF (whitelist-based IFD rebuild with strip/tile relocation and offset patching; BigTIFF rejected loudly), BMP (validated no-op), PDF (`lopdf`: trailer `/Info` + catalog `/Metadata` XMP stream, orphan pruning), Office OOXML (`zip`: `docProps/core.xml`/`app.xml`/`custom.xml`/thumbnails plus `[Content_Types].xml` Override and `_rels/.rels` Relationship surgery so packages stay valid), MP3 / FLAC / OGG / WAV / MP4-MOV (`lofty`: ID3v1/v2, APE, Vorbis comments, RIFF INFO, iTunes ilst with chunk-offset patching — tags are replaced with empty ones because lofty's save is a no-op when no tags are registered).
  - **Fail-closed detection**: magic-byte sniffing rejects unknown formats, plain zips, VAULTX encrypted files and BigTIFF with an explicit "unsupported" error instead of a silent copy. HEIC/HEIF is detected but rejected until structural scrubbing lands.
  - **Non-destructive by default**: cleaned output is written atomically as `<name>.clean.<ext>` beside the source through the same tmp+hard-link/rename machinery as encryption (unix mode 0600). Post-write validation re-sniffs the output before persisting; every error/cancel path removes scratch files. Optional in-place replacement and post-copy secure wipe.
- **CLI `scrub` subcommand**: `scrub -i <file> [-o <out>] [--in-place] [--wipe-original] [--json] [-F]`. JSON gains `operation`, `format`, `removed` fields (encrypt/decrypt schema unchanged). Exit codes: 0 success, 1 failure, 2 unsupported format. Piped stdin rejected (scrubbing requires seeking).
- **Desktop GUI**: new Encrypt / Decrypt / Scrub operation switcher; passphrase UI hidden while scrubbing; success screen summarises removed categories. Batch screen gains "Scrub metadata only (no passphrase)" checkbox with per-file format/removal summaries.
- **Android**: new `nativeScrub` JNI export using **staged streaming** — the input descriptor is copied through a fixed 1 MiB buffer into the app-private cache dir, the path-based core scrubber runs there (audio/video containers stream via lofty internally), and the result streams back to the output descriptor. Peak memory stays flat regardless of file size; temporary disk use (~2x source) is guarded by a statvfs free-space check; temps are deleted on every exit path. A watcher thread bridges the Java cancellation flag into the core's chunk-boundary checks, and progress phases are rescaled to stay monotonic. Single-file screen gains a Scrub tab (passphrase fields hidden); batch screen gains the same tab with per-file unsupported-format skip messaging.

### Fixed
- **Android mid-chunk cancel busy-loop** (latent since v2.1.2): `CancelableReader` returned `ErrorKind::Interrupted` on cancellation, which std-style read loops treat as "retry" — cancelling during a 1 MiB chunk read could spin forever. It now returns a distinct error that `map_error` still classifies as cancellation.
- **Android fd leak edge case**: if the second `openFileDescriptor` threw after the first succeeded, the first fd leaked. All three operations nest try/finally so both descriptors close on every path.

### Changed
- **Version bump** 2.1.2 → 2.2.0 (core + JNI crates, Android versionName), Android versionCode 5 → 6.
- New dependencies behind the `metadata` feature: `lopdf`, `zip` (deflate only), `lofty`; `kamadak-exif` as test-only dev-dependency for independent EXIF verification. `deny.toml` now lives at the crate root where `cargo deny check` resolves it.

### Test Results
- `cargo test --lib --release`: **63/63 pass** (38 crypto + 25 metadata tests).
- Metadata coverage: programmatic round-trip fixtures for JPEG/PNG/WebP/GIF/TIFF/BMP/PDF/OOXML/MP3/WAV/FLAC; detection matrix incl. BigTIFF/HEIC/plain-zip negatives; orchestration tests (default naming, dest conflicts, unsupported rejection without output, truncated-input fail-closed with tmp cleanup, cancel no-op, in-place replace, wipe-original, idempotence across five formats); TIFF rebuild verified pixel-exact with an independent minimal reader.
- `cargo clippy -D warnings` clean (core all-targets all-features + JNI crate); `cargo fmt --check` clean.

## [2.1.2] — 2026-08-10

### Fixed
- **Empty output files from Drive/cloud storage**: The Android JNI bridge no longer calls `ParcelFileDescriptor.detachFd()` on the input file before encryption/decryption finishes. Detaching signals the content provider that the file is closed early, so the provider finalizes the stream and the output came out as 0 bytes. The Kotlin layer now passes the raw fd, keeps the `ParcelFileDescriptor` open, and closes it in `finally`; the Rust layer duplicates the fd (`dup(2)`) and owns only its own copy. Files from remote providers (e.g. Drive) now come out intact.
- **Android predictive-back warning**: `android:enableOnBackInvokedCallback` is now enabled on `MainActivity`, removing the "framework flag / component flag" warning on Android 13+.

### Changed
- **Version bump** 2.1.1 → 2.1.2 (core + JNI crates, Android `versionName`), Android `versionCode` 4 → 5.
- JNI now depends on `libc` for `dup(2)`.

### Test Results
- `cargo test --lib`: 38/38 pass (unchanged).
- Rust code unchanged in behavior on desktop; Android fd handling verified by code review (no emulator available locally — NDK not installed).

## [2.1.1] — 2026-08-03

### Fixed
- **Android ANR on older phones**: Crypto now runs on `Dispatchers.IO` instead of the main thread. Provider metadata queries (`getFileInfo`, `detectMagicBytes`, `persistUriPermission`) were also moved off the main thread in the single-file and batch pickers, so slow/remote providers (e.g. Drive) can no longer freeze or ANR the UI.
- **"100% complete while still encrypting"**: The JNI output is now wrapped in a `DurableFile` whose `flush()` performs `sync_data()` before the stream layer broadcasts the final 100%, plus a final best-effort `sync_all`. The app no longer reports completion while data is still sitting in the kernel page cache.
- **CancellationException swallowed**: Navigating away mid-operation previously deleted the (possibly finished) output file and showed a spurious error. `CancellationException` is now re-thrown in both screens instead of being treated as a failure.
- **V3/V4 decrypt dirty-page backlog**: Added the I/O governor (periodic flush every 100 chunks) to `decrypt_stream_v3`/`decrypt_stream_v4`, mirroring `encrypt_stream`, so the final sync is fast and dirty pages stay bounded.
- **Round icon crash on API 24/25**: `@mipmap/ic_launcher_round` only existed as an adaptive icon in `anydpi-v26`. Added vector fallbacks to all density folders.

### Changed
- **Batch mode now runs under the foreground service**: The batch screen starts `CryptoService` for the duration of the batch (with throttled notification progress) and stops it on every exit path, so the process survives backgrounding mid-batch.
- **Proper Cancelled state**: Single-file cancel now shows a neutral "Operation cancelled" notice instead of a red error box.
- **Passphrase hygiene**: Batch hoists the passphrase to a single `ByteArray` converted once before the loop; both screens zero the byte array in `finally` on top of the native-side zeroing.
- **Version bump** 2.1.0 → 2.1.1 (core + JNI crates, Android `versionName`).

### Housekeeping
- Removed the accidentally-committed `offline-gmaven-stable.zip` (already gitignored) and fixed the mangled `.gitignore` tail.

### Test Results
- `cargo test --lib`: 38/38 pass.
- `:app:compileStandardDebugKotlin` and `:app:processStandardDebugResources` clean.

## [2.1.0] — 2026-07-16

### Security
- **VAULTX04 format with header AAD**: New encryptions now authenticate the full header (magic || salt || stream_nonce) as Additional Authenticated Data on every chunk. Closes the defensive-in-depth gap from the v2.0 audit (V3 did not authenticate the header at the AEAD layer). V3 and V2 files remain fully readable for backward compatibility.
- **GUI Cancel button**: Single-file and batch operations can now be aborted mid-operation. The Cancel button polls a flag at every 1 MB chunk boundary, cleans up the `.tmp` file, and returns a calm "Operation cancelled" message instead of a scary red error.
- **WIPE SOURCE FILE confirmation dialogs**: Both single-file and batch WIPE buttons now require an explicit "Delete permanently" confirmation. Previously a single misclick permanently deleted the original plaintext.
- **JNI file-descriptor leak fix**: Raw file descriptors from Android's `ParcelFileDescriptor.detachFd()` are now wrapped in `File::from_raw_fd` immediately, so any failure in subsequent JNI setup drops the File and closes the fd instead of leaking it.
- **Binary password files**: `--password-file` now accepts arbitrary bytes (not just UTF-8). The buffer is wrapped in `Zeroizing<Vec<u8>>` from the start, so even on UTF-8 failure the bytes are zeroed before being freed.
- **Type-safe ParcelFileDescriptor handling**: `MainActivity.getParcelableExtra` now uses the API 33+ typed overload with a `ClassCastException` fallback for older Android versions, preventing crashes from attacker apps sending non-Uri Parcelables.
- **4 PiB file size limit enforced**: The EncryptorBE32 32-bit counter limits V3/V4 files to 2^32 × 1 MiB = 4 PiB. Encryption now explicitly rejects larger files with `FileTooLarge` instead of silently wrapping the counter (which would cause catastrophic GCM-SIV nonce reuse). A runtime counter guard was also added to `encrypt_stream` for cases where the source size is unknown.
- **V2 stream-decrypt 1 GiB limit fixed**: Previously a 1 GiB V2 file decrypted via `decrypt -i f.vx2` but failed via `cat f.vx2 | decrypt -i -`. Both paths now use the same `take(limit+1)` + `>` comparison.
- **Batch mode hash fix**: Batch mode now hashes the OUTPUT file (ciphertext on encrypt, plaintext on decrypt) instead of the source plaintext — closes a screenshot-leak verifier for the plaintext.
- **AndroidManifest hardening**: `allowBackup=false`, `fullBackupContent=false`.
- **URI permission pruning**: Stale persisted URI permissions are released at startup so the ~128-permission cap is never hit.
- **JNI `panic = "abort"` removed**: `panic::catch_unwind` in the JNI layer now actually catches panics, converting them to Java exceptions instead of crashing the app.
- **JNI cancel detection**: Uses `ErrorKind::Interrupted` instead of fragile string comparison.
- **`std::env::set_var` wrapped in `unsafe`**: Forward-compatibility with Rust edition 2024.
- **`constant_time_eq` doc warning**: Documents that it leaks the longer input length and is unsafe for secret comparison.

### Added
- **V4 format** (`VAULTX04`): AAD-authenticated streaming format, current default for new encryptions.
- **GUI Cancel button** on Processing screen.
- **"Advanced" collapsible panel** in Configure screen showing cipher / KDF / format details (default closed).
- **Contextual one-liner** above the password field explaining what's happening.
- **Collapsible "Details" section** on Result screen for the SHA-256 hash.
- **22 new tests**: 13 V3 edge cases (empty file, single byte, chunk boundaries, truncation, tampered salt/nonce/chunk, magic-swap, reorder, extension) + 9 V4 tests (roundtrip, AAD tamper detection, magic swap, empty file, wrong password, pipe roundtrip). Total: 38 tests.
- **Android CI lint-and-test job**: runs rustfmt, clippy, cargo test, and cargo audit on both the core and JNI crates before building the APK.
- **APK release workflow** (`.github/workflows/android-release.yml`): triggers on `v*` tag push, builds release APK for all 4 ABIs, signs it (with upload-keystore secret or debug fallback), attaches to GitHub release.
- **Project website** in `/docs` for GitHub Pages: dark theme, single-page site with hero, features, download, how-it-works, security threat model, FAQ.

### Changed
- **minSdk lowered 26 → 24** (Android 7.0+ support, ~95% device coverage).
- **GUI simplified** per UI research: removed scramble-text "ACTIVITY" panel (fake hacking animation), removed version stamp from every screen, simplified strength meter (single bar + one word, removed misleading "use at least N chars" hint per NIST 800-63B Rev. 4).
- **Version bump** 2.0.0 → 2.1.0 in Cargo.toml (both crates), build.gradle.kts, installer .nsi, README badge.
- **README "What's New in 2.1" section** documenting all changes.

### Backward Compatibility
- V2 (VAULTX02) and V3 (VAULTX03) files remain fully readable.
- New encryptions default to V4 (VAULTX04) with AAD-authenticated header.
- There is no V3→V4 auto-migration; users who want V4 must re-encrypt.

### Test Results
- `cargo test --lib --release`: 38/38 pass in 26.04s
- `cargo clippy --all-targets -- -D warnings`: clean (both core and JNI crates)
- `cargo fmt --all -- --check`: clean (both crates)
- Fuzzing: 6 tamper attacks (flip salt/nonce/magic/body byte, truncate, append garbage) all correctly rejected. 5/5 ciphertexts unique with 5/5 distinct salt+nonce regions.

## [2.0.0] — 2026

Initial public release.

- AES-256-GCM-SIV (RFC 8452) with BE32 streaming
- Argon2id (256 MiB / 3 iter / 4 lanes) KDF
- HKDF-SHA512 key expansion with V2/V3 domain separation
- VAULTX03 streaming format (1 MiB chunks, per-chunk auth tags)
- VAULTX02 legacy format (single-shot, ≤1 GiB)
- Cross-platform: Windows x64, macOS Universal, Linux x64
- Android app via JNI (arm64, armv7, x86_64, x86)
- NSIS Windows installer with `.vx2` file association
- CLI with piping, JSON output, shell completions
- 100% Safe Rust, `Zeroizing<T>` memory hygiene, `OsRng` CSPRNG

[2.1.2]: https://gitlab.com/theredhacker0345/neuron-encrypt/-/releases
[2.1.1]: https://gitlab.com/theredhacker0345/neuron-encrypt/-/releases
[2.1.0]: https://gitlab.com/theredhacker0345/neuron-encrypt/-/releases
[2.0.0]: https://gitlab.com/theredhacker0345/neuron-encrypt/-/releases
