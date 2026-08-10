# Changelog

All notable changes to Neuron Encrypt are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
