# Neuron Encrypt v2.1.0 — Release Notes

**Local file encryption. No accounts. No internet. No compromise.**

AES-256-GCM-SIV · Argon2id · HKDF-SHA512 · 100% Safe Rust

---

## 🔒 Core Changes

- **VAULTX04 format with header AAD**: New encryptions now authenticate the full header (magic \|\| salt \|\| stream_nonce) as Additional Authenticated Data on every chunk. Closes the defensive-in-depth gap from the v2.0 audit (V3 did not authenticate the header at the AEAD layer). V3 and V2 files remain fully readable for backward compatibility.
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

---

## 📱 Android

- **minSdk lowered 26 → 24** (Android 7.0+ support, ~95% device coverage).
- **Universal APK**: Single APK contains all 4 ABIs (arm64-v8a, armeabi-v7a, x86_64, x86).
- **F-Droid flavor**: `fdroidRelease` build variant for F-Droid submission (unsigned, no proprietary dependencies).
- **File picker UX**: Subtitle added to file selection screen ("Any file type · Any size").

---

## 🔐 Security Audit Results

| Metric | Result |
|--------|--------|
| Total findings | 44 |
| **Critical** | **0** |
| **High** | **0** |
| Medium (fixed) | 9 |
| Low | 10 |
| Info | 25 |

Full report: [SECURITY_AUDIT.md](SECURITY_AUDIT.md)

---

## 📦 Format Versions

| Format | Name | Description |
|--------|------|-------------|
| V2 | VAULTX02 | Legacy single-shot format, entire file in RAM, ≤1 GiB |
| V3 | VAULTX03 | Streaming format, 1 MiB chunks, no size limit, header NOT authenticated |
| V4 | VAULTX04 | Current default — same as V3 but with header authenticated as AAD on every chunk |

All three are readable by v2.1. New encryptions use V4. There is no auto-migration — re-encrypt to upgrade.

---

## 🔄 Migration

**No file format changes — v2.0 .vx2 files decrypt normally.** All existing V2, V3, and V4 files remain readable. New encryptions default to V4.

---

## 📥 Assets

| Asset | SHA-256 |
|-------|---------|
| `NeuronEncrypt-v2.1.0-x86_64-unknown-linux-gnu.tar.gz` | `SHA256_PLACEHOLDER` |
| `NeuronEncrypt-v2.1.0-x86_64-pc-windows-msvc.zip` | `SHA256_PLACEHOLDER` |
| `NeuronEncrypt-v2.1.0-aarch64-apple-darwin.tar.gz` | `SHA256_PLACEHOLDER` |
| `NeuronEncrypt-v2.1.0-arm64-v8a-android.apk` | `SHA256_PLACEHOLDER` |
| `NeuronEncrypt-v2.1.0-x86_64-android.apk` | `SHA256_PLACEHOLDER` |

**Verify your download:** SHA-256 hashes are published in each [release note](https://github.com/darkmaster0345/Neuron-Encrypt/releases).

---

## 🔧 CLI Changes

- **Binary password files**: `--password-file` now accepts arbitrary bytes (not just UTF-8).
- **JSON output for CI/CD**: `neuron-encrypt-cli encrypt -i artifact.zip --json --password-file /secrets/key`
- **Pipe over SSH**: `neuron-encrypt-cli encrypt -i backup.tar.gz -o - \| ssh user@host 'cat > backup.vx2'`

---

*Made with Rust · No tracking · No cookies · No analytics*
