# Neuron Encrypt v2.1.2 — Release Notes

**Local file encryption. No accounts. No internet. No compromise.**

AES-256-GCM-SIV · Argon2id · HKDF-SHA512 · 100% Safe Rust

---

## 🐛 Bug Fixes

- **Fixed: empty output files from Drive/cloud storage**: The Android JNI bridge no longer calls `ParcelFileDescriptor.detachFd()` on the input file before encryption/decryption finishes. Detaching prematurely signals the content provider that the file is closed, so the provider finalizes the stream early and the output came out as **0 bytes** — affecting any file opened from remote/cloud providers (e.g. Google Drive). The Kotlin layer now passes the raw fd, keeps the `ParcelFileDescriptor` open, and closes it in `finally`; the Rust layer duplicates the fd (`dup(2)`) and owns only its own copy. Files from remote providers now come out intact.
- **Fixed: Android predictive-back warning**: `android:enableOnBackInvokedCallback` is now enabled on `MainActivity`, removing the framework flag warning on Android 13+.

---

## 🧰 What Changed Under the Hood

- **Version bump** 2.1.1 → 2.1.2 (core + JNI crates, Android `versionName`), Android `versionCode` 4 → 5.
- JNI crate now depends on `libc` for the `dup(2)` fd duplication.
- Core crypto format, CLI, and desktop behavior are **unchanged** — this is a focused Android fix.

---

## 📱 Android

- Fixes empty/corrupt output when the source file lives on a content provider that needs an explicit close signal (Drive, Photos, etc.).
- No new permissions. Still zero network access.

---

## ✅ Verification

- `cargo test --lib`: 38/38 pass (unchanged).
- fd-handling fix verified by code review against the [tauri plugins-workspace #3356](https://github.com/tauri-apps/plugins-workspace/issues/3356) detachFd bug class.

---

## 🔄 Migration

**No file format changes — all existing V2, V3, and V4 files decrypt normally.**

---

## 📥 Assets

| Asset | Description |
|-------|-------------|
| `NeuronEncrypt-Windows.exe` | Windows x64 |
| `NeuronEncrypt-Windows-x64-Setup.exe` | Windows x64 installer |
| `NeuronEncrypt-Linux` | Linux x64 static binary |
| `NeuronEncrypt-macOS` | macOS Universal (Intel + Apple Silicon) |
| `NeuronEncrypt-Android.apk` | Android APK (all 4 ABIs, Android 7.0+) |
| `SHA256SUMS.txt` | SHA-256 hashes for all assets |

**Verify your download:** SHA-256 hashes are published in each [release note](https://gitlab.com/theredhacker0345/neuron-encrypt/-/releases).

---

*Made with Rust · No tracking · No cookies · No analytics*
