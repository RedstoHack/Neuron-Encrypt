<div align="center">

# 🔒 Neuron Encrypt

**Local file encryption. No accounts. No internet. No compromise.**

AES-256-GCM-SIV · Argon2id · HKDF-SHA512 · 100% Safe Rust

[![Version](https://img.shields.io/badge/version-2.1.0-6366f1?style=flat-square)](https://github.com/darkmaster0345/Neuron-Encrypt/releases)
[![License](https://img.shields.io/badge/license-GPLv3-22c55e?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-f74c00?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-6366f1?style=flat-square)](#download)
[![Tests](https://img.shields.io/badge/tests-38%20passing-22c55e?style=flat-square)](#security)
[![Audit](https://img.shields.io/badge/audit-0%20critical%20%7C%200%20high-22c55e?style=flat-square)](SECURITY_AUDIT.md)

[**Download**](#download) · [**Website**](https://darkmaster0345.github.io/Neuron-Encrypt/) · [**Security**](#security) · [**Docs**](#how-it-works) · [**FAQ**](#faq)

</div>

---

<div align="center">

<img src="docs/screenshots/demo.gif" alt="Neuron Encrypt demo" width="280" />

</div>

---

## Why Neuron Encrypt?

You have files you don't want anyone to see. Tax returns. Medical records. Source code. Photos.

**Neuron Encrypt encrypts them on your device — no cloud, no account, no phone-home.** Your passphrase never leaves your machine. The encrypted `.vx2` file is useless to anyone who doesn't have it.

- **🔒 Nonce-misuse resistant** — AES-256-GCM-SIV (RFC 8452) stays secure even if nonce reuse happens
- **🧠 Memory-hard KDF** — Argon2id at 256 MiB makes GPU brute-force prohibitively expensive
- **🛡️ Authenticated header** — V4 format verifies the full header on every chunk (not just the body)
- **⚡ Stream any size** — 1 KB or 1 TB, constant ~258 MB RAM, up to 4 PiB max
- **🧹 Memory hygiene** — Every key and plaintext buffer is `Zeroizing<T>`, wiped on drop
- **🌍 4 platforms** — Windows, macOS, Linux, Android 7.0+ (all from one Rust codebase)
- **🔇 Offline-first** — Zero network permissions on Android, zero telemetry, zero tracking
- **📦 Atomic writes** — Output goes to `.tmp` first, then renames. No partial files on crash

---

## Download

| Platform | Type | Link |
|----------|------|------|
| 🪟 Windows | x64 installer + portable | [Latest release ↗](https://github.com/darkmaster0345/Neuron-Encrypt/releases/latest) |
| 🍎 macOS | Universal (Intel + Apple Silicon) | [Latest release ↗](https://github.com/darkmaster0345/Neuron-Encrypt/releases/latest) |
| 🐧 Linux | x64 static binary | [Latest release ↗](https://github.com/darkmaster0345/Neuron-Encrypt/releases/latest) |
| 🤖 Android | APK (Android 7.0+) | [Latest release ↗](https://github.com/darkmaster0345/Neuron-Encrypt/releases/latest) |
| ⌨️ CLI | For scripts and CI/CD | `cargo install --git https://github.com/darkmaster0345/Neuron-Encrypt --bin neuron-encrypt-cli` |

**Verify your download:** SHA-256 hashes are published in each [release note](https://github.com/darkmaster0345/Neuron-Encrypt/releases).

---

## Screenshots

<div align="center">

<!-- Animated demo GIF — cycles through all 4 screens -->
<img src="docs/screenshots/demo.gif" alt="Neuron Encrypt demo" width="300" />

*Neuron Encrypt in action — Home → File Selection → Encryption Complete → About*

<!-- Static screenshots with proper sizing via HTML img tags -->
<table>
  <tr>
    <td align="center"><img src="docs/screenshots/thumbs/home.png" width="200" alt="Home Screen"/><br/><sub>Home</sub></td>
    <td align="center"><img src="docs/screenshots/thumbs/picker.png" width="200" alt="File Picker"/><br/><sub>File Selection</sub></td>
    <td align="center"><img src="docs/screenshots/thumbs/success.png" width="200" alt="Success"/><br/><sub>Encryption Complete</sub></td>
    <td align="center"><img src="docs/screenshots/thumbs/about.png" width="200" alt="About"/><br/><sub>About</sub></td>
  </tr>
</table>

*Android app — dark theme, Material 3*

</div>

---

## How it works

```
┌─────────────────────────────────────────────────────────┐
│  Your file  ──►  Passphrase  ──►  AES-256-GCM-SIV  ──►  .vx2  │
└─────────────────────────────────────────────────────────┘
```

1. **Drop a file** — or click Browse. Auto-detects encrypt vs decrypt from magic bytes.
2. **Enter a passphrase** — strength meter gives instant feedback.
3. **Click ENCRYPT** — file streams through 1 MiB chunks, written atomically to `.vx2`.
4. **Done** — original is untouched. Optionally wipe it (with confirmation).

Your passphrase is held in memory only long enough to derive the key via Argon2id, then zeroed. It's never written to disk, never sent over network, never logged.

---

## Security

### Cipher suite

| Layer | Algorithm | Parameters |
|-------|-----------|------------|
| Encryption | AES-256-GCM-SIV (RFC 8452) | BE32 streaming, 1 MiB chunks, per-chunk auth tag |
| Key derivation | Argon2id (RFC 9106) | m=256 MiB, t=3, p=4, 64-byte output |
| Key expansion | HKDF-SHA512 (RFC 5869) | Per-version domain separation (V2/V3/V4) |
| Randomness | OsRng (OS CSPRNG) | Fresh salt + nonce per file, never reused |
| Memory hygiene | `Zeroizing<T>` | Keys + plaintext wiped from RAM on drop |
| File format | VAULTX04 | Header authenticated as AAD on every chunk |

### Threat model

**Protected against:**
- ✅ Offline brute-force (Argon2id 256 MiB memory cost)
- ✅ Ciphertext tampering (per-chunk GCM-SIV authentication tags)
- ✅ Header tampering (V4 AAD authenticates magic + salt + nonce)
- ✅ Nonce reuse (GCM-SIV is misuse-resistant; fresh random nonce per file)
- ✅ Truncation, reordering, substitution attacks (BE32 counter + flag binding)
- ✅ Plaintext lingering in RAM (`Zeroizing<T>` on all secret buffers)

**Not protected against:**
- ❌ Cold-boot / DMA attacks (no in-memory encryption)
- ❌ Keyloggers and screen recorders
- ❌ SSD wear-leveling (secure wipe is best-effort on flash storage)
- ❌ Weak passphrases (strength meter is advisory, not enforced)
- ❌ Metadata leakage (file names, sizes, timestamps are visible)

**Full audit:** 44 findings, 0 CRITICAL, 0 HIGH, 9 MEDIUM (all fixed), 10 LOW, 25 INFO. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) and [CHANGELOG.md](CHANGELOG.md).

---

## Quick start

### GUI (desktop)

```bash
git clone https://github.com/darkmaster0345/Neuron-Encrypt.git
cd Neuron-Encrypt/neuron-encrypt
cargo build --release --bin neuron-encrypt
./target/release/neuron-encrypt
```

### CLI

```bash
# Encrypt (interactive prompt)
neuron-encrypt-cli encrypt -i secret.pdf

# Decrypt
neuron-encrypt-cli decrypt -i secret.pdf.vx2

# Pipe over SSH
neuron-encrypt-cli encrypt -i backup.tar.gz -o - | ssh user@host 'cat > backup.vx2'

# JSON output for CI/CD
neuron-encrypt-cli encrypt -i artifact.zip --json --password-file /secrets/key
```

### Android

Build from source or download the APK from [releases](https://github.com/darkmaster0345/Neuron-Encrypt/releases). Minimum: Android 7.0 (API 24). No Google Play account required.

---

## FAQ

<details>
<summary><b>Can I recover my files if I forget the passphrase?</b></summary>

No. There is no backdoor, no recovery key, no master password. If you forget the passphrase, the files are gone. This is by design — a backdoor that lets you in also lets an attacker in.
</details>

<details>
<summary><b>Is my passphrase stored anywhere?</b></summary>

No. The passphrase is held in memory only long enough to derive the encryption key via Argon2id, then it's zeroed. It's never written to disk, never sent over the network, never logged.
</details>

<details>
<summary><b>What's the difference between V2, V3, and V4 formats?</b></summary>

- **V2 (VAULTX02)** — legacy single-shot format, entire file in RAM, ≤1 GiB
- **V3 (VAULTX03)** — streaming format, 1 MiB chunks, no size limit, header NOT authenticated
- **V4 (VAULTX04)** — current default, same as V3 but with header authenticated as AAD on every chunk

All three are readable by v2.1. New encryptions use V4. There is no auto-migration — re-encrypt to upgrade.
</details>

<details>
<summary><b>Why is the binary not code-signed?</b></summary>

Code signing requires an Authenticode certificate ($200-400/year for OV, more for EV). This is an open-source project without a budget for that yet. Windows SmartScreen will warn on first install — click "Run anyway". Always verify the SHA-256 hash in the release notes against your download.
</details>

<details>
<summary><b>How does this compare to VeraCrypt / Cryptomator / 7-Zip?</b></summary>

| Feature | Neuron Encrypt | VeraCrypt | Cryptomator | 7-Zip AES |
|---------|---------------|-----------|-------------|-----------|
| Scope | File-level | Volume/container | Cloud-file | File-level |
| Cipher | AES-256-GCM-SIV | AES-256-XTS | AES-256-GCM | AES-256 |
| Nonce-misuse resistant | ✅ | ❌ | ❌ | ❌ |
| KDF | Argon2id 256 MiB | PBKDF2 | PBKDF2 | PBKDF2 |
| Authenticated header | ✅ (V4) | ❌ | ❌ | ❌ |
| Memory-hard | ✅ | ❌ | ❌ | ❌ |
| RAM usage | ~258 MB | Varies | Low | Low |
| Max file size | 4 PiB | 16 EiB | Unlimited | Unlimited |
| Cross-platform | ✅ 4 platforms | ✅ | ✅ | ✅ |
| Open source | ✅ GPLv3 | ✅ | ✅ | ✅ |
</details>

<details>
<summary><b>Is there a CLI?</b></summary>

Yes — `neuron-encrypt-cli` ships with the desktop build. Supports piping, JSON output, password files, shell completions, and exit codes for scripting. See [CLI usage](#quick-start) above.
</details>

<details>
<summary><b>How do I report a vulnerability?</b></summary>

**Do NOT open a public GitHub issue.** Use the [GitHub Security Advisory](https://github.com/darkmaster0345/Neuron-Encrypt/security/advisories) to report privately. We'll acknowledge within 48 hours and work with you on a fix before public disclosure.
</details>

---

## Build from source

**Prerequisites:** Rust 1.70+ ([rustup.rs](https://rustup.rs)), Git.

```bash
git clone https://github.com/darkmaster0345/Neuron-Encrypt.git
cd Neuron-Encrypt/neuron-encrypt

# Desktop GUI + CLI
cargo build --release

# CLI only (faster, no GUI deps)
cargo build --release --bin neuron-encrypt-cli

# Run tests
cargo test --lib --release
```

**Android:** See [android/README.md](android/README.md) for JNI build instructions.

**Windows installer:** See [installer/README.md](installer/README.md) for NSIS build.

---

## Project structure

```
Neuron-Encrypt/
├── neuron-encrypt/          # Rust core (crypto + GUI + CLI)
│   ├── src/crypto.rs        # AES-256-GCM-SIV, Argon2id, V2/V3/V4 formats
│   ├── src/gui.rs           # egui desktop GUI
│   ├── src/bin/cli.rs       # CLI binary
│   └── Cargo.toml
├── android/                 # Android app (Kotlin + Rust JNI)
│   ├── app/                 # Compose Material3 UI
│   ├── neuron-encrypt-jni/  # Rust JNI bridge
│   └── build-rust.sh        # Cross-compile 4 ABIs
├── installer/               # NSIS Windows installer
├── docs/                    # Website (GitHub Pages)
├── fastlane/                # F-Droid metadata
├── SECURITY_AUDIT.md        # Full audit report (44 findings)
├── CHANGELOG.md             # Version history
└── README.md                # This file
```

---

## Contributing

Bug reports and pull requests welcome. For security vulnerabilities, use [GitHub Security Advisory](https://github.com/darkmaster0345/Neuron-Encrypt/security/advisories) instead of a public issue.

```bash
rustup component add rustfmt clippy
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --lib --release
```

---

## License

GPLv3 — Copyright (c) 2024–2026 Ubaid ur Rehman. See [LICENSE](LICENSE) for full text.

---

<div align="center">

**[Download](#download)** · **[Website](https://darkmaster0345.github.io/Neuron-Encrypt/)** · **[Security](#security)** · **[FAQ](#faq)**

Made with Rust · No tracking · No cookies · No analytics

</div>
