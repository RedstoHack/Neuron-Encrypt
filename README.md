<div align="center">

# 🔒 Neuron Encrypt

**Local file encryption. No accounts. No internet. No compromise.**

AES-256-GCM-SIV · Argon2id · HKDF-SHA512 · 100% Safe Rust

[![Version](https://img.shields.io/badge/version-2.3.0-6366f1?style=flat-square)](https://gitlab.com/theredhacker0345/neuron-encrypt/releases)
[![License](https://img.shields.io/badge/license-GPLv3-22c55e?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-f74c00?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![crates.io](https://img.shields.io/crates/v/neuron-encrypt?style=flat-square&logo=rust&label=crates.io)](https://crates.io/crates/neuron-encrypt)
[![F-Droid](https://img.shields.io/badge/F--Droid-available-22c55e?style=flat-square&logo=f-droid)](https://f-droid.org/packages/com.neuronencrypt.app/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-6366f1?style=flat-square)](#download)
[![Tests](https://img.shields.io/badge/tests-38%20passing-22c55e?style=flat-square)](#security)
[![Audit](https://img.shields.io/badge/audit-0%20critical%20%7C%200%20high-22c55e?style=flat-square)](docs/SECURITY_AUDIT.md)

[**Download**](#download) · [**Website**](https://theredhacker0345.gitlab.io/neuron-encrypt/) · [**Security**](#security) · [**Docs**](#how-it-works) · [**FAQ**](#faq)

</div>

---

<div align="center">

<img src="docs/screenshots/demo.gif" alt="Neuron Encrypt demo" width="280" />

</div>

---

## Why Neuron Encrypt?

You have files you don't want anyone to see. Tax returns. Medical records. Source code. Photos.

**Neuron Encrypt encrypts them on your device — no cloud, no account, no phone-home.** Your passphrase never leaves your machine. The encrypted `.vx2` file is useless to anyone who doesn't have the passphrase.

- **🔒 Nonce-misuse resistant** — AES-256-GCM-SIV (RFC 8452) stays secure even if nonce reuse happens
- **🧠 Memory-hard KDF** — Argon2id at 256 MiB makes GPU brute-force prohibitively expensive
- **🛡️ Authenticated header** — V4 format verifies the full header on every chunk (not just the body)
- **⚡ Stream any size** — 1 KB or 1 TB, constant ~258 MB RAM, up to 4 PiB max
- **🧹 Memory hygiene** — Every key and plaintext buffer is `Zeroizing<T>`, wiped on drop
- **🌍 4 platforms** — Windows, macOS, Linux, Android 7.0+ (all from one Rust codebase)
- **🔇 Offline-first** — Zero network permissions on Android, zero telemetry, zero tracking
- **📦 Atomic writes** — Output goes to `.tmp` first, then renames. No partial files on crash
- **🧽 Metadata scrubbing** — Remove EXIF/GPS, XMP, IPTC, ID3 and document properties from JPEG, PNG, WebP, GIF, TIFF, BMP, PDF, Office, MP3, AAC, M4A, FLAC, OGG, Opus, WAV, AIFF, MP4/MOV and 3GP/3G2 files

---

## What's new in 2.3.0

- **Four more scrub formats — 18 in total.** Metadata removal now works on **AAC, M4A, Opus, AIFF and 3GP/3G2**, joining JPEG, PNG, WebP, GIF, TIFF, BMP, PDF, Office, MP3, FLAC, OGG, WAV, MP4 and MOV. All four are handled by the tag writer that was already a dependency, so there is no new runtime cost. Raw AAC used to be misdetected as MP3 and could not be scrubbed at all; 3GP was detected but written out with a `.mp4` extension.
- **HEIC/HEIF stays rejected on purpose.** These carry GPS and device data in ISO-BMFF item boxes whose offsets point into the media payload. The available Rust crates either cannot write the container back or say so explicitly, and a bad rewrite would silently corrupt your photo — so HEIC fails closed with a clear message instead.
- **Fixed: a truncated image could be replaced by a corrupt stub.** A PNG cut off at a chunk boundary was reported as *successfully scrubbed*, and `scrub --in-place` would replace the original with a header-only file containing no image data. WebP and GIF had the same flaw. All three now fail closed and leave the source untouched.
- **Fixed: the Android notification that would not go away.** After a finished operation an ongoing notification sometimes stayed in the shade and could not be swiped away — it survived until the app was force-stopped from Settings. Progress updates bypassed the service, so `stopForeground()` could not remove them; they are now cancelled by id on every teardown path, and a late progress tick can no longer resurrect one.
- **Android: batch runs report completion.** A multi-file batch finished silently for a backgrounded user; it now posts a counted summary.
- **An in-app list of supported formats** so you can check before picking a file, and see exactly what is removed.
- **Fixed: `webbrowser` 1.2.1 advisory (RUSTSEC-2026-0257)** — allowed argument injection through the Unix `BROWSER` variable. Bumped to 1.2.4.
- **An AppImage for Linux**, alongside the tar.gz.
- **Release engineering**: a CI quality gate (`fmt`, `clippy -D warnings`, tests, `cargo audit`) now runs on every push, and a single `vX.Y.Z` tag builds Linux, Windows and Android in parallel and attaches the APK, EXE, archives and checksums to one release. The macOS job is removed — it needed a runner that does not exist. F-Droid metadata is corrected from its long-stale 2.1.0/3.

Tests: **86/86 pass** (63 at 2.2.0), with 14 new adversarial tests covering zero-byte, truncated, garbage and lookalike inputs, a byte-by-byte truncation sweep of every supported container, symlinks, cancellation and concurrent scrubs.

---

Older releases are documented in [CHANGELOG.md](CHANGELOG.md).

---

## Download

| Platform | Type | Link |
|----------|------|------|
| 🪟 Windows | x86_64 GUI + CLI ZIP | [GitLab packages ↗](https://gitlab.com/theredhacker0345/neuron-encrypt/-/packages) |
| 🍎 macOS | x86_64 GUI + CLI archive; Apple Silicon build is best-effort | [GitLab packages ↗](https://gitlab.com/theredhacker0345/neuron-encrypt/-/packages) |
| 🐧 Linux | x86_64 GUI + CLI archive | [Download from GitLab Package Registry ↗](https://gitlab.com/theredhacker0345/neuron-encrypt/-/packages) |
| 🤖 Android | APK (Android 7.0+) | [Latest release ↗](https://gitlab.com/theredhacker0345/neuron-encrypt/releases/latest) |
| 🖥️ Desktop GUI | Built alongside the CLI on Linux, Windows, and macOS | Use the platform archive above |
| 📦 Linux AppImage | Single self-contained file, no package manager | [Release assets ↗](https://gitlab.com/theredhacker0345/neuron-encrypt/releases/latest) |
| ⌨️ Linux CLI | Standalone x86_64 binary | [Direct GitLab download ↗](https://gitlab.com/api/v4/projects/84892701/packages/generic/neuron-encrypt-cli/2.3.0/neuron-encrypt-cli-2.3.0-linux-x86_64) |
| ⌨️ Windows CLI | Standalone x86_64 `.exe` | [Direct GitLab download ↗](https://gitlab.com/api/v4/projects/84892701/packages/generic/neuron-encrypt-cli/2.3.0/neuron-encrypt-cli-2.3.0-windows-x86_64.exe) |
| ⌨️ macOS CLI | Standalone Intel binary | [Direct GitLab download ↗](https://gitlab.com/api/v4/projects/84892701/packages/generic/neuron-encrypt-cli/2.3.0/neuron-encrypt-cli-2.3.0-macos-x86_64) |

**No account is required.** The GUI+CLI archives and standalone CLI binaries are published through GitLab's Generic Package Registry, so users do not need a Cargo account, GitHub account, or GitHub sign-in. The Linux and Windows CLI links above are live for version `2.3.0`. A signed Android APK is attached to each GitLab release alongside the F-Droid (unsigned) build.

<details>
<summary>Install the CLI from source (needs a Rust toolchain)</summary>

`cargo install` works against **crates.io**, which is independent of any GitHub account — the project's original GitHub account was banned, but that does not affect crates.io installs:

```sh
cargo install neuron-encrypt-cli
```

The published crates.io version lags behind the GitLab releases (it is at **2.1.1**), so this gives you an older build. For the current version use the prebuilt binary above, or build from the GitLab repository itself:

```sh
# Linux / macOS — compiles from source, needs Rust and the eframe GUI dependencies
cargo install --git https://gitlab.com/theredhacker0345/neuron-encrypt --tag v2.3.0 -p neuron-encrypt-cli
```

`-p` is required because the repository root is a workspace containing both binaries. The CLI itself has no GUI dependencies, so this works on a headless box.


### One-line install (recommended)

**Linux / macOS** — downloads the binary, verifies SHA-256, and adds it to your PATH:

```sh
curl -fsSL https://theredhacker0345.gitlab.io/neuron-encrypt/install.sh | sh
```

**Windows (PowerShell)** — downloads, verifies, installs to `%LOCALAPPDATA%\Programs\NeuronEncrypt\bin`, and updates your User PATH:

```powershell
irm https://theredhacker0345.gitlab.io/neuron-encrypt/install.ps1 | iex
```

Both scripts verify the SHA-256 hash before running. [View the Linux installer source](https://gitlab.com/theredhacker0345/neuron-encrypt/-/blob/main/docs/install.sh) · [View the Windows installer source](https://gitlab.com/theredhacker0345/neuron-encrypt/-/blob/main/docs/install.ps1)

<details>
<summary>Manual install (Linux — curl + sha256sum)</summary>

```bash
VERSION=2.3.0
CLI_FILE="neuron-encrypt-cli-${VERSION}-linux-x86_64"
curl -fL "https://gitlab.com/api/v4/projects/84892701/packages/generic/neuron-encrypt-cli/${VERSION}/${CLI_FILE}" -o "$CLI_FILE"
curl -fL "https://gitlab.com/api/v4/projects/84892701/packages/generic/neuron-encrypt-cli/${VERSION}/SHA256SUMS-cli-linux.txt" -o SHA256SUMS-cli-linux.txt
sha256sum --check SHA256SUMS-cli-linux.txt
chmod +x "$CLI_FILE"
install -Dm755 "$CLI_FILE" "$HOME/.local/bin/neuron-encrypt-cli"
neuron-encrypt-cli --help
```

</details>

**Verify your download:** SHA-256 hashes are published with each package and in the [release notes](https://gitlab.com/theredhacker0345/neuron-encrypt/releases). Standalone CLI checksums are published beside the binaries as `SHA256SUMS-cli-linux.txt`, `SHA256SUMS-cli-windows.txt`, and `SHA256SUMS-cli-macos.txt` when the corresponding platform package is published.

---

## Screenshots

### Desktop app (Windows)

| Home | Configure | Processing | Success |
|------|-----------|------------|---------|
| ![Home](docs/screenshots/desktop-home.png) | ![Configure](docs/screenshots/desktop-configure.png) | ![Processing](docs/screenshots/desktop-processing.png) | ![Success](docs/screenshots/desktop-success.png) |

*Real captures of the desktop build — drop zone, Encrypt/Decrypt/Scrub switcher with live cipher details, cancellable progress, and the completion screen.*

### Android app

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

## Metadata scrubbing

Scrubbing removes the metadata that leaks who/where/when — without touching your file's contents.

| Family | Formats | What gets removed |
|--------|---------|-------------------|
| Images | JPEG, PNG, WebP, GIF, TIFF, BMP | EXIF + GPS, XMP, IPTC, Photoshop blocks, ICC profiles, comments, timestamps |
| Documents | PDF, Office (`docx`/`xlsx`/`pptx`) | Author/title/dates Info dictionary, XMP streams, `docProps/*`, embedded thumbnails |
| Audio | MP3, AAC, M4A, FLAC, OGG, Opus, WAV, AIFF | ID3v1/v2, APE tags, iTunes/`ilst`, Vorbis comments, RIFF INFO, IFF text chunks |
| Video | MP4, MOV, 3GP, 3G2 | iTunes/`ilst` atoms, GPS, device and encoder tags |

Guarantees:

- **Cleaned copy by default** — `<name>.clean.<ext>` is written atomically beside your file; the original is untouched. In-place replacement and post-copy secure wipe are opt-in.
- **Fail closed** — unrecognized formats return an explicit error. A scrubber that can't understand a structure aborts rather than emitting a possibly-broken file; every output is re-validated before it replaces anything.
- **Payload integrity** — kept chunks/segments are copied byte-for-byte, so decoders see identical image/audio data. Tests verify pixels survive TIFF relocation and CRCs stay valid.
- **Bounded memory on mobile** — the Android engine stages files through app-private cache storage with a fixed 1 MiB buffer, so audio/video scrubbing keeps peak RAM flat. Formats that must be parsed whole (images, PDFs, office docs) hold ~2x the file size in memory, so Android caps them at 64 MiB (desktop: 1 GiB) and reports "too large to scrub" instead of being killed.
- **Not for HEIC yet** — HEIF/HEIC files are detected but rejected with guidance rather than riskily rewritten.

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

**Full audit:** 44 findings, 0 CRITICAL, 0 HIGH, 9 MEDIUM (all fixed), 10 LOW, 25 INFO. See [SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) and [CHANGELOG.md](CHANGELOG.md).

---

## Quick start

### Install

#### Recommended: download the Linux archive

This is the easiest option for Linux Mint. It does not require Rust, Cargo, a Cargo account, or GitHub authentication.

1. Open the [Neuron Encrypt GitLab packages](https://gitlab.com/theredhacker0345/neuron-encrypt/-/packages) page and choose the version you want.
2. Download the Linux `.tar.gz` package and its checksum file.
3. Verify the archive, extract it, and install the binaries locally:

```bash
VERSION=2.3.0
ARCHIVE="neuron-encrypt-${VERSION}-linux-x86_64.tar.gz"

# Download SHA256SUMS-linux.txt beside the archive, then verify the archive.
sha256sum "$ARCHIVE"
# Compare the output with the matching archive entry in SHA256SUMS-linux.txt.

tar -xzf "$ARCHIVE"
install -Dm755 "neuron-encrypt-${VERSION}-linux-x86_64/neuron-encrypt" "$HOME/.local/bin/neuron-encrypt"
install -Dm755 "neuron-encrypt-${VERSION}-linux-x86_64/neuron-encrypt-cli" "$HOME/.local/bin/neuron-encrypt-cli"
```

Compare the printed SHA-256 value with the matching entry in `SHA256SUMS-linux.txt` before running the binaries. Start a new terminal if `~/.local/bin` is not already on your `PATH`.

#### Optional: build from source

A Cargo account is **not** needed for a normal public dependency download. If you prefer a local build, Linux Mint users can use the distribution packages instead of installing `rustup`:

```bash
sudo apt update
sudo apt install --yes cargo rustc build-essential pkg-config libssl-dev

git clone https://gitlab.com/theredhacker0345/neuron-encrypt.git
cd neuron-encrypt
cargo build --release --locked --bin neuron-encrypt --bin neuron-encrypt-cli
```

The resulting files are `neuron-encrypt/target/release/neuron-encrypt` and `neuron-encrypt/target/release/neuron-encrypt-cli`. This build path is optional; most users should use the prebuilt GitLab archive above.

#### Remove only this source build

A source build does not require removing Rust from the whole system. To reclaim the space used by this checkout, run the following from the repository directory:

```bash
cargo clean
cd ..
rm -rf neuron-encrypt
```

These commands remove only this project’s `target/` directory and checkout. They do not remove Cargo, Rust, or other Rust projects. If you installed Rust only for Neuron Encrypt through `rustup`, you may later run `rustup self uninstall`; otherwise keep the toolchain for your other projects.

### GUI

```bash
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

# Strip metadata (writes photo.clean.jpg beside the original)
neuron-encrypt-cli scrub -i photo.jpg

# Scrub in place instead, with machine-readable output
neuron-encrypt-cli scrub -i video.mp4 --in-place --json
```

### Android

Download the APK from [releases](https://gitlab.com/theredhacker0345/neuron-encrypt/releases) or build with the [JNI toolchain](android/README.md). Minimum: Android 7.0 (API 24).

### Run tests

```bash
cargo test --lib --release
```

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

Windows is the only platform that requires code signing, and Authenticode certificates cost $200-400/year. F-Droid distribution is already live (unsigned build), so Windows signing is the last remaining platform for code signing. For now, Windows SmartScreen will warn on first install — click "Run anyway". Always verify the SHA-256 hash in the release notes against your download.
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

**Do NOT open a public issue.** Use the [GitLab confidential issue](https://gitlab.com/theredhacker0345/neuron-encrypt/-/issues/new?issue[confidential]=true) to report privately. We'll acknowledge within 48 hours and work with you on a fix before public disclosure.
</details>

<details>
<summary><b>What are the CLI limitations?</b></summary>

- **No stdin encrypt / scrub** — both require seeking, so piped input is decrypt-only for now
- **Argon2id params are fixed** — no `--memory-cost` / `--time-cost` flags (set by design)
- **No batch/glob mode** — single-file only; use `find -exec` or a loop for batch (the GUI and Android app support batch scrubbing)
- **No `--dry-run`** — no preview without processing
- **No password generation flag** — use a password manager
</details>

---



## Project structure

```
Neuron-Encrypt/
├── neuron-encrypt/          # Rust core (crypto + metadata + GUI + CLI)
│   ├── src/crypto.rs        # AES-256-GCM-SIV, Argon2id, V2/V3/V4 formats
│   ├── src/metadata/        # Metadata scrubbing (EXIF/GPS/XMP/ID3/docProps)
│   ├── src/gui.rs           # egui desktop GUI
│   ├── src/bin/cli.rs       # CLI binary
│   └── Cargo.toml
├── android/                 # Android app (Kotlin + Rust JNI)
│   ├── app/                 # Compose Material3 UI
│   ├── neuron-encrypt-jni/  # Rust JNI bridge
│   └── build-rust.sh        # Cross-compile 4 ABIs
├── installer/               # NSIS Windows installer
├── docs/                    # Website, audits, release notes, CI/CD reference
│   ├── index.html           # GitLab Pages site
│   ├── install.sh/.ps1      # One-line installers
│   ├── SECURITY_AUDIT.md    # Full audit report (44 findings)
│   ├── CI_CD.md             # Pipeline reference
│   └── releases/            # Per-version release notes
├── fastlane/                # F-Droid / Play metadata
├── metadata/                # F-Droid build definitions
├── CHANGELOG.md             # Version history
└── README.md                # This file
```

---

## Contributing

Bug reports and pull requests welcome. For security vulnerabilities, use [GitLab confidential issue](https://gitlab.com/theredhacker0345/neuron-encrypt/-/issues/new?issue[confidential]=true) instead of a public issue.

```bash
rustup component add rustfmt clippy
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --lib --release
```

See [CLI_IMPROVEMENT_PLAN.md](CLI_IMPROVEMENT_PLAN.md) for the post-review improvement backlog.

---

## Distribution
| Channel | Package | Status |
|---------|---------|--------|
| [GitLab Package Registry](https://gitlab.com/theredhacker0345/neuron-encrypt/-/packages) | GUI + CLI archives and standalone CLI binaries for desktop platforms | ✅ Recommended; no account required |
| [GitLab Releases](https://gitlab.com/theredhacker0345/neuron-encrypt/releases) | Release notes, source archives, and platform assets | ✅ Published; platform assets depend on the completed packaging job |
| [crates.io](https://crates.io/crates/neuron-encrypt) | `neuron-encrypt` core + `neuron-encrypt-cli` CLI | ✅ Developer channel; login is not required to install public crates |
| [F-Droid](https://f-droid.org/packages/com.neuronencrypt.app/) | Android APK | ✅ Available |
| [Homebrew](https://brew.sh) | `neuron-encrypt` formula | ❓ Planned if there is demand |
| AppImage / Snap / Scoop | — | ❓ Future packaging options; direct GitLab packages are the current easiest desktop path |

---

## License

GPLv3 — Copyright (c) 2024–2026 Ubaid ur Rehman. See [LICENSE](LICENSE) for full text.

---

<div align="center">

**[Download](#download)** · **[Website](https://theredhacker0345.gitlab.io/neuron-encrypt/)** · **[Security](#security)** · **[FAQ](#faq)**

Made with Rust · No tracking · No cookies · No analytics

</div>
