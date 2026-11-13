# Neuron Encrypt 2.4.0

**A correctness and hardening release.** No format or UI redesign — every change fixes a bug found in a full-codebase review, and each fix has a regression test where the platform allows one.

## Highlights

- **TIFF scrubber:** two-strip SHORT-offset images are no longer silently corrupted; big-endian TIFFs now round-trip; Orientation and YCbCr decoding tags are preserved.
- **CLI:** `--password-file` works non-interactively (CI no longer hangs); piped decrypt requires `--force` before replacing an existing file.
- **Desktop GUI:** the save dialog's overwrite confirmation is honored, and egui's passphrase undo history is cleared.
- **Android:** magic-byte detection fills the full header; `WIPE SOURCE` requests and persists write access; AAC/AIFF/3GP/3G2 MIME types are mapped; stale scrub staging files are swept at startup.
- **Metadata:** OOXML cleanup is quote/namespace aware and fails closed on dangling `docProps` references; PDF deletion failures are propagated.
- **Build/CI:** Rust 1.89 images, tag-triggered release workflow with the correct permissions, keystore cleanup, and `build-all.sh` fixed.

## Downloads

| Platform | Asset |
|---|---|
| Windows x64 | `neuron-encrypt-2.4.0-windows-x86_64.zip` (GUI + CLI) · `neuron-encrypt-cli-2.4.0-windows-x86_64.exe` |
| Linux x64 | `NeuronEncrypt-2.4.0-x86_64.AppImage` · `neuron-encrypt_2.4.0_amd64.deb` · `neuron-encrypt-2.4.0-linux-x86_64.tar.gz` (GUI + CLI) · `neuron-encrypt-cli-2.4.0-linux-x86_64` |
| Android | `neuron-encrypt-2.4.0-android.apk` (F-Droid unsigned build) |

All assets are listed with SHA-256 digests in `SHA256SUMS.txt`.

## Verify

```sh
sha256sum -c SHA256SUMS.txt
```

## Tests

- `cargo test --all-targets`: **94/94 pass** (92 library + 2 CLI).
- `cargo clippy --all-targets`: clean except one pre-existing test warning.
- Windows, Linux and Android release builds completed from this tag.

## Security

This release fixes data-integrity and privacy bugs in the metadata scrubber, a passphrase-lifetime issue in the desktop GUI, and an Android wipe-permission bug. See [CHANGELOG.md](../../CHANGELOG.md) for the full list.