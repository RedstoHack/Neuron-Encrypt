# CI/CD Pipeline Documentation

## Overview
This project uses GitLab CI/CD to automatically build and test Neuron Encrypt for:
- **Linux** (x86_64-unknown-linux-gnu) - native build
- **Windows** (x86_64-pc-windows-gnu) - cross-compiled from Linux
- **macOS** (x86_64-apple-darwin) - cross-compiled from Linux
- **Android** (ARM64, ARMv7, x86_64, x86) - native build via cargo-ndk + Gradle

## Pipeline Stages

### 1. Prepare
- Fetch dependencies
- Generate lockfile
- Run code quality checks (fmt, clippy, audit, deny)

### 2. Build (Parallel)
- **Linux**: Native release build + tests
- **Windows**: Cross-compile using mingw-w64 + wine64
- **macOS**: Cross-compile using osxcross (requires macOS SDK)
- **Android**: Native build via cargo-ndk + Gradle

### 3. Package
- Creates release archives for each platform
- Generates SHA256 checksums
- Packages APK for Android

### 4. Release (Manual)
- Creates GitLab Release with artifacts
- Triggered manually on tag push

## Manual Trigger

### Via GitLab UI
1. Go to **CI/CD > Pipelines**
2. Click **Run pipeline**
3. Select branch/tag
4. Click **Run pipeline**

### Via API
```bash
curl -X POST \
  -H "PRIVATE-TOKEN: <your_token>" \
  -F "ref=main" \
  "https://gitlab.com/api/v4/projects/<project_id>/pipeline"
```

### Scheduled Builds
- Runs nightly with address sanitizer
- Runs on tag push for releases

## Local Development

### Quick Commands
```bash
# Build all platforms locally
./scripts/build-all.sh all

# Build specific platform
./scripts/build-all.sh linux
./scripts/build-all.sh windows
./scripts/build-all.sh macos
./scripts/build-all.sh android

# Package only
./scripts/build-all.sh package
```

### Prerequisites
```bash
# Linux
sudo apt-get install mingw-w64 wine64

# macOS (for cross-compilation)
brew install osxcross

# Android
# - Install Android SDK/NDK
# - Set ANDROID_SDK_ROOT, ANDROID_NDK_HOME
# - Install cargo-ndk: cargo install cargo-ndk --locked
```

## Artifacts

### Linux
- `neuron-encrypt-<version>-linux-x86_64.tar.gz`

### Windows
- `neuron-encrypt-<version>-windows-x86_64.zip`

### macOS
- `neuron-encrypt-<version>-macos-x86_64.tar.gz`

### Android
- `neuron-encrypt-<version>.apk`

### Checksums
- `SHA256SUMS.txt` in release directory

## Troubleshooting

### Windows Cross-Compilation Fails
```bash
# Install mingw-w64
sudo apt-get install mingw-w64

# Verify
x86_64-w64-mingw32-gcc --version
```

### macOS Cross-Compilation Fails
```bash
# Install osxcross
brew install osxcross

# Set SDKROOT
export SDKROOT=/opt/macos-sdk/MacOSX13.3.sdk
```

### Android Build Fails
```bash
# Ensure SDK/NDK paths are set
export ANDROID_SDK_ROOT=$HOME/Android/Sdk
export ANDROID_NDK_HOME=$ANDROID_SDK_ROOT/ndk/26.1.10909125

# Accept licenses
yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses
```

### SSL Certificate Issues
```bash
# Add intercept CA to truststore
# The CI config includes truststore configuration
export GRADLE_OPTS="-Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts -Djavax.net.ssl.trustStorePassword=changeit"
```

## Release Process

1. Update version in `neuron-encrypt/Cargo.toml`
2. Update CHANGELOG.md
3. Create and push tag:
   ```bash
   git tag v2.2.0
   git push origin v2.2.0
   ```
4. Go to GitLab > CI/CD > Pipelines
5. Run pipeline for the tag
6. When package stage completes, manually trigger `release` job
6. Release will be created with all artifacts

## Security

- All dependencies audited with `cargo audit`
- License compliance checked with `cargo deny`
- SBOM generated on release
- Provenance verification via SLSA
