#!/usr/bin/env bash
# Local build script for all platforms
# Run this script locally to test builds before pushing

set -euo pipefail

VERSION=$(grep '^version =' neuron-encrypt/Cargo.toml | cut -d'"' -f2)
echo "Building Neuron Encrypt v$VERSION for all platforms..."

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[BUILD]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# Check dependencies
check_deps() {
    log "Checking dependencies..."
    command -v cargo >/dev/null || error "cargo not found"
    command -v rustup >/dev/null || error "rustup not found"
    
    # Check for cross-compilation targets
    rustup target list --installed | grep -q "x86_64-unknown-linux-gnu" || rustup target add x86_64-unknown-linux-gnu
    rustup target list --installed | grep -q "x86_64-pc-windows-gnu" || rustup target add x86_64-pc-windows-gnu
    rustup target list --installed | grep -q "x86_64-apple-darwin" || rustup target add x86_64-apple-darwin
    rustup target list --installed | grep -q "aarch64-linux-android" || rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
}

build_linux() {
    log "Building Linux (x86_64-unknown-linux-gnu)..."
    cargo build --release --locked --all-targets
    cargo test --release --locked --lib
    log "Linux build complete"
}

build_windows() {
    log "Building Windows (x86_64-pc-windows-gnu)..."
    if ! command -v x86_64-w64-mingw32-gcc >/dev/null; then
        warn "mingw-w64 not installed, skipping Windows build"
        return
    fi
    cargo build --release --locked --target x86_64-pc-windows-gnu
    log "Windows build complete"
}

build_macos() {
    log "Building macOS (x86_64-apple-darwin)..."
    if [[ "$OSTYPE" != "darwin"* ]]; then
        warn "Not on macOS, skipping native macOS build (use cross-compilation with osxcross)"
        return
    fi
    cargo build --release --locked --target x86_64-apple-darwin
    log "macOS build complete"
}

build_android() {
    log "Building Android APK..."
    cd android
    chmod +x build-rust.sh
    ./build-rust.sh
    
    export ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}
    export ANDROID_HOME=$ANDROID_SDK_ROOT
    export JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}
    export PATH="$JAVA_HOME/bin:$PATH"
    
    ./gradlew :app:assembleStandardDebug --no-daemon
    cd ..
    log "Android build complete"
}

package() {
    log "Packaging releases..."
    mkdir -p release
    
    # Linux
    mkdir -p release/neuron-encrypt-$VERSION-linux-x86_64
    cp neuron-encrypt/target/release/neuron-encrypt release/neuron-encrypt-$VERSION-linux-x86_64/
    cp neuron-encrypt/target/release/neuron-encrypt-cli release/neuron-encrypt-$VERSION-linux-x86_64/
    tar -czf release/neuron-encrypt-$VERSION-linux-x86_64.tar.gz -C release neuron-encrypt-$VERSION-linux-x86_64
    
    # Windows
    if [[ -f neuron-encrypt/target/x86_64-pc-windows-gnu/release/neuron-encrypt.exe ]]; then
        mkdir -p release/neuron-encrypt-$VERSION-windows-x86_64
        cp neuron-encrypt/target/x86_64-pc-windows-gnu/release/neuron-encrypt.exe release/neuron-encrypt-$VERSION-windows-x86_64/
        cp neuron-encrypt/target/x86_64-pc-windows-gnu/release/neuron-encrypt-cli.exe release/neuron-encrypt-$VERSION-windows-x86_64/
        zip -r release/neuron-encrypt-$VERSION-windows-x86_64.zip release/neuron-encrypt-$VERSION-windows-x86_64
    fi
    
    # macOS
    if [[ -f neuron-encrypt/target/x86_64-apple-darwin/release/neuron-encrypt ]]; then
        mkdir -p release/neuron-encrypt-$VERSION-macos-x86_64
        cp neuron-encrypt/target/x86_64-apple-darwin/release/neuron-encrypt release/neuron-encrypt-$VERSION-macos-x86_64/
        cp neuron-encrypt/target/x86_64-apple-darwin/release/neuron-encrypt-cli release/neuron-encrypt-$VERSION-macos-x86_64/
        tar -czf release/neuron-encrypt-$VERSION-macos-x86_64.tar.gz -C release neuron-encrypt-$VERSION-macos-x86_64
    fi
    
    # Android
    if [[ -f android/app/build/outputs/apk/standard/debug/app-standard-debug.apk ]]; then
        mkdir -p release/neuron-encrypt-$VERSION-android
        cp android/app/build/outputs/apk/standard/debug/app-standard-debug.apk release/neuron-encrypt-$VERSION-android/neuron-encrypt-$VERSION.apk
    fi
    
    # Checksums
    cd release && sha256sum *.tar.gz *.zip *.apk > SHA256SUMS.txt 2>/dev/null || true
    cat SHA256SUMS.txt 2>/dev/null || true
    log "Packaging complete"
}

# Main
main() {
    check_deps
    
    case "${1:-all}" in
        linux) build_linux ;;
        windows) build_windows ;;
        macos) build_macos ;;
        android) build_android ;;
        package) package ;;
        all)
            build_linux
            build_windows
            build_macos
            build_android
            package
            ;;
        *)
            echo "Usage: $0 {linux|windows|macos|android|package|all}"
            exit 1
            ;;
    esac
    log "Build complete!"
}

main "$@"
