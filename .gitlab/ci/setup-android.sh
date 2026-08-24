#!/usr/bin/env bash
# Android CI setup: JDK env, cached SDK/NDK install, rust targets, cargo-ndk.
# Called from .gitlab/ci/android.yml before_script.
set -euo pipefail

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH="$JAVA_HOME/bin:$HOME/.cargo/bin:$PATH"

# ---- Android SDK + NDK (skips when restored from cache) --------------------
if [ ! -f "$ANDROID_NDK_HOME/source.properties" ]; then
  echo "Installing Android SDK + NDK into $ANDROID_HOME ..."
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdtools.zip
  unzip -q /tmp/cmdtools.zip -d "$ANDROID_HOME/cmdline-tools"
  mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
  # pipefail-safe license acceptance (yes dies of SIGPIPE once sdkmanager exits)
  (printf 'y\n%.0s' $(seq 1 30)) | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$ANDROID_HOME" --licenses >/dev/null || true
  "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$ANDROID_HOME" \
    "platforms;android-34" "build-tools;34.0.0" "platform-tools" "ndk;26.1.10909125" > /dev/null
else
  echo "SDK/NDK restored from cache"
fi

test -f "$ANDROID_NDK_HOME/source.properties" || { echo "FATAL: NDK missing after setup"; exit 1; }

# ---- Rust targets ----------------------------------------------------------
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# ---- cargo-ndk: prebuilt binary (any archive layout), fallback to source ---
mkdir -p "$CARGO_HOME/bin"
if [ ! -x "$CARGO_HOME/bin/cargo-ndk" ]; then
  tmpd=$(mktemp -d)
  if curl -sSfL https://github.com/bbqsrc/cargo-ndk/releases/download/v4.1.2/cargo-ndk-x86_64-unknown-linux-gnu-v4.1.2.tgz \
       | tar -xz -C "$tmpd"; then
    BIN=$(find "$tmpd" -type f -name cargo-ndk | head -1)
    [ -n "$BIN" ] && install -m 755 "$BIN" "$CARGO_HOME/bin/cargo-ndk"
  fi
  rm -rf "$tmpd"
  if [ ! -x "$CARGO_HOME/bin/cargo-ndk" ]; then
    echo "prebuilt unavailable; compiling cargo-ndk from source"
    cargo install cargo-ndk --locked --version 4.1.2
  fi
fi
export PATH="$CARGO_HOME/bin:$PATH"
cargo ndk --version
