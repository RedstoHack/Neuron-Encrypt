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
#
# The prebuilt release binary is linked against glibc 2.39 (built on Ubuntu
# 24.04) while this image is Debian bookworm with glibc 2.36, so it can be
# present and executable yet fail with "version `GLIBC_2.39' not found" on
# first run. Testing that it actually *executes* is the only reliable check;
# a successful download and a 0755 mode do not imply it will run. Without this
# the source fallback below was skipped and the job died at the final
# `cargo ndk --version`.
mkdir -p "$CARGO_HOME/bin"
if [ ! -x "$CARGO_HOME/bin/cargo-ndk" ] || ! "$CARGO_HOME/bin/cargo-ndk" --version >/dev/null 2>&1; then
  rm -f "$CARGO_HOME/bin/cargo-ndk"
  tmpd=$(mktemp -d)
  if curl -sSfL https://github.com/bbqsrc/cargo-ndk/releases/download/v4.1.2/cargo-ndk-x86_64-unknown-linux-gnu-v4.1.2.tgz \
       | tar -xz -C "$tmpd"; then
    BIN=$(find "$tmpd" -type f -name cargo-ndk | head -1)
    if [ -n "$BIN" ]; then
      install -m 755 "$BIN" "$CARGO_HOME/bin/cargo-ndk"
      # Same problem as above: verify it runs before trusting it.
      if ! "$CARGO_HOME/bin/cargo-ndk" --version >/dev/null 2>&1; then
        echo "prebuilt cargo-ndk cannot run on this image (glibc too old); building from source"
        rm -f "$CARGO_HOME/bin/cargo-ndk"
      fi
    fi
  fi
  rm -rf "$tmpd"
  if [ ! -x "$CARGO_HOME/bin/cargo-ndk" ]; then
    echo "prebuilt unavailable; compiling cargo-ndk from source"
    cargo install cargo-ndk --locked --version 4.1.2
  fi
fi
export PATH="$CARGO_HOME/bin:$PATH"
cargo ndk --version
