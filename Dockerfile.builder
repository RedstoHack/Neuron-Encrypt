# Dockerfile.builder - Builder image with ALL toolchains for local/CI builds
FROM rust:1.88-slim AS builder

# Install ALL system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    lld \
    ca-certificates \
    curl \
    file \
    git \
    pkg-config \
    libssl-dev \
    build-essential \
    cmake \
    ninja-build \
    mingw-w64 \
    wine64 \
    openjdk-17-jdk-headless \
    gradle \
    unzip \
    wget \
    clang \
    lld \
    libxml2-dev \
    libxml2-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Android SDK
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_NDK_HOME=/opt/android-sdk/ndk/26.1.10909125
ENV ANDROID_NDK_ROOT=/opt/android-sdk/ndk/26.1.10909125

RUN mkdir -p /opt/android-sdk && \
    cd /opt/android-sdk && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O cmdtools.zip && \
    unzip -q cmdtools.zip -d cmdline-tools && \
    mv cmdline-tools latest && \
    rm cmdtools.zip

ENV PATH="/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:$PATH"

RUN yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=/opt/android-sdk --licenses && \
    /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=/opt/android-sdk \
    "platforms;android-34" "build-tools;34.0.0" "platform-tools" "ndk;26.1.10909125"

ENV ANDROID_NDK_HOME=/opt/android-sdk/ndk/26.1.10909125
ENV ANDROID_NDK_ROOT=/opt/android-sdk/ndk/26.1.10909125

# Install cargo-ndk
RUN cargo install cargo-ndk --locked --version 4.1.2

# Install osxcross for macOS cross-compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    xz-utils \
    python3 \
    libxml2-utils \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/tpoechtrager/osxcross.git /opt/osxcross && \
    cd /opt/osxcross && \
    # Download macOS SDK
    wget -q https://github.com/phracker/MacOSX-SDKs/releases/download/13.3/MacOSX13.3.sdk.tar.xz -O tarballs/MacOSX13.3.sdk.tar.xz && \
    UNATTENDED=1 ./build.sh && \
    rm -rf tarballs

ENV PATH="/opt/osxcross/target/bin:$PATH"
ENV SDKROOT=/opt/osxcross/target/SDK/MacOSX13.3.sdk

# Install Rust targets
RUN rustup component add rustfmt clippy && \
    rustup target add \
    x86_64-unknown-linux-gnu \
    x86_64-pc-windows-gnu \
    x86_64-apple-darwin \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android

# Install cargo tools
RUN cargo install cargo-ndk --locked --version 4.1.2 && \
    cargo install cargo-audit --locked && \
    cargo install cargo-deny --locked

WORKDIR /workspace

CMD ["bash"]
