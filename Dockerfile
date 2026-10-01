# =============================================================================
# Neuron Encrypt — runtime image
#
# Builds the release binaries and copies just those into a slim Debian image
# running as an unprivileged user.
#
# This is NOT a development image. For the full toolchain — Android SDK and
# NDK, osxcross, mingw-w64, wine, JDK, Gradle — use Dockerfile.builder.
#
# Build from the repository root:
#   docker build -t neuron-encrypt .
#   docker run --rm -v "$PWD/data:/data" neuron-encrypt --help
# =============================================================================

ARG RUST_IMAGE=rust:1.88-slim
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${RUST_IMAGE} AS builder

WORKDIR /src

# Toolchain only. clang/lld are link-time, cmake/ninja are build-time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    lld \
    ca-certificates \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first so dependency compilation is cached independently of
# source edits.
COPY neuron-encrypt/Cargo.toml neuron-encrypt/Cargo.lock ./neuron-encrypt/
RUN mkdir -p neuron-encrypt/src \
    && echo 'fn main() {}' > neuron-encrypt/src/main.rs \
    && echo '' > neuron-encrypt/src/lib.rs \
    && cd neuron-encrypt \
    && cargo build --release --locked --bin neuron-encrypt --bin neuron-encrypt-cli \
    && rm -rf src

# Now the real source. The crate lives in neuron-encrypt/, not the repository
# root — `COPY . .` followed by a bare `cargo build` at the root fails with
# "could not find `Cargo.toml`", which is what this image used to do.
COPY neuron-encrypt/src ./neuron-encrypt/src
COPY neuron-encrypt/assets ./neuron-encrypt/assets
COPY neuron-encrypt/build.rs ./neuron-encrypt/build.rs
RUN cd neuron-encrypt && cargo build --release --locked --bin neuron-encrypt --bin neuron-encrypt-cli

# -----------------------------------------------------------------------------

FROM ${RUNTIME_IMAGE} AS runtime

# libssl3 for the crypto stack. The GUI additionally needs GL/X11/Wayland
# libraries, which are deliberately not installed here — see the note below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged, no login shell, no home.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin neuron-encrypt

COPY --from=builder /src/neuron-encrypt/target/release/neuron-encrypt /usr/local/bin/
COPY --from=builder /src/neuron-encrypt/target/release/neuron-encrypt-cli /usr/local/bin/

USER neuron-encrypt
WORKDIR /data

# Default is the CLI, not the GUI.
#
# `neuron-encrypt` is an eframe (winit) windowed application: it opens an X11
# or Wayland window at startup and cannot run in a container with no display,
# so using it as the entrypoint made every bare `docker run` fail. The GUI
# binary is still present for callers that mount a display and override the
# entrypoint explicitly:
#
#   docker run --rm -it -v /tmp/.X11-unix:/tmp/.X11-unix \
#     -e DISPLAY=:0 neuron-encrypt neuron-encrypt
#
# and it needs GL/X11/Wayland runtime libraries that this image does not ship.
ENTRYPOINT ["neuron-encrypt-cli"]
CMD ["--help"]
