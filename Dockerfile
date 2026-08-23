# Multi-stage Dockerfile for Neuron Encrypt
# Build stage
FROM rust:1.88-slim AS builder

WORKDIR /app

# Install system dependencies
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
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY . .

# Build release binaries
RUN cargo build --release --locked

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false neuron-encrypt

# Copy binaries
COPY --from=builder /app/target/release/neuron-encrypt /usr/local/bin/
COPY --from=builder /app/target/release/neuron-encrypt-cli /usr/local/bin/

# Set up user
USER neuron-encrypt
WORKDIR /data

# Default command
ENTRYPOINT ["neuron-encrypt"]
CMD ["--help"]
