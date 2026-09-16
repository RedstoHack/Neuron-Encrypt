#!/usr/bin/env sh
# neuron-encrypt-cli — one-line installer
# Usage:  curl -fsSL https://theredhacker0345.gitlab.io/neuron-encrypt/install.sh | sh
# Env overrides:
#   NEURON_VERSION   — pin a specific release (default: latest)
#   NEURON_INSTALL_DIR — installation directory (default: /usr/local/bin or ~/.local/bin)

set -eu

# ── constants ──────────────────────────────────────────────────────────────────
GITLAB_PROJECT_ID="84892701"
PACKAGE_NAME="neuron-encrypt-cli"
BINARY_NAME="neuron-encrypt-cli"
PAGES_BASE="https://theredhacker0345.gitlab.io/neuron-encrypt"
REGISTRY_BASE="https://gitlab.com/api/v4/projects/${GITLAB_PROJECT_ID}/packages/generic/${PACKAGE_NAME}"

# ── helpers ────────────────────────────────────────────────────────────────────
say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
    for cmd in "$@"; do
        command -v "$cmd" > /dev/null 2>&1 || die "Required command not found: $cmd — please install it and retry."
    done
}

# ── detect OS / arch ───────────────────────────────────────────────────────────
detect_target() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS_SLUG="linux"  ;;
        Darwin) OS_SLUG="macos"  ;;
        *)      die "Unsupported OS: $OS. Only Linux and macOS are supported by this script." ;;
    esac

    case "$ARCH" in
        x86_64|amd64)    ARCH_SLUG="x86_64"  ;;
        aarch64|arm64)   ARCH_SLUG="aarch64" ;;
        *)               die "Unsupported architecture: $ARCH." ;;
    esac

    # macOS aarch64 falls back to x86_64 via Rosetta if no native binary yet
    if [ "$OS_SLUG" = "macos" ] && [ "$ARCH_SLUG" = "aarch64" ]; then
        warn "No native Apple Silicon build yet — falling back to x86_64 (Rosetta 2 required)."
        ARCH_SLUG="x86_64"
    fi

    TARGET="${BINARY_NAME}-latest-${OS_SLUG}-${ARCH_SLUG}"
}

# ── resolve version ────────────────────────────────────────────────────────────
resolve_version() {
    if [ -n "${NEURON_VERSION:-}" ]; then
        VERSION="$NEURON_VERSION"
        say "Using pinned version: $VERSION"
    else
        say "Resolving latest version…"
        # Read the latest version from the Pages-hosted file (updated by CI on each release).
        LATEST_URL="${PAGES_BASE}/latest-version.txt"
        if command -v curl > /dev/null 2>&1; then
            VERSION="$(curl -fsSL "$LATEST_URL" 2>/dev/null | tr -d '[:space:]')" || true
        elif command -v wget > /dev/null 2>&1; then
            VERSION="$(wget -qO- "$LATEST_URL" 2>/dev/null | tr -d '[:space:]')" || true
        fi
        # Fallback: hardcoded minimum if Pages file is unavailable
        if [ -z "${VERSION:-}" ]; then
            VERSION="2.2.0"
            warn "Could not fetch latest version — falling back to $VERSION."
        fi
        say "Latest version: $VERSION"
    fi
}

# ── download helper ────────────────────────────────────────────────────────────
download() {
    URL="$1"
    DEST="$2"
    if command -v curl > /dev/null 2>&1; then
        curl -fSL --progress-bar "$URL" -o "$DEST"
    elif command -v wget > /dev/null 2>&1; then
        wget -q --show-progress "$URL" -O "$DEST"
    else
        die "Neither curl nor wget found. Please install one and retry."
    fi
}

# ── verify SHA-256 ─────────────────────────────────────────────────────────────
verify_sha256() {
    BINARY="$1"
    CHECKSUMS="$2"
    say "Verifying SHA-256…"
    if command -v sha256sum > /dev/null 2>&1; then
        # sha256sum checks all entries in the file; grep for our binary name only
        grep "$(basename "$BINARY")" "$CHECKSUMS" | sha256sum --check --status \
            || die "SHA-256 verification FAILED. The download may be corrupt or tampered with."
    elif command -v shasum > /dev/null 2>&1; then
        grep "$(basename "$BINARY")" "$CHECKSUMS" | shasum -a 256 --check --status \
            || die "SHA-256 verification FAILED."
    else
        warn "No sha256sum or shasum found — skipping integrity check (NOT recommended)."
    fi
    say "Checksum OK."
}

# ── install dir ────────────────────────────────────────────────────────────────
pick_install_dir() {
    if [ -n "${NEURON_INSTALL_DIR:-}" ]; then
        INSTALL_DIR="$NEURON_INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
        return
    fi

    if [ -w /usr/local/bin ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
        mkdir -p "$INSTALL_DIR"
        # Advise user to add to PATH if not already there
        case ":${PATH}:" in
            *":${INSTALL_DIR}:"*) ;;
            *) warn "${INSTALL_DIR} is not on your PATH. Add the following to your shell profile:"
               warn "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
               ;;
        esac
    fi
}

# ── main ───────────────────────────────────────────────────────────────────────
main() {
    say "neuron-encrypt-cli installer"
    need uname

    detect_target
    resolve_version
    pick_install_dir

    # versioned binary name from the registry
    VERSIONED_BIN="${BINARY_NAME}-${VERSION}-${OS_SLUG}-${ARCH_SLUG}"
    CHECKSUM_FILE="SHA256SUMS-cli-${OS_SLUG}.txt"
    BIN_URL="${REGISTRY_BASE}/${VERSION}/${VERSIONED_BIN}"
    SUM_URL="${REGISTRY_BASE}/${VERSION}/${CHECKSUM_FILE}"

    TMPDIR_WORK="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap 'rm -rf "$TMPDIR_WORK"' EXIT INT TERM

    say "Downloading binary…"
    say "  ${BIN_URL}"
    download "$BIN_URL" "${TMPDIR_WORK}/${VERSIONED_BIN}"

    say "Downloading checksums…"
    download "$SUM_URL" "${TMPDIR_WORK}/${CHECKSUM_FILE}"

    verify_sha256 "${TMPDIR_WORK}/${VERSIONED_BIN}" "${TMPDIR_WORK}/${CHECKSUM_FILE}"

    chmod +x "${TMPDIR_WORK}/${VERSIONED_BIN}"
    cp "${TMPDIR_WORK}/${VERSIONED_BIN}" "${INSTALL_DIR}/${BINARY_NAME}"

    say "Installed → ${INSTALL_DIR}/${BINARY_NAME}"
    say "Run: ${BINARY_NAME} --help"
}

main "$@"
