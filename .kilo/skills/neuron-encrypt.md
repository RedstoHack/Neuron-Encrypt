# Neuron Encrypt - AI Agent Skill

## Overview
Neuron Encrypt is a cross-platform file encryption tool with military-grade cryptography (AES-256-GCM-SIV, Argon2id, HKDF-SHA512). It provides a CLI, desktop GUI, and Android app.

**Version:** 2.2.0  
**License:** GPL-3.0-only  
**Repository:** https://gitlab.com/theredhacker0345/neuron-encrypt

---

## Capabilities

### Core Operations
- **Encrypt files** - AES-256-GCM-SIV with Argon2id key derivation
- **Decrypt files** - Authenticated decryption with integrity verification
- **Metadata scrubbing** - Remove EXIF, GPS, XMP, ID3, document properties from images, PDFs, Office docs, audio/video files

### Interfaces
1. **CLI** (`neuron-encrypt-cli`) - Scriptable, JSON output support
2. **Desktop GUI** (egui) - Cross-platform (Linux, Windows, macOS)
3. **Android App** - Native app with SAF file access

---

## CLI Usage (Programmatic)

### Encrypt
```bash
neuron-encrypt-cli encrypt -i <input> -o <output> [--password-file <file>] [--json] [-F]
```

### Decrypt
```bash
neuron-encrypt-cli decrypt -i <input.vx2> -o <output> [--password-file <file>] [--json]
```

### Scrub Metadata
```bash
neuron-encrypt-cli scrub -i <input> [-o <output>] [--in-place] [--wipe-original] [--json]
```

### JSON Output Format
```json
{
  "status": "success|error",
  "operation": "encrypt|decrypt|scrub",
  "output_path": "/path/to/output",
  "bytes_processed": 1024,
  "duration_ms": 150,
  "sha256": "hex...",
  "format": "JPEG|PNG|PDF|...",
  "removed": ["EXIF", "GPS", "XMP", "..."],
  "error": "error message if failed"
}
```

### Exit Codes
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | I/O or runtime error |
| 2 | Bad input / unsupported format / wrong password |

---

## Rust Library API

### Core Module (`neuron_encrypt_core`)
```rust
use neuron_encrypt_core::{crypto, error, metadata, utils};

// Encrypt file
crypto::encrypt_file(
    src: &Path,
    dest: Option<&Path>,
    password: &[u8],
    overwrite: bool,
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<EncryptReport>

// Decrypt file
crypto::decrypt_file(
    src: &Path,
    dest: Option<&Path>,
    password: &[u8],
    overwrite: bool,
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<Arc<AtomicBool>>,
) -> CryptoResult<DecryptReport>

// Scrub metadata
metadata::scrub_file(
    src: &Path,
    dest: Option<&Path>,
    mode: ScrubOutput,
    wipe_original: bool,
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<ScrubReport>
```

### Progress Reporting
```rust
trait ProgressReporter: Send + Sync {
    fn report(&self, progress: f32, message: &str);
}

struct ThrottledReporter { ... }
```

### Error Types
```rust
enum CryptoError {
    Io(std::io::Error),
    WrongPassword,
    DecryptionFailed,
    FileTooLarge { size_gb: f64, max_gb: f64 },
    SourceAndDestinationSame(PathBuf),
    FileAlreadyExists(PathBuf),
    NotAFile(PathBuf),
    UnsupportedMediaFormat(&'static str),
    MalformedFile(String),
    ScrubFailed(String),
    Cancelled,
    // ...
}
```

---

## Android Integration

### JNI Interface
```kotlin
// Native methods
external fun nativeEncrypt(
    inputFd: Int, outputFd: Int, password: ByteArray,
    totalSize: Long, listener: ProgressListener, cancelFlag: AtomicBoolean
): Int

external fun nativeDecrypt(...): Int
external fun nativeScrub(
    inputFd: Int, outputFd: Int, cacheDir: String,
    listener: ProgressListener, cancelFlag: AtomicBoolean
): Int
```

### Kotlin Wrapper
```kotlin
fun encrypt(contentResolver: ContentResolver, inputUri: Uri, outputUri: Uri,
            password: ByteArray, listener: ProgressListener, cancelFlag: AtomicBoolean): Int

fun decrypt(...): Int
fun scrub(
    contentResolver: ContentResolver, inputUri: Uri, outputUri: Uri,
    cacheDir: String, listener: ProgressListener, cancelFlag: AtomicBoolean
): Int
```

### Return Codes
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | I/O error |
| 2 | Unsupported format / wrong password / cancelled |

---

## Cryptographic Details

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Encryption | AES-256-GCM-SIV | 256-bit key, 96-bit nonce |
| KDF | Argon2id | m=256 MiB, t=3, p=4 |
| Key Derivation | HKDF-SHA512 | Per-version domain separation |
| RNG | ChaCha20 (getrandom) | OS entropy |

### File Format Versions
| Version | Magic | Features |
|---------|-------|----------|
| V2 | `VAULTX02` | Single-shot, ≤1 GiB |
| V3 | `VAULTX03` | Streaming, 1 MiB chunks |
| V4 | `VAULTX04` | Header as AAD (current) |

---

## Build Commands

### Local Development
```bash
# All platforms
./scripts/build-all.sh all

# Specific platforms
./scripts/build-all.sh linux
./scripts/build-all.sh windows
./scripts/build-all.sh macos
./scripts/build-all.sh android
./scripts/build-all.sh package
```

### Cargo Commands
```bash
# Linux
cargo build --release --locked --all-targets
cargo test --release --locked --lib

# Windows cross-compile
cargo build --release --locked --target x86_64-pc-windows-gnu

# macOS cross-compile (requires osxcross)
cargo build --release --locked --target x86_64-apple-darwin

# Android
cd android && ./build-rust.sh
./gradlew :app:assembleStandardDebug
```

### Docker
```bash
# Builder image
docker build -t neuron-encrypt-builder -f Dockerfile.builder .

# Runtime image
docker build -t neuron-encrypt -f Dockerfile .
docker run --rm -v $(pwd)/data:/data neuron-encrypt encrypt -i /data/file.txt -o /data/file.vx2
```

---

## Security Notes

- **No backdoors** - Open source, auditable
- **Memory safety** - 100% Rust (except JNI/FFI boundaries)
- **Zeroizing** - Secrets zeroed on drop
- **Constant-time** - Where applicable (password comparison)
- **Secure wipe** - 3-pass overwrite (best effort on SSD)
- **No network** - Zero network permissions on Android

---

## Integration Examples

### Python Wrapper
```python
import subprocess, json

def encrypt_file(input_path, output_path, password):
    result = subprocess.run([
        'neuron-encrypt-cli', 'encrypt',
        '-i', input_path,
        '-o', output_path,
        '--password-file', '/dev/stdin',
        '--json'
    ], input=password.encode(), capture_output=True)
    return json.loads(result.stdout)

def scrub_metadata(input_path, output_path=None):
    args = ['neuron-encrypt-cli', 'scrub', '-i', input_path, '--json']
    if output_path:
        args.extend(['-o', output_path])
    result = subprocess.run(args, capture_output=True)
    return json.loads(result.stdout)
```

### Node.js Wrapper
```javascript
const { spawn } = require('child_process');

function encryptFile(input, output, password) {
    return new Promise((resolve, reject) => {
        const proc = spawn('neuron-encrypt-cli', [
            'encrypt', '-i', input, '-o', output, '--json'
        ]);
        proc.stdin.write(password);
        proc.stdin.end();
        let stdout = '';
        proc.stdout.on('data', d => stdout += d);
        proc.on('close', code => {
            if (code === 0) resolve(JSON.parse(stdout));
            else reject(new Error(`Exit code ${code}`));
        });
    });
}
```

---

## File Formats Supported for Scrubbing

| Category | Formats | Removed Metadata |
|----------|---------|------------------|
| Images | JPEG, PNG, WebP, GIF, TIFF, BMP | EXIF, GPS, XMP, IPTC, ICC, comments, timestamps |
| Documents | PDF, DOCX, XLSX, PPTX | Author, dates, XMP streams, docProps, thumbnails |
| Audio | MP3, FLAC, OGG, WAV | ID3v1/v2, APE, Vorbis comments, RIFF INFO |
| Video | MP4, MOV | iTunes ilst atoms |

---

## Error Handling

All operations return structured errors. Always check:
1. Exit code (0 = success)
2. JSON `status` field ("success" | "error")
3. `error` field for human-readable message

Common errors:
- `WrongPassword` - Incorrect passphrase
- `UnsupportedMediaFormat` - No scrubber for this format
- `FileTooLarge` - Exceeds 1 GiB in-memory limit
- `Cancelled` - User cancelled operation

---

## Version Compatibility

| Neuron Encrypt | File Format | Rust MSRV |
|----------------|-------------|-----------|
| 2.2.x | V4 (VAULTX04) | 1.70+ |
| 2.1.x | V3 (VAULTX03) | 1.70+ |
| 2.0.x | V2 (VAULTX02) | 1.65+ |

Older formats can be decrypted but new files use current version.

---

## Support

- **Issues:** https://gitlab.com/theredhacker0345/neuron-encrypt/-/issues
- **Security:** GitLab confidential issues
- **Docs:** https://docs.rs/neuron-encrypt