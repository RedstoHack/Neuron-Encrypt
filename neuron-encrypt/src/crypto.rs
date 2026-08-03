// crypto.rs - standalone cryptographic library
// Zero egui imports. Zero GUI logic. Zero platform-specific behavior in the API.

use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use std::time::SystemTime;
use std::time::{Duration, Instant};

use aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, CryptoResult};

// ── V2 (legacy) constants ──
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = 8 + SALT_LEN + NONCE_LEN;
pub const MAGIC: &[u8; 8] = b"VAULTX02";
pub const TAG_LEN: usize = 16;
pub const EXTENSION: &str = ".vx2";

// ── V3 (streaming) constants ──
/// VAULTX03 file header layout (31 bytes total):
///
/// | Offset | Length | Field          | Description                                    |
/// |--------|--------|----------------|------------------------------------------------|
/// | 0      | 8      | Magic Bytes    | Literal `b"VAULTX03"` identifies format version |
/// | 8      | 16     | Salt           | Fresh `OsRng`-generated per file (128-bit entropy) |
/// | 24     | 7      | Stream Nonce   | Fresh `OsRng`-generated per file; EncryptorBE32 appends an internal 5-byte counter/flag |
///
/// Body follows immediately after the header: a sequence of AES-256-GCM-SIV
/// encrypted chunks via the BE32 streaming API. Each chunk carries a 16-byte
/// authentication tag. The final chunk is sealed with `encrypt_last`/`decrypt_last`
/// to prevent truncation attacks.
///
/// Memory profile: Argon2id (256 MB) during key derivation, then ~2 MB constant
/// during 1 MB chunk streaming — peak ~258 MB regardless of file size.
pub const MAGIC_V3: &[u8; 8] = b"VAULTX03";
/// 16-byte salt — 128-bit entropy, recommended minimum for Argon2.
pub const SALT_V3_LEN: usize = 16;
/// EncryptorBE32 uses 5 bytes of the 12-byte nonce (4-byte counter + 1-byte flag).
pub const STREAM_NONCE_LEN: usize = 7;
/// V3 header: 8 (magic) + 16 (salt) + 7 (stream_nonce) = 31 bytes.
pub const HEADER_V3_LEN: usize = 8 + SALT_V3_LEN + STREAM_NONCE_LEN;
/// 1 MB chunks — balances memory usage vs per-chunk overhead.
pub const CHUNK_SIZE: usize = 1_048_576;

/// EncryptorBE32 uses a 4-byte (32-bit) counter, so the maximum number of
/// intermediate chunks is 2^32. At 1 MiB per chunk, the maximum safe file
/// size before counter wraparound is 2^32 * 1 MiB = 2^52 bytes = 4 PiB.
/// Encrypting a file larger than this would cause counter wraparound,
/// reusing (key, nonce, counter) triples and catastrophically breaking
/// GCM-SIV confidentiality and integrity.
pub const MAX_V3_FILE_SIZE: u64 = (1u64 << 32) * CHUNK_SIZE as u64;

// ── V4 (current) constants ──
//
// V4 is identical to V3 in every way (same cipher, KDF, chunking, header
// layout, file-size limit) EXCEPT that every encrypt_next / encrypt_last /
// decrypt_next / decrypt_last call passes the header bytes
// (MAGIC_V4 || salt || stream_nonce) as Additional Authenticated Data (AAD).
//
// This closes the defensive-in-depth gap identified in audit finding 5-1:
// V3 does not authenticate the salt or stream_nonce, so an attacker who
// tampers with them in transit causes a silent DoS (wrong key derived →
// all chunk tags fail → DecryptionFailed). V4 makes any tampering with
// the header detectable at the AEAD layer on every chunk, not just via
// the indirect effect on the derived key.
//
// V3 files remain fully readable for backward compatibility. New encryptions
// default to V4. There is no V3->V4 auto-migration; users who want V4 must
// re-encrypt.
pub const MAGIC_V4: &[u8; 8] = b"VAULTX04";
/// V4 reuses the V3 header layout: 8 (magic) + 16 (salt) + 7 (stream_nonce) = 31 bytes.
pub const HEADER_V4_LEN: usize = HEADER_V3_LEN;
/// V4 file-size limit is the same as V3 (same BE32 counter constraint).
pub const MAX_V4_FILE_SIZE: u64 = MAX_V3_FILE_SIZE;

// ── V2 legacy limits (kept for backward-compat decryption) ──
pub const MAX_FILE_SIZE: u64 = 8_000_000_000;
pub const MAX_ENCRYPTED_FILE_SIZE: u64 = MAX_FILE_SIZE + HEADER_LEN as u64 + TAG_LEN as u64;

/// Minimum passphrase length for security.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Receives best-effort progress updates from long-running crypto operations.
pub trait ProgressReporter: Send + Sync {
    fn report(&self, progress: f32, message: &str);
}

fn source_file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("file"))
}

/// Return the default encrypted output file name for `path`.
pub fn default_encrypt_output_name(path: &Path) -> String {
    format!("{}{}", source_file_name(path), EXTENSION)
}

/// Return the default decrypted output file name for `path`.
///
/// The function strips exactly one trailing `.vx2` suffix case-insensitively.
/// If that would produce an empty file name, it returns `decrypted` instead.
pub fn default_decrypt_output_name(path: &Path) -> String {
    let name = source_file_name(path);
    if name.len() >= EXTENSION.len()
        && name[name.len() - EXTENSION.len()..].eq_ignore_ascii_case(EXTENSION)
    {
        let stripped = &name[..name.len() - EXTENSION.len()];
        if stripped.is_empty() {
            String::from("decrypted")
        } else {
            stripped.to_owned()
        }
    } else {
        name
    }
}

/// A reporter that only forwards materially different updates.
pub struct ThrottledReporter<'a> {
    inner: &'a dyn ProgressReporter,
    last_progress: AtomicU32,
    last_time: Mutex<Option<Instant>>,
    last_message: Mutex<String>,
}

impl<'a> ThrottledReporter<'a> {
    pub fn new(inner: &'a dyn ProgressReporter) -> Self {
        Self {
            inner,
            last_progress: AtomicU32::new(f32::to_bits(-1.0)),
            last_time: Mutex::new(None),
            last_message: Mutex::new(String::new()),
        }
    }
}

impl<'a> ProgressReporter for ThrottledReporter<'a> {
    fn report(&self, progress: f32, message: &str) {
        let now = Instant::now();
        let last_progress = f32::from_bits(self.last_progress.load(Ordering::Relaxed));

        let (last_message, last_time) = {
            let message_guard = self.last_message.lock().unwrap_or_else(|e| e.into_inner());
            let time_guard = self.last_time.lock().unwrap_or_else(|e| e.into_inner());
            (message_guard.clone(), *time_guard)
        };

        let should_report = match last_time {
            Some(last_time) => {
                let elapsed_ms = now.duration_since(last_time).as_millis();
                (progress - last_progress).abs() > 0.01
                    || elapsed_ms > 100
                    || last_message != message
            }
            None => true,
        };

        if should_report {
            self.inner.report(progress, message);
            *self
                .last_message
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = message.to_owned();
            *self
                .last_time
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(now);
            self.last_progress
                .store(progress.to_bits(), Ordering::Relaxed);
        }
    }
}

fn derive_key(password: &[u8], salt: &[u8]) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let mut final_key = Zeroizing::new(vec![0u8; 32]);

    let mut intermediate = Zeroizing::new(vec![0u8; 64]);
    let params = Params::new(262_144, 3, 4, Some(64))
        .map_err(|error| CryptoError::Argon2Failed(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(password, salt, &mut intermediate)
        .map_err(|error| CryptoError::Argon2Failed(error.to_string()))?;

    let hkdf = Hkdf::<Sha512>::new(None, &intermediate);
    hkdf.expand(b"VAULTX02_AES_256_GCM_SIV", &mut final_key)
        .map_err(|error| CryptoError::HkdfFailed(error.to_string()))?;
    intermediate.zeroize();

    Ok(final_key)
}

/// V3 key derivation — same Argon2id + HKDF pipeline, different HKDF info
/// for cryptographic domain separation from V2.
fn derive_key_v3(password: &[u8], salt: &[u8]) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let mut final_key = Zeroizing::new(vec![0u8; 32]);
    let mut intermediate = Zeroizing::new(vec![0u8; 64]);
    let params = Params::new(262_144, 3, 4, Some(64))
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(password, salt, &mut intermediate)
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))?;
    let hkdf = Hkdf::<Sha512>::new(None, &intermediate);
    hkdf.expand(b"VAULTX03_AES_256_GCM_SIV_STREAM", &mut final_key)
        .map_err(|e| CryptoError::HkdfFailed(e.to_string()))?;
    intermediate.zeroize();
    Ok(final_key)
}

/// V4 key derivation — same Argon2id + HKDF pipeline as V3, but with a
/// distinct HKDF info string so V3 and V4 keys are cryptographically
/// independent even for identical (password, salt) pairs.
fn derive_key_v4(password: &[u8], salt: &[u8]) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let mut final_key = Zeroizing::new(vec![0u8; 32]);
    let mut intermediate = Zeroizing::new(vec![0u8; 64]);
    let params = Params::new(262_144, 3, 4, Some(64))
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(password, salt, &mut intermediate)
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))?;
    let hkdf = Hkdf::<Sha512>::new(None, &intermediate);
    hkdf.expand(b"VAULTX04_AES_256_GCM_SIV_STREAM_AAD", &mut final_key)
        .map_err(|e| CryptoError::HkdfFailed(e.to_string()))?;
    intermediate.zeroize();
    Ok(final_key)
}

fn build_aad(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SALT_LEN + NONCE_LEN);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/// V4 AAD builder — authenticates the full header (magic || salt || stream_nonce)
/// so any tampering with header bytes is detected at the AEAD layer on every chunk.
fn build_aad_v4(salt: &[u8], stream_nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + SALT_V3_LEN + STREAM_NONCE_LEN);
    aad.extend_from_slice(MAGIC_V4);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(stream_nonce);
    aad
}

fn open_regular_file(path: &Path) -> CryptoResult<(fs::File, fs::Metadata)> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CryptoError::NotAFile(path.to_path_buf()));
    }

    Ok((file, metadata))
}

fn normalize_destination_path(path: &Path) -> CryptoResult<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| CryptoError::InvalidDestination(path.to_path_buf()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let canonical_parent = fs::canonicalize(parent)?;

    if !canonical_parent.is_dir() {
        return Err(CryptoError::InvalidDestination(path.to_path_buf()));
    }

    Ok(canonical_parent.join(file_name))
}

#[cfg(target_os = "windows")]
fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

#[cfg(not(target_os = "windows"))]
fn same_path(a: &Path, b: &Path) -> bool {
    a == b
}

fn validate_destination_path(src: &Path, dest: &Path, overwrite: bool) -> CryptoResult<PathBuf> {
    let canonical_src = fs::canonicalize(src)?;
    let canonical_dest = normalize_destination_path(dest)?;

    if same_path(&canonical_src, &canonical_dest) {
        return Err(CryptoError::SourceAndDestinationSame(canonical_dest));
    }

    match fs::symlink_metadata(&canonical_dest) {
        Ok(_) if overwrite => fs::remove_file(&canonical_dest)?,
        Ok(_) => return Err(CryptoError::FileAlreadyExists(canonical_dest)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    Ok(canonical_dest)
}

fn read_limited_file(file: fs::File, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut reader = file.take(limit + 1);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn persist_temp_file(tmp: &Path, dest: &Path) -> CryptoResult<()> {
    #[cfg(unix)]
    {
        match fs::hard_link(tmp, dest) {
            Ok(()) => {
                let _ = fs::remove_file(tmp);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(tmp);
                Err(CryptoError::FileAlreadyExists(dest.to_path_buf()))
            }
            Err(error) => {
                let _ = fs::remove_file(tmp);
                Err(error.into())
            }
        }
    }

    #[cfg(not(unix))]
    {
        match fs::rename(tmp, dest) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(tmp);
                Err(CryptoError::FileAlreadyExists(dest.to_path_buf()))
            }
            Err(error) => {
                let _ = fs::remove_file(tmp);
                Err(error.into())
            }
        }
    }
}

fn tmp_path(dest: &Path) -> PathBuf {
    let mut rng_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rng_bytes);
    let suffix = hex::encode(rng_bytes);
    let mut tmp = dest.to_path_buf();
    let name = dest.file_name().unwrap_or_default().to_string_lossy();
    tmp.set_file_name(format!("{name}.{suffix}.tmp"));
    tmp
}

#[allow(clippy::type_complexity)]
pub fn encrypt_bytes(
    plaintext: &[u8],
    password: &[u8],
) -> CryptoResult<(Zeroizing<Vec<u8>>, [u8; SALT_LEN], [u8; NONCE_LEN])> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(CryptoError::PassphraseTooShort(MIN_PASSWORD_LEN));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = build_aad(&salt, &nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|error| CryptoError::EncryptionFailed(error.to_string()))?;

    Ok((Zeroizing::new(ciphertext), salt, nonce_bytes))
}

pub fn decrypt_bytes(
    ciphertext: &[u8],
    password: &[u8],
    salt: &[u8],
    nonce_bytes: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(CryptoError::PassphraseTooShort(MIN_PASSWORD_LEN));
    }
    if salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidSaltLength {
            expected: SALT_LEN,
            actual: salt.len(),
        });
    }
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength {
            expected: NONCE_LEN,
            actual: nonce_bytes.len(),
        });
    }

    let key = derive_key(password, salt)?;
    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let aad = build_aad(salt, nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

pub fn parse_header(raw: &[u8]) -> CryptoResult<(&[u8], &[u8], &[u8])> {
    if raw.len() < HEADER_LEN + TAG_LEN {
        return Err(CryptoError::FileTooSmall);
    }
    if &raw[..8] != MAGIC {
        return Err(CryptoError::InvalidMagic);
    }

    let salt = &raw[8..40];
    let nonce = &raw[40..52];
    let ciphertext = &raw[52..];
    Ok((salt, nonce, ciphertext))
}

pub fn encrypt_file(
    src: &Path,
    dest: &Path,
    overwrite: bool,
    password: &[u8],
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<PathBuf> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(CryptoError::PassphraseTooShort(MIN_PASSWORD_LEN));
    }

    let (mut file, source_metadata) = open_regular_file(src)?;
    let dest = validate_destination_path(src, dest, overwrite)?;
    let source_len = source_metadata.len();

    // Guard against counter-wraparound in EncryptorBE32 (4-byte counter at 1 MiB chunks).
    // V4 uses the same BE32 stream cipher as V3, so the limit is identical.
    if source_len > MAX_V4_FILE_SIZE {
        return Err(CryptoError::FileTooLarge {
            size_gb: source_len as f64 / 1_000_000_000.0,
            max_gb: MAX_V4_FILE_SIZE as f64 / 1_000_000_000.0,
        });
    }

    let mut salt = [0u8; SALT_V3_LEN];
    let mut stream_nonce = [0u8; STREAM_NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut stream_nonce);

    reporter.report(0.05, "Deriving encryption key (Argon2id)...");
    // P1-6: V4 uses a distinct HKDF info string for cross-version domain separation.
    let key = derive_key_v4(password, &salt)?;

    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let mut encryptor = EncryptorBE32::from_aead(cipher, (&stream_nonce).into());

    // P1-6: V4 AAD authenticates the full header (magic || salt || stream_nonce)
    // so any tampering with header bytes is detected at the AEAD layer on every chunk.
    let aad = build_aad_v4(&salt, &stream_nonce);

    let tmp = tmp_path(&dest);
    let write_result = (|| -> CryptoResult<()> {
        #[cfg(unix)]
        let mut out = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;

        // Write V4 header
        out.write_all(MAGIC_V4)?;
        out.write_all(&salt)?;
        out.write_all(&stream_nonce)?;

        // Stream encryption in 1 MB chunks
        let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
        let mut bytes_done: u64 = 0;
        let mut chunk_counter: u64 = 0;
        const IO_GOVENER_INTERVAL: u64 = 100; // ~100 MB between flushes

        loop {
            // P1-2: check for user cancellation at the top of each chunk iteration.
            // Cleanup the .tmp file and return Cancelled so the caller can show
            // an appropriate message.
            if let Some(flag) = cancel_flag {
                if flag.load(Ordering::SeqCst) {
                    let _ = fs::remove_file(&tmp);
                    return Err(CryptoError::Cancelled);
                }
            }

            let n = read_exact_or_eof(&mut file, buf.as_mut_slice())?;
            if n == 0 {
                // Empty file or exact chunk boundary — finalize with empty last
                let ct = encryptor
                    .encrypt_last(Payload {
                        msg: &[][..],
                        aad: &aad,
                    })
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                out.write_all(&ct)?;
                break;
            }

            bytes_done += n as u64;
            let frac = if source_len > 0 {
                0.10 + 0.85 * (bytes_done as f32 / source_len as f32)
            } else {
                0.95
            };

            // Check if there is more data after this chunk
            let mut peek = [0u8; 1];
            let peeked = file.read(&mut peek)?;

            if peeked == 0 {
                // This is the last chunk
                reporter.report(frac, "Encrypting final chunk...");
                let ct = encryptor
                    .encrypt_last(Payload {
                        msg: &buf[..n],
                        aad: &aad,
                    })
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                out.write_all(&ct)?;
                break;
            } else {
                // More data follows — encrypt as intermediate chunk
                reporter.report(frac, "Encrypting...");
                let ct = encryptor
                    .encrypt_next(Payload {
                        msg: &buf[..n],
                        aad: &aad,
                    })
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                out.write_all(&ct)?;
                chunk_counter += 1;

                // I/O Governor: periodically flush dirty pages to prevent OS lag.
                if chunk_counter.is_multiple_of(IO_GOVENER_INTERVAL) {
                    out.sync_data()?;
                    std::thread::sleep(Duration::from_millis(5));
                }

                // Put the peeked byte back by seeking back 1
                file.seek(std::io::SeekFrom::Current(-1))?;
            }
        }

        out.sync_all()?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }

    // A2-4 fix: re-check cancel AFTER the loop completes but BEFORE persisting
    // the temp file. Without this, if cancel fires after encrypt_last succeeds
    // but before persist_temp_file renames, the user sees "cancelled" but the
    // output file is still written — contradicting the cancel message.
    if let Some(flag) = cancel_flag {
        if flag.load(Ordering::SeqCst) {
            let _ = fs::remove_file(&tmp);
            return Err(CryptoError::Cancelled);
        }
    }

    persist_temp_file(&tmp, &dest)?;
    reporter.report(1.00, "Encryption complete.");
    Ok(dest)
}

/// Read up to `buf.len()` bytes, returning how many were read (may be less at EOF).
fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

pub fn decrypt_file(
    src: &Path,
    dest: &Path,
    overwrite: bool,
    password: &[u8],
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<PathBuf> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(CryptoError::PassphraseTooShort(MIN_PASSWORD_LEN));
    }

    // Check for cancellation before starting work.
    if let Some(flag) = cancel_flag {
        if flag.load(Ordering::SeqCst) {
            return Err(CryptoError::Cancelled);
        }
    }

    // Read magic bytes to determine format version
    let mut magic_buf = [0u8; 8];
    {
        let mut f = fs::File::open(src)?;
        f.read_exact(&mut magic_buf)
            .map_err(|_| CryptoError::FileTooSmall)?;
    }

    if &magic_buf == MAGIC {
        decrypt_file_legacy(src, dest, overwrite, password, reporter, cancel_flag)
    } else if &magic_buf == MAGIC_V4 {
        // P1-6: V4 path — AAD-authenticated streaming format (current default).
        decrypt_file_streaming_v4(src, dest, overwrite, password, reporter, cancel_flag)
    } else if &magic_buf == MAGIC_V3 {
        // V3 path — backward compat, no AAD on header.
        decrypt_file_streaming(src, dest, overwrite, password, reporter, cancel_flag)
    } else {
        Err(CryptoError::InvalidMagic)
    }
}

/// Legacy V2 decryption — loads entire file into RAM.
fn decrypt_file_legacy(
    src: &Path,
    dest: &Path,
    overwrite: bool,
    password: &[u8],
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<PathBuf> {
    let (file, source_metadata) = open_regular_file(src)?;
    let dest = validate_destination_path(src, dest, overwrite)?;
    let source_len = source_metadata.len();
    #[cfg(target_os = "windows")]
    let (src_accessed, src_modified) = (
        source_metadata.accessed().ok(),
        source_metadata.modified().ok(),
    );

    if source_len > MAX_ENCRYPTED_FILE_SIZE {
        return Err(CryptoError::FileTooLarge {
            size_gb: source_len as f64 / 1_000_000_000.0,
            max_gb: MAX_ENCRYPTED_FILE_SIZE as f64 / 1_000_000_000.0,
        });
    }

    // Check for cancellation before starting V2 decryption (Argon2id is expensive).
    if let Some(flag) = cancel_flag {
        if flag.load(Ordering::SeqCst) {
            return Err(CryptoError::Cancelled);
        }
    }

    eprintln!("[INFO] VAULTX02 (V2) format detected. Consider re-encrypting with V3 for streaming support and no memory limits.");
    reporter.report(0.10, "Reading encrypted file (legacy V2)...");
    let raw = read_limited_file(file, 1_073_741_824u64)?;
    if raw.len() as u64 > 1_073_741_824u64 {
        return Err(CryptoError::LegacyFileTooLarge);
    }

    let (salt, nonce, ciphertext) = parse_header(&raw)?;

    reporter.report(0.20, "Deriving decryption key (Argon2id)...");
    let key = derive_key(password, salt)?;

    reporter.report(0.50, "Decrypting data (AES-256-GCM-SIV)...");
    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let aad = build_aad(salt, nonce);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
    );

    let tmp = tmp_path(&dest);
    reporter.report(0.75, "Writing decrypted file...");
    let write_result = (|| -> CryptoResult<()> {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(&plaintext)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }

    // A2-4 fix: re-check cancel before persisting the temp file.
    if let Some(flag) = cancel_flag {
        if flag.load(Ordering::SeqCst) {
            let _ = fs::remove_file(&tmp);
            return Err(CryptoError::Cancelled);
        }
    }

    persist_temp_file(&tmp, &dest)?;

    #[cfg(target_os = "windows")]
    {
        if let Ok(file) = fs::File::open(&dest) {
            let times = fs::FileTimes::new()
                .set_accessed(src_accessed.unwrap_or(SystemTime::now()))
                .set_modified(src_modified.unwrap_or(SystemTime::now()));
            let _ = file.set_times(times);
        }
    }

    reporter.report(1.00, "Decryption complete.");
    Ok(dest)
}

/// V3 streaming decryption — constant memory usage.
fn decrypt_file_streaming(
    src: &Path,
    dest: &Path,
    overwrite: bool,
    password: &[u8],
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<PathBuf> {
    let (mut file, source_metadata) = open_regular_file(src)?;
    let dest = validate_destination_path(src, dest, overwrite)?;
    let file_len = source_metadata.len();
    #[cfg(target_os = "windows")]
    let (src_accessed, src_modified) = (
        source_metadata.accessed().ok(),
        source_metadata.modified().ok(),
    );

    if file_len < HEADER_V3_LEN as u64 + TAG_LEN as u64 {
        return Err(CryptoError::FileTooSmall);
    }

    // Skip magic (already read by dispatcher), read salt + nonce
    file.seek(std::io::SeekFrom::Start(8))?;
    let mut salt = [0u8; SALT_V3_LEN];
    let mut stream_nonce = [0u8; STREAM_NONCE_LEN];
    file.read_exact(&mut salt)?;
    file.read_exact(&mut stream_nonce)?;

    reporter.report(0.05, "Deriving decryption key (Argon2id)...");
    let key = derive_key_v3(password, &salt)?;

    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let mut decryptor = DecryptorBE32::from_aead(cipher, (&stream_nonce).into());

    let encrypted_body = file_len - HEADER_V3_LEN as u64;
    let enc_chunk_size = CHUNK_SIZE + TAG_LEN;

    let tmp = tmp_path(&dest);
    let write_result = (|| -> CryptoResult<()> {
        #[cfg(unix)]
        let mut out = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;

        let mut buf = Zeroizing::new(vec![0u8; enc_chunk_size]);
        let mut bytes_done: u64 = 0;
        let mut last_chunk: Option<Zeroizing<Vec<u8>>> = None;

        // Read all chunks, processing intermediate ones immediately
        loop {
            // P1-2: check for user cancellation. Clean up the .tmp file and return.
            if let Some(flag) = cancel_flag {
                if flag.load(Ordering::SeqCst) {
                    let _ = fs::remove_file(&tmp);
                    return Err(CryptoError::Cancelled);
                }
            }

            let n = read_exact_or_eof(&mut file, &mut buf)?;
            if n == 0 {
                break;
            }

            // If we had a pending chunk, it wasn't the last — decrypt it now
            if let Some(prev) = last_chunk.take() {
                let frac = 0.10 + 0.85 * (bytes_done as f32 / encrypted_body as f32);
                reporter.report(frac, "Decrypting...");
                let pt = Zeroizing::new(
                    decryptor
                        .decrypt_next(prev.as_slice())
                        .map_err(|_| CryptoError::DecryptionFailed)?,
                );
                out.write_all(pt.as_slice())?;
            }

            bytes_done += n as u64;
            last_chunk = Some(Zeroizing::new(buf[..n].to_vec()));
        }

        // Process the final chunk
        if let Some(final_data) = last_chunk {
            reporter.report(0.95, "Decrypting final chunk...");
            let pt = Zeroizing::new(
                decryptor
                    .decrypt_last(final_data.as_slice())
                    .map_err(|_| CryptoError::DecryptionFailed)?,
            );
            out.write_all(pt.as_slice())?;
        }

        out.sync_all()?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }

    // A2-4 fix: re-check cancel before persisting the temp file.
    if let Some(flag) = cancel_flag {
        if flag.load(Ordering::SeqCst) {
            let _ = fs::remove_file(&tmp);
            return Err(CryptoError::Cancelled);
        }
    }

    persist_temp_file(&tmp, &dest)?;

    #[cfg(target_os = "windows")]
    {
        if let Ok(file) = fs::File::open(&dest) {
            let times = fs::FileTimes::new()
                .set_accessed(src_accessed.unwrap_or(SystemTime::now()))
                .set_modified(src_modified.unwrap_or(SystemTime::now()));
            let _ = file.set_times(times);
        }
    }

    reporter.report(1.00, "Decryption complete.");
    Ok(dest)
}

/// V4 streaming decryption — same chunking as V3 but with AAD covering the header.
/// Used for files with the VAULTX04 magic bytes (the current default format).
fn decrypt_file_streaming_v4(
    src: &Path,
    dest: &Path,
    overwrite: bool,
    password: &[u8],
    reporter: &dyn ProgressReporter,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> CryptoResult<PathBuf> {
    let (mut file, source_metadata) = open_regular_file(src)?;
    let dest = validate_destination_path(src, dest, overwrite)?;
    let file_len = source_metadata.len();
    #[cfg(target_os = "windows")]
    let (src_accessed, src_modified) = (
        source_metadata.accessed().ok(),
        source_metadata.modified().ok(),
    );

    if file_len < HEADER_V4_LEN as u64 + TAG_LEN as u64 {
        return Err(CryptoError::FileTooSmall);
    }

    // Skip magic (already read by dispatcher), read salt + nonce
    file.seek(std::io::SeekFrom::Start(8))?;
    let mut salt = [0u8; SALT_V3_LEN];
    let mut stream_nonce = [0u8; STREAM_NONCE_LEN];
    file.read_exact(&mut salt)?;
    file.read_exact(&mut stream_nonce)?;

    reporter.report(0.05, "Deriving decryption key (Argon2id)...");
    let key = derive_key_v4(password, &salt)?;

    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let mut decryptor = DecryptorBE32::from_aead(cipher, (&stream_nonce).into());

    // P1-6: V4 AAD authenticates the full header. Every chunk's tag is computed
    // over (plaintext, AAD, counter, flag) — any tampering with the header bytes
    // is detected on the first chunk's tag verification.
    let aad = build_aad_v4(&salt, &stream_nonce);

    let encrypted_body = file_len - HEADER_V4_LEN as u64;
    let enc_chunk_size = CHUNK_SIZE + TAG_LEN;

    let tmp = tmp_path(&dest);
    let write_result = (|| -> CryptoResult<()> {
        #[cfg(unix)]
        let mut out = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;

        let mut buf = Zeroizing::new(vec![0u8; enc_chunk_size]);
        let mut bytes_done: u64 = 0;
        let mut last_chunk: Option<Zeroizing<Vec<u8>>> = None;

        // Read all chunks, processing intermediate ones immediately
        loop {
            // P1-2: check for user cancellation. Clean up the .tmp file and return.
            if let Some(flag) = cancel_flag {
                if flag.load(Ordering::SeqCst) {
                    let _ = fs::remove_file(&tmp);
                    return Err(CryptoError::Cancelled);
                }
            }

            let n = read_exact_or_eof(&mut file, &mut buf)?;
            if n == 0 {
                break;
            }

            // If we had a pending chunk, it wasn't the last — decrypt it now
            if let Some(prev) = last_chunk.take() {
                let frac = 0.10 + 0.85 * (bytes_done as f32 / encrypted_body as f32);
                reporter.report(frac, "Decrypting...");
                let pt = Zeroizing::new(
                    decryptor
                        .decrypt_next(Payload {
                            msg: prev.as_slice(),
                            aad: &aad,
                        })
                        .map_err(|_| CryptoError::DecryptionFailed)?,
                );
                out.write_all(pt.as_slice())?;
            }

            bytes_done += n as u64;
            last_chunk = Some(Zeroizing::new(buf[..n].to_vec()));
        }

        // Process the final chunk
        if let Some(final_data) = last_chunk {
            reporter.report(0.95, "Decrypting final chunk...");
            let pt = Zeroizing::new(
                decryptor
                    .decrypt_last(Payload {
                        msg: final_data.as_slice(),
                        aad: &aad,
                    })
                    .map_err(|_| CryptoError::DecryptionFailed)?,
            );
            out.write_all(pt.as_slice())?;
        }

        out.sync_all()?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }

    // A2-4 fix: re-check cancel before persisting the temp file.
    if let Some(flag) = cancel_flag {
        if flag.load(Ordering::SeqCst) {
            let _ = fs::remove_file(&tmp);
            return Err(CryptoError::Cancelled);
        }
    }

    persist_temp_file(&tmp, &dest)?;

    #[cfg(target_os = "windows")]
    {
        if let Ok(file) = fs::File::open(&dest) {
            let times = fs::FileTimes::new()
                .set_accessed(src_accessed.unwrap_or(SystemTime::now()))
                .set_modified(src_modified.unwrap_or(SystemTime::now()));
            let _ = file.set_times(times);
        }
    }

    reporter.report(1.00, "Decryption complete.");
    Ok(dest)
}

/// Attempts a 3-pass random overwrite, rename, and deletion of `path`.
///
/// WARNING: This is not cryptographically guaranteed on SSDs, APFS, Btrfs, ZFS,
/// or NTFS with shadow copies enabled.
pub fn secure_wipe(path: &Path) -> CryptoResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err(CryptoError::NotAFile(path.to_path_buf()));
    }

    let len = metadata.len();
    let mut file = fs::OpenOptions::new().write(true).open(path)?;

    let mut buffer = vec![0u8; 64 * 1024];
    for _ in 0..3 {
        file.seek(std::io::SeekFrom::Start(0))?;
        let mut written = 0;

        while written < len {
            let to_write = std::cmp::min(buffer.len() as u64, len - written) as usize;
            OsRng.fill_bytes(&mut buffer[..to_write]);
            file.write_all(&buffer[..to_write])?;
            written += to_write as u64;
        }

        file.sync_all()?;
    }

    #[cfg(target_os = "windows")]
    {
        let epoch = SystemTime::UNIX_EPOCH;
        let times = fs::FileTimes::new().set_accessed(epoch).set_modified(epoch);
        let _ = file.set_times(times);
    }

    drop(file);

    for _ in 0..8 {
        let mut random_name = [0u8; 16];
        OsRng.fill_bytes(&mut random_name);
        let renamed_path = path.with_file_name(hex::encode(random_name));

        match fs::rename(path, &renamed_path) {
            Ok(()) => {
                fs::remove_file(renamed_path)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to generate a unique wipe filename",
    )
    .into())
}

/// Stream-encrypt from any reader to any writer.
/// Used by the CLI for stdin/stdout piping. Does not create temp files or handle renaming.
pub fn encrypt_stream<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    source_size: Option<u64>,
    reporter: &dyn ProgressReporter,
) -> CryptoResult<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(CryptoError::PassphraseTooShort(MIN_PASSWORD_LEN));
    }

    // Guard against counter-wraparound if the caller knows the size.
    if let Some(size) = source_size {
        if size > MAX_V4_FILE_SIZE {
            return Err(CryptoError::FileTooLarge {
                size_gb: size as f64 / 1_000_000_000.0,
                max_gb: MAX_V4_FILE_SIZE as f64 / 1_000_000_000.0,
            });
        }
    }

    let mut salt = [0u8; SALT_V3_LEN];
    let mut stream_nonce = [0u8; STREAM_NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut stream_nonce);

    reporter.report(0.05, "Deriving encryption key (Argon2id)...");
    // P1-6: V4 uses a distinct HKDF info string for cross-version domain separation.
    let key = derive_key_v4(password, &salt)?;

    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let mut encryptor = EncryptorBE32::from_aead(cipher, (&stream_nonce).into());

    // P1-6: V4 AAD authenticates the full header.
    let aad = build_aad_v4(&salt, &stream_nonce);

    // Write V4 header
    writer.write_all(MAGIC_V4)?;
    writer.write_all(&salt)?;
    writer.write_all(&stream_nonce)?;

    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut bytes_done: u64 = 0;
    let mut chunk_counter: u64 = 0;
    const IO_GOVERNOR_INTERVAL: u64 = 100;

    loop {
        let n = read_exact_or_eof(reader, buf.as_mut_slice())?;
        if n == 0 {
            let ct = encryptor
                .encrypt_last(Payload {
                    msg: &[][..],
                    aad: &aad,
                })
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            writer.write_all(&ct)?;
            break;
        }

        bytes_done += n as u64;
        let frac = if let Some(total) = source_size {
            if total > 0 {
                0.10 + 0.85 * (bytes_done as f32 / total as f32)
            } else {
                0.95
            }
        } else {
            0.50
        };

        let mut peek = [0u8; 1];
        let peeked = reader.read(&mut peek)?;

        if peeked == 0 {
            reporter.report(frac, "Encrypting final chunk...");
            let ct = encryptor
                .encrypt_last(Payload {
                    msg: &buf[..n],
                    aad: &aad,
                })
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            writer.write_all(&ct)?;
            break;
        } else {
            reporter.report(frac, "Encrypting...");
            let ct = encryptor
                .encrypt_next(Payload {
                    msg: &buf[..n],
                    aad: &aad,
                })
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            writer.write_all(&ct)?;
            chunk_counter += 1;

            // A2-1 fix: runtime counter guard — even when source_size=None
            // (e.g. caller doesn't know the size), we still prevent counter
            // wraparound. 2^32 intermediate chunks is the BE32 limit.
            if chunk_counter >= u32::MAX as u64 {
                return Err(CryptoError::FileTooLarge {
                    size_gb: (chunk_counter * CHUNK_SIZE as u64) as f64 / 1_000_000_000.0,
                    max_gb: MAX_V4_FILE_SIZE as f64 / 1_000_000_000.0,
                });
            }

            if chunk_counter.is_multiple_of(IO_GOVERNOR_INTERVAL) {
                writer.flush()?;
                std::thread::sleep(Duration::from_millis(5));
            }

            reader.seek(std::io::SeekFrom::Current(-1))?;
        }
    }

    writer.flush()?;
    reporter.report(1.00, "Encryption complete.");
    Ok(())
}

/// Stream-decrypt from any reader to any writer.
/// Used by the CLI for stdin/stdout piping. Does not create temp files or handle renaming.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    total_size: Option<u64>,
    reporter: &dyn ProgressReporter,
) -> CryptoResult<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(CryptoError::PassphraseTooShort(MIN_PASSWORD_LEN));
    }

    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => CryptoError::FileTooSmall,
            _ => CryptoError::Io(error),
        })?;

    if &magic == MAGIC_V4 {
        // P1-6: V4 path — AAD-authenticated streaming format (current default).
        decrypt_stream_v4(reader, writer, password, total_size, reporter)
    } else if &magic == MAGIC_V3 {
        decrypt_stream_v3(reader, writer, password, total_size, reporter)
    } else if &magic == MAGIC {
        decrypt_stream_v2(reader, writer, password, reporter)
    } else {
        Err(CryptoError::InvalidMagic)
    }
}

fn decrypt_stream_v3<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    total_size: Option<u64>,
    reporter: &dyn ProgressReporter,
) -> CryptoResult<()> {
    let mut salt = [0u8; SALT_V3_LEN];
    let mut stream_nonce = [0u8; STREAM_NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut stream_nonce)?;

    reporter.report(0.05, "Deriving decryption key (Argon2id)...");
    let key = derive_key_v3(password, &salt)?;

    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let mut decryptor = DecryptorBE32::from_aead(cipher, (&stream_nonce).into());

    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG_LEN]);
    let mut bytes_done: u64 = 0;
    let mut last_chunk: Option<Zeroizing<Vec<u8>>> = None;
    let mut chunk_counter: u64 = 0;
    const IO_GOVERNOR_INTERVAL: u64 = 100;

    loop {
        let n = read_exact_or_eof(reader, &mut buf)?;
        if n == 0 {
            break;
        }

        if let Some(prev) = last_chunk.take() {
            let frac = if let Some(total) = total_size {
                if total > 0 {
                    0.10 + 0.85 * (bytes_done as f32 / total as f32)
                } else {
                    0.50
                }
            } else {
                0.50
            };
            reporter.report(frac, "Decrypting...");
            let pt = Zeroizing::new(
                decryptor
                    .decrypt_next(prev.as_slice())
                    .map_err(|_| CryptoError::DecryptionFailed)?,
            );
            writer.write_all(pt.as_slice())?;
            chunk_counter += 1;

            // I/O Governor: periodically flush written plaintext so the kernel
            // page cache never holds the whole file. Keeps the final sync fast
            // and prevents the UI from claiming 100% while gigabytes of data
            // are still being written back to slow storage.
            if chunk_counter.is_multiple_of(IO_GOVERNOR_INTERVAL) {
                writer.flush()?;
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        bytes_done += n as u64;
        last_chunk = Some(Zeroizing::new(buf[..n].to_vec()));
    }

    if let Some(final_data) = last_chunk {
        reporter.report(0.95, "Decrypting final chunk...");
        let pt = Zeroizing::new(
            decryptor
                .decrypt_last(final_data.as_slice())
                .map_err(|_| CryptoError::DecryptionFailed)?,
        );
        writer.write_all(pt.as_slice())?;
    } else {
        return Err(CryptoError::FileTooSmall);
    }

    writer.flush()?;
    reporter.report(1.00, "Decryption complete.");
    Ok(())
}

/// V4 stream decryption — same chunking as V3 but with AAD covering the header.
fn decrypt_stream_v4<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    total_size: Option<u64>,
    reporter: &dyn ProgressReporter,
) -> CryptoResult<()> {
    let mut salt = [0u8; SALT_V3_LEN];
    let mut stream_nonce = [0u8; STREAM_NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut stream_nonce)?;

    reporter.report(0.05, "Deriving decryption key (Argon2id)...");
    let key = derive_key_v4(password, &salt)?;

    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let mut decryptor = DecryptorBE32::from_aead(cipher, (&stream_nonce).into());

    // P1-6: V4 AAD authenticates the full header.
    let aad = build_aad_v4(&salt, &stream_nonce);

    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG_LEN]);
    let mut bytes_done: u64 = 0;
    let mut last_chunk: Option<Zeroizing<Vec<u8>>> = None;
    let mut chunk_counter: u64 = 0;
    const IO_GOVERNOR_INTERVAL: u64 = 100;

    loop {
        let n = read_exact_or_eof(reader, &mut buf)?;
        if n == 0 {
            break;
        }

        if let Some(prev) = last_chunk.take() {
            let frac = if let Some(total) = total_size {
                if total > 0 {
                    0.10 + 0.85 * (bytes_done as f32 / total as f32)
                } else {
                    0.50
                }
            } else {
                0.50
            };
            reporter.report(frac, "Decrypting...");
            let pt = Zeroizing::new(
                decryptor
                    .decrypt_next(Payload {
                        msg: prev.as_slice(),
                        aad: &aad,
                    })
                    .map_err(|_| CryptoError::DecryptionFailed)?,
            );
            writer.write_all(pt.as_slice())?;
            chunk_counter += 1;

            // I/O Governor: same rationale as decrypt_stream_v3 — keep kernel
            // dirty pages bounded so completion is only reported once the data
            // is actually on disk.
            if chunk_counter.is_multiple_of(IO_GOVERNOR_INTERVAL) {
                writer.flush()?;
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        bytes_done += n as u64;
        last_chunk = Some(Zeroizing::new(buf[..n].to_vec()));
    }

    if let Some(final_data) = last_chunk {
        reporter.report(0.95, "Decrypting final chunk...");
        let pt = Zeroizing::new(
            decryptor
                .decrypt_last(Payload {
                    msg: final_data.as_slice(),
                    aad: &aad,
                })
                .map_err(|_| CryptoError::DecryptionFailed)?,
        );
        writer.write_all(pt.as_slice())?;
    } else {
        return Err(CryptoError::FileTooSmall);
    }

    writer.flush()?;
    reporter.report(1.00, "Decryption complete.");
    Ok(())
}

fn decrypt_stream_v2<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    reporter: &dyn ProgressReporter,
) -> CryptoResult<()> {
    eprintln!("[INFO] VAULTX02 (V2) format detected. Consider re-encrypting with V3 for streaming support and no memory limits.");
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut nonce)?;

    reporter.report(0.05, "Deriving decryption key (Argon2id)...");
    let key = derive_key(password, &salt)?;

    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    const V2_STREAM_MAX_BYTES: u64 = 1_073_741_824;
    let mut ciphertext = Vec::new();
    reader
        .take(V2_STREAM_MAX_BYTES + 1)
        .read_to_end(&mut ciphertext)?;
    if ciphertext.len() as u64 > V2_STREAM_MAX_BYTES {
        return Err(CryptoError::LegacyFileTooLarge);
    }

    let aad = build_aad(&salt, &nonce);
    reporter.report(0.50, "Decrypting data (AES-256-GCM-SIV)...");
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
    );
    writer.write_all(plaintext.as_slice())?;

    writer.flush()?;
    reporter.report(1.00, "Decryption complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestReporter;

    impl ProgressReporter for TestReporter {
        fn report(&self, _progress: f32, _message: &str) {}
    }

    fn unique_test_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "neuron_test_{}",
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ))
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let plaintext = b"Hello, security audit!";
        let password = b"supersecretpassword";

        let (ciphertext, salt, nonce) = encrypt_bytes(plaintext, password).unwrap();
        let decrypted = decrypt_bytes(&ciphertext, password, &salt, &nonce).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_file() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();

        let src_path = tmp_dir.join("src.txt");
        let encrypted_path = tmp_dir.join("dest.vx2");
        let decrypted_path = tmp_dir.join("final.txt");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src_path, b"File content for testing").unwrap();

        encrypt_file(
            &src_path,
            &encrypted_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        )
        .unwrap();
        assert!(encrypted_path.exists());

        decrypt_file(
            &encrypted_path,
            &decrypted_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        )
        .unwrap();
        assert!(decrypted_path.exists());

        let final_content = fs::read(decrypted_path).unwrap();
        assert_eq!(final_content, b"File content for testing");

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_password_too_short() {
        let plaintext = b"some data";
        let password = b"short";
        let result = encrypt_bytes(plaintext, password);
        assert!(matches!(result, Err(CryptoError::PassphraseTooShort(_))));
    }

    #[test]
    fn test_invalid_magic() {
        let mut raw = vec![0u8; 100];
        raw[0..8].copy_from_slice(b"NOTMAGIC");
        let result = parse_header(&raw);
        assert!(matches!(result, Err(CryptoError::InvalidMagic)));
    }

    #[test]
    fn test_default_output_names_strip_one_vx2_suffix() {
        assert_eq!(
            default_encrypt_output_name(Path::new("report.pdf")),
            "report.pdf.vx2"
        );
        assert_eq!(
            default_decrypt_output_name(Path::new("report.pdf.vx2")),
            "report.pdf"
        );
        assert_eq!(
            default_decrypt_output_name(Path::new("archive.vx2.vx2")),
            "archive.vx2"
        );
        assert_eq!(default_decrypt_output_name(Path::new(".vx2")), "decrypted");
    }

    #[test]
    fn test_decrypt_bytes_rejects_invalid_nonce_length() {
        let result = decrypt_bytes(
            b"ciphertext",
            b"supersecretpassword",
            &[1u8; SALT_LEN],
            &[0u8; 8],
        );
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength {
                expected: NONCE_LEN,
                actual: 8
            })
        ));
    }

    #[test]
    fn test_decrypt_bytes_rejects_short_password() {
        let result = decrypt_bytes(b"ciphertext", b"short", &[1u8; SALT_LEN], &[0u8; NONCE_LEN]);
        assert!(matches!(result, Err(CryptoError::PassphraseTooShort(_))));
    }

    #[test]
    fn test_encrypt_file_rejects_existing_destination() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();

        let src_path = tmp_dir.join("src.txt");
        let dest_path = tmp_dir.join("dest.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src_path, b"secret").unwrap();
        fs::write(&dest_path, b"already here").unwrap();

        let result = encrypt_file(
            &src_path,
            &dest_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        );
        assert!(matches!(result, Err(CryptoError::FileAlreadyExists(_))));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_encrypt_file_overwrites_existing_destination_with_force() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();

        let src_path = tmp_dir.join("src.txt");
        let dest_path = tmp_dir.join("dest.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src_path, b"secret").unwrap();
        fs::write(&dest_path, b"already here").unwrap();

        let result = encrypt_file(
            &src_path,
            &dest_path,
            true,
            password.as_bytes(),
            &reporter,
            None,
        );
        assert!(result.is_ok());
        assert!(dest_path.exists());
        assert_ne!(fs::read(&dest_path).unwrap(), b"already here");

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_encrypt_file_rejects_same_source_and_destination() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();

        let src_path = tmp_dir.join("src.txt");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src_path, b"secret").unwrap();

        let result = encrypt_file(
            &src_path,
            &src_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        );
        assert!(matches!(
            result,
            Err(CryptoError::SourceAndDestinationSame(_))
        ));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_stream_roundtrip_multi_chunk() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();

        let src_path = tmp_dir.join("big.bin");
        let encrypted_path = tmp_dir.join("big.vx2");
        let decrypted_path = tmp_dir.join("big_dec.bin");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        // Create a file larger than CHUNK_SIZE (2.5 MB)
        let data: Vec<u8> = (0u8..=255)
            .cycle()
            .take(CHUNK_SIZE * 2 + CHUNK_SIZE / 2)
            .collect();
        fs::write(&src_path, &data).unwrap();

        encrypt_file(
            &src_path,
            &encrypted_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        )
        .unwrap();

        // Verify the file starts with VAULTX04 (V4 is the current default format).
        let header = fs::read(&encrypted_path).unwrap();
        assert_eq!(&header[..8], MAGIC_V4);

        decrypt_file(
            &encrypted_path,
            &decrypted_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        )
        .unwrap();
        let result = fs::read(&decrypted_path).unwrap();
        assert_eq!(result, data);

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_stream_roundtrip_exact_chunk() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();

        let src_path = tmp_dir.join("exact.bin");
        let encrypted_path = tmp_dir.join("exact.vx2");
        let decrypted_path = tmp_dir.join("exact_dec.bin");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        // Exactly 1 chunk
        let data = vec![42u8; CHUNK_SIZE];
        fs::write(&src_path, &data).unwrap();

        encrypt_file(
            &src_path,
            &encrypted_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        )
        .unwrap();
        decrypt_file(
            &encrypted_path,
            &decrypted_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        )
        .unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), data);

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_wrong_password() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();

        let src_path = tmp_dir.join("secret.txt");
        let encrypted_path = tmp_dir.join("secret.vx2");
        let decrypted_path = tmp_dir.join("secret_dec.txt");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let wrong = "y".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src_path, b"top secret data").unwrap();
        encrypt_file(
            &src_path,
            &encrypted_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        )
        .unwrap();

        let result = decrypt_file(
            &encrypted_path,
            &decrypted_path,
            false,
            wrong.as_bytes(),
            &reporter,
            None,
        );
        assert!(result.is_err());

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_stream_decrypt_rejects_header_only_input() {
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;
        let mut input = Vec::new();
        input.extend_from_slice(MAGIC_V3);
        input.extend_from_slice(&[0u8; SALT_V3_LEN]);
        input.extend_from_slice(&[0u8; STREAM_NONCE_LEN]);

        let mut reader = std::io::Cursor::new(input);
        let mut output = Vec::new();
        let result = decrypt_stream(
            &mut reader,
            &mut output,
            password.as_bytes(),
            None,
            &reporter,
        );

        assert!(matches!(result, Err(CryptoError::FileTooSmall)));
        assert!(output.is_empty());
    }

    #[test]
    fn test_v2_backward_compat() {
        // Manually create a V2-format encrypted file and verify decrypt_file can handle it
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();

        let plaintext = b"Legacy V2 content";
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        let (ciphertext, salt, nonce) = encrypt_bytes(plaintext, password.as_bytes()).unwrap();

        let v2_path = tmp_dir.join("legacy.vx2");
        {
            let mut f = fs::File::create(&v2_path).unwrap();
            f.write_all(MAGIC).unwrap();
            f.write_all(&salt).unwrap();
            f.write_all(&nonce).unwrap();
            f.write_all(&ciphertext).unwrap();
            f.sync_all().unwrap();
        }

        let dec_path = tmp_dir.join("legacy_dec.txt");
        decrypt_file(
            &v2_path,
            &dec_path,
            false,
            password.as_bytes(),
            &reporter,
            None,
        )
        .unwrap();
        assert_eq!(fs::read(&dec_path).unwrap(), plaintext);

        let _ = fs::remove_dir_all(tmp_dir);
    }

    // ── P2-1 regression tests — edge cases, tamper, reorder, format-confusion ──

    #[test]
    fn test_v3_empty_file_roundtrip() {
        // Encrypt a 0-byte file; should produce a 47-byte .vx2 (31 header + 16 tag)
        // and decrypt back to a 0-byte file.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("empty.bin");
        let enc = tmp_dir.join("empty.vx2");
        let dec = tmp_dir.join("empty_dec.bin");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();
        assert_eq!(fs::metadata(&enc).unwrap().len(), 47);
        decrypt_file(&enc, &dec, false, password.as_bytes(), &reporter, None).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), b"");

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_single_byte_roundtrip() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("one.bin");
        let enc = tmp_dir.join("one.vx2");
        let dec = tmp_dir.join("one_dec.bin");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"A").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();
        decrypt_file(&enc, &dec, false, password.as_bytes(), &reporter, None).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), b"A");

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_truncated_at_chunk_boundary_fails() {
        // Truncating after the first chunk should make decrypt_last treat the
        // first chunk as the last — flag mismatch → DecryptionFailed.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("big.bin");
        let enc = tmp_dir.join("big.vx2");
        let truncated = tmp_dir.join("trunc.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        let data: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 2 + 100).collect();
        fs::write(&src, &data).unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        // Truncate: keep 31-byte header + first chunk only (CHUNK_SIZE + TAG_LEN bytes)
        let full = fs::read(&enc).unwrap();
        let cut_len = HEADER_V3_LEN + CHUNK_SIZE + TAG_LEN;
        assert!(full.len() > cut_len);
        fs::write(&truncated, &full[..cut_len]).unwrap();

        let dec = tmp_dir.join("dec.bin");
        let result = decrypt_file(
            &truncated,
            &dec,
            false,
            password.as_bytes(),
            &reporter,
            None,
        );
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_tampered_salt_fails() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"sensitive data").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        // Flip a bit in the salt (bytes 8..24)
        let mut bytes = fs::read(&enc).unwrap();
        bytes[8] ^= 0x01;
        let tampered = tmp_dir.join("tampered.vx2");
        fs::write(&tampered, &bytes).unwrap();

        let dec = tmp_dir.join("dec.txt");
        let result = decrypt_file(&tampered, &dec, false, password.as_bytes(), &reporter, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_tampered_nonce_fails() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"sensitive data").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        // Flip a bit in the stream_nonce (bytes 24..31)
        let mut bytes = fs::read(&enc).unwrap();
        bytes[24] ^= 0x80;
        let tampered = tmp_dir.join("tampered.vx2");
        fs::write(&tampered, &bytes).unwrap();

        let dec = tmp_dir.join("dec.txt");
        let result = decrypt_file(&tampered, &dec, false, password.as_bytes(), &reporter, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_tampered_chunk_byte_fails() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"sensitive data here").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        // Flip a bit in the body (after header)
        let mut bytes = fs::read(&enc).unwrap();
        let body_start = HEADER_V3_LEN;
        assert!(bytes.len() > body_start + 4);
        bytes[body_start + 4] ^= 0x10;
        let tampered = tmp_dir.join("tampered.vx2");
        fs::write(&tampered, &bytes).unwrap();

        let dec = tmp_dir.join("dec.txt");
        let result = decrypt_file(&tampered, &dec, false, password.as_bytes(), &reporter, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v4_magic_swap_v4_to_v2_fails() {
        // Attacker rewrites VAULTX04 → VAULTX02. Dispatcher should route to V2 path,
        // which fails because the V4 layout is incompatible with V2 expectations.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"sensitive data").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        bytes[..8].copy_from_slice(MAGIC); // overwrite VAULTX04 with VAULTX02
        let swapped = tmp_dir.join("swapped.vx2");
        fs::write(&swapped, &bytes).unwrap();

        let dec = tmp_dir.join("dec.txt");
        let result = decrypt_file(&swapped, &dec, false, password.as_bytes(), &reporter, None);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_reordered_chunks_fail() {
        // Build a 3-chunk file, swap chunks 0 and 1, expect DecryptionFailed.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("big.bin");
        let enc = tmp_dir.join("big.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        let data: Vec<u8> = (0u8..=255)
            .cycle()
            .take(CHUNK_SIZE * 2 + CHUNK_SIZE / 2)
            .collect();
        fs::write(&src, &data).unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        let body = &mut bytes[HEADER_V3_LEN..];
        let chunk_stride = CHUNK_SIZE + TAG_LEN;
        assert!(body.len() >= 2 * chunk_stride);
        // Swap chunks 0 and 1 using split_at_mut to avoid overlapping borrows.
        let (first_half, _second_half) = body.split_at_mut(2 * chunk_stride);
        let (chunk0, chunk1) = first_half.split_at_mut(chunk_stride);
        for i in 0..chunk_stride {
            std::mem::swap(&mut chunk0[i], &mut chunk1[i]);
        }

        let reordered = tmp_dir.join("reordered.vx2");
        fs::write(&reordered, &bytes).unwrap();

        let dec = tmp_dir.join("dec.bin");
        let result = decrypt_file(
            &reordered,
            &dec,
            false,
            password.as_bytes(),
            &reporter,
            None,
        );
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_extended_with_garbage_fails() {
        // Appending bytes after the last chunk should promote the original last
        // (sealed with encrypt_last, flag=1) to decrypt_next (flag=0) → fail.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"sensitive data here").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        bytes.extend_from_slice(&[0xABu8; 64]);
        let extended = tmp_dir.join("extended.vx2");
        fs::write(&extended, &bytes).unwrap();

        let dec = tmp_dir.join("dec.txt");
        let result = decrypt_file(&extended, &dec, false, password.as_bytes(), &reporter, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_password_length_boundary() {
        // 7-byte password should be rejected; 8-byte should succeed.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let reporter = TestReporter;

        fs::write(&src, b"data").unwrap();

        let r1 = encrypt_file(&src, &enc, false, b"1234567", &reporter, None);
        assert!(matches!(r1, Err(CryptoError::PassphraseTooShort(_))));

        let r2 = encrypt_file(&src, &enc, false, b"12345678", &reporter, None);
        assert!(r2.is_ok());

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_chunk_minus_one_roundtrip() {
        // File of exactly CHUNK_SIZE - 1 bytes (just under one chunk).
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("under.bin");
        let enc = tmp_dir.join("under.vx2");
        let dec = tmp_dir.join("under_dec.bin");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        let data: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE - 1).collect();
        fs::write(&src, &data).unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();
        decrypt_file(&enc, &dec, false, password.as_bytes(), &reporter, None).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), data);

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_chunk_plus_one_roundtrip() {
        // File of exactly CHUNK_SIZE + 1 bytes (just over one chunk).
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("over.bin");
        let enc = tmp_dir.join("over.vx2");
        let dec = tmp_dir.join("over_dec.bin");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        let data: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE + 1).collect();
        fs::write(&src, &data).unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();
        decrypt_file(&enc, &dec, false, password.as_bytes(), &reporter, None).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), data);

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v3_stream_decrypt_rejects_v2_magic_via_stream() {
        // V2 file fed to decrypt_stream should route to decrypt_stream_v2,
        // which we just exercise for a non-V2 body to confirm dispatch logic.
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        // Build a tiny "V2" file with garbage body (just to test dispatch)
        let mut input = Vec::new();
        input.extend_from_slice(MAGIC);
        input.extend_from_slice(&[0u8; SALT_LEN]);
        input.extend_from_slice(&[0u8; NONCE_LEN]);
        input.extend_from_slice(&[0u8; TAG_LEN + 16]); // fake ciphertext+tag

        let mut reader = std::io::Cursor::new(input);
        let mut output = Vec::new();
        let result = decrypt_stream(
            &mut reader,
            &mut output,
            password.as_bytes(),
            None,
            &reporter,
        );
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_v3_rejects_oversize_file_via_constant() {
        // Sanity: MAX_V3_FILE_SIZE = 2^32 * 1MiB = 4 PiB. Just verify the constant.
        assert_eq!(MAX_V3_FILE_SIZE, (1u64 << 32) * CHUNK_SIZE as u64);
        // 4 PiB expressed in bytes:
        assert_eq!(MAX_V3_FILE_SIZE, 1u64 << 52);
    }

    // ── P1-6 V4 format tests ──

    #[test]
    fn test_v4_constants_sanity() {
        // V4 reuses V3 header layout and file-size limit.
        assert_eq!(HEADER_V4_LEN, HEADER_V3_LEN);
        assert_eq!(MAX_V4_FILE_SIZE, MAX_V3_FILE_SIZE);
        assert_eq!(MAGIC_V4, b"VAULTX04");
        // V3 and V4 magics must be distinct (else dispatch is ambiguous).
        assert_ne!(MAGIC_V3, MAGIC_V4);
    }

    #[test]
    fn test_v4_encrypt_produces_v4_magic() {
        // New encryptions must default to V4.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"hello v4").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        let bytes = fs::read(&enc).unwrap();
        assert_eq!(&bytes[..8], MAGIC_V4);
        assert_ne!(&bytes[..8], MAGIC_V3);
        assert_ne!(&bytes[..8], MAGIC);

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v4_roundtrip_multi_chunk() {
        // V4 encrypt -> decrypt roundtrip with a 2.5 MB file (multiple chunks).
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("big.bin");
        let enc = tmp_dir.join("big.vx2");
        let dec = tmp_dir.join("big_dec.bin");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        let data: Vec<u8> = (0u8..=255)
            .cycle()
            .take(CHUNK_SIZE * 2 + CHUNK_SIZE / 2)
            .collect();
        fs::write(&src, &data).unwrap();

        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();
        assert_eq!(&fs::read(&enc).unwrap()[..8], MAGIC_V4);

        decrypt_file(&enc, &dec, false, password.as_bytes(), &reporter, None).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), data);

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v4_tampered_salt_fails_at_aad() {
        // V4 AAD covers the salt. Tampering with the salt byte must cause
        // DecryptionFailed (either because the derived key changes OR because
        // the AAD no longer matches what was used at encrypt time).
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"sensitive data").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        bytes[8] ^= 0x01; // flip a bit in salt[0]
        let tampered = tmp_dir.join("tampered.vx2");
        fs::write(&tampered, &bytes).unwrap();

        let dec = tmp_dir.join("dec.txt");
        let result = decrypt_file(&tampered, &dec, false, password.as_bytes(), &reporter, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v4_tampered_nonce_fails_at_aad() {
        // V4 AAD covers the stream_nonce. Tampering must cause DecryptionFailed.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"sensitive data").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        bytes[24] ^= 0x80; // flip a bit in stream_nonce[0]
        let tampered = tmp_dir.join("tampered.vx2");
        fs::write(&tampered, &bytes).unwrap();

        let dec = tmp_dir.join("dec.txt");
        let result = decrypt_file(&tampered, &dec, false, password.as_bytes(), &reporter, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v4_tampered_magic_fails() {
        // V4 AAD covers MAGIC_V4. If an attacker changes magic to anything else
        // (e.g., MAGIC_V3 to try the V3 path), the V3 path will run derive_key_v3
        // (wrong key, because V4 used derive_key_v4) and fail. So this is
        // defense-in-depth: even if dispatcher misroutes, decryption fails.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("plain.txt");
        let enc = tmp_dir.join("plain.vx2");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"sensitive data").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        bytes[..8].copy_from_slice(MAGIC_V3); // try to force V3 path on a V4 file
        let swapped = tmp_dir.join("swapped.vx2");
        fs::write(&swapped, &bytes).unwrap();

        let dec = tmp_dir.join("dec.txt");
        let result = decrypt_file(&swapped, &dec, false, password.as_bytes(), &reporter, None);
        // V3 path will derive a V3 key (different HKDF info) and fail at tag verification.
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v4_empty_file_roundtrip() {
        // V4 encrypt -> decrypt of a 0-byte file.
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("empty.bin");
        let enc = tmp_dir.join("empty.vx2");
        let dec = tmp_dir.join("empty_dec.bin");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();
        // 31-byte header + 16-byte tag for empty last chunk = 47 bytes total.
        assert_eq!(fs::metadata(&enc).unwrap().len(), 47);
        decrypt_file(&enc, &dec, false, password.as_bytes(), &reporter, None).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), b"");

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v4_wrong_password_fails() {
        let tmp_dir = unique_test_dir();
        fs::create_dir_all(&tmp_dir).unwrap();
        let src = tmp_dir.join("secret.txt");
        let enc = tmp_dir.join("secret.vx2");
        let dec = tmp_dir.join("dec.txt");
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let wrong = "y".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;

        fs::write(&src, b"top secret").unwrap();
        encrypt_file(&src, &enc, false, password.as_bytes(), &reporter, None).unwrap();

        let result = decrypt_file(&enc, &dec, false, wrong.as_bytes(), &reporter, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_v4_stream_roundtrip_via_pipe() {
        // V4 encrypt_stream -> decrypt_stream roundtrip (CLI pipe path).
        let password = "x".repeat(MIN_PASSWORD_LEN + 4);
        let reporter = TestReporter;
        let data: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE + 100).collect();

        let mut encrypted = Vec::new();
        let mut reader = std::io::Cursor::new(&data);
        encrypt_stream(
            &mut reader,
            &mut encrypted,
            password.as_bytes(),
            Some(data.len() as u64),
            &reporter,
        )
        .unwrap();

        // Verify V4 magic.
        assert_eq!(&encrypted[..8], MAGIC_V4);

        let mut decrypted = Vec::new();
        let mut enc_reader = std::io::Cursor::new(&encrypted);
        decrypt_stream(
            &mut enc_reader,
            &mut decrypted,
            password.as_bytes(),
            Some(encrypted.len() as u64),
            &reporter,
        )
        .unwrap();

        assert_eq!(decrypted, data);
    }
}
