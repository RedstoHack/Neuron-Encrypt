use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::{FromRawFd, RawFd};

use libc::dup;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

use jni::objects::{GlobalRef, JByteArray, JClass, JObject};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use jni::JavaVM;

use neuron_encrypt_core::crypto::{
    decrypt_stream, encrypt_stream, ProgressReporter, ThrottledReporter,
};
use neuron_encrypt_core::error::CryptoError;
use zeroize::Zeroizing;

const EXCEPTION_CLASS: &str = "com/neuronencrypt/app/NeuronEncryptException";
const CANCELLED_IO_MESSAGE: &str = "operation cancelled";

/// Wraps the output file so that `flush()` also makes the data durable before
/// the stream layer broadcasts its final 100% progress. Without this, the app
/// could report "complete" while the kernel page cache was still writing back
/// the last buffered data (visible as "100% but still working" on slow flash).
struct DurableFile(File);

impl Write for DurableFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()?;
        // Best-effort: some storage providers reject fsync; durability is a
        // guarantee we try to provide, not a failure condition.
        let _ = self.0.sync_data();
        Ok(())
    }
}

struct CancelableReader {
    inner: File,
    cancel: GlobalRef,
    vm: Arc<JavaVM>,
}

impl CancelableReader {
    fn is_cancelled(&self) -> bool {
        if let Ok(mut env) = self.vm.attach_current_thread() {
            if let Ok(res) = env.call_method(&self.cancel, "get", "()Z", &[]) {
                if let Ok(val) = res.z() {
                    return val;
                }
            }
        }
        false
    }
}

impl Read for CancelableReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.is_cancelled() {
            // Not ErrorKind::Interrupted: std's read loops (and the core's
            // read_exact_or_eof) treat Interrupted as "retry", which would
            // spin forever once the flag latches. A distinct error kind
            // propagates as a real failure; map_error recognises it below.
            return Err(io::Error::other(CANCELLED_IO_MESSAGE));
        }
        self.inner.read(buf)
    }
}

impl Seek for CancelableReader {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        if self.is_cancelled() {
            return Err(io::Error::other(CANCELLED_IO_MESSAGE));
        }
        self.inner.seek(pos)
    }
}

fn is_cancellation(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
        || err.kind() == io::ErrorKind::Other && err.to_string() == CANCELLED_IO_MESSAGE
}

struct JniReporter {
    listener: GlobalRef,
    vm: Arc<JavaVM>,
}

impl ProgressReporter for JniReporter {
    fn report(&self, progress: f32, message: &str) {
        if let Ok(mut env) = self.vm.attach_current_thread() {
            if let Ok(java_msg) = env.new_string(message) {
                let args = [
                    jni::objects::JValue::from(progress),
                    jni::objects::JValue::from(&java_msg),
                ];
                let _ = env.call_method(
                    &self.listener,
                    "onProgress",
                    "(FLjava/lang/String;)V",
                    &args,
                );
            }
        }
    }
}

fn map_error(env: &mut JNIEnv, err: CryptoError) -> jint {
    let (code, message) = match err {
        CryptoError::Io(ref io_err) if is_cancellation(io_err) => (1, "Cancelled".to_owned()),
        CryptoError::DecryptionFailed
        | CryptoError::InvalidMagic
        | CryptoError::UnsupportedVersion(_)
        | CryptoError::FileTooSmall => (3, "Wrong passphrase or corrupted file.".to_owned()),

        CryptoError::PassphraseTooShort(min) => {
            (2, format!("Passphrase must be at least {min} bytes."))
        }
        CryptoError::FileAlreadyExists(_)
        | CryptoError::InvalidDestination(_)
        | CryptoError::SourceAndDestinationSame(_)
        | CryptoError::NotAFile(_)
        | CryptoError::InvalidSaltLength { .. }
        | CryptoError::InvalidNonceLength { .. }
        | CryptoError::FileTooLarge { .. } => (2, "Invalid input or output file.".to_owned()),

        CryptoError::Io(_) => (1, "Storage I/O failed.".to_owned()),
        CryptoError::LegacyFileTooLarge => {
            (1, "Legacy file too large for this operation.".to_owned())
        }
        CryptoError::Argon2Failed(_)
        | CryptoError::HkdfFailed(_)
        | CryptoError::EncryptionFailed(_) => (1, "Cryptographic operation failed.".to_owned()),
        CryptoError::UnsupportedMediaFormat(reason) => {
            (2, format!("Unsupported format \u{2014} {reason}"))
        }
        CryptoError::MalformedFile(detail) => (1, format!("Corrupted file: {detail}")),
        CryptoError::ScrubFailed(detail) => (1, format!("Metadata removal failed: {detail}")),
        CryptoError::Cancelled => (1, "Cancelled".to_owned()),
    };

    let _ = env.throw_new(EXCEPTION_CLASS, message);
    code
}

fn zero_java_array(env: &mut JNIEnv, array: &JByteArray) {
    if let Ok(len) = env.get_array_length(array) {
        if len > 0 {
            let zeros = vec![0i8; len as usize];
            let _ = env.set_byte_array_region(array, 0, &zeros);
        }
    }
}

fn fail_with_exception(env: &mut JNIEnv, password: &JByteArray, code: jint, message: &str) -> jint {
    zero_java_array(env, password);
    let _ = env.throw_new(EXCEPTION_CLASS, message);
    code
}

/// Duplicate a file descriptor. On Android the Java side keeps ownership of the
/// original `ParcelFileDescriptor`, which must stay alive for the whole write so
/// the content provider receives its close signal only after all bytes are on
/// disk. Duplicating lets Rust own a private copy that it closes on drop without
/// invalidating the provider-facing descriptor (see tauri #3356 — detachFd()
/// caused providers to finalize the file at 0 bytes).
///
/// Returns `None` if `dup(2)` fails.
fn duplicate_fd(fd: jint) -> Option<RawFd> {
    if fd < 0 {
        return None;
    }
    let duped = unsafe { dup(fd) };
    if duped < 0 {
        None
    } else {
        Some(duped)
    }
}

fn native_encrypt_impl(
    env: &mut JNIEnv,
    input_fd: jint,
    output_fd: jint,
    password: &JByteArray,
    source_size: jlong,
    progress_listener: &JObject,
    cancel_flag: &JObject,
) -> jint {
    if input_fd < 0 || output_fd < 0 {
        return fail_with_exception(env, password, 2, "Invalid file descriptor.");
    }

    // Duplicate (not detach) the fds. The Java side keeps the original
    // ParcelFileDescriptors open until this call returns, so the content
    // provider is only told the write finished once the data is actually on
    // disk. We own the dup'd copies here and close them on drop.
    let input_dup = match duplicate_fd(input_fd) {
        Some(fd) => fd,
        None => {
            return fail_with_exception(
                env,
                password,
                1,
                "Failed to duplicate input file descriptor.",
            )
        }
    };
    let output_dup = match duplicate_fd(output_fd) {
        Some(fd) => fd,
        None => {
            unsafe { libc::close(input_dup) };
            return fail_with_exception(
                env,
                password,
                1,
                "Failed to duplicate output file descriptor.",
            );
        }
    };

    let input_file = unsafe { File::from_raw_fd(input_dup) };
    let mut output_file = DurableFile(unsafe { File::from_raw_fd(output_dup) });

    let vm = match env.get_java_vm() {
        Ok(v) => Arc::new(v),
        Err(_) => return fail_with_exception(env, password, 1, "Failed to access JVM."),
    };

    let cancel_ref = match env.new_global_ref(cancel_flag) {
        Ok(r) => r,
        Err(_) => {
            return fail_with_exception(env, password, 1, "Failed to retain cancellation flag.");
        }
    };

    let listener_ref = match env.new_global_ref(progress_listener) {
        Ok(r) => r,
        Err(_) => {
            return fail_with_exception(env, password, 1, "Failed to retain progress listener.");
        }
    };

    let password_bytes = match env.convert_byte_array(password) {
        Ok(b) => b,
        Err(_) => {
            return fail_with_exception(env, password, 2, "Failed to read passphrase.");
        }
    };
    let password_bytes = Zeroizing::new(password_bytes);

    let mut reader = CancelableReader {
        inner: input_file,
        cancel: cancel_ref,
        vm: Arc::clone(&vm),
    };

    let reporter = JniReporter {
        listener: listener_ref,
        vm: Arc::clone(&vm),
    };
    let throttled = ThrottledReporter::new(&reporter);

    let size_opt = if source_size >= 0 {
        Some(source_size as u64)
    } else {
        None
    };

    let run_result = encrypt_stream(
        &mut reader,
        &mut output_file,
        &password_bytes,
        size_opt,
        &throttled,
    );

    // GlobalRefs are automatically released when reader/reporter are dropped here

    zero_java_array(env, password);

    match run_result {
        Ok(()) => {
            // Full durability (metadata included) once the data is already
            // synced by DurableFile::flush — best-effort, same as above.
            let _ = output_file.0.sync_all();
            0
        }
        Err(e) => map_error(env, e),
    }
}

fn native_decrypt_impl(
    env: &mut JNIEnv,
    input_fd: jint,
    output_fd: jint,
    password: &JByteArray,
    total_size: jlong,
    progress_listener: &JObject,
    cancel_flag: &JObject,
) -> jint {
    if input_fd < 0 || output_fd < 0 {
        return fail_with_exception(env, password, 2, "Invalid file descriptor.");
    }

    // Duplicate (not detach) the fds — see native_encrypt_impl for the rationale.
    let input_dup = match duplicate_fd(input_fd) {
        Some(fd) => fd,
        None => {
            return fail_with_exception(
                env,
                password,
                1,
                "Failed to duplicate input file descriptor.",
            )
        }
    };
    let output_dup = match duplicate_fd(output_fd) {
        Some(fd) => fd,
        None => {
            unsafe { libc::close(input_dup) };
            return fail_with_exception(
                env,
                password,
                1,
                "Failed to duplicate output file descriptor.",
            );
        }
    };

    let input_file = unsafe { File::from_raw_fd(input_dup) };
    let mut output_file = DurableFile(unsafe { File::from_raw_fd(output_dup) });

    let vm = match env.get_java_vm() {
        Ok(v) => Arc::new(v),
        Err(_) => return fail_with_exception(env, password, 1, "Failed to access JVM."),
    };

    let cancel_ref = match env.new_global_ref(cancel_flag) {
        Ok(r) => r,
        Err(_) => {
            return fail_with_exception(env, password, 1, "Failed to retain cancellation flag.");
        }
    };

    let listener_ref = match env.new_global_ref(progress_listener) {
        Ok(r) => r,
        Err(_) => {
            return fail_with_exception(env, password, 1, "Failed to retain progress listener.");
        }
    };

    let password_bytes = match env.convert_byte_array(password) {
        Ok(b) => b,
        Err(_) => {
            return fail_with_exception(env, password, 2, "Failed to read passphrase.");
        }
    };
    let password_bytes = Zeroizing::new(password_bytes);

    let mut reader = CancelableReader {
        inner: input_file,
        cancel: cancel_ref,
        vm: Arc::clone(&vm),
    };

    let reporter = JniReporter {
        listener: listener_ref,
        vm: Arc::clone(&vm),
    };
    let throttled = ThrottledReporter::new(&reporter);

    let size_opt = if total_size >= 0 {
        Some(total_size as u64)
    } else {
        None
    };

    let run_result = decrypt_stream(
        &mut reader,
        &mut output_file,
        &password_bytes,
        size_opt,
        &throttled,
    );

    // GlobalRefs are automatically released when reader/reporter are dropped here

    zero_java_array(env, password);

    match run_result {
        Ok(()) => {
            // Full durability (metadata included) once the data is already
            // synced by DurableFile::flush — best-effort, same as above.
            let _ = output_file.0.sync_all();
            0
        }
        Err(e) => map_error(env, e),
    }
}

/// JNI entry point for `NeuronEncryptNative.nativeEncrypt`.
///
/// # Safety
///
/// This function is `unsafe extern "system"` because it is called by the JVM
/// via the Java Native Interface. The caller (the JVM) must:
///
/// - Pass valid `input_fd` and `output_fd` values that refer to open OS file
///   descriptors. The function duplicates these fds (via `dup(2)`) and takes
///   ownership of the duplicates only; the Java side must keep the original
///   `ParcelFileDescriptor`s open until this function returns (do NOT call
///   `detachFd()`), so the content provider receives its close signal after
///   the write completes.
/// - Pass a non-null `password: JByteArray` reference owned by the current
///   JNI frame. The function reads its contents and zeroes the array in-place
///   before returning.
/// - Pass non-null `progress_listener` and `cancel_flag` references that
///   implement `ProgressListener.onProgress(float, String)` and
///   `AtomicBoolean.get(): boolean` respectively.
///
/// Violating any of these may cause undefined behavior (use-after-free,
/// null-pointer dereference, or closing of unrelated fds).
#[no_mangle]
pub unsafe extern "system" fn Java_com_neuronencrypt_app_NeuronEncryptNative_nativeEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    input_fd: jint,
    output_fd: jint,
    password: JByteArray,
    source_size: jlong,
    progress_listener: JObject,
    cancel_flag: JObject,
) -> jint {
    let res = panic::catch_unwind(AssertUnwindSafe(|| {
        native_encrypt_impl(
            &mut env,
            input_fd,
            output_fd,
            &password,
            source_size,
            &progress_listener,
            &cancel_flag,
        )
    }));

    match res {
        Ok(code) => code,
        Err(_) => {
            zero_java_array(&mut env, &password);
            let _ = env.throw_new(EXCEPTION_CLASS, "Unexpected native failure.");
            1
        }
    }
}

/// JNI entry point for `NeuronEncryptNative.nativeDecrypt`.
///
/// # Safety
///
/// Same safety contract as `Java_com_neuronencrypt_app_NeuronEncryptNative_nativeEncrypt`.
/// See that function's safety doc for the full requirements on `input_fd`,
/// `output_fd`, `password`, `progress_listener`, and `cancel_flag`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_neuronencrypt_app_NeuronEncryptNative_nativeDecrypt(
    mut env: JNIEnv,
    _class: JClass,
    input_fd: jint,
    output_fd: jint,
    password: JByteArray,
    total_size: jlong,
    progress_listener: JObject,
    cancel_flag: JObject,
) -> jint {
    let res = panic::catch_unwind(AssertUnwindSafe(|| {
        native_decrypt_impl(
            &mut env,
            input_fd,
            output_fd,
            &password,
            total_size,
            &progress_listener,
            &cancel_flag,
        )
    }));

    match res {
        Ok(code) => code,
        Err(_) => {
            zero_java_array(&mut env, &password);
            let _ = env.throw_new(EXCEPTION_CLASS, "Unexpected native failure.");
            1
        }
    }
}

// ===========================================================================
// Metadata scrubbing (v2.2.0)
//
// Design note - why staging instead of in-memory or direct streaming:
// Encryption is a pure sequential byte transform, so it streams natively.
// Metadata removal rewrites container structure; several formats carry
// absolute byte offsets (MP4 stco tables, TIFF IFDs, PDF xref) that shift
// when metadata is excised, so single-pass stream rewriting is not safely
// possible for every supported format. Instead of loading whole files into
// RAM, the input descriptor is copied to the app-private cache directory
// through a fixed 1 MiB buffer, the battle-tested path-based `scrub_file`
// runs there (audio/video containers are streamed by lofty internally), and
// the result streams back to the output descriptor. Peak RSS stays flat
// regardless of file size; the cost is temporary disk usage (~2x source),
// guarded by a free-space check before scrubbing begins.
// ===========================================================================

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn random_token() -> String {
    let mut bytes = [0u8; 8];
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut bytes).is_ok() {
            return hex_encode(&bytes);
        }
    }
    // Fallback entropy: wall clock + pid (uniqueness within one process).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ ((unsafe { libc::getpid() } as u64) << 32);
    hex_encode(nanos.to_le_bytes().as_slice())
}

/// Polls the Java-side AtomicBoolean into a Rust Arc<AtomicBool> so core
/// operations can observe cancellation at their chunk boundaries without
/// making JNI calls from the worker thread.
struct CancelBridge {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    rust_flag: Arc<std::sync::atomic::AtomicBool>,
}

impl CancelBridge {
    fn spawn(vm: Arc<JavaVM>, java_flag: GlobalRef) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = Arc::new(AtomicBool::new(false));
        let rust_flag = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let rust2 = Arc::clone(&rust_flag);

        let handle = std::thread::spawn(move || loop {
            if stop2.load(Ordering::SeqCst) {
                break;
            }
            let cancelled = vm
                .attach_current_thread()
                .ok()
                .and_then(|mut env| env.call_method(&java_flag, "get", "()Z", &[]).ok())
                .and_then(|res| res.z().ok())
                .unwrap_or(false);
            if cancelled {
                rust2.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        });

        Self {
            stop,
            handle: Some(handle),
            rust_flag,
        }
    }

    fn flag(&self) -> &Arc<std::sync::atomic::AtomicBool> {
        &self.rust_flag
    }
}

impl Drop for CancelBridge {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Rescales an inner reporter's [0,1] progress into [lo,hi] so multi-phase
/// operations present monotonic overall progress to the UI.
struct PhaseReporter<'a> {
    inner: &'a JniReporter,
    lo: f32,
    hi: f32,
}

impl ProgressReporter for PhaseReporter<'_> {
    fn report(&self, progress: f32, message: &str) {
        let scaled = self.lo + progress.clamp(0.0, 1.0) * (self.hi - self.lo);
        self.inner.report(scaled, message);
    }
}

const SCRUB_STAGE_BUFFER: usize = 1024 * 1024;
const SCRUB_MIN_HEADROOM: u64 = 8 * 1024 * 1024;

fn cache_free_bytes(dir: &std::path::Path) -> Option<u64> {
    let c = std::ffi::CString::new(dir.to_str()?).ok()?;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut vfs) };
    if rc != 0 {
        return None;
    }
    // f_frsize is the fragment size allocations are actually made of; f_bsize
    // is the "preferred" block size and can overstate usable space. Fall back
    // if a volume reports 0 (some FUSE-backed providers do).
    let unit = if vfs.f_frsize > 0 {
        vfs.f_frsize as u64
    } else {
        vfs.f_bsize as u64
    };
    Some(vfs.f_bavail as u64 * unit)
}

/// Fails fast when the app cache directory cannot hold the scratch copies a
/// scrub needs (~2x the source: staged input + scrubbed output), so an
/// oversized file is rejected up front instead of filling the data partition
/// and then failing with a bare "Storage I/O failed".
///
/// `source_size` is the fd's reported size (0 when the provider does not
/// report one, e.g. pipes); `statvfs` being unavailable fails open because the
/// write itself will surface a real error.
fn ensure_scratch_space(dir: &std::path::Path, source_len: u64) -> Result<(), CryptoError> {
    let Some(free) = cache_free_bytes(dir) else {
        return Ok(());
    };
    let needed = source_len
        .saturating_mul(2)
        .saturating_add(SCRUB_MIN_HEADROOM);
    if free < needed {
        return Err(CryptoError::Io(io::Error::new(
            io::ErrorKind::StorageFull,
            format!("app cache has {free} bytes free but {needed} are required"),
        )));
    }
    Ok(())
}

// The parameter list deliberately mirrors the JNI entry point it serves (and
// its Java-side declaration), so the bridge stays a 1:1 mapping rather than an
// invented struct that both sides would have to keep in sync.
#[allow(clippy::too_many_arguments)]
fn native_scrub_impl(
    env: &mut JNIEnv,
    input_fd: jint,
    output_fd: jint,
    cache_dir: &std::ffi::CStr,
    source_size: jlong,
    progress_listener: &JObject,
    report_listener: &JObject,
    cancel_flag: &JObject,
) -> jint {
    use std::io::Read;
    use std::sync::atomic::Ordering;

    if input_fd < 0 || output_fd < 0 {
        let _ = env.throw_new(EXCEPTION_CLASS, "Invalid file descriptor.");
        return 2;
    }

    let input_dup = match duplicate_fd(input_fd) {
        Some(fd) => fd,
        None => {
            let _ = env.throw_new(
                EXCEPTION_CLASS,
                "Failed to duplicate input file descriptor.",
            );
            return 1;
        }
    };
    let output_dup = match duplicate_fd(output_fd) {
        Some(fd) => fd,
        None => {
            unsafe { libc::close(input_dup) };
            let _ = env.throw_new(
                EXCEPTION_CLASS,
                "Failed to duplicate output file descriptor.",
            );
            return 1;
        }
    };

    let mut input_file = unsafe { File::from_raw_fd(input_dup) };
    let mut output_file = DurableFile(unsafe { File::from_raw_fd(output_dup) });

    let vm = match env.get_java_vm() {
        Ok(v) => Arc::new(v),
        Err(_) => {
            let _ = env.throw_new(EXCEPTION_CLASS, "Failed to access JVM.");
            return 1;
        }
    };

    let listener_ref = match env.new_global_ref(progress_listener) {
        Ok(r) => r,
        Err(_) => {
            let _ = env.throw_new(EXCEPTION_CLASS, "Failed to retain progress listener.");
            return 1;
        }
    };
    let reporter = JniReporter {
        listener: listener_ref,
        vm: Arc::clone(&vm),
    };

    // Second global ref owned by the watcher thread.
    let cancel_java_ref = match env.new_global_ref(cancel_flag) {
        Ok(r) => r,
        Err(_) => {
            let _ = env.throw_new(EXCEPTION_CLASS, "Failed to retain cancellation flag.");
            return 1;
        }
    };
    let bridge = CancelBridge::spawn(Arc::clone(&vm), cancel_java_ref);

    let dir = std::path::PathBuf::from(cache_dir.to_string_lossy().as_ref());
    let token = random_token();
    let staged_in = dir.join(format!("neuron-scrub-{token}.in"));
    let staged_out = dir.join(format!("neuron-scrub-{token}.out"));

    // Runs to completion regardless of outcome; temps are always removed.
    let outcome = (|| -> Result<neuron_encrypt_core::metadata::ScrubReport, CryptoError> {
        if !dir.is_dir() {
            return Err(CryptoError::InvalidDestination(dir));
        }

        // ---- Phase 0: free-space pre-flight ----
        // Reject files that cannot fit *before* writing anything: staging a
        // huge file only to fail afterwards fills the data partition and
        // surfaces as a generic storage error.
        let stat_len = input_file.metadata().map(|m| m.len()).unwrap_or(0);
        let expected_len = if source_size > 0 {
            stat_len.max(source_size as u64)
        } else {
            stat_len
        };
        ensure_scratch_space(&dir, expected_len)?;

        // ---- Phase 1: stage input -> cache temp through a fixed buffer ----
        reporter.report(0.02, "Staging file...");
        let source_len = input_file.metadata()?.len();
        let staged_len = {
            let mut staged = fs_create_private(&staged_in)?;
            let mut chunk = vec![0u8; SCRUB_STAGE_BUFFER];
            let mut copied: u64 = 0;
            loop {
                if bridge.flag().load(Ordering::SeqCst) {
                    return Err(CryptoError::Cancelled);
                }
                let n = input_file.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                staged.write_all(&chunk[..n])?;
                copied += n as u64;
                if source_len > 0 {
                    reporter.report(
                        0.02 + 0.10 * (copied as f32 / source_len as f32),
                        "Staging file...",
                    );
                }
            }
            staged.flush()?;
            copied
        };
        drop(input_file);

        // A provider that hands us nothing readable (or a stale cache evicted
        // mid-copy) would otherwise be "scrubbed" as an empty file; fail closed.
        if staged_len == 0 {
            return Err(CryptoError::MalformedFile(
                "input file produced no readable bytes".to_owned(),
            ));
        }

        // ---- Phase 2: core scrubber on the staged paths ----
        let phase2 = PhaseReporter {
            inner: &reporter,
            lo: 0.15,
            hi: 0.90,
        };
        neuron_encrypt_core::metadata::scrub_file(
            &staged_in,
            Some(&staged_out),
            neuron_encrypt_core::metadata::ScrubOutput::CleanedCopy,
            false,
            false,
            &phase2,
            Some(bridge.flag()),
        )
    })();

    // ---- Phase 3: stream result back to the output descriptor ----
    let final_result = outcome.and_then(|report| {
        reporter.report(0.92, "Writing output...");
        let out_len = std::fs::metadata(&staged_out)?.len();
        let mut src = File::open(&staged_out)?;
        let mut chunk = vec![0u8; SCRUB_STAGE_BUFFER];
        let mut copied: u64 = 0;
        loop {
            if bridge.flag().load(Ordering::SeqCst) {
                return Err(CryptoError::Cancelled);
            }
            let n = src.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            output_file.write_all(&chunk[..n])?;
            copied += n as u64;
            if out_len > 0 {
                reporter.report(
                    0.92 + 0.07 * (copied as f32 / out_len as f32),
                    "Writing output...",
                );
            }
        }
        output_file.flush()?;
        let _ = output_file.0.sync_all();
        Ok(report)
    });

    // Durability contract matches encrypt/decrypt: full sync best-effort done
    // above; temps are always removed.
    drop(output_file);
    let _ = std::fs::remove_file(&staged_in);
    let _ = std::fs::remove_file(&staged_out);

    match final_result {
        Ok(report) => {
            let summary = if report.removed.is_empty() {
                format!("{}: no removable metadata", report.format.name())
            } else {
                format!(
                    "{}: removed {}",
                    report.format.name(),
                    report.removed.join("; ")
                )
            };
            reporter.report(1.00, &summary);
            report_to_java(env, report_listener, &report);
            0
        }
        Err(CryptoError::UnsupportedMediaFormat(reason)) => {
            let _ = env.throw_new(
                EXCEPTION_CLASS,
                format!("Unsupported format \u{2014} {reason}"),
            );
            2
        }
        // Scrub-specific failures, reported in terms the user can act on
        // instead of the generic "Storage I/O failed." / "Invalid input".
        Err(CryptoError::Io(ref io_err)) if io_err.kind() == io::ErrorKind::StorageFull => {
            let _ = env.throw_new(
                EXCEPTION_CLASS,
                "Not enough free storage to remove metadata \u{2014} scrubbing needs about twice \
                 the file size of free space in app storage. Encrypt or decrypt instead.",
            );
            2
        }
        Err(CryptoError::FileTooLarge { size_gb, max_gb }) => {
            let _ = env.throw_new(
                EXCEPTION_CLASS,
                format!(
                    "This file is too large to scrub on this device ({size_gb:.2} GB, limit \
                     {max_gb:.2} GB). Encryption and decryption still work for it."
                ),
            );
            2
        }
        Err(e) => map_error(env, e),
    }
}

/// Creates a scratch file with private permissions (best-effort on unix).
fn fs_create_private(path: &std::path::Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(Into::into)
    }
}

/// JNI entry point for `NeuronEncryptNative.nativeScrub`.
///
/// # Safety
///
/// Same fd contract as the encrypt/decrypt entry points: the Java side must
/// keep both original `ParcelFileDescriptor`s open until this returns. The
/// input is staged through the app-private cache directory (never fully held
/// in RAM); temporary files are deleted on every exit path.
///
/// `source_size` is the input fd's reported size, used for the free-space
/// pre-flight so an oversized file is rejected before anything is written.
/// `report_listener` must implement `ScrubReportListener.onScrubReport(
/// String, String, long, long)`; it is called once on success.
#[no_mangle]
pub unsafe extern "system" fn Java_com_neuronencrypt_app_NeuronEncryptNative_nativeScrub(
    mut env: JNIEnv,
    _class: JClass,
    input_fd: jint,
    output_fd: jint,
    cache_dir: jni::objects::JString,
    source_size: jlong,
    progress_listener: JObject,
    report_listener: JObject,
    cancel_flag: JObject,
) -> jint {
    let res = panic::catch_unwind(AssertUnwindSafe(|| {
        let dir = match env.get_string(&cache_dir) {
            Ok(s) => s.to_string_lossy().into_owned(),
            Err(_) => {
                let _ = env.throw_new(EXCEPTION_CLASS, "Invalid cache directory path.");
                return 2;
            }
        };
        let Ok(dir_cstr) = std::ffi::CString::new(dir) else {
            let _ = env.throw_new(EXCEPTION_CLASS, "Cache directory path contains a NUL byte.");
            return 2;
        };
        native_scrub_impl(
            &mut env,
            input_fd,
            output_fd,
            &dir_cstr,
            source_size,
            &progress_listener,
            &report_listener,
            &cancel_flag,
        )
    }));

    match res {
        Ok(code) => code,
        Err(_) => {
            let _ = env.throw_new(EXCEPTION_CLASS, "Unexpected native failure.");
            1
        }
    }
}

/// Pushes the structured scrub outcome to Kotlin so the UI can show what was
/// removed (and post a completion notification) instead of only knowing that
/// the operation returned successfully.
fn report_to_java(
    env: &mut JNIEnv,
    listener: &JObject,
    report: &neuron_encrypt_core::metadata::ScrubReport,
) {
    let Ok(format_name) = env.new_string(report.format.name()) else {
        return;
    };
    let Ok(removed) = env.new_string(report.removed.join(", ")) else {
        return;
    };
    let args = [
        jni::objects::JValue::from(&format_name),
        jni::objects::JValue::from(&removed),
        jni::objects::JValue::Long(report.bytes_before as jlong),
        jni::objects::JValue::Long(report.bytes_after as jlong),
    ];
    let _ = env.call_method(
        listener,
        "onScrubReport",
        "(Ljava/lang/String;Ljava/lang/String;JJ)V",
        &args,
    );
}

/// JNI entry point for `NeuronEncryptNative.nativeScrubFormatName`.
///
/// # Safety
///
/// `header` must be a valid Java byte array belonging to the current JNI frame.
/// Returns the detected format's display name, or `null` when the bytes carry
/// no format this build can scrub. The Android UI uses this as a cheap
/// pre-flight check so an unsupported pick is rejected before an output
/// document is created (and deleted again).
#[no_mangle]
pub unsafe extern "system" fn Java_com_neuronencrypt_app_NeuronEncryptNative_nativeScrubFormatName(
    env: JNIEnv,
    _class: JClass,
    header: JByteArray,
) -> jstring {
    let unsupported: jstring = std::ptr::null_mut();
    let res = panic::catch_unwind(AssertUnwindSafe(|| {
        let Ok(len) = env.get_array_length(&header) else {
            return unsupported;
        };
        if len <= 0 {
            return unsupported;
        }
        let mut raw = vec![0i8; len as usize];
        if env.get_byte_array_region(&header, 0, &mut raw).is_err() {
            return unsupported;
        }
        let bytes: Vec<u8> = raw.iter().map(|&b| b as u8).collect();
        match neuron_encrypt_core::metadata::detect_media_format(&bytes) {
            // HEIC/HEIF is detected but has no structural scrubber yet, so it
            // must read as "unsupported" here exactly as `scrub_file` treats it.
            Some(neuron_encrypt_core::metadata::MediaFormat::Heif) | None => unsupported,
            Some(format) => match env.new_string(format.name()) {
                Ok(name) => name.into_raw(),
                Err(_) => unsupported,
            },
        }
    }));

    res.unwrap_or(unsupported)
}
