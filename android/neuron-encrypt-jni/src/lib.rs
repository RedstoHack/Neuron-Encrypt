use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::{FromRawFd, RawFd};

use libc::dup;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

use jni::objects::{GlobalRef, JByteArray, JClass, JObject};
use jni::sys::{jint, jlong};
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
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                CANCELLED_IO_MESSAGE,
            ));
        }
        self.inner.read(buf)
    }
}

impl Seek for CancelableReader {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        if self.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                CANCELLED_IO_MESSAGE,
            ));
        }
        self.inner.seek(pos)
    }
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
        CryptoError::Io(ref io_err) if io_err.kind() == io::ErrorKind::Interrupted => {
            (1, "Cancelled".to_owned())
        }
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
        None => return fail_with_exception(env, password, 1, "Failed to duplicate input file descriptor."),
    };
    let output_dup = match duplicate_fd(output_fd) {
        Some(fd) => fd,
        None => {
            unsafe { libc::close(input_dup) };
            return fail_with_exception(env, password, 1, "Failed to duplicate output file descriptor.");
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
        None => return fail_with_exception(env, password, 1, "Failed to duplicate input file descriptor."),
    };
    let output_dup = match duplicate_fd(output_fd) {
        Some(fd) => fd,
        None => {
            unsafe { libc::close(input_dup) };
            return fail_with_exception(env, password, 1, "Failed to duplicate output file descriptor.");
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
