# Neuron Encrypt for Android

Neuron Encrypt is a native Android application that integrates the core Rust cryptographic engine via Java Native Interface (JNI). It provides a secure, local-only interface for file encryption and decryption without requiring intrusive storage permissions.

---

## Architecture & Data Flow

```
┌────────────────────────────────────────────────────────┐
│               Jetpack Compose Mobile UI                │
└───────────────────────────┬────────────────────────────┘
                            │ (Passphrase & URIs)
                            ▼
┌────────────────────────────────────────────────────────┐
│                   Kotlin Coroutines                    │
│   · Resolves SAF Document URIs                         │
│   · Passes raw fds (kept open, NOT detached)           │
└───────────────────────────┬────────────────────────────┘
                            │ (FD ints, GlobalRefs)
                            ▼
┌────────────────────────────────────────────────────────┐
│                   Rust JNI wrapper                     │
│  · Wraps raw FDs into std::fs::File                    │
│  · Cancels I/O via AtomicBoolean GlobalRef             │
│  · Invokes neuron_encrypt_core stream engine           │
└────────────────────────────────────────────────────────┘
```

### JNI Interoperability
- **File Descriptor Sharing**: Android uses the Storage Access Framework (SAF) to restrict file system access. The Kotlin app requests document access from the OS, obtains `ParcelFileDescriptor`, and passes the raw fd ints to the Rust JNI layer **without detaching them**. The JNI layer `dup()`s each fd and reconstructs standard `std::fs::File` objects from the duplicates. The Java-side `ParcelFileDescriptor`s stay open for the full operation and are closed only after the write completes, so the content provider receives its close signal once all bytes are actually on disk (calling `detachFd()` instead caused providers to finalize files at 0 bytes — see tauri #3356).
- **Cancellation Hook**: Because Rust's cryptographic engine runs in a continuous stream loop, cancellation is implemented at the I/O layer. The Rust reader (`CancelableReader`) wraps the input file and checks the state of the Kotlin `AtomicBoolean` on every single block read/write operation. If cancelled, it throws an `io::ErrorKind::Interrupted` error, halting the operation instantly.
- **Progress Updates**: The Rust streaming engine implements `ProgressReporter` through `JniReporter`, which makes reflective calls back to the Kotlin `ProgressListener.onProgress(fraction, stage)`. It is wrapped in a `ThrottledReporter` to avoid clogging the JVM JNI bridge with excessive UI refresh requests.

---

## Security Mitigations
- **Zero Internet Permissions**: The Android app does not request `android.permission.INTERNET`. No networking is compiled in, ensuring complete air-gapped isolation of your files.
- **No External Storage Permissions**: Operating exclusively through SAF ensures that Neuron Encrypt never accesses other private files or databases on your device.
- **Zeroized Memory**: Passphrase byte arrays converted from JNI are wrapped in Rust's `Zeroizing<T>` container. In addition, the JNI bridge explicitly zeros out the JVM's `ByteArray` memory region before returning, preventing secrets from remaining in Java's heap. The Kotlin screens also zero their passphrase byte arrays in a `finally` block and clear the Compose `String` state after each operation.

---

## Reliability

- **Crypto runs off the main thread** — encrypt/decrypt execute on `Dispatchers.IO`, and provider metadata queries (`getFileInfo`, `detectMagicBytes`, URI permission persistence) were moved off the UI thread too, preventing ANR on slow or remote storage providers.
- **Foreground service** — single-file **and** batch operations run under `CryptoService`, so the process survives being backgrounded mid-operation. Progress updates post in-process (`CryptoService.updateProgress`) rather than re-starting the service per tick, every start request enters the foreground state (the platform kills services that do not), and the notification is removed on every exit path — including swiping the app out of Recents. `POST_NOTIFICATIONS` is requested at runtime on Android 13+; without it the notification (and the protection it signals) is invisible.
- **Operations cannot be abandoned mid-write** — navigating away latches the cancel flag instead of stopping the service, the native dispatch runs under `NonCancellable`, and the service is stopped only after the JNI call has returned.
- **Scrub is bounded** — input/output is staged through the app-private cache dir, whose free space is checked against the file size *before* anything is written (scrubbing needs ~2x the file size in scratch space), and in-memory scrubbing is capped at 64 MiB on Android so oversized images/PDFs fail with a clear message instead of being killed by the OS.
- **"100%" means durable** — the JNI output is wrapped in a `DurableFile` whose `flush()` calls `sync_data()` before the stream layer reports 100%, plus a final best-effort `sync_all()`. The app never reports completion while data is still in the kernel page cache.
- **Cancellation is safe** — `CancellationException` is re-thrown (never swallowed) so navigating away mid-op can't delete a finished output file, and cancelling shows a neutral "Operation cancelled" state rather than an error.

---

## Build Instructions

### Prerequisites
1. **Java Development Kit (JDK)**: Version 17
2. **Android SDK & NDK**: NDK version `r26b` is recommended. Ensure `ANDROID_NDK_HOME` is set.
3. **Rust Toolchain**: Install target triples for Android architectures:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
   ```
4. **cargo-ndk**: CLI helper for cross-compiling Rust crates:
   ```bash
   cargo install cargo-ndk
   ```

### Step 1: Compile Rust Shared Libraries
From the root of the project, run the build script to compile the shared library binaries:
```bash
./android/build-rust.sh
```
This places the compiled `.so` files in `android/app/src/main/jniLibs/<abi>/`.

### Step 2: Build the Android Application
Navigate to the `android/` directory and use the Gradle Wrapper to assemble the application:
```bash
cd android
./gradlew assembleDebug
```
The output APK will be generated at `android/app/build/outputs/apk/debug/app-debug.apk`.
