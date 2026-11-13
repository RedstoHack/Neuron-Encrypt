package com.neuronencrypt.app

import android.content.ContentResolver
import android.net.Uri
import java.util.concurrent.atomic.AtomicBoolean

fun encrypt(
    contentResolver: ContentResolver,
    inputUri: Uri,
    outputUri: Uri,
    password: ByteArray,
    listener: ProgressListener,
    cancelFlag: AtomicBoolean
): Int {
    val inputFd = contentResolver.openFileDescriptor(inputUri, "r") ?: return -1
    try {
        val outputFd = contentResolver.openFileDescriptor(outputUri, "w") ?: return -1
        try {
            val sourceSize = inputFd.statSize
            // Pass the raw fds WITHOUT detaching (see rationale in git history /
            // v2.1.2 notes): detach invalidates the Java descriptor early and
            // providers finalize the file at 0 bytes.
            return NeuronEncryptNative.nativeEncrypt(
                inputFd.fd,
                outputFd.fd,
                password,
                sourceSize,
                listener,
                cancelFlag
            )
        } finally {
            outputFd.close()
        }
    } finally {
        inputFd.close()
        zeroByteArray(password)
    }
}

fun decrypt(
    contentResolver: ContentResolver,
    inputUri: Uri,
    outputUri: Uri,
    password: ByteArray,
    listener: ProgressListener,
    cancelFlag: AtomicBoolean
): Int {
    val inputFd = contentResolver.openFileDescriptor(inputUri, "r") ?: return -1
    try {
        val outputFd = contentResolver.openFileDescriptor(outputUri, "w") ?: return -1
        try {
            val sourceSize = inputFd.statSize
            return NeuronEncryptNative.nativeDecrypt(
                inputFd.fd,
                outputFd.fd,
                password,
                sourceSize,
                listener,
                cancelFlag
            )
        } finally {
            outputFd.close()
        }
    } finally {
        inputFd.close()
        zeroByteArray(password)
    }
}

fun scrub(
    contentResolver: ContentResolver,
    inputUri: Uri,
    outputUri: Uri,
    cacheDir: String,
    reportListener: ScrubReportListener,
    listener: ProgressListener,
    cancelFlag: AtomicBoolean
): Int {
    val inputFd = contentResolver.openFileDescriptor(inputUri, "r") ?: return -1
    try {
        val outputFd = contentResolver.openFileDescriptor(outputUri, "w") ?: return -1
        try {
            // Handed to the native side so it can refuse to start when the app
            // cache could not hold the ~2x scratch copies scrubbing needs,
            // instead of failing halfway through with a generic I/O error.
            val sourceSize = inputFd.statSize
            return NeuronEncryptNative.nativeScrub(
                inputFd.fd,
                outputFd.fd,
                cacheDir,
                sourceSize,
                listener,
                reportListener,
                cancelFlag
            )
        } finally {
            outputFd.close()
        }
    } finally {
        inputFd.close()
    }
}

/// Bytes sniffed for a scrub pre-flight; the core reads the same 4 KiB header.
///
/// The window has to be this wide because the OOXML detector looks for the
/// `[Content_Types].xml` entry name inside the zip local-header region. With
/// a 64-byte window a legal `.docx` whose first entry carries an extra field
/// was reported as "unsupported format" and could not be scrubbed at all.
private const val SCRUB_SNIFF_BYTES = 4096

/**
 * Pre-flight format check for metadata scrubbing.
 *
 * Reads the leading bytes from the provider and asks the native scrubber what
 * the file is. Returns the detected format's display name (e.g. "JPEG") when
 * the core has a scrubber for it, or `null` when it does not — the same
 * fail-closed rule `scrub_file` applies (unknown formats, plain zips, BigTIFF
 * and HEIC/HEIF all report `null`).
 *
 * Screens use this to explain *why* a file cannot be scrubbed and to avoid
 * creating (and then deleting) an output document for a file the core will
 * reject anyway.
 */
fun scrubFormatName(contentResolver: ContentResolver, uri: Uri): String? {
    return try {
        contentResolver.openInputStream(uri)?.use { stream ->
            val header = ByteArray(SCRUB_SNIFF_BYTES)
            var filled = 0
            while (filled < header.size) {
                val read = stream.read(header, filled, header.size - filled)
                if (read <= 0) break
                filled += read
            }
            if (filled < 12) {
                null
            } else {
                NeuronEncryptNative.nativeScrubFormatName(header.copyOf(filled))
            }
        }
    } catch (_: Exception) {
        // Unreadable input: report "unknown" rather than blocking the whole
        // screen; the operation itself will surface the real error.
        null
    }
}

/**
 * Best-effort MIME type for a destination file name.
 *
 * Outputs used to be created with a wildcard MIME type, which storage providers
 * record as `application/octet-stream`; cleaned photos then stay invisible to
 * gallery and media apps. Deriving the type from the (preserved) extension
 * fixes that.
 */
fun mimeTypeForOutputName(name: String): String {
    return when (name.substringAfterLast('.', "").lowercase()) {
        "jpg", "jpeg" -> "image/jpeg"
        "png" -> "image/png"
        "webp" -> "image/webp"
        "gif" -> "image/gif"
        "bmp" -> "image/bmp"
        "tif", "tiff" -> "image/tiff"
        "heic", "heif" -> "image/heic"
        "pdf" -> "application/pdf"
        "docx" -> "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        "xlsx" -> "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        "pptx" -> "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        "mp3" -> "audio/mpeg"
        "flac" -> "audio/flac"
        "ogg", "oga", "opus" -> "audio/ogg"
        "wav" -> "audio/wav"
        "aif", "aiff" -> "audio/aiff"
        "aac" -> "audio/aac"
        "m4a" -> "audio/mp4"
        "mp4", "m4v" -> "video/mp4"
        "3gp" -> "video/3gpp"
        "3g2" -> "video/3gpp2"
        "mov" -> "video/quicktime"
        "vx2" -> "application/octet-stream"
        else -> "*/*"
    }
}

private fun zeroByteArray(bytes: ByteArray) {
    java.util.Arrays.fill(bytes, 0)
}

/**
 * Remove scratch copies left behind if the process was killed mid-scrub.
 * The JNI names them `neuron-scrub-<token>.in` / `.out` in cacheDir.
 */
fun sweepStaleScrubFiles(context: Context) {
    try {
        // Only remove files older than an hour: a rotation can recreate the
        // activity while a scrub is still staging, and those files are live.
        val cutoff = System.currentTimeMillis() - 60L * 60L * 1000L
        context.cacheDir.listFiles()?.forEach { file ->
            if (file.name.startsWith("neuron-scrub-") && file.lastModified() < cutoff) {
                try {
                    file.delete()
                } catch (_: Exception) {
                    // Best effort only.
                }
            }
        }
    } catch (_: Exception) {
        // Cache directory unavailable; nothing to clean.
    }
}
