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
    listener: ProgressListener,
    cancelFlag: AtomicBoolean
): Int {
    val inputFd = contentResolver.openFileDescriptor(inputUri, "r") ?: return -1
    try {
        val outputFd = contentResolver.openFileDescriptor(outputUri, "w") ?: return -1
        try {
            return NeuronEncryptNative.nativeScrub(
                inputFd.fd,
                outputFd.fd,
                cacheDir,
                listener,
                cancelFlag
            )
        } finally {
            outputFd.close()
        }
    } finally {
        inputFd.close()
    }
}

private fun zeroByteArray(bytes: ByteArray) {
    java.util.Arrays.fill(bytes, 0)
}
