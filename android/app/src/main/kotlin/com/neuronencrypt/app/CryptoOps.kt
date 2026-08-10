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
    val inputFd = contentResolver.openFileDescriptor(inputUri, "r")
    val outputFd = contentResolver.openFileDescriptor(outputUri, "w")
    if (inputFd == null || outputFd == null) {
        inputFd?.close()
        outputFd?.close()
        zeroByteArray(password)
        return -1
    }
    val sourceSize = inputFd.statSize
    try {
        // Pass the raw fds WITHOUT detaching. detachFd() invalidates the Java
        // ParcelFileDescriptor immediately, so the content provider receives
        // its close signal before any bytes are written and finalizes the file
        // at 0 bytes (tauri #3356). The native side dup()s the fds and closes
        // its own copies; we keep the originals open and close them here only
        // after the whole write has completed.
        return NeuronEncryptNative.nativeEncrypt(
            inputFd.fd,
            outputFd.fd,
            password,
            sourceSize,
            listener,
            cancelFlag
        )
    } finally {
        inputFd.close()
        outputFd.close()
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
    val inputFd = contentResolver.openFileDescriptor(inputUri, "r")
    val outputFd = contentResolver.openFileDescriptor(outputUri, "w")
    if (inputFd == null || outputFd == null) {
        inputFd?.close()
        outputFd?.close()
        zeroByteArray(password)
        return -1
    }
    val sourceSize = inputFd.statSize
    try {
        // Pass the raw fds WITHOUT detaching — see encrypt() for the rationale.
        return NeuronEncryptNative.nativeDecrypt(
            inputFd.fd,
            outputFd.fd,
            password,
            sourceSize,
            listener,
            cancelFlag
        )
    } finally {
        inputFd.close()
        outputFd.close()
        zeroByteArray(password)
    }
}

private fun zeroByteArray(bytes: ByteArray) {
    java.util.Arrays.fill(bytes, 0)
}
