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
        return -1
    }
    val sourceSize = inputFd.statSize
    // detachFd() transfers ownership of the raw fds to the native side, which
    // wraps them in File::from_raw_fd and closes them itself. Closing the same
    // fd numbers again here double-closes them; on Android 13+ the numbers get
    // recycled and the second close can crash the process mid-batch, which is
    // why only the first file appeared to be encrypted.
    val inputRawFd = inputFd.detachFd()
    val outputRawFd = outputFd.detachFd()
    return NeuronEncryptNative.nativeEncrypt(
        inputRawFd,
        outputRawFd,
        password,
        sourceSize,
        listener,
        cancelFlag
    )
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
        return -1
    }
    val sourceSize = inputFd.statSize
    // detachFd() transfers ownership of the raw fds to the native side, which
    // wraps them in File::from_raw_fd and closes them itself. Closing the same
    // fd numbers again here double-closes them; on Android 13+ the numbers get
    // recycled and the second close can crash the process mid-batch, which is
    // why only the first file appeared to be encrypted.
    val inputRawFd = inputFd.detachFd()
    val outputRawFd = outputFd.detachFd()
    return NeuronEncryptNative.nativeDecrypt(
        inputRawFd,
        outputRawFd,
        password,
        sourceSize,
        listener,
        cancelFlag
    )
}
