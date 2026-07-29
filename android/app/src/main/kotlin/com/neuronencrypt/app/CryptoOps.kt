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
    return try {
        NeuronEncryptNative.nativeEncrypt(
            inputFd.fd,
            outputFd.fd,
            password,
            inputFd.statSize,
            listener,
            cancelFlag
        )
    } finally {
        inputFd.close()
        outputFd.close()
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
        return -1
    }
    return try {
        NeuronEncryptNative.nativeDecrypt(
            inputFd.fd,
            outputFd.fd,
            password,
            inputFd.statSize,
            listener,
            cancelFlag
        )
    } finally {
        inputFd.close()
        outputFd.close()
    }
}
