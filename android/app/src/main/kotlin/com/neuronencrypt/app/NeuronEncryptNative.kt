package com.neuronencrypt.app

class NeuronEncryptException(message: String) : Exception(message)

object NeuronEncryptNative {
    init {
        System.loadLibrary("neuron_encrypt_jni")
    }

    external fun nativeEncrypt(
        inputFd: Int,
        outputFd: Int,
        password: ByteArray,
        sourceSize: Long,
        progressListener: ProgressListener,
        cancelFlag: java.util.concurrent.atomic.AtomicBoolean
    ): Int

    external fun nativeDecrypt(
        inputFd: Int,
        outputFd: Int,
        password: ByteArray,
        totalSize: Long,
        progressListener: ProgressListener,
        cancelFlag: java.util.concurrent.atomic.AtomicBoolean
    ): Int

    external fun nativeScrub(
        inputFd: Int,
        outputFd: Int,
        cacheDir: String,
        sourceSize: Long,
        progressListener: ProgressListener,
        reportListener: ScrubReportListener,
        cancelFlag: java.util.concurrent.atomic.AtomicBoolean
    ): Int

    /**
     * Pre-flight format check backed by the core's magic-byte sniffer. Returns
     * the detected format's display name (e.g. `"JPEG"`) when this build has a
     * scrubber for it, or `null` when it does not (unknown format, plain zip,
     * VAULTX container, BigTIFF, HEIC/HEIF).
     */
    external fun nativeScrubFormatName(header: ByteArray): String?
}
