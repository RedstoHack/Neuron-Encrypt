package com.neuronencrypt.app

interface ProgressListener {
    fun onProgress(fraction: Float, stage: String)
}

/**
 * Receives the structured outcome of a successful metadata scrub, so the UI can
 * show *what* was removed (and post a completion notification) instead of only
 * knowing that the native call returned.
 *
 * Called from the native worker thread exactly once per successful scrub, just
 * before the JNI call returns.
 */
interface ScrubReportListener {
    fun onScrubReport(format: String, removed: String, bytesBefore: Long, bytesAfter: Long)
}
