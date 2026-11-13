package com.neuronencrypt.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts

/**
 * ACTION_OPEN_DOCUMENT that requests read *and* write access.
 *
 * The stock OpenDocument contract only requests read access, so providers hand
 * back a read-only grant and DocumentsContract.deleteDocument() later fails.
 * Requesting write here lets the user opt into the "wipe source" action;
 * providers that do not support write simply return a read-only grant and
 * persistUriPermission falls back to read.
 */
class OpenDocumentWithWrite :
    ActivityResultContracts.ActivityResultContract<Array<String>, Uri?>() {
    override fun createIntent(context: Context, input: Array<String>): Intent =
        Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("*/*")
            .putExtra(Intent.EXTRA_MIME_TYPES, input)
            .addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )

    override fun parseResult(resultCode: Int, intent: Intent?): Uri? =
        if (resultCode == Activity.RESULT_OK) intent?.data else null
}

/** Multiple-document variant of [OpenDocumentWithWrite]. */
class OpenMultipleDocumentsWithWrite :
    ActivityResultContracts.ActivityResultContract<Array<String>, List<Uri>>() {
    override fun createIntent(context: Context, input: Array<String>): Intent =
        Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("*/*")
            .putExtra(Intent.EXTRA_MIME_TYPES, input)
            .putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
            .addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )

    override fun parseResult(resultCode: Int, intent: Intent?): List<Uri> {
        if (resultCode != Activity.RESULT_OK || intent == null) return emptyList()
        val clip = intent.clipData
        if (clip != null) {
            return (0 until clip.itemCount).map { clip.getItemAt(it).uri }
        }
        val data = intent.data
        return if (data != null) listOf(data) else emptyList()
    }
}
