package com.neuronencrypt.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.neuronencrypt.app.ui.theme.*

/**
 * Static description of what the scrubber can and cannot do.
 *
 * Kept as a literal (rather than queried from the native layer) so it stays
 * readable on the one screen a user reaches *before* picking a file, which is
 * exactly when they want to know whether their format is supported. The lists
 * mirror `metadata::detect_media_format` in the core crate; the two must be
 * updated together.
 */
data class FormatGroup(
    val title: String,
    val extensions: String,
    val removes: String
)

private val SUPPORTED = listOf(
    FormatGroup(
        "Photos &amp; images",
        "JPEG, PNG, WebP, GIF, BMP, TIFF",
        "EXIF (incl. GPS), XMP, IPTC, comments, thumbnails, timestamps"
    ),
    FormatGroup(
        "Documents",
        "PDF, Word, Excel, PowerPoint (.docx/.xlsx/.pptx)",
        "Author, company, creator, last-modified, revision history, embedded XMP"
    ),
    FormatGroup(
        "Audio",
        "MP3, AAC, M4A, FLAC, OGG, Opus, WAV, AIFF",
        "Title, artist, album, year, comments, embedded cover art, encoder tags"
    ),
    FormatGroup(
        "Video",
        "MP4, MOV, 3GP, 3G2",
        "Title, artist, creation &amp; recording time, GPS, device and encoder tags"
    )
)

private val NOT_SUPPORTED = listOf(
    FormatGroup(
        "HEIC / HEIF",
        "iPhone photos",
        "Not yet supported. Rejected rather than partially cleaned, so your photo is never damaged."
    ),
    FormatGroup(
        "Camera RAW",
        "CR2, CR3, NEF, ARW, DNG, ORF",
        "Not supported — these embed GPS and serial numbers in a structure that cannot be safely rewritten."
    ),
    FormatGroup(
        "Archive &amp; disk images",
        "ZIP, RAR, 7z, SQLite",
        "Not supported. Scrubbing a container means rewriting every entry, which risks corrupting the archive."
    )
)

@Composable
fun FormatsScreen(onBack: () -> Unit) {
    Scaffold(
        containerColor = Background,
        topBar = {
            TopAppBar(
                title = { Text("Supported formats", color = TextHi) },
                navigationIcon = {
                    TextButton(onClick = onBack) {
                        Text("BACK", color = Accent, fontFamily = JetBrainsMonoFamily)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Background)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp)
        ) {
            Text(
                "Metadata scrubbing rewrites the file, so it is only offered for formats that can be " +
                    "rebuilt without losing the actual content. Everything listed below is processed " +
                    "entirely on this device.",
                color = TextMed,
                style = MaterialTheme.typography.bodyMedium
            )

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                "CAN BE SCRUBBED",
                style = MaterialTheme.typography.labelMedium,
                color = AccentHover,
                fontFamily = JetBrainsMonoFamily
            )
            Spacer(modifier = Modifier.height(10.dp))

            SUPPORTED.forEach { group ->
                FormatCard(group)
                Spacer(modifier = Modifier.height(10.dp))
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                "NOT SUPPORTED (YET)",
                style = MaterialTheme.typography.labelMedium,
                color = TextLo,
                fontFamily = JetBrainsMonoFamily
            )
            Spacer(modifier = Modifier.height(10.dp))

            NOT_SUPPORTED.forEach { group ->
                FormatCard(group, unsupported = true)
                Spacer(modifier = Modifier.height(10.dp))
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                "A file we do not recognise is always rejected with an explanation and left untouched — " +
                    "it is never partially rewritten. Large images and PDFs (over 64 MiB) are refused on " +
                    "Android to avoid the system killing the app mid-write.",
                color = TextLo,
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun FormatCard(group: FormatGroup, unsupported: Boolean = false) {
    Surface(
        color = SurfaceHi,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(
                1.dp,
                if (unsupported) Border else Border.copy(alpha = 0.7f),
                RoundedCornerShape(12.dp)
            )
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                group.title,
                color = if (unsupported) TextMed else TextHi,
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                group.extensions,
                color = AccentHover,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = JetBrainsMonoFamily
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                group.removes,
                color = TextLo,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
