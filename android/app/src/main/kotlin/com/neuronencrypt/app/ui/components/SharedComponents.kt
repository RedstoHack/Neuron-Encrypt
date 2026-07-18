package com.neuronencrypt.app.ui.components

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.neuronencrypt.app.ui.theme.*
import com.neuronencrypt.app.StrengthResult
import com.neuronencrypt.app.evalStrength

/**
 * Reusable password input field with show/hide toggle and strength meter.
 *
 * Used by both SingleFileScreen and BatchScreen to avoid duplication.
 */
@Composable
fun PasswordField(
    label: String,
    password: String,
    onPasswordChange: (String) -> Unit,
    showPassword: Boolean,
    onToggleShow: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier) {
        OutlinedTextField(
            value = password,
            onValueChange = onPasswordChange,
            modifier = Modifier.fillMaxWidth(),
            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                IconButton(onClick = onToggleShow) {
                    Icon(
                        imageVector = if (showPassword) androidx.compose.material.icons.Icons.Default.VisibilityOff else androidx.compose.material.icons.Icons.Default.Visibility,
                        contentDescription = if (showPassword) "Hide password" else "Show password",
                        tint = TextMed
                    )
                }
            },
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = Surface,
                unfocusedContainerColor = Surface,
                focusedBorderColor = Accent,
                unfocusedBorderColor = Border
            ),
            singleLine = true
        )
    }
}

/**
 * Reusable strength meter — single bar + one word.
 * Uses the entropy-based evalStrength() from Strength.kt.
 */
@Composable
fun StrengthMeter(
    password: String,
    modifier: Modifier = Modifier
) {
    if (password.isEmpty()) return

    val result = evalStrength(password)
    val color = when (result.strength) {
        com.neuronencrypt.app.Strength.None -> TextLo
        com.neuronencrypt.app.Strength.Weak -> Error
        com.neuronencrypt.app.Strength.Fair -> Warning
        com.neuronencrypt.app.Strength.Strong -> Accent
        com.neuronencrypt.app.Strength.Elite -> Success
    }

    Column(modifier = modifier) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = "Strength",
                style = MaterialTheme.typography.labelSmall,
                color = TextLo
            )
            Spacer(modifier = Modifier.weight(1f))
            Text(
                text = result.label,
                style = MaterialTheme.typography.labelSmall,
                color = color,
                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { result.fraction },
            color = color,
            trackColor = Border,
            modifier = Modifier
                .fillMaxWidth()
                .height(3.dp)
        )
    }
}

/**
 * Reusable error banner for inline error display.
 */
@Composable
fun ErrorBanner(
    title: String,
    message: String,
    modifier: Modifier = Modifier
) {
    Surface(
        color = Error.copy(alpha = 0.08f),
        shape = RoundedCornerShape(8.dp),
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, Error, RoundedCornerShape(8.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = androidx.compose.material.icons.Icons.Default.Error,
                    contentDescription = "Error",
                    tint = Error
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(title, color = Error, style = MaterialTheme.typography.titleMedium)
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(message, color = TextHi, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/**
 * Reusable success card for post-operation display.
 */
@Composable
fun SuccessCard(
    inputName: String,
    outputName: String,
    sizeBytes: Long,
    durationMs: Long,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, Border, RoundedCornerShape(8.dp)),
        colors = CardDefaults.cardColors(containerColor = Surface),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            DetailRow("Source", inputName)
            DetailRow("Output", outputName)
            DetailRow("Size", formatSize(sizeBytes))
            val seconds = durationMs / 1000f
            val speed = if (seconds > 0) formatSize((sizeBytes / seconds).toLong()) + "/s" else "N/A"
            DetailRow("Time elapsed", String.format("%.2fs", seconds))
            DetailRow("Average speed", speed)
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = TextLo)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = TextHi,
            maxLines = 1,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            modifier = Modifier.padding(start = 16.dp)
        )
    }
}

private fun formatSize(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
    val pre = "KMGTPE"[exp - 1].toString()
    return String.format("%.2f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
}
