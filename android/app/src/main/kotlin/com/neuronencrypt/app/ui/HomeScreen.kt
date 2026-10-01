package com.neuronencrypt.app.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.neuronencrypt.app.BuildConfig
import com.neuronencrypt.app.ui.theme.*

@Composable
fun HomeScreen(
    onEncryptDecrypt: () -> Unit,
    onBatch: () -> Unit,
    onFormats: () -> Unit,
    onAbout: () -> Unit
) {
    val context = LocalContext.current
    var showAbout by remember { mutableStateOf(false) }

    // First-run onboarding: warn about passphrase irrecoverability.
    // Stored in SharedPreferences so it only shows once per install.
    val prefs = remember { context.getSharedPreferences("neuron_encrypt_prefs", android.content.Context.MODE_PRIVATE) }
    var showOnboarding by remember { mutableStateOf(!prefs.getBoolean("onboarding_seen", false)) }

    // ---- Android 13+ notification permission ----
    // Declaring POST_NOTIFICATIONS in the manifest is not enough: the runtime
    // permission is denied by default, and a denied notification hides the
    // foreground-service notice completely. A long scrub then runs invisibly in
    // the background (and is reaped more aggressively), which users experience
    // as "scrub hung" or "the notification never appeared".
    var notificationsAllowed by remember { mutableStateOf(notificationsEnabled(context)) }
    var notificationBannerDismissed by remember { mutableStateOf(false) }
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        prefs.edit().putBoolean("notif_prompt_done", true).apply()
        notificationsAllowed = granted && notificationsEnabled(context)
    }
    // Ask once, and only after onboarding, so the two dialogs never stack.
    LaunchedEffect(showOnboarding, notificationsAllowed) {
        if (!showOnboarding &&
            !notificationsAllowed &&
            !prefs.getBoolean("notif_prompt_done", false) &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        ) {
            prefs.edit().putBoolean("notif_prompt_done", true).apply()
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    if (showOnboarding) {
        AlertDialog(
            onDismissRequest = { },
            containerColor = Surface,
            title = {
                Text("Before you begin", color = TextHi, fontWeight = FontWeight.Bold)
            },
            text = {
                Column {
                    Text(
                        "Neuron Encrypt uses a passphrase to encrypt your files. " +
                        "There is no password recovery, no backdoor, and no way to " +
                        "reset a forgotten passphrase.",
                        color = TextMed,
                        fontSize = 13.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        "If you forget your passphrase, your encrypted files are " +
                        "permanently unrecoverable. This is a security feature — " +
                        "a backdoor that lets you in would also let an attacker in.",
                        color = TextMed,
                        fontSize = 13.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        "• Use a passphrase you can remember\n" +
                        "• Store it in a password manager\n" +
                        "• Write it down somewhere safe offline\n" +
                        "• Test with a non-critical file first",
                        color = TextHi,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        prefs.edit().putBoolean("onboarding_seen", true).apply()
                        showOnboarding = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Accent)
                ) {
                    Text("I understand", color = TextHi)
                }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Background)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        if (!notificationsAllowed && !notificationBannerDismissed) {
            NotificationPermissionBanner(
                onAllow = {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    } else {
                        openNotificationSettings(context)
                    }
                },
                onOpenSettings = { openNotificationSettings(context) },
                onDismiss = { notificationBannerDismissed = true }
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        // Badge
        Surface(
            color = Accent.copy(alpha = 0.12f),
            shape = RoundedCornerShape(11.dp),
            modifier = Modifier.border(1.dp, Border, RoundedCornerShape(11.dp))
        ) {
            Text(
                text = "LOCAL ONLY",
                style = MaterialTheme.typography.labelSmall,
                color = AccentHover,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "NEURON ENCRYPT",
            style = MaterialTheme.typography.headlineLarge,
            color = TextHi
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Local file encryption.\nNo accounts. No internet.",
            style = MaterialTheme.typography.bodyLarge,
            color = TextMed,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(48.dp))

        // Primary action button
        Button(
            onClick = onEncryptDecrypt,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = Accent
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = "Encrypt or Decrypt a file",
                style = MaterialTheme.typography.labelLarge,
                color = TextHi
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Batch button
        OutlinedButton(
            onClick = onBatch,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = TextHi
            ),
            border = ButtonDefaults.outlinedButtonBorder.copy(
                brush = androidx.compose.ui.graphics.SolidColor(Border)
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = "Batch upload",
                style = MaterialTheme.typography.labelLarge,
                color = TextMed
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Lets the user check whether their file type is scrubbable *before*
        // picking it, instead of discovering it only from an error.
        OutlinedButton(
            onClick = onFormats,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = TextHi
            ),
            border = ButtonDefaults.outlinedButtonBorder.copy(
                brush = androidx.compose.ui.graphics.SolidColor(Border)
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = "Supported formats",
                style = MaterialTheme.typography.labelLarge,
                color = TextMed
            )
        }

        Spacer(modifier = Modifier.height(32.dp))

        TextButton(onClick = {
            onAbout()
            showAbout = true
        }) {
            Text(
                text = "About",
                style = MaterialTheme.typography.bodySmall,
                color = TextLo
            )
        }
    }

    if (showAbout) {
        AlertDialog(
            onDismissRequest = { showAbout = false },
            containerColor = Surface,
            title = {
                Text("Neuron Encrypt", color = TextHi)
            },
            text = {
                Column {
                    Text("Version ${BuildConfig.VERSION_NAME}", color = TextMed, fontSize = 13.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "AES-256-GCM-SIV + Argon2id + HKDF-SHA512",
                        color = TextMed,
                        fontSize = 12.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "GPLv3 -- Copyright (c) 2024-2026 Ubaid ur Rehman",
                        color = TextLo,
                        fontSize = 11.sp
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showAbout = false }) {
                    Text("Close", color = Accent)
                }
            }
        )
    }
}

/** Whether the app is currently allowed to post notifications. */
private fun notificationsEnabled(context: Context): Boolean {
    val permissionGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
    } else {
        true
    }
    return permissionGranted && NotificationManagerCompat.from(context).areNotificationsEnabled()
}

/** Opens this app's notification settings screen (best effort). */
private fun openNotificationSettings(context: Context) {
    try {
        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
        } else {
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(android.net.Uri.fromParts("package", context.packageName, null))
        }
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (_: Exception) {
        // Some OEM builds ship no matching settings activity.
    }
}

/**
 * Explains why the notification permission matters: it is what keeps a long
 * scrub (the slowest operation, since it copies and rewrites the whole file)
 * alive and visible once the app goes to the background.
 */
@Composable
private fun NotificationPermissionBanner(
    onAllow: () -> Unit,
    onOpenSettings: () -> Unit,
    onDismiss: () -> Unit
) {
    Surface(
        color = Warning.copy(alpha = 0.10f),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Warning, RoundedCornerShape(8.dp))
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                "Notifications are off",
                color = Warning,
                style = MaterialTheme.typography.labelLarge
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Progress for long scrubs and encryptions is shown there. Without it, " +
                    "Android may kill a job that keeps running in the background.",
                color = TextMed,
                style = MaterialTheme.typography.bodySmall
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onAllow) {
                    Text("ALLOW", color = Accent, fontFamily = JetBrainsMonoFamily)
                }
                TextButton(onClick = onOpenSettings) {
                    Text("SETTINGS", color = TextMed, fontFamily = JetBrainsMonoFamily)
                }
                TextButton(onClick = onDismiss) {
                    Text("DISMISS", color = TextLo, fontFamily = JetBrainsMonoFamily)
                }
            }
        }
    }
}
