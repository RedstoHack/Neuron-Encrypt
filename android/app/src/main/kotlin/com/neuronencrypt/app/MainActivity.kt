package com.neuronencrypt.app

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.*
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.neuronencrypt.app.ui.BatchScreen
import com.neuronencrypt.app.ui.FormatsScreen
import com.neuronencrypt.app.ui.HomeScreen
import com.neuronencrypt.app.ui.SingleFileScreen
import com.neuronencrypt.app.ui.theme.NeuronEncryptTheme

class MainActivity : ComponentActivity() {

    private var sharedUriState = mutableStateOf<Uri?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Prune stale persisted URI permissions (Android caps at ~128).
        pruneOldUriPermissions()

        // Parse intent on cold start
        sharedUriState.value = handleIntent(intent)

        setContent {
            NeuronEncryptTheme {
                val navController = rememberNavController()

                // Route automatically if we have a shared Uri
                LaunchedEffect(sharedUriState.value) {
                    val uri = sharedUriState.value
                    if (uri != null) {
                        // Encode URI to pass safely as navigation argument
                        val encodedUri = Uri.encode(uri.toString())
                        navController.navigate("single?uri=$encodedUri") {
                            popUpTo("home") { saveState = true }
                            launchSingleTop = true
                        }
                        // Reset intent uri state after routing
                        sharedUriState.value = null
                    }
                }

                NavHost(navController = navController, startDestination = "home") {
                    composable("home") {
                        HomeScreen(
                            onEncryptDecrypt = { navController.navigate("single") },
                            onBatch = { navController.navigate("batch") },
                            onFormats = { navController.navigate("formats") },
                            onAbout = {}
                        )
                    }

                    composable("formats") {
                        FormatsScreen(onBack = { navController.popBackStack() })
                    }

                    composable(
                        route = "single?uri={uri}",
                        arguments = listOf(
                            navArgument("uri") {
                                type = NavType.StringType
                                nullable = true
                                defaultValue = null
                            }
                        )
                    ) { backStackEntry ->
                        val uriStr = backStackEntry.arguments?.getString("uri")
                        val uri = uriStr?.let { Uri.parse(Uri.decode(it)) }
                        SingleFileScreen(
                            onBack = { navController.popBackStack() },
                            sharedUri = uri
                        )
                    }

                    composable("batch") {
                        BatchScreen(
                            onBack = { navController.popBackStack() }
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        sharedUriState.value = handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?): Uri? {
        if (intent == null) return null
        return when (intent.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> {
                // Type-safe overload on API 33+; deprecated form on older APIs
                // with try-catch for ClassCastException (attacker may send non-Uri Parcelable).
                val streamUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    try {
                        intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
                    } catch (e: ClassCastException) {
                        null
                    }
                }
                streamUri ?: intent.data
            }
            else -> null
        }
    }

    /// Release persisted URI permissions beyond a sane cap so we don't hit
    /// Android's ~128-permission limit after many file selections.
    private fun pruneOldUriPermissions(keepCount: Int = 16) {
        try {
            val perms = contentResolver.persistedUriPermissions
            if (perms.size > keepCount) {
                perms.drop(keepCount).forEach { p ->
                    try {
                        // Compute flags from read/write permission booleans
                        // (the public 'flags' field is not accessible via Kotlin)
                        var flags = 0
                        if (p.isReadPermission) flags = flags or Intent.FLAG_GRANT_READ_URI_PERMISSION
                        if (p.isWritePermission) flags = flags or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        if (flags != 0) {
                            contentResolver.releasePersistableUriPermission(p.uri, flags)
                        }
                    } catch (_: SecurityException) {
                        // Permission may already be released
                    }
                }
            }
        } catch (_: Exception) {
            // Best-effort cleanup
        }
    }
}
