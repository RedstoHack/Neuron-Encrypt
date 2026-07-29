package com.neuronencrypt.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * Foreground service that keeps the encryption/decryption process alive when
 * the user backgrounds the app. Without this, Android may kill the process
 * and the JNI thread will be terminated mid-operation, leaving a .tmp file.
 *
 * The service shows a sticky notification with the current operation and
 * progress percentage. It runs for the duration of the crypto operation.
 *
 * Usage from Kotlin:
 *   val intent = Intent(context, CryptoService::class.java)
 *   intent.putExtra("filename", "secret.pdf")
 *   intent.putExtra("action", "Encrypting")
 *   ContextCompat.startForegroundService(context, intent)
 *   // ... do the crypto work ...
 *   context.stopService(intent)
 */
class CryptoService : Service() {

    companion object {
        const val CHANNEL_ID = "neuron_encrypt_crypto"
        const val NOTIFICATION_ID = 1
        const val EXTRA_FILENAME = "filename"
        const val EXTRA_ACTION = "action"
        const val EXTRA_PROGRESS = "progress"

        const val ACTION_START = "com.neuronencrypt.app.START"
        const val ACTION_UPDATE = "com.neuronencrypt.app.UPDATE"
        const val ACTION_STOP = "com.neuronencrypt.app.STOP"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val filename = intent.getStringExtra(EXTRA_FILENAME) ?: "file"
                val action = intent.getStringExtra(EXTRA_ACTION) ?: "Processing"
                val notification = buildNotification(action, filename, 0)
                startForeground(NOTIFICATION_ID, notification)
            }
            ACTION_UPDATE -> {
                val filename = intent.getStringExtra(EXTRA_FILENAME) ?: "file"
                val action = intent.getStringExtra(EXTRA_ACTION) ?: "Processing"
                val progress = intent.getIntExtra(EXTRA_PROGRESS, 0)
                val notification = buildNotification(action, filename, progress)
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.notify(NOTIFICATION_ID, notification)
            }
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Encryption Operations",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress of file encryption/decryption operations"
                setShowBadge(false)
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(action: String, filename: String, progress: Int): Notification {
        val title = if (progress > 0) "$action $filename" else "$action $filename..."
        val text = if (progress > 0) "$progress%" else "Starting..."

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setOngoing(true)
            .setProgress(100, progress, progress == 0)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
