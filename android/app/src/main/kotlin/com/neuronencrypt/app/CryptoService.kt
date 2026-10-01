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
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground service that keeps encryption/decryption/scrubbing alive when the
 * user backgrounds the app. Without it Android may kill the process and the
 * native worker mid-operation, leaving a `.tmp` file or a half-written output.
 *
 * Platform contract this class has to respect (Android FGS docs):
 * - Any start request delivered through `startForegroundService()` **must** be
 *   answered with `startForeground()` promptly, otherwise the system raises
 *   `ForegroundServiceDidNotStartInTimeException` and kills the app. Every
 *   branch of [onStartCommand] therefore enters the foreground state.
 * - Progress updates do **not** need a service start per tick: [updateProgress]
 *   posts through `NotificationManagerCompat` in-process, which is what the
 *   screens use.
 * - `stopService()` does not deliver an intent, so [ACTION_STOP] exists only for
 *   completeness; [stop] plus [onDestroy] do the real teardown.
 *
 * Usage from a screen:
 *   CryptoService.start(context, "Encrypting", "secret.pdf")
 *   CryptoService.setOperationInFlight(true)
 *   CryptoService.updateProgress(context, "Encrypting", "secret.pdf", 42)
 *   CryptoService.setOperationInFlight(false)
 *   CryptoService.stop(context)
 */
class CryptoService : Service() {

    companion object {
        const val CHANNEL_ID = "neuron_encrypt_crypto"
        const val NOTIFICATION_ID = 1
        const val NOTIFICATION_ID_COMPLETED = 2
        const val EXTRA_FILENAME = "filename"
        const val EXTRA_ACTION = "action"
        const val EXTRA_PROGRESS = "progress"

        const val ACTION_START = "com.neuronencrypt.app.START"
        const val ACTION_UPDATE = "com.neuronencrypt.app.UPDATE"
        const val ACTION_STOP = "com.neuronencrypt.app.STOP"

        /**
         * True while a native operation is running. [onTaskRemoved] uses this so
         * swiping the app out of Recents cannot tear down a running operation
         * (which would drop the foreground protection it depends on) while still
         * clearing the notification of an idle service.
         *
         * It also gates [updateProgress]. Progress ticks are posted through
         * [NotificationManagerCompat] rather than via the service, so a tick
         * delivered after the operation ended would otherwise re-create an
         * ongoing notification that no service owns and nothing can dismiss.
         */
        private val operationInFlight = AtomicBoolean(false)

        fun setOperationInFlight(inFlight: Boolean) {
            operationInFlight.set(inFlight)
        }

        /**
         * Starts the foreground service for a new operation.
         *
         * Cancels any leftover notification first. A previous run that was
         * killed (process death, task swiped away, `stopService` racing a final
         * progress tick) can leave an ongoing entry behind that would otherwise
         * still be showing when the next operation begins.
         */
        fun start(context: Context, action: String, filename: String) {
            NotificationManagerCompat.from(context).apply {
                if (areNotificationsEnabled()) cancel(NOTIFICATION_ID)
            }
            val intent = Intent(context, CryptoService::class.java).apply {
                setAction(ACTION_START)
                putExtra(EXTRA_ACTION, action)
                putExtra(EXTRA_FILENAME, filename)
            }
            ContextCompat.startForegroundService(context, intent)
        }

        /**
         * Updates the ongoing notification without touching the service. Cheap
         * enough for throttled progress ticks, safe from any thread, and it can
         * never resurrect a stopped service (which is what made the previous
         * `startForegroundService()`-per-tick approach crash-prone).
         *
         * Dropped once the operation is no longer in flight: the native call
         * keeps reporting while it unwinds, and a late `notify()` would put an
         * ongoing notification back into the shade *after* teardown, which the
         * user cannot swipe away — it survives until the app is force-stopped.
         */
        fun updateProgress(context: Context, action: String, filename: String, progress: Int) {
            if (!operationInFlight.get()) return
            val manager = NotificationManagerCompat.from(context)
            if (!manager.areNotificationsEnabled()) return
            manager.notify(NOTIFICATION_ID, buildNotification(context, action, filename, progress))
        }

        /**
         * Removes the ongoing notification and stops the service.
         *
         * The notification is cancelled explicitly rather than relying on
         * `stopForeground()` in [onDestroy]. `stopForeground(REMOVE)` only
         * detaches the notification the *service* posted through
         * `startForeground()`; because progress updates are posted directly
         * through [NotificationManagerCompat] under the same id, that call is
         * not sufficient and the shade entry could survive. Cancelling by id
         * removes whichever posted it.
         *
         * The completion notice ([NOTIFICATION_ID_COMPLETED]) is deliberately
         * left alone: callers post it before reaching this method, and it is
         * dismissible, which is the whole point of telling a backgrounded user
         * the operation finished.
         */
        fun stop(context: Context) {
            NotificationManagerCompat.from(context).apply {
                if (areNotificationsEnabled()) cancel(NOTIFICATION_ID)
            }
            context.stopService(Intent(context, CryptoService::class.java))
        }

        /**
         * Posts a dismissible completion notice so a backgrounded user learns
         * the operation finished. The ongoing progress notification is removed
         * first, so no stale "Removing metadata..." entry is left behind.
         */
        fun notifyCompleted(context: Context, title: String, text: String) {
            val manager = NotificationManagerCompat.from(context)
            if (!manager.areNotificationsEnabled()) return
            manager.cancel(NOTIFICATION_ID)
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setAutoCancel(true)
                .setOngoing(false)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .build()
            manager.notify(NOTIFICATION_ID_COMPLETED, notification)
        }

        private fun buildNotification(
            context: Context,
            action: String,
            filename: String,
            progress: Int
        ): Notification {
            val title = if (progress > 0) "$action $filename" else "$action $filename..."
            val text = if (progress > 0) "$progress%" else "Starting..."

            return NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setOngoing(true)
                .setProgress(100, progress, progress == 0)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setCategory(NotificationCompat.CATEGORY_PROGRESS)
                .build()
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_UPDATE -> {
                val filename = intent.getStringExtra(EXTRA_FILENAME) ?: "file"
                val action = intent.getStringExtra(EXTRA_ACTION) ?: "Processing"
                val progress = intent.getIntExtra(EXTRA_PROGRESS, 0)
                // startForeground (not just notify): this branch is only ever
                // reached through a startForegroundService() request, which the
                // platform requires us to answer with startForeground().
                startForeground(
                    NOTIFICATION_ID,
                    buildNotification(this, action, filename, progress)
                )
            }
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> {
                // ACTION_START and any unexpected start request: always enter the
                // foreground state so the platform contract above holds.
                val filename = intent?.getStringExtra(EXTRA_FILENAME) ?: "file"
                val action = intent?.getStringExtra(EXTRA_ACTION) ?: "Processing"
                startForeground(NOTIFICATION_ID, buildNotification(this, action, filename, 0))
            }
        }
        return START_NOT_STICKY
    }

    /**
     * Swiping the app out of Recents does not stop a foreground service, which
     * left an ongoing notification stuck in the shade. Stop ourselves only when
     * no operation is running.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        if (!operationInFlight.get()) {
            dismissNotification()
            stopSelf()
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        // Covers the stopService() path: ACTION_STOP is never delivered because
        // stopService() does not deliver intents.
        //
        // Cancel by id as well as via stopForeground(): the ongoing notification
        // is also posted directly by updateProgress(), and stopForeground()
        // alone does not remove an entry that was never attached to this
        // service — which is what left an undismissable notification behind
        // until the user force-stopped the app.
        dismissNotification()
        super.onDestroy()
    }

    /**
     * Removes the ongoing progress notification. The dismissible completion
     * notice is intentionally kept so a backgrounded user still learns the
     * operation finished.
     */
    private fun dismissNotification() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        NotificationManagerCompat.from(this).apply {
            if (areNotificationsEnabled()) cancel(NOTIFICATION_ID)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Encryption Operations",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Progress of file encryption, decryption and metadata scrubbing"
                setShowBadge(false)
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
