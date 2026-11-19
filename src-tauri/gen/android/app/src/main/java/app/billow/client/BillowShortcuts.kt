package app.billow.client

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper

/**
 * The ways the tile and the widget reach the connection and the app (R41).
 *
 * Rust owns the toggle, so a tap asks it first; only a tap it cannot serve
 * (no profile, no VPN permission, or a runtime that is not loaded yet) opens
 * Billow, which continues the same tap once the runtime is up.
 */
object BillowShortcuts {
    /** Marks an activity launch that should continue a tile or widget tap. */
    const val EXTRA_TAP = "app.billow.client.extra.TAP"

    /** Rust answers a tap with: handled, the app has to show a page, or not ready yet. */
    const val HANDLED = 0
    const val OPEN_APP = 1
    const val NOT_READY = 2

    private val main = Handler(Looper.getMainLooper())

    /**
     * Runs one tap off the main thread: Rust holds its connection lock while a
     * connect or a profile switch runs, and a tap must never block the panel or
     * the launcher for that long. The answer arrives back on the main thread.
     */
    fun tap(inApp: Boolean, callback: (Int) -> Unit) {
        Thread {
            val result = try {
                BillowVpnBridge.tap(inApp)
            } catch (_: Throwable) {
                NOT_READY
            }
            main.post { callback(result) }
        }.start()
    }

    fun launchIntent(context: Context, toggle: Boolean): Intent =
        Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(EXTRA_TAP, toggle)
        }

    fun activityIntent(context: Context, requestCode: Int, toggle: Boolean): PendingIntent =
        PendingIntent.getActivity(
            context,
            requestCode,
            launchIntent(context, toggle),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
}
