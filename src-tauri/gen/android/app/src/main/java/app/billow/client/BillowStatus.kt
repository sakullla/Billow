package app.billow.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.os.Build
import android.service.quicksettings.TileService
import java.util.Locale

/**
 * The connection state Rust publishes for the Quick Settings tile, the home
 * screen widget and the foreground notification (R41).
 *
 * One cached status feeds all three, so they can never disagree, and it is
 * written to the preferences because the tile and the widget can be tapped with
 * no activity around: the process then starts just for them.
 */
object BillowStatus {
    const val CONNECTED = "connected"
    const val CONNECTING = "connecting"
    const val DISCONNECTED = "disconnected"

    /** The foreground notification of [BillowVpnService]; the system expects a stable id. */
    const val VPN_CHANNEL = "vpn"
    const val VPN_NOTIFICATION = 1
    private const val ALERTS_CHANNEL = "alerts"
    private const val FAILED_NOTIFICATION = 2

    private const val PREFS = "billow-status"
    private const val KEY_STATE = "state"
    private const val KEY_PROFILE = "profile"
    private const val KEY_LANGUAGE = "language"
    private const val KEY_REASON = "reason"
    private const val KEY_ANNOUNCED = "reason-announced"

    data class Status(
        val state: String,
        val profile: String,
        val up: Long,
        val down: Long,
        val language: String,
        val reason: String,
    )

    @Volatile
    private var cached: Status? = null

    /** Set by [BillowVpnService] while it runs, so it can re-render its notification. */
    @Volatile
    var service: BillowVpnService? = null

    @Synchronized
    fun current(context: Context): Status {
        cached?.let { return it }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val status = Status(
            prefs.getString(KEY_STATE, DISCONNECTED) ?: DISCONNECTED,
            prefs.getString(KEY_PROFILE, "") ?: "",
            0L,
            0L,
            prefs.getString(KEY_LANGUAGE, defaultLanguage()) ?: defaultLanguage(),
            prefs.getString(KEY_REASON, "") ?: "",
        )
        cached = status
        return status
    }

    /**
     * The context the surface renders its own text with: the language picked in
     * Billow (T1), not the system one, so a notification, a tile and a widget all
     * follow the app setting (R41, R42).
     */
    fun localized(context: Context, status: Status = current(context)): Context {
        val locale = if (status.language == "en") Locale.ENGLISH else Locale.SIMPLIFIED_CHINESE
        val configuration = Configuration(context.resources.configuration)
        configuration.setLocale(locale)
        return context.createConfigurationContext(configuration)
    }

    fun stateText(view: Context, state: String): String = view.getString(
        when (state) {
            CONNECTED -> R.string.state_connected
            CONNECTING -> R.string.state_connecting
            else -> R.string.state_disconnected
        }
    )

    fun formatSpeed(bytes: Long): String {
        val value = if (bytes > 0) bytes else 0L
        return when {
            value >= 1024L * 1024L -> String.format(Locale.US, "%.1f MB/s", value / (1024.0 * 1024.0))
            value >= 1024L -> String.format(Locale.US, "%.0f KB/s", value / 1024.0)
            else -> String.format(Locale.US, "%d B/s", value)
        }
    }

    /**
     * Called by Rust through `BillowStatus.publish` whenever the connection, the
     * profile, the two rates or the language changed. It runs on a Rust thread,
     * so nothing here touches a view.
     */
    @JvmStatic
    @Synchronized
    fun publish(
        context: Context,
        state: String,
        profile: String,
        up: Long,
        down: Long,
        language: String,
        reason: String,
    ) {
        val previous = current(context)
        val status = Status(state, profile, up, down, language, reason)
        cached = status
        // Only the widget displays volatile rates. Persist fields that are still
        // meaningful after a process restart and update the other surfaces when
        // the fields they show change.
        val stateChanged = previous.state != state
        val languageChanged = previous.language != language
        val profileChanged = previous.profile != profile
        val reasonChanged = previous.reason != reason
        if (stateChanged || languageChanged || profileChanged || reasonChanged) {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_STATE, status.state)
                .putString(KEY_PROFILE, status.profile)
                .putString(KEY_LANGUAGE, status.language)
                .putString(KEY_REASON, status.reason)
                .apply()
        }
        if (stateChanged || languageChanged) refreshTile(context)
        BillowWidgetProvider.refresh(context)
        if (stateChanged || profileChanged || languageChanged) service?.render(status)
        if (stateChanged || reasonChanged) announceFailure(context, previous.state, status)
    }

    fun ensureChannel(context: Context, channel: String, name: String, importance: Int) {
        if (Build.VERSION.SDK_INT < 26) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(NotificationChannel(channel, name, importance))
    }

    fun builder(context: Context, channel: String): Notification.Builder =
        if (Build.VERSION.SDK_INT >= 26) Notification.Builder(context, channel) else Notification.Builder(context)

    fun openApp(context: Context, requestCode: Int): PendingIntent = PendingIntent.getActivity(
        context,
        requestCode,
        Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        },
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun defaultLanguage(): String = if (Locale.getDefault().language == "zh") "zh-CN" else "en"

    private fun refreshTile(context: Context) {
        try {
            // The panel re-reads the cached status through onStartListening (R41).
            TileService.requestListeningState(context, ComponentName(context, BillowTileService::class.java))
        } catch (_: Exception) {
            // Not placed in the panel yet: nothing to refresh.
        }
    }

    /**
     * A failed connect leaves no foreground service behind, so the reason the
     * tile returned to 未连接 gets its own notification (R41). Only a connect
     * that just failed announces: a reason left over from an earlier run is not
     * a new failure, and the same reason is never announced twice.
     */
    private fun announceFailure(context: Context, previousState: String, status: Status) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (status.state != DISCONNECTED || status.reason.isEmpty()) {
            manager.cancel(FAILED_NOTIFICATION)
            prefs.edit().remove(KEY_ANNOUNCED).apply()
            return
        }
        if (previousState != CONNECTING) return
        if (prefs.getString(KEY_ANNOUNCED, "") == status.reason) return
        prefs.edit().putString(KEY_ANNOUNCED, status.reason).apply()
        val view = localized(context, status)
        ensureChannel(
            context,
            ALERTS_CHANNEL,
            view.getString(R.string.notify_channel_alerts),
            NotificationManager.IMPORTANCE_DEFAULT,
        )
        val notification = builder(context, ALERTS_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_billow)
            .setContentTitle(view.getString(R.string.notify_failed))
            .setContentText(status.reason)
            .setStyle(Notification.BigTextStyle().bigText(status.reason))
            .setContentIntent(openApp(context, 2))
            .setAutoCancel(true)
            .build()
        manager.notify(FAILED_NOTIFICATION, notification)
    }
}
