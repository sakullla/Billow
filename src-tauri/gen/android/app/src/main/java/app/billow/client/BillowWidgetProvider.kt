package app.billow.client

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

/**
 * Home screen widget: the connection state, the running profile's name and the
 * two rates, with a switch that toggles the connection (R41).
 *
 * The switch goes through Rust, which owns the connection; the values only
 * change when Rust publishes a new status, so the widget, the tile, the
 * notification and the app always agree.
 */
class BillowWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        val views = render(context)
        for (id in ids) manager.updateAppWidget(id, views)
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_TOGGLE) {
            val pending = goAsync()
            BillowShortcuts.tap(false) { result ->
                try {
                    if (result != BillowShortcuts.HANDLED) {
                        // The activity continues taps that require a profile or VPN permission.
                        context.startActivity(BillowShortcuts.launchIntent(context, true))
                    }
                } finally {
                    pending.finish()
                }
            }
            return
        }
        super.onReceive(context, intent)
    }

    companion object {
        const val ACTION_TOGGLE = "app.billow.client.action.TOGGLE"

        /** Re-render every placed widget after Rust published a new status. */
        fun refresh(context: Context) {
            val manager = AppWidgetManager.getInstance(context) ?: return
            val component = ComponentName(context, BillowWidgetProvider::class.java)
            if (manager.getAppWidgetIds(component).isEmpty()) return
            manager.updateAppWidget(component, render(context))
        }

        private fun render(context: Context): RemoteViews {
            val status = BillowStatus.current(context)
            val view = BillowStatus.localized(context, status)
            val connected = status.state == BillowStatus.CONNECTED
            val views = RemoteViews(context.packageName, R.layout.billow_widget)
            views.setTextViewText(R.id.widget_state, BillowStatus.stateText(view, status.state))
            views.setTextViewText(
                R.id.widget_profile,
                status.profile.ifEmpty { view.getString(R.string.widget_no_profile) },
            )
            // No speed while disconnected: the rates of a stopped kernel are
            // meaningless, so the row stays empty (R41).
            views.setTextViewText(
                R.id.widget_speed,
                if (connected) {
                    view.getString(
                        R.string.widget_speed,
                        BillowStatus.formatSpeed(status.down),
                        BillowStatus.formatSpeed(status.up),
                    )
                } else {
                    ""
                },
            )
            views.setTextViewText(
                R.id.widget_toggle,
                view.getString(if (connected) R.string.widget_disconnect else R.string.widget_connect),
            )
            views.setOnClickPendingIntent(R.id.widget_root, BillowStatus.openApp(context, 4))
            views.setOnClickPendingIntent(R.id.widget_toggle, toggleIntent(context))
            return views
        }

        private fun toggleIntent(context: Context): PendingIntent = PendingIntent.getBroadcast(
            context,
            5,
            Intent(context, BillowWidgetProvider::class.java).setAction(ACTION_TOGGLE),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }
}
