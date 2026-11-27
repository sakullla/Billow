package app.billow.client

import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * Quick Settings tile: connected, disconnected or connecting, and a tap that
 * runs the same connection toggle as the tray (R41).
 *
 * The tile renders the status Rust published, so it keeps showing the truth
 * after the process was restarted for the tap, and a tap that needs a profile or
 * the VPN permission opens Billow instead of failing silently.
 */
class BillowTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        render()
    }

    override fun onClick() {
        super.onClick()
        BillowShortcuts.tap(false) { result ->
            if (result == BillowShortcuts.HANDLED) {
                render()
            } else {
                // No profile (profiles page) or no VPN permission (the activity
                // runs the system dialog, R41).
                open()
            }
        }
    }

    private fun open() {
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(BillowShortcuts.activityIntent(this, 3, true))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(BillowShortcuts.launchIntent(this, true))
        }
    }

    private fun render() {
        val tile = qsTile ?: return
        val status = BillowStatus.current(this)
        val view = BillowStatus.localized(this, status)
        val state = BillowStatus.stateText(view, status.state)
        tile.label = if (Build.VERSION.SDK_INT >= 29) {
            view.getString(R.string.tile_label)
        } else {
            // Without a subtitle the state has to travel in the label.
            "${view.getString(R.string.tile_label)} · $state"
        }
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = state
            tile.contentDescription = view.getString(R.string.tile_description, state)
        }
        tile.state = if (status.state == BillowStatus.CONNECTED) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.updateTile()
    }
}
