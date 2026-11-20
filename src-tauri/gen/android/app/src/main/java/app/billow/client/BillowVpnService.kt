package app.billow.client

import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

/**
 * System VpnService. Rust calls prepare, then start with an app filter: either
 * the packages that bypass the VPN, or (allowlist) the only packages that use it.
 * This class only opens the TUN and returns the fd. Its foreground notification
 * renders the state Rust publishes, in the language picked in Billow (R41).
 */
class BillowVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        // The background toggle and the revoke path need this instance to update
        // the notification the moment Rust publishes (R41).
        BillowStatus.service = this
        startForeground(BillowStatus.VPN_NOTIFICATION, notification(BillowStatus.current(this)))
    }

    override fun onDestroy() {
        tunnel?.close()
        tunnel = null
        BillowVpnBridge.reportFd(-1)
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (BillowStatus.service === this) BillowStatus.service = null
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val packages = intent?.getStringArrayListExtra(EXTRA_EXCLUDED) ?: arrayListOf()
        val only = intent?.getBooleanExtra(EXTRA_ONLY, false) ?: false
        val fd = establishTun(packages, only)
        if (fd == null) {
            BillowVpnBridge.reportFd(-1)
            stopSelf()
            return START_NOT_STICKY
        }
        BillowVpnBridge.reportFd(fd)
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        // The permission is gone: Rust disconnects, so the app, the tile, the
        // widget and the notification all leave 已连接 together (R41).
        BillowVpnBridge.reportConsent(false)
        BillowVpnBridge.reportRevoked()
        stopSelf()
    }

    /** Re-render the foreground notification after Rust published a new status. */
    fun render(status: BillowStatus.Status) {
        // 未连接 means this service is being torn down; the notification goes with it.
        if (status.state == BillowStatus.DISCONNECTED) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(BillowStatus.VPN_NOTIFICATION, notification(status))
    }

    private fun notification(status: BillowStatus.Status): Notification {
        val view = BillowStatus.localized(this, status)
        BillowStatus.ensureChannel(
            this,
            BillowStatus.VPN_CHANNEL,
            view.getString(R.string.notify_channel_vpn),
            NotificationManager.IMPORTANCE_LOW,
        )
        val text = when (status.state) {
            BillowStatus.CONNECTED -> if (status.profile.isEmpty()) {
                view.getString(R.string.notify_connected)
            } else {
                view.getString(R.string.notify_connected_profile, status.profile)
            }
            BillowStatus.CONNECTING -> view.getString(R.string.state_connecting)
            else -> view.getString(R.string.state_disconnected)
        }
        return BillowStatus.builder(this, BillowStatus.VPN_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_billow)
            .setContentTitle(view.getString(R.string.notify_title))
            .setContentText(text)
            .setContentIntent(BillowStatus.openApp(this, 0))
            .setOngoing(true)
            .build()
    }

    fun establishTun(packages: List<String>, only: Boolean): Int? {
        val builder = Builder()
            .setSession("Billow")
            .setMtu(1500)
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("172.19.0.2")
        // The core shares our UID; its upstream sockets must not re-enter its own VPN.
        if (!only) builder.addDisallowedApplication(packageName)
        // Allowed and disallowed lists cannot be mixed on one Builder.
        for (packageName in packages.filter { it != this.packageName }) {
            try {
                if (only) builder.addAllowedApplication(packageName)
                else builder.addDisallowedApplication(packageName)
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                // Rust still owns the list when a package is not installed (yet).
            }
        }
        val opened = builder.establish() ?: return null
        android.system.Os.fcntlInt(opened.fileDescriptor, android.system.OsConstants.F_SETFD, 0)
        tunnel?.close()
        tunnel = opened
        return opened.fd
    }

    companion object {
        const val EXTRA_EXCLUDED = "excluded_packages"
        const val EXTRA_ONLY = "only_listed_packages"
    }
}

class BillowVpnBridge {
    companion object {
        const val REQUEST_CONSENT = 44

        private var activityRef = java.lang.ref.WeakReference<Activity>(null)

        fun attach(activity: Activity) { activityRef = java.lang.ref.WeakReference(activity) }

        @JvmStatic
        fun prepare(context: Context): Boolean {
            val intent = VpnService.prepare(context)
            if (intent == null) {
                reportConsent(true)
                return true
            }
            val activity = activityRef.get()
            if (activity == null) {
                reportConsent(false)
                return false
            }
            activity.runOnUiThread { activity.startActivityForResult(intent, REQUEST_CONSENT) }
            return false
        }

        /**
         * Whether the system already trusts Billow to start a VPN. `VpnService.prepare`
         * answers without showing the dialog, so a tile tap can tell whether it may
         * connect on its own (R41).
         */
        @JvmStatic
        fun hasConsent(context: Context): Boolean = VpnService.prepare(context) == null

        /**
         * One tap on the tile or the widget switch, answered by Rust (R41):
         * 0 = handled, 1 = the app has to show a page, 2 = the runtime is not
         * loaded yet (a tap can start the process before Tauri is up).
         */
        @JvmStatic
        fun tap(inApp: Boolean): Int = try {
            nativeTap(if (inApp) 1 else 0)
        } catch (_: Throwable) {
            2
        }

        @JvmStatic
        fun onActivityResult(resultCode: Int) {
            reportConsent(resultCode == Activity.RESULT_OK)
        }

        @JvmStatic
        fun start(context: Context, packages: List<String>, only: Boolean) {
            val intent = Intent(context, BillowVpnService::class.java)
            intent.putStringArrayListExtra(BillowVpnService.EXTRA_EXCLUDED, ArrayList(packages))
            intent.putExtra(BillowVpnService.EXTRA_ONLY, only)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }

        @JvmStatic
        fun stop(context: Context) {
            context.stopService(Intent(context, BillowVpnService::class.java))
        }

        @JvmStatic
        fun reportConsent(granted: Boolean) {
            nativeConsent(if (granted) 1 else 0)
        }

        @JvmStatic
        fun reportFd(fd: Int) {
            nativeTunFd(fd)
        }

        /** `onRevoke` reached Rust: disconnect and republish every surface (R41). */
        @JvmStatic
        fun reportRevoked() {
            nativeRevoked()
        }

        @JvmStatic
        private external fun nativeConsent(granted: Int)

        @JvmStatic
        private external fun nativeTunFd(fd: Int)

        @JvmStatic
        private external fun nativeTap(inApp: Int): Int

        @JvmStatic
        private external fun nativeRevoked()
    }
}
