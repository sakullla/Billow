package app.billow.client

import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager

/**
 * System VpnService. Rust calls prepare, then start with an app filter: either
 * the packages that bypass the VPN, or (allowlist) the only packages that use it.
 * This class opens the TUN, tracks underlying physical networks and Doze exits
 * so the tunnel survives network roaming and idle sleep, and renders the
 * foreground notification from Rust state (R41).
 */
class BillowVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private val networkLock = Any()
    private val underlyingCandidates = LinkedHashMap<Network, NetworkCapabilities>()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var idleReceiver: BroadcastReceiver? = null
    private var lastNetworkSignature: String? = null
    private var pendingNetworkReason: String = "network_change"
    private val notifyNetworkChanged = Runnable {
        val reason = synchronized(networkLock) { pendingNetworkReason }
        Thread { BillowVpnBridge.reportNetworkChanged(reason) }.start()
    }

    override fun onCreate() {
        super.onCreate()
        // The background toggle and the revoke path need this instance to update
        // the notification the moment Rust publishes (R41).
        // publish() is static and synchronized; a newer state must render after startForeground.
        synchronized(BillowStatus::class.java) {
            val current = BillowStatus.current(this)
            val starting = if (current.state == BillowStatus.DISCONNECTED) {
                current.copy(state = BillowStatus.CONNECTING)
            } else current
            startForeground(BillowStatus.VPN_NOTIFICATION, notification(starting))
            BillowStatus.service = this
        }
    }

    override fun onDestroy() {
        closeTunnel()
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

    @Synchronized
    fun closeTunnel() {
        unregisterNetworkMonitors()
        val opened = tunnel ?: return
        opened.close()
        tunnel = null
        BillowVpnBridge.reportFd(-1)
    }

    @Synchronized
    fun establishTun(packages: List<String>, only: Boolean): Int? {
        val builder = Builder()
            .setSession("Billow")
            .setMtu(1500)
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("172.19.0.2")
        if (Build.VERSION.SDK_INT >= 29) {
            builder.setMetered(false)
        }
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
        android.system.Os.fcntlInt(opened.fileDescriptor, android.system.OsConstants.F_SETFD, android.system.OsConstants.FD_CLOEXEC)
        tunnel?.close()
        tunnel = opened
        registerNetworkMonitors()
        return opened.fd
    }

    private fun registerNetworkMonitors() {
        unregisterNetworkMonitors()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network)
                synchronized(networkLock) {
                    if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        underlyingCandidates[network] = caps
                    }
                }
                applyUnderlyingNetworks(cm, "available", cm.getLinkProperties(network))
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                synchronized(networkLock) {
                    underlyingCandidates[network] = networkCapabilities
                }
                applyUnderlyingNetworks(cm, "capabilities", cm.getLinkProperties(network))
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                applyUnderlyingNetworks(cm, "link_properties", linkProperties)
            }

            override fun onLost(network: Network) {
                synchronized(networkLock) {
                    underlyingCandidates.remove(network)
                }
                applyUnderlyingNetworks(cm, "lost", null)
            }
        }
        try {
            cm.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (_: Throwable) {
            // Some OEM ROMs may throw if network callback quota is exceeded; keep VPN alive.
        }

        val pm = getSystemService(PowerManager::class.java)
        if (pm != null) {
            BillowVpnBridge.reportScreenInteractive(pm.isInteractive)
        }
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_ON -> BillowVpnBridge.reportScreenInteractive(true)
                    Intent.ACTION_SCREEN_OFF -> BillowVpnBridge.reportScreenInteractive(false)
                    PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                        if (Build.VERSION.SDK_INT < 23) return
                        val power = context.getSystemService(PowerManager::class.java) ?: return
                        if (!power.isDeviceIdleMode) {
                            val connectivity = context.getSystemService(ConnectivityManager::class.java)
                            if (connectivity != null) {
                                applyUnderlyingNetworks(connectivity, "doze_exit", null, forceNotify = true)
                            } else {
                                scheduleNetworkNotify("doze_exit")
                            }
                        }
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            if (Build.VERSION.SDK_INT >= 23) {
                addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            }
        }
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                registerReceiver(receiver, filter)
            }
            idleReceiver = receiver
        } catch (_: Throwable) {
        }
    }

    private fun unregisterNetworkMonitors() {
        mainHandler.removeCallbacks(notifyNetworkChanged)
        val callback = networkCallback
        networkCallback = null
        if (callback != null) {
            try {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
            } catch (_: Throwable) {
            }
        }
        val receiver = idleReceiver
        idleReceiver = null
        if (receiver != null) {
            try {
                unregisterReceiver(receiver)
            } catch (_: Throwable) {
            }
        }
        synchronized(networkLock) {
            underlyingCandidates.clear()
            lastNetworkSignature = null
        }
    }

    private fun pickBestUnderlyingNetwork(): Network? = synchronized(networkLock) {
        underlyingCandidates.entries.maxByOrNull { (_, caps) ->
            var score = 0
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 100
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) score += 40
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) score += 30
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) score += 20
            score
        }?.key
    }

    private fun applyUnderlyingNetworks(
        cm: ConnectivityManager,
        reason: String,
        latestProps: LinkProperties?,
        forceNotify: Boolean = false,
    ) {
        val best = pickBestUnderlyingNetwork()
        try {
            setUnderlyingNetworks(if (best != null) arrayOf(best) else null)
        } catch (_: Throwable) {
        }
        val props = if (best != null) (latestProps ?: cm.getLinkProperties(best)) else null
        val addrs = props?.linkAddresses?.map { it.toString() }?.sorted()?.joinToString(",") ?: ""
        val dns = props?.dnsServers?.mapNotNull { it.hostAddress }?.sorted()?.joinToString(",") ?: ""
        val signature = "${best?.toString() ?: "none"}|$addrs|$dns"
        val changed = synchronized(networkLock) {
            val prev = lastNetworkSignature
            lastNetworkSignature = signature
            prev != null && prev != signature
        }
        if (forceNotify || changed) {
            scheduleNetworkNotify(reason)
        }
    }

    private fun scheduleNetworkNotify(reason: String) {
        synchronized(networkLock) {
            pendingNetworkReason = reason
        }
        mainHandler.removeCallbacks(notifyNetworkChanged)
        mainHandler.postDelayed(notifyNetworkChanged, NETWORK_CHANGE_DEBOUNCE_MS)
    }

    companion object {
        const val EXTRA_EXCLUDED = "excluded_packages"
        const val EXTRA_ONLY = "only_listed_packages"
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 1200L
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
            // Android keeps an established VPN bound after stopService until its fd closes.
            BillowStatus.service?.closeTunnel()
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

        /** Underlying network changed or device woke from Doze: flush stale sockets/DNS or recover kernel. */
        @JvmStatic
        fun reportNetworkChanged(reason: String) {
            try {
                nativeNetworkChanged(reason)
            } catch (_: Throwable) {
            }
        }

        /** App returned to foreground: verify kernel liveness so UI never shows a stale connected state. */
        @JvmStatic
        fun checkHealthOnResume() {
            try {
                nativeResumeCheck()
            } catch (_: Throwable) {
            }
        }

        /** Screen on/off hint so background polling backs off aggressively while screen is off. */
        @JvmStatic
        fun reportScreenInteractive(interactive: Boolean) {
            try {
                nativeScreenInteractive(if (interactive) 1 else 0)
            } catch (_: Throwable) {
            }
        }

        @JvmStatic
        private external fun nativeConsent(granted: Int)

        @JvmStatic
        private external fun nativeTunFd(fd: Int)

        @JvmStatic
        private external fun nativeTap(inApp: Int): Int

        @JvmStatic
        private external fun nativeRevoked()

        @JvmStatic
        private external fun nativeNetworkChanged(reason: String)

        @JvmStatic
        private external fun nativeResumeCheck()

        @JvmStatic
        private external fun nativeScreenInteractive(interactive: Int)
    }
}
