package app.billow.client

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.File

/**
 * System VpnService only. Rust decides which packages are excluded and whether
 * the session is connected. This class opens the TUN device and reports consent.
 */
class BillowVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val excluded = readExcludedPackages(this)
        if (!establishTun(excluded)) {
            BillowVpnBridge.reportConsent(false)
            stopSelf()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        closeTun()
        BillowVpnBridge.reportConsent(false)
        stopSelf()
    }

    override fun onDestroy() {
        closeTun()
        super.onDestroy()
    }

    fun establishTun(excludedPackages: List<String>): Boolean {
        closeTun()
        val builder = Builder()
            .setSession("Billow")
            .setMtu(1500)
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)
        for (packageName in excludedPackages) {
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                // Rust still owns the exclusion list when the package is not installed.
            }
        }
        val opened = builder.establish() ?: return false
        tun = opened
        return true
    }

    private fun closeTun() {
        tun?.close()
        tun = null
    }

    companion object {
        @JvmStatic
        external fun nativeConsent(granted: Int)

        fun readExcludedPackages(context: Context): List<String> {
            // Same file HostVpn writes under the Android config dir: dataDir/profiles/vpn.
            val file = File(context.applicationInfo.dataDir, "profiles/vpn/vpn-excluded.txt")
            if (!file.exists()) return emptyList()
            return file.readLines().map { it.trim() }.filter { it.isNotEmpty() }
        }
    }
}

class BillowVpnBridge {
    companion object {
        const val REQUEST_CONSENT = 44

        @JvmStatic
        fun prepare(activity: Activity): Boolean {
            val intent = VpnService.prepare(activity)
            if (intent == null) {
                reportConsent(true)
                return true
            }
            activity.startActivityForResult(intent, REQUEST_CONSENT)
            return false
        }

        @JvmStatic
        fun onActivityResult(resultCode: Int) {
            reportConsent(resultCode == Activity.RESULT_OK)
        }

        @JvmStatic
        fun reportConsent(granted: Boolean) {
            BillowVpnService.nativeConsent(if (granted) 1 else 0)
        }
    }
}
