package app.billow.client

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileDescriptor

/**
 * System VpnService. Rust calls prepare, then start with an app filter: either
 * the packages that bypass the VPN, or (allowlist) the only packages that use it.
 * This class only opens the TUN and returns the fd.
 */
class BillowVpnService : VpnService() {
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
        return START_STICKY
    }

    override fun onRevoke() {
        BillowVpnBridge.reportConsent(false)
        stopSelf()
    }

    fun establishTun(packages: List<String>, only: Boolean): Int? {
        val builder = Builder()
            .setSession("Billow")
            .setMtu(1500)
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)
        // Allowed and disallowed lists cannot be mixed on one Builder.
        for (packageName in packages) {
            try {
                if (only) builder.addAllowedApplication(packageName)
                else builder.addDisallowedApplication(packageName)
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                // Rust still owns the list when a package is not installed (yet).
            }
        }
        val opened = builder.establish() ?: return null
        val fd = opened.detachFd()
        clearCloseOnExec(fd)
        return fd
    }

    private fun clearCloseOnExec(fd: Int) {
        try {
            val descriptor = FileDescriptor()
            val field = FileDescriptor::class.java.getDeclaredField("descriptor")
            field.isAccessible = true
            field.setInt(descriptor, fd)
            android.system.Os.fcntlInt(descriptor, android.system.OsConstants.F_SETFD, 0)
        } catch (_: Exception) {
        }
    }

    companion object {
        const val EXTRA_EXCLUDED = "excluded_packages"
        const val EXTRA_ONLY = "only_listed_packages"
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
        fun start(context: Context, packages: List<String>, only: Boolean) {
            val intent = Intent(context, BillowVpnService::class.java)
            intent.putStringArrayListExtra(BillowVpnService.EXTRA_EXCLUDED, ArrayList(packages))
            intent.putExtra(BillowVpnService.EXTRA_ONLY, only)
            context.startService(intent)
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

        @JvmStatic
        private external fun nativeConsent(granted: Int)

        @JvmStatic
        private external fun nativeTunFd(fd: Int)
    }
}
