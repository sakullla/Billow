package app.billow.client

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
    /** Latest insets in CSS pixels; read by the page on load and pushed on every change. */
    @Volatile private var insetsJson = "{\"top\":0,\"right\":0,\"bottom\":0,\"left\":0,\"ime\":0}"
    private var webView: WebView? = null
    private var insetsTarget: View? = null
    /** A tile or widget tap that still has to reach Rust (R41). */
    private var pendingTap = false
    private var tapAttempts = 0
    private var tapping = false
    private val tapRetry = Runnable { runPendingTap() }

    override fun onCreate(savedInstanceState: Bundle?) {
        pendingTap = takeTap(intent)
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        BillowVpnBridge.attach(this)
        requestNotificationPermission()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (takeTap(intent)) {
            pendingTap = true
            tapAttempts = 0
        }
    }

    /** Reads the tap flag and clears it, so a configuration change cannot repeat it. */
    private fun takeTap(intent: Intent?): Boolean {
        if (intent?.getBooleanExtra(BillowShortcuts.EXTRA_TAP, false) != true) return false
        intent.removeExtra(BillowShortcuts.EXTRA_TAP)
        return true
    }

    override fun onResume() {
        super.onResume()
        runPendingTap()
        BillowVpnBridge.checkHealthOnResume()
    }

    override fun onDestroy() {
        pendingTap = false
        window.decorView.removeCallbacks(tapRetry)
        insetsTarget?.let { ViewCompat.setOnApplyWindowInsetsListener(it, null) }
        insetsTarget = null
        webView?.removeJavascriptInterface("BillowInsets")
        webView?.removeJavascriptInterface("BillowApps")
        webView = null
        super.onDestroy()
    }

    /**
     * A tile tap that needed the app continues here (R41). Rust keeps the tap
     * until its runtime is up, so a cold start still reaches the same toggle,
     * and the permission dialog appears with this activity in front.
     */
    private fun runPendingTap() {
        if (!pendingTap || tapping) return
        tapping = true
        BillowShortcuts.tap(true) { result ->
            if (isDestroyed) return@tap
            tapping = false
            when (result) {
                BillowShortcuts.HANDLED, BillowShortcuts.OPEN_APP -> pendingTap = false
                else -> {
                    tapAttempts += 1
                    if (tapAttempts > TAP_ATTEMPTS) {
                        pendingTap = false
                    } else {
                        window.decorView.postDelayed(tapRetry, TAP_RETRY_MS)
                    }
                }
            }
        }
    }

    /** The tile returns to 未连接 with a reason, which needs a notification (R41). */
    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) return
        if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
    }

    override fun onWebViewCreate(webView: WebView) {
        this.webView = webView
        webView.addJavascriptInterface(InsetsBridge(), "BillowInsets")
        webView.addJavascriptInterface(AppIconBridge(), "BillowApps")
        // Edge-to-edge windows no longer resize for the keyboard, and some WebView
        // builds report env(safe-area-inset-*) as 0. Measure the insets here, hand
        // them to CSS, and shrink the WebView by the IME height so the page layout
        // (sheets, focused inputs) stays above the keyboard.
        // The WebView is attached to the content frame only after this callback, so
        // the listener and the IME padding live on that frame instead.
        val target: View = window.decorView.findViewById<ViewGroup>(android.R.id.content)
        insetsTarget = target
        ViewCompat.setOnApplyWindowInsetsListener(target) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            val imeHeight = (ime.bottom - bars.bottom).coerceAtLeast(0)
            view.setPadding(0, 0, 0, ime.bottom)
            val density = resources.displayMetrics.density
            fun css(px: Int) = Math.round(px / density)
            insetsJson = "{\"top\":${css(bars.top)},\"right\":${css(bars.right)}," +
                "\"bottom\":${if (ime.bottom > 0) 0 else css(bars.bottom)},\"left\":${css(bars.left)}," +
                "\"ime\":${css(imeHeight)}}"
            push()
            // CSS reads these values from the bridge; consuming them keeps the
            // WebView's own env(safe-area-inset-*) from counting them twice.
            WindowInsetsCompat.CONSUMED
        }
        ViewCompat.requestApplyInsets(target)
    }

    private fun push() {
        val view = webView ?: return
        val script = "window.__billowInsets&&window.__billowInsets($insetsJson)"
        view.post {
            if (view === webView) view.evaluateJavascript(script, null)
        }
    }

    private inner class InsetsBridge {
        @JavascriptInterface
        fun get(): String = insetsJson

        /** Light page → dark status/navigation icons, and the reverse. */
        @JavascriptInterface
        fun setLightBars(light: Boolean) {
            runOnUiThread {
                val controller = WindowCompat.getInsetsController(window, window.decorView)
                controller.isAppearanceLightStatusBars = light
                controller.isAppearanceLightNavigationBars = light
            }
        }
    }

    /** App icons for the access-control list, as small PNG data URLs, cached per package. */
    private inner class AppIconBridge {
        // Data URLs are UTF-16 strings. Bound retained icon bytes even on phones
        // with hundreds of installed packages; LruCache methods are synchronized.
        private val cache = object : android.util.LruCache<String, String>(2 * 1024 * 1024) {
            override fun sizeOf(key: String, value: String): Int = (value.length * 2).coerceAtLeast(1)
        }

        @JavascriptInterface
        fun icon(packageName: String): String {
            cache[packageName]?.let { return it }
            val url = try {
                val drawable = packageManager.getApplicationIcon(packageName)
                val size = (40 * resources.displayMetrics.density).toInt().coerceIn(48, 128)
                val bitmap = android.graphics.Bitmap.createBitmap(size, size, android.graphics.Bitmap.Config.ARGB_8888)
                try {
                    val canvas = android.graphics.Canvas(bitmap)
                    drawable.setBounds(0, 0, size, size)
                    drawable.draw(canvas)
                    val out = java.io.ByteArrayOutputStream()
                    bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out)
                    "data:image/png;base64," +
                        android.util.Base64.encodeToString(out.toByteArray(), android.util.Base64.NO_WRAP)
                } finally {
                    bitmap.recycle()
                }
            } catch (_: Exception) {
                ""
            }
            cache.put(packageName, url)
            return url
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == BillowVpnBridge.REQUEST_CONSENT) {
            BillowVpnBridge.onActivityResult(resultCode)
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    private companion object {
        /** 40 tries × 250 ms: long enough for the runtime to come up on a cold start. */
        const val TAP_ATTEMPTS = 40
        const val TAP_RETRY_MS = 250L
        const val REQUEST_NOTIFICATIONS = 45
    }
}
