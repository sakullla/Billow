package app.billow.client

import android.content.Intent
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

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
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
        view.post { view.evaluateJavascript(script, null) }
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
        private val cache = java.util.concurrent.ConcurrentHashMap<String, String>()

        @JavascriptInterface
        fun icon(packageName: String): String {
            cache[packageName]?.let { return it }
            val url = try {
                val drawable = packageManager.getApplicationIcon(packageName)
                val size = (40 * resources.displayMetrics.density).toInt().coerceIn(48, 128)
                val bitmap = android.graphics.Bitmap.createBitmap(size, size, android.graphics.Bitmap.Config.ARGB_8888)
                val canvas = android.graphics.Canvas(bitmap)
                drawable.setBounds(0, 0, size, size)
                drawable.draw(canvas)
                val out = java.io.ByteArrayOutputStream()
                bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out)
                bitmap.recycle()
                "data:image/png;base64," + android.util.Base64.encodeToString(out.toByteArray(), android.util.Base64.NO_WRAP)
            } catch (_: Exception) {
                ""
            }
            cache[packageName] = url
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
}
