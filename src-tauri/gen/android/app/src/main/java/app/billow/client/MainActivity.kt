package app.billow.client

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == BillowVpnBridge.REQUEST_CONSENT) {
            BillowVpnBridge.onActivityResult(resultCode)
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }
}
