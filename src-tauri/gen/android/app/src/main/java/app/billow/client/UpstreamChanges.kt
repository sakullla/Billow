package app.billow.client

internal enum class UpstreamChange { DNS, ROUTE }

/** Tracks only the default network. Each VPN registration starts with a fresh baseline. */
internal class UpstreamChanges(private var network: Long?) {
    private var addresses: Set<String>? = null
    private var dns: List<String>? = null
    private var unvalidatedSince: Long? = null
    var pending: UpstreamChange? = null
        private set

    fun available(handle: Long): Boolean {
        if (network == handle) return false
        network = handle
        addresses = null
        dns = null
        unvalidatedSince = null
        pending = UpstreamChange.ROUTE
        return true
    }

    fun lost(handle: Long): Boolean {
        if (network != handle) return false
        network = null
        pending = null
        return true
    }

    fun validationChanged(handle: Long, validated: Boolean, now: Long): Boolean {
        if (network != handle) return false
        if (!validated) {
            if (unvalidatedSince == null) unvalidatedSince = now
            return false
        }
        val since = unvalidatedSince ?: return false
        unvalidatedSince = null
        if (now - since < LONG_OUTAGE_MS) return false
        pending = UpstreamChange.ROUTE
        return true
    }

    fun linkChanged(handle: Long, nextAddresses: Set<String>, nextDns: List<String>): Boolean {
        if (network != handle) return false
        val change = when {
            addresses != null && addresses != nextAddresses -> UpstreamChange.ROUTE
            dns != null && dns != nextDns -> UpstreamChange.DNS
            else -> null
        }
        addresses = nextAddresses
        dns = nextDns
        if (change == null || pending == UpstreamChange.ROUTE) return false
        pending = change
        return true
    }

    fun takePending(): UpstreamChange? = pending.also { pending = null }

    private companion object {
        // Brief validation gaps are common while joining Wi-Fi. Measure on callbacks only.
        const val LONG_OUTAGE_MS = 30_000L
    }
}
