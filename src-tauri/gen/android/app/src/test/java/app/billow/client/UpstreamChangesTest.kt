package app.billow.client

import org.junit.Assert.*
import org.junit.Test

class UpstreamChangesTest {
    private val addresses = setOf("192.0.2.1/24")
    private val dns = listOf("192.0.2.53", "192.0.2.54")

    @Test fun initialReplayAndOldNetworkEventsAreSilent() {
        val changes = UpstreamChanges(1)
        assertFalse(changes.available(1))
        assertFalse(changes.linkChanged(1, addresses, dns))
        assertTrue(changes.available(2))
        assertFalse(changes.linkChanged(2, addresses, dns))
        assertFalse(changes.lost(1))
        assertFalse(changes.linkChanged(1, emptySet(), emptyList()))
        assertEquals(UpstreamChange.ROUTE, changes.takePending())
        assertNull(changes.takePending())
    }

    @Test fun offlineStartAndReconnectionRecoverWhenAnUpstreamExists() {
        val changes = UpstreamChanges(null)
        assertTrue(changes.available(1))
        assertTrue(changes.lost(1))
        assertNull(changes.takePending())
        assertTrue(changes.available(1))
        assertEquals(UpstreamChange.ROUTE, changes.takePending())
    }

    @Test fun dnsOrderChangesPreserveSocketsAndAddressChangesTakePriority() {
        val changes = UpstreamChanges(1)
        changes.linkChanged(1, addresses, dns)
        assertTrue(changes.linkChanged(1, addresses, dns.reversed()))
        assertEquals(UpstreamChange.DNS, changes.takePending())
        assertTrue(changes.linkChanged(1, emptySet(), dns))
        changes.linkChanged(1, emptySet(), dns.reversed())
        assertEquals(UpstreamChange.ROUTE, changes.takePending())
        assertFalse(changes.linkChanged(1, emptySet(), dns.reversed()))
    }

    @Test fun prolongedInternetLossOnTheSameWifiRecoversOnce() {
        val changes = UpstreamChanges(1)
        assertFalse(changes.validationChanged(1, false, 0))
        assertFalse(changes.validationChanged(1, true, 500))
        assertNull(changes.takePending())
        assertFalse(changes.validationChanged(1, false, 1_000))
        assertFalse(changes.validationChanged(1, false, 25_000))
        assertFalse(changes.validationChanged(2, true, 31_000))
        assertTrue(changes.validationChanged(1, true, 31_000))
        assertEquals(UpstreamChange.ROUTE, changes.takePending())
        assertFalse(changes.validationChanged(1, true, 32_000))
    }
}
