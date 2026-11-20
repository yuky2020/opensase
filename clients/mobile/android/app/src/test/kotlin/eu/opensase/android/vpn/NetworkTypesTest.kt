package eu.opensase.android.vpn

import eu.opensase.android.core.NetworkType
import org.junit.Assert.assertEquals
import org.junit.Test

class NetworkTypesTest {
    private data class Case(val wifi: Boolean, val cell: Boolean, val eth: Boolean, val notRoaming: Boolean, val want: NetworkType)

    @Test
    fun mapsTransportsToPolicyNetworkTypes() {
        val cases = listOf(
            Case(wifi = true, cell = false, eth = false, notRoaming = true, want = NetworkType.WIFI),
            Case(wifi = true, cell = false, eth = false, notRoaming = false, want = NetworkType.WIFI),
            Case(wifi = false, cell = true, eth = false, notRoaming = true, want = NetworkType.CELLULAR),
            Case(wifi = false, cell = true, eth = false, notRoaming = false, want = NetworkType.ROAMING),
            Case(wifi = false, cell = false, eth = true, notRoaming = true, want = NetworkType.ETHERNET),
            Case(wifi = true, cell = true, eth = false, notRoaming = true, want = NetworkType.WIFI),
            Case(wifi = true, cell = false, eth = true, notRoaming = true, want = NetworkType.ETHERNET),
            Case(wifi = false, cell = false, eth = false, notRoaming = true, want = NetworkType.UNKNOWN),
        )
        for (c in cases) assertEquals(c.toString(), c.want, mapNetworkType(c.wifi, c.cell, c.eth, c.notRoaming))
    }

    @Test
    fun parsesTunnelConfigAndCidr() {
        assertEquals("100.64.0.7" to 32, parseCidr("100.64.0.7/32"))
        assertEquals("fd7a:5a5e::7" to 128, parseCidr("fd7a:5a5e::7/128"))
        assertEquals(null, parseCidr("garbage"))
    }

    @Test
    fun sumsBlockedFromStatsEvent() {
        assertEquals(8L, OpenSaseVpnService.sumBlocked("""[{"app":"a","blocked":3},{"app":"","blocked":5,"dnsBlocked":2}]"""))
        assertEquals(0L, OpenSaseVpnService.sumBlocked("not json"))
    }
}
