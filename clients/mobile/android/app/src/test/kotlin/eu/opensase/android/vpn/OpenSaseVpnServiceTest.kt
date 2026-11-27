package eu.opensase.android.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class OpenSaseVpnServiceTest {

    @Test
    fun parseCidr_table() {
        data class Case(val input: String, val want: Pair<String, Int>?)

        val cases = listOf(
            Case("100.64.0.7/32", "100.64.0.7" to 32),
            Case("fd7a:5a5e::7/128", "fd7a:5a5e::7" to 128),
            Case(" fd7a:5a5e::7/64 ", "fd7a:5a5e::7" to 64),
            Case("", null),
            Case("   ", null),
            Case("/32", null),
            Case("100.64.0.7", null),
            Case("100.64.0.7/abc", null),
            Case("100.64.0.7/-1", null),
            Case("100.64.0.7/33", null),
            Case("fd7a:5a5e::7/129", null),
        )

        for (c in cases) {
            assertEquals("parseCidr(${c.input})", c.want, parseCidr(c.input))
        }
    }

    @Test
    fun buildVpnInterfaceSpec_populatedIpv6() {
        val cfg = TunnelConfig(
            ipv4 = "100.64.0.7/32",
            ipv6 = "fd7a:5a5e::7/128",
            dns = listOf("100.64.0.1", "fd7a:5a5e::1"),
            mtu = 1420,
        )

        val spec = buildVpnInterfaceSpec(cfg)

        assertEquals(
            listOf("100.64.0.7" to 32, "fd7a:5a5e::7" to 128),
            spec.addresses,
        )
        assertEquals(
            listOf("0.0.0.0" to 0, "::" to 0),
            spec.routes,
        )
        assertEquals(listOf("100.64.0.1", "fd7a:5a5e::1"), spec.dnsServers)
        assertEquals(1420, spec.mtu)
    }

    @Test
    fun buildVpnInterfaceSpec_emptyOrInvalidIpv6AddsSinkAndCapturesDefaultRoute() {
        data class Case(
            val name: String,
            val cfg: TunnelConfig,
            val wantAddresses: List<Pair<String, Int>>,
            val wantDns: List<String>,
            val wantMtu: Int,
        )

        val sink = IPV6_SINK_ADDRESS to IPV6_SINK_PREFIX
        val cases = listOf(
            Case(
                name = "empty ipv6 uses deterministic sink and keeps ipv4 dns",
                cfg = TunnelConfig(
                    ipv4 = "100.64.0.7/32",
                    ipv6 = "",
                    dns = listOf("100.64.0.1"),
                    mtu = 1280,
                ),
                wantAddresses = listOf("100.64.0.7" to 32, sink),
                wantDns = listOf("100.64.0.1"),
                wantMtu = 1280,
            ),
            Case(
                name = "blank ipv6 drops unreachable ipv6 dns server",
                cfg = TunnelConfig(
                    ipv4 = "100.64.0.7/32",
                    ipv6 = "   ",
                    dns = listOf("100.64.0.1", "fd7a:5a5e::1"),
                    mtu = 0,
                ),
                wantAddresses = listOf("100.64.0.7" to 32, sink),
                wantDns = listOf("100.64.0.1"),
                wantMtu = DEFAULT_MTU,
            ),
            Case(
                name = "malformed ipv6 falls back to sink",
                cfg = TunnelConfig(
                    ipv4 = "100.64.0.7/32",
                    ipv6 = "not-a-cidr",
                    dns = listOf("100.64.0.1"),
                    mtu = -1,
                ),
                wantAddresses = listOf("100.64.0.7" to 32, sink),
                wantDns = listOf("100.64.0.1"),
                wantMtu = DEFAULT_MTU,
            ),
            Case(
                name = "ipv4 address in ipv6 field falls back to sink",
                cfg = TunnelConfig(
                    ipv4 = "100.64.0.7/32",
                    ipv6 = "100.64.0.9/32",
                    dns = listOf("100.64.0.1"),
                    mtu = 1360,
                ),
                wantAddresses = listOf("100.64.0.7" to 32, sink),
                wantDns = listOf("100.64.0.1"),
                wantMtu = 1360,
            ),
        )

        for (c in cases) {
            val spec = buildVpnInterfaceSpec(c.cfg)
            assertEquals("${c.name}: addresses", c.wantAddresses, spec.addresses)
            assertEquals(
                "${c.name}: routes",
                listOf("0.0.0.0" to 0, "::" to 0),
                spec.routes,
            )
            assertEquals("${c.name}: dns", c.wantDns, spec.dnsServers)
            assertEquals("${c.name}: mtu", c.wantMtu, spec.mtu)
        }
    }

    @Test
    fun tunnelConfigParse_handlesMissingEmptyNullAndPopulatedIpv6() {
        data class Case(
            val name: String,
            val json: String,
            val wantIpv6Addr: Pair<String, Int>,
        )

        val sink = IPV6_SINK_ADDRESS to IPV6_SINK_PREFIX
        val cases = listOf(
            Case(
                name = "populated ipv6",
                json = """{"ipv4":"100.64.0.7/32","ipv6":"fd7a:5a5e::7/128","dns":["100.64.0.1","fd7a:5a5e::1"],"mtu":1280}""",
                wantIpv6Addr = "fd7a:5a5e::7" to 128,
            ),
            Case(
                name = "empty ipv6",
                json = """{"ipv4":"100.64.0.7/32","ipv6":"","dns":["100.64.0.1"],"mtu":1280}""",
                wantIpv6Addr = sink,
            ),
            Case(
                name = "missing ipv6 key",
                json = """{"ipv4":"100.64.0.7/32","dns":["100.64.0.1"],"mtu":1280}""",
                wantIpv6Addr = sink,
            ),
            Case(
                name = "explicit json null ipv6",
                json = """{"ipv4":"100.64.0.7/32","ipv6":null,"dns":["100.64.0.1"],"mtu":1280}""",
                wantIpv6Addr = sink,
            ),
        )

        for (c in cases) {
            val cfg = TunnelConfig.parse(c.json)
            val spec = buildVpnInterfaceSpec(cfg)
            assertEquals(
                "${c.name}: addresses",
                listOf("100.64.0.7" to 32, c.wantIpv6Addr),
                spec.addresses,
            )
            assertEquals(
                "${c.name}: routes",
                listOf("0.0.0.0" to 0, "::" to 0),
                spec.routes,
            )
        }
    }
}
