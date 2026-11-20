package eu.opensase.android.core

import eu.opensase.core.mobile.Engine
import eu.opensase.core.mobile.Mobile
import eu.opensase.core.mobile.Platform
import java.io.File

/** Adapts the gomobile-generated Platform interface to [PlatformBridge]. Go int is Java long. */
private class GoPlatform(private val bridge: PlatformBridge) : Platform {
    override fun connectionOwnerUID(protocol: Long, srcIP: String, srcPort: Long, dstIP: String, dstPort: Long): Long =
        bridge.connectionOwnerUid(protocol.toInt(), srcIP, srcPort.toInt(), dstIP, dstPort.toInt()).toLong()

    override fun packagesForUID(uid: Long): String = bridge.packagesForUid(uid.toInt())

    override fun protect(fd: Long): Boolean = bridge.protect(fd.toInt())

    override fun onEvent(kind: String, payload: String) = bridge.onEvent(kind, payload)
}

/** [CoreEngine] backed by the Go core (eu.opensase.core.mobile.Engine). */
class GoCoreEngine(stateDir: File, bridge: PlatformBridge) : CoreEngine {
    private val engine: Engine = try {
        Mobile.newEngine(stateDir.absolutePath, GoPlatform(bridge))
    } catch (e: Exception) {
        throw classifyCoreError(e)
    }

    private inline fun <T> call(block: () -> T): T = try {
        block()
    } catch (e: Exception) {
        throw classifyCoreError(e)
    }

    override fun isEnrolled(): Boolean = call { engine.isEnrolled() }
    override fun enroll(controlUrl: String, provisioningKey: String, deviceName: String) =
        call { engine.enroll(controlUrl, provisioningKey, deviceName) }
    override fun unenroll() = call { engine.unenroll() }
    override fun tunnelConfig(): String = call { engine.tunnelConfig() }
    override fun start(tunFd: Int, networkType: String) = call { engine.start(tunFd.toLong(), networkType) }
    // stop() uploads remaining flow records (3 s budget), wipes keys and closes the TUN fd.
    override fun stop() = call { engine.stop() }
    override fun setNetworkType(networkType: String) = call { engine.setNetworkType(networkType) }
    override fun snapshot(): String = call { engine.snapshot() }
    override fun setUserRules(json: String) = call { engine.setUserRules(json) }
    override fun setAppPolicy(pkg: String, wifi: String, cellular: String, roaming: String) =
        call { engine.setAppPolicy(pkg, wifi, cellular, roaming) }
    override fun recentFlows(limit: Int): String = call { engine.recentFlows(limit.toLong()) }
    override fun appStats(): String = call { engine.appStats() }
    override fun status(): String = call { engine.status() }
}
