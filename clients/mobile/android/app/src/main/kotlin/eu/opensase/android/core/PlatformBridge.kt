package eu.opensase.android.core

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Platform callbacks for the Go core (mobile.Platform). The gomobile interface itself is only
 * on the classpath when the .aar is present, so the logic lives here and the generated
 * interface is adapted in src/gocore (GoPlatform). Every method is called from Go
 * goroutines and must return within a few milliseconds.
 */
class PlatformBridge(
    private val connectivity: ConnectivityManager?,
    private val packageManager: PackageManager?,
) {
    /** The running VpnService, needed for protect() and getConnectionOwnerUid(). */
    @Volatile
    var vpnService: VpnService? = null

    private val _events = MutableSharedFlow<CoreEvent>(
        replay = 0,
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val events: SharedFlow<CoreEvent> = _events.asSharedFlow()

    /** protocol is 6 (TCP) or 17 (UDP). Returns -1 if unknown. */
    fun connectionOwnerUid(protocol: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): Int {
        val cm = connectivity ?: return -1
        return try {
            // The strings are numeric literals from the packet header: no DNS lookup happens.
            val src = InetSocketAddress(InetAddress.getByName(srcIp), srcPort)
            val dst = InetSocketAddress(InetAddress.getByName(dstIp), dstPort)
            cm.getConnectionOwnerUid(protocol, src, dst)
        } catch (e: Exception) {
            // SecurityException if we are not the active VPN, IllegalArgumentException for
            // protocols other than TCP/UDP.
            -1
        }
    }

    fun packagesForUid(uid: Int): String {
        val pm = packageManager ?: return ""
        return try {
            pm.getPackagesForUid(uid)?.joinToString(",") ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Excludes a socket the core opens from our tunnel. The core calls this for every socket
     * (enrollment, snapshot polling, Edge session, WireGuard) and refuses the connection if it
     * returns false (fail-closed).
     *
     * With no OpenSASE VpnService alive there is no tunnel of ours the socket could loop
     * through (e.g. enrollment before the first connect), so the socket is already "protected":
     * return true. With the service alive, the real VpnService.protect result is returned.
     */
    fun protect(fd: Int): Boolean {
        val svc = vpnService ?: return true
        return try {
            svc.protect(fd)
        } catch (e: Exception) {
            false
        }
    }

    /** Never blocks: the buffer drops the oldest events when the UI cannot keep up. */
    fun onEvent(kind: String, payload: String) {
        if (kind == CoreEvent.LOG || kind == CoreEvent.ERROR) {
            Log.println(if (kind == CoreEvent.ERROR) Log.WARN else Log.DEBUG, TAG, payload.take(500))
        }
        _events.tryEmit(CoreEvent(kind, payload))
    }

    companion object {
        private const val TAG = "OpenSaseCore"
    }
}
