package eu.opensase.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import eu.opensase.android.graph
import kotlin.concurrent.thread

/**
 * Reconnects after boot if the user left the VPN on. Skipped when always-on VPN is set:
 * then the system starts the service itself and a second start would race with it.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val pending = goAsync()
        thread(name = "boot-connect") {
            try {
                val g = context.graph
                if (g.prefs.connectOnBoot && g.prefs.wantConnected && !g.prefs.alwaysOnSeen &&
                    VpnService.prepare(context) == null && g.engine.isEnrolled()
                ) {
                    OpenSaseVpnService.connect(context)
                }
            } catch (_: Exception) {
            } finally {
                pending.finish()
            }
        }
    }
}
