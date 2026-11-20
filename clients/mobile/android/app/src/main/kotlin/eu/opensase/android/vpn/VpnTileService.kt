package eu.opensase.android.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import eu.opensase.android.MainActivity
import eu.opensase.android.R
import eu.opensase.android.graph
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** Quick Settings tile: toggles the VPN; opens the app when VPN consent is still needed. */
class VpnTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var job: Job? = null

    override fun onStartListening() {
        job?.cancel()
        job = scope.launch { graph.vpnState.collect { render(it) } }
    }

    override fun onStopListening() {
        job?.cancel()
        job = null
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onClick() {
        when (graph.vpnState.value) {
            VpnState.Running, VpnState.Connecting -> OpenSaseVpnService.disconnect(this)
            else -> if (VpnService.prepare(this) == null) {
                OpenSaseVpnService.connect(this)
            } else {
                openApp()
            }
        }
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(MainActivity.EXTRA_CONNECT, true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION", "StartActivityAndCollapseDeprecated")
            startActivityAndCollapse(intent)
        }
    }

    private fun render(state: VpnState) {
        val tile = qsTile ?: return
        tile.label = getString(R.string.app_name)
        tile.state = when (state) {
            VpnState.Running, VpnState.Connecting -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(
                when (state) {
                    VpnState.Running -> R.string.state_connected
                    VpnState.Connecting -> R.string.state_connecting
                    is VpnState.Failed -> R.string.state_error
                    VpnState.Idle -> R.string.state_disconnected
                },
            )
        }
        tile.updateTile()
    }
}
