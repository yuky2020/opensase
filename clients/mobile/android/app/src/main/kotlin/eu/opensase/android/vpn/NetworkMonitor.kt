package eu.opensase.android.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import eu.opensase.android.core.NetworkType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Tracks the default network of this app. The app is excluded from its own VPN
 * (addDisallowedApplication), so this is the underlying physical network.
 */
class NetworkMonitor(private val cm: ConnectivityManager) {
    data class Current(val network: Network?, val type: NetworkType)

    private val _current = MutableStateFlow(Current(null, NetworkType.UNKNOWN))
    val current: StateFlow<Current> = _current.asStateFlow()

    private var registered = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
            _current.value = Current(network, caps.toNetworkType())
        }

        override fun onLost(network: Network) {
            if (_current.value.network == network) _current.value = Current(null, NetworkType.UNKNOWN)
        }
    }

    fun start() {
        if (registered) return
        val active = cm.activeNetwork
        val caps = active?.let { cm.getNetworkCapabilities(it) }
        if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            _current.value = Current(active, caps.toNetworkType())
        }
        cm.registerDefaultNetworkCallback(callback)
        registered = true
    }

    fun stop() {
        if (!registered) return
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {
        }
        registered = false
    }
}
