package eu.opensase.android.vpn

/** State of the VpnService itself (before and around the engine). */
sealed interface VpnState {
    data object Idle : VpnState
    data object Connecting : VpnState
    data object Running : VpnState
    data class Failed(val message: String) : VpnState
}
