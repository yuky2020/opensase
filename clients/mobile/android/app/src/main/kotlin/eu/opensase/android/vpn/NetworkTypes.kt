package eu.opensase.android.vpn

import android.net.NetworkCapabilities
import eu.opensase.android.core.NetworkType

/**
 * Maps transport flags to the policy NetworkType. Pure so it can be unit tested.
 * Cellular without NET_CAPABILITY_NOT_ROAMING is "roaming". Wi-Fi wins over cellular when a
 * network reports both (e.g. Wi-Fi calling bearers), ethernet wins over both.
 */
fun mapNetworkType(wifi: Boolean, cellular: Boolean, ethernet: Boolean, notRoaming: Boolean): NetworkType = when {
    ethernet -> NetworkType.ETHERNET
    wifi -> NetworkType.WIFI
    cellular -> if (notRoaming) NetworkType.CELLULAR else NetworkType.ROAMING
    else -> NetworkType.UNKNOWN
}

fun NetworkCapabilities?.toNetworkType(): NetworkType {
    if (this == null) return NetworkType.UNKNOWN
    return mapNetworkType(
        wifi = hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
        cellular = hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
        ethernet = hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
        notRoaming = hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING),
    )
}
