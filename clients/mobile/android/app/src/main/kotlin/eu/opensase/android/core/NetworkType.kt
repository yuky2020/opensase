package eu.opensase.android.core

/** policy.NetworkType wire values (pkg/policy/types.go). */
enum class NetworkType(val wire: String) {
    WIFI("wifi"),
    CELLULAR("cellular"),
    ROAMING("roaming"),
    ETHERNET("ethernet"),
    UNKNOWN("unknown"),
}
