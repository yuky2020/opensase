package eu.opensase.android.core

/**
 * Kotlin view of the gomobile `Engine` (mobile/api.go). Methods take and return the raw JSON
 * strings of the contract so that the real and fake engines are interchangeable and the
 * parsing is tested once, in [CoreClient].
 *
 * All methods may block (network I/O): call them off the main thread.
 * Errors are thrown as [CoreException].
 */
interface CoreEngine {
    fun isEnrolled(): Boolean
    fun enroll(controlUrl: String, provisioningKey: String, deviceName: String)
    fun unenroll()

    /** JSON [TunnelConfig]. Performs session setup with the Edge; call before establish(). */
    fun tunnelConfig(): String

    /** Takes ownership of [tunFd]. */
    fun start(tunFd: Int, networkType: String)
    fun stop()
    fun setNetworkType(networkType: String)
    fun setPosture(json: String)
    fun postureFailing(): String

    /** JSON [Snapshot] or "". */
    fun snapshot(): String

    /** JSON [UserRules] -> PUT /v1/self/rules. Throws [UserRulesForbiddenException] on 403. */
    fun setUserRules(json: String)
    fun setAppPolicy(pkg: String, wifi: String, cellular: String, roaming: String)

    /** JSON list of [FlowRecord], newest first. */
    fun recentFlows(limit: Int): String

    /** JSON list of [AppStat]. */
    fun appStats(): String

    /** JSON [EngineStatus]. */
    fun status(): String
}

open class CoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The tenant does not allow user rules (HTTP 403 from PUT /v1/self/rules). */
class UserRulesForbiddenException(message: String, cause: Throwable? = null) :
    CoreException(message, cause)

/**
 * Maps an error from the Go core to a typed exception. gomobile turns a Go `error` into a
 * plain Exception whose message is err.Error(), so 403 is detected from the text.
 */
fun classifyCoreError(t: Throwable): CoreException {
    if (t is CoreException) return t
    val msg = t.message ?: t.javaClass.simpleName
    val lower = msg.lowercase()
    return if ("403" in lower || "forbidden" in lower || "user rules not allowed" in lower) {
        UserRulesForbiddenException(msg, t)
    } else {
        CoreException(msg, t)
    }
}

/** Asynchronous event from the core (Platform.OnEvent). */
data class CoreEvent(val kind: String, val payload: String) {
    companion object {
        const val STATE = "state"
        const val FLOW = "flow"
        const val STATS = "stats"
        const val SNAPSHOT = "snapshot"
        const val ERROR = "error"
        const val LOG = "log"
    }
}
