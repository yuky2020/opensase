package eu.opensase.android.core

import java.io.File

/** Built when app/libs/opensase-core.aar is absent: the app runs, every core call fails clearly. */
object EngineFactory {
    const val NAME = "stub (no opensase-core.aar)"

    fun create(stateDir: File, bridge: PlatformBridge): CoreEngine = StubCoreEngine()
}

class StubCoreEngine : CoreEngine {
    private fun missing(): Nothing = throw CoreException("Go core not bundled: build with clients/mobile/android/app/libs/opensase-core.aar")
    override fun isEnrolled() = false
    override fun enroll(controlUrl: String, provisioningKey: String, deviceName: String) = missing()
    override fun unenroll() {}
    override fun tunnelConfig(): String = missing()
    override fun start(tunFd: Int, networkType: String) = missing()
    override fun stop() {}
    override fun setNetworkType(networkType: String) {}
    override fun snapshot() = ""
    override fun setUserRules(json: String) = missing()
    override fun setAppPolicy(pkg: String, wifi: String, cellular: String, roaming: String) = missing()
    override fun recentFlows(limit: Int) = "[]"
    override fun appStats() = "[]"
    override fun setPosture(json: String) {}
    override fun postureFailing() = "[]"
    override fun status() = """{"state":"stopped","error":"Go core not bundled"}"""
}
