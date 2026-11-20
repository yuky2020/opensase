package eu.opensase.android.core

import java.io.File

/** Built when app/libs/opensase-core.aar exists: the real Go core. */
object EngineFactory {
    const val NAME = "go-core"

    fun create(stateDir: File, bridge: PlatformBridge): CoreEngine = GoCoreEngine(stateDir, bridge)
}
