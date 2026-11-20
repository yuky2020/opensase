package eu.opensase.android

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.net.ConnectivityManager
import eu.opensase.android.core.CoreEngine
import eu.opensase.android.core.EngineFactory
import eu.opensase.android.core.PlatformBridge
import eu.opensase.android.vpn.VpnState
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.File

/** Native process graph: one Go engine per process, shared by the VpnService and the channel. */
class NativeGraph(context: Context) {
    val connectivity: ConnectivityManager = context.getSystemService(ConnectivityManager::class.java)
    val bridge = PlatformBridge(connectivity, context.packageManager)
    val engine: CoreEngine = EngineFactory.create(File(context.filesDir, "opensase").apply { mkdirs() }, bridge)
    val engineName: String = EngineFactory.NAME
    val vpnState = MutableStateFlow<VpnState>(VpnState.Idle)
    val prefs = NativePrefs(context.getSharedPreferences("native", Context.MODE_PRIVATE))
}

/** Native-only flags used by the service and the boot receiver. No secrets here. */
class NativePrefs(private val p: SharedPreferences) {
    var connectOnBoot: Boolean
        get() = p.getBoolean("connect_on_boot", true)
        set(v) = p.edit().putBoolean("connect_on_boot", v).apply()
    var wantConnected: Boolean
        get() = p.getBoolean("want_connected", false)
        set(v) = p.edit().putBoolean("want_connected", v).apply()
    var alwaysOnSeen: Boolean
        get() = p.getBoolean("always_on_seen", false)
        set(v) = p.edit().putBoolean("always_on_seen", v).apply()
    var lockdownSeen: Boolean
        get() = p.getBoolean("lockdown_seen", false)
        set(v) = p.edit().putBoolean("lockdown_seen", v).apply()
}

class OpenSaseApp : Application() {
    lateinit var graph: NativeGraph
        private set

    override fun onCreate() {
        super.onCreate()
        graph = NativeGraph(this)
    }
}

val Context.graph: NativeGraph get() = (applicationContext as OpenSaseApp).graph
