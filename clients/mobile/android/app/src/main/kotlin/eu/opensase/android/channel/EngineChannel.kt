package eu.opensase.android.channel

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.net.VpnService
import android.provider.Settings
import android.util.LruCache
import eu.opensase.android.MainActivity
import eu.opensase.android.NativeGraph
import eu.opensase.android.core.UserRulesForbiddenException
import eu.opensase.android.core.classifyCoreError
import eu.opensase.android.vpn.OpenSaseVpnService
import eu.opensase.android.vpn.VpnState
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream

/**
 * Flutter bridge. MethodChannel `eu.opensase/engine` exposes the engine and VPN controls;
 * EventChannel `eu.opensase/events` streams core events (kind + JSON) and `vpn` state
 * changes. JSON stays as strings: Dart parses it.
 *
 * Error codes: "forbidden" (403 on user rules), "core" (Go core errors), "vpn".
 */
class EngineChannel(
    private val activity: MainActivity,
    private val graph: NativeGraph,
    messenger: BinaryMessenger,
) : MethodChannel.MethodCallHandler, EventChannel.StreamHandler {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val methods = MethodChannel(messenger, "eu.opensase/engine")
    private val events = EventChannel(messenger, "eu.opensase/events")
    private var eventJobs = listOf<Job>()

    init {
        methods.setMethodCallHandler(this)
        events.setStreamHandler(this)
    }

    fun dispose() {
        methods.setMethodCallHandler(null)
        events.setStreamHandler(null)
        scope.cancel()
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        scope.launch {
            try {
                result.success(handle(call))
            } catch (e: NotImplementedError) {
                result.notImplemented()
            } catch (e: Exception) {
                val ce = classifyCoreError(e)
                val code = if (ce is UserRulesForbiddenException) "forbidden" else "core"
                result.error(code, ce.message, null)
            }
        }
    }

    private suspend fun handle(call: MethodCall): Any? {
        val e = graph.engine
        return when (call.method) {
            "isEnrolled" -> io { e.isEnrolled() }
            "enroll" -> io {
                // The control URL may carry "#sha256=<hex>" (CA pin): pass it through unchanged.
                e.enroll(call.arg<String>("controlUrl")!!, call.arg<String>("provisioningKey")!!, call.arg<String>("deviceName")!!)
                null
            }
            "unenroll" -> {
                if (graph.vpnState.value != VpnState.Idle) OpenSaseVpnService.disconnect(activity)
                io { e.unenroll() }
                graph.prefs.wantConnected = false
                null
            }
            "prepareVpn" -> {
                val consent = VpnService.prepare(activity)
                if (consent == null) true else activity.requestVpnConsent(consent)
            }
            "connect" -> {
                if (VpnService.prepare(activity) != null) {
                    throw IllegalStateException("VPN permission not granted")
                }
                activity.requestNotificationPermission()
                OpenSaseVpnService.connect(activity)
                null
            }
            "disconnect" -> {
                OpenSaseVpnService.disconnect(activity)
                null
            }
            "status" -> io { e.status() }
            "snapshot" -> io { e.snapshot() }
            "setUserRules" -> io { e.setUserRules(call.arg<String>("json")!!); null }
            "setAppPolicy" -> io {
                e.setAppPolicy(call.arg("pkg")!!, call.arg("wifi") ?: "", call.arg("cellular") ?: "", call.arg("roaming") ?: "")
                null
            }
            "recentFlows" -> io { e.recentFlows(call.argument<Int>("limit") ?: 200) }
            "appStats" -> io { e.appStats() }
            "installedApps" -> io { installedApps(activity) }
            "vpnStatus" -> vpnJson(graph.vpnState.value)
            "openVpnSettings" -> {
                activity.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                null
            }
            "openBrowser" -> {
                val url = call.arg<String>("url")
                if (url == null || !url.startsWith("https://")) {
                    throw IllegalArgumentException("URL must start with https://")
                }
                val uri = android.net.Uri.parse(url)
                if (uri.scheme != "https") {
                    throw IllegalArgumentException("URL must use https")
                }
                activity.startActivity(Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                null
            }
            "saveFile" -> activity.saveFile(call.arg("fileName")!!, call.arg("content")!!)
            "takeEnrollLink" -> activity.takeEnrollLink()
            "setConnectOnBoot" -> {
                graph.prefs.connectOnBoot = call.arg<Boolean>("enabled") ?: true
                null
            }
            else -> throw NotImplementedError()
        }
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }

    private fun <T> MethodCall.arg(name: String): T? = argument<T>(name)

    // ---- events ----

    override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
        eventJobs.forEach { it.cancel() }
        eventJobs = listOf(
            scope.launch {
                graph.bridge.events.collect { ev -> sink.success(mapOf("kind" to ev.kind, "payload" to ev.payload)) }
            },
            scope.launch {
                activity.enrollLinks.collect { link -> sink.success(mapOf("kind" to "enrollLink", "payload" to link)) }
            },
            scope.launch {
                graph.vpnState.collect { st -> sink.success(mapOf("kind" to "vpn", "payload" to vpnJson(st))) }
            },
        )
    }

    override fun onCancel(arguments: Any?) {
        eventJobs.forEach { it.cancel() }
        eventJobs = emptyList()
    }

    private fun vpnJson(st: VpnState): String = JSONObject()
        .put("phase", when (st) {
            VpnState.Idle -> "idle"
            VpnState.Connecting -> "connecting"
            VpnState.Running -> "running"
            is VpnState.Failed -> "failed"
        })
        .put("message", (st as? VpnState.Failed)?.message ?: "")
        .put("alwaysOn", graph.prefs.alwaysOnSeen)
        .put("lockdown", graph.prefs.lockdownSeen)
        .toString()

    companion object {
        private const val ICON_PX = 96
        private val iconCache = LruCache<String, ByteArray>(400)

        /** Installed apps with PNG icons (cached per process). Excludes this app. */
        fun installedApps(context: Context): List<Map<String, Any?>> {
            val pm = context.packageManager
            @Suppress("DEPRECATION")
            val pkgs = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            return pkgs.mapNotNull { pi ->
                val ai = pi.applicationInfo ?: return@mapNotNull null
                if (pi.packageName == context.packageName) return@mapNotNull null
                mapOf(
                    "package" to pi.packageName,
                    "label" to ai.loadLabel(pm).toString(),
                    "uid" to ai.uid,
                    "isSystem" to ((ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0),
                    "hasInternetPermission" to (pi.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true),
                    "icon" to icon(pm, pi.packageName, ai),
                )
            }.sortedBy { (it["label"] as String).lowercase() }
        }

        private fun icon(pm: PackageManager, pkg: String, ai: ApplicationInfo): ByteArray? {
            iconCache.get(pkg)?.let { return it }
            return try {
                val d = ai.loadIcon(pm)
                val bmp = Bitmap.createBitmap(ICON_PX, ICON_PX, Bitmap.Config.ARGB_8888)
                d.setBounds(0, 0, ICON_PX, ICON_PX)
                d.draw(Canvas(bmp))
                val out = ByteArrayOutputStream()
                bmp.compress(Bitmap.CompressFormat.PNG, 100, out)
                bmp.recycle()
                out.toByteArray().also { iconCache.put(pkg, it) }
            } catch (_: Exception) {
                null
            }
        }
    }
}
