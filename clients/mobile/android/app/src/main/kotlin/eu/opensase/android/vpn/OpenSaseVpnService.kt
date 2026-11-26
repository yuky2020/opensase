package eu.opensase.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import eu.opensase.android.MainActivity
import eu.opensase.android.R
import eu.opensase.android.core.CoreEvent
import eu.opensase.android.core.PostureCollector
import eu.opensase.android.core.classifyCoreError
import eu.opensase.android.graph
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** Interface parameters from Engine.tunnelConfig(). */
data class TunnelConfig(val ipv4: String, val ipv6: String, val dns: List<String>, val mtu: Int) {
    companion object {
        fun parse(json: String): TunnelConfig {
            val o = JSONObject(json)
            val dns = o.optJSONArray("dns")?.let { a -> List(a.length()) { a.getString(it) } }.orEmpty()
            return TunnelConfig(o.optString("ipv4"), o.optString("ipv6"), dns, o.optInt("mtu", 1280))
        }
    }
}

/** Splits "100.64.0.7/32" into ("100.64.0.7", 32). */
fun parseCidr(cidr: String): Pair<String, Int>? {
    val slash = cidr.indexOf('/')
    if (slash <= 0) return null
    val prefix = cidr.substring(slash + 1).toIntOrNull() ?: return null
    return cidr.substring(0, slash) to prefix
}

/**
 * Captures all device traffic (0.0.0.0/0 and ::/0) and hands the TUN fd to the Go core.
 * The app itself is excluded so its control traffic never loops through the tunnel.
 *
 * Started by the Flutter UI (via the engine channel), the Quick Settings tile, the boot
 * receiver, or the system for always-on VPN (action [VpnService.SERVICE_INTERFACE] or a
 * null intent after a restart).
 */
class OpenSaseVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val lifecycle = Mutex()
    private lateinit var monitor: NetworkMonitor
    private var running = false
    private var connectJob: Job? = null
    private val watchJobs = mutableListOf<Job>()

    override fun onCreate() {
        super.onCreate()
        monitor = NetworkMonitor(graph.connectivity)
        graph.bridge.vpnService = this
        createChannel(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                scope.launch { disconnect(userInitiated = true) }
                return START_NOT_STICKY
            }
            null, ACTION_CONNECT, SERVICE_INTERFACE -> {
                startInForeground(buildNotification(getString(R.string.vpn_notif_connecting), null))
                if (connectJob?.isActive != true && !running) connectJob = scope.launch { connect() }
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked us in system settings.
        scope.launch { disconnect(userInitiated = true) }
    }

    override fun onDestroy() {
        if (running) {
            graph.engine.stop()
            running = false
        }
        monitor.stop()
        graph.bridge.vpnService = null
        if (graph.vpnState.value !is VpnState.Failed) graph.vpnState.value = VpnState.Idle
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun connect(): Unit = lifecycle.withLock {
        if (running) return@withLock
        val g = graph
        g.vpnState.value = VpnState.Connecting
        g.prefs.wantConnected = true
        g.prefs.alwaysOnSeen = isAlwaysOn
        g.prefs.lockdownSeen = isLockdownEnabled
        monitor.start()
        try {
            if (!withContext(Dispatchers.IO) { g.engine.isEnrolled() }) error(getString(R.string.vpn_error_not_enrolled))
            withContext(Dispatchers.IO) { g.engine.setPosture(PostureCollector.collect(this@OpenSaseVpnService)) }
            // tunnelConfig() performs session setup with the Edge (network I/O).
            val cfg = TunnelConfig.parse(withContext(Dispatchers.IO) { g.engine.tunnelConfig() })
            val pfd = buildInterface(cfg).establish() ?: error(getString(R.string.vpn_error_not_prepared))
            // From here the fd belongs to the Go core, which closes it on stop() and on a
            // failed start. Never close it from Kotlin.
            val fd = pfd.detachFd()
            val net = monitor.current.value.type.wire
            withContext(NonCancellable + Dispatchers.IO) {
                g.engine.setPosture(PostureCollector.collect(this@OpenSaseVpnService))
                g.engine.start(fd, net)
                running = true
            }
            g.vpnState.value = VpnState.Running
            watch()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val msg = classifyCoreError(e).message ?: e.javaClass.simpleName
            Log.w(TAG, "connect failed: $msg")
            g.vpnState.value = VpnState.Failed(msg)
            updateNotification(buildNotification(getString(R.string.vpn_notif_failed), msg, retry = true))
            if (isAlwaysOn) {
                // Always-on: keep the service alive (with lockdown, traffic stays blocked) and retry.
                scope.launch {
                    delay(RETRY_MILLIS)
                    connectJob = scope.launch { connect() }
                }
            }
        }
    }

    private fun buildInterface(cfg: TunnelConfig): Builder {
        val b = Builder().setSession(getString(R.string.app_name))
        parseCidr(cfg.ipv4)?.let { (a, p) -> b.addAddress(a, p) }
        parseCidr(cfg.ipv6)?.let { (a, p) -> b.addAddress(a, p) }
        b.addRoute("0.0.0.0", 0)
        b.addRoute("::", 0)
        cfg.dns.forEach { b.addDnsServer(it) }
        b.setMtu(if (cfg.mtu > 0) cfg.mtu else 1280)
        b.addDisallowedApplication(packageName)
        b.setBlocking(false)
        b.setUnderlyingNetworks(monitor.current.value.network?.let { arrayOf(it) })
        b.setMetered(false)
        b.setConfigureIntent(openAppIntent(this))
        return b
    }

    private fun watch() {
        val g = graph
        var blocked = 0L
        watchJobs += scope.launch {
            monitor.current.collect { cur ->
                setUnderlyingNetworks(cur.network?.let { arrayOf(it) })
                withContext(Dispatchers.IO) { g.engine.setNetworkType(cur.type.wire) }
            }
        }
        // "stats" events carry the appStats() array every 5 s.
        watchJobs += scope.launch {
            g.bridge.events.collect { ev ->
                if (ev.kind == CoreEvent.STATS) blocked = sumBlocked(ev.payload)
            }
        }
        watchJobs += scope.launch {
            var last = ""
            while (isActive) {
                val st = try {
                    JSONObject(withContext(Dispatchers.IO) { g.engine.status() })
                } catch (_: Exception) {
                    JSONObject()
                }
                val state = st.optString("state")
                val title = when (state) {
                    "connected" -> getString(R.string.vpn_notif_connected, st.optString("edge").ifEmpty { "Edge" })
                    "error" -> getString(R.string.vpn_notif_failed)
                    else -> getString(R.string.vpn_notif_connecting)
                }
                val pq = if (state == "connected" && st.optBoolean("pq")) {
                    getString(R.string.vpn_notif_pq, st.optString("kex").ifEmpty { "X25519MLKEM768" })
                } else {
                    null
                }
                val text = listOfNotNull(pq, getString(R.string.vpn_notif_blocked, blocked)).joinToString(" · ")
                if (title + text != last) {
                    updateNotification(buildNotification(title, text))
                    last = title + text
                }
                delay(STATUS_POLL_MILLIS)
            }
        }
    }

    private suspend fun disconnect(userInitiated: Boolean) {
        connectJob?.cancel() // before taking the lock: connect() holds it during session setup
        lifecycle.withLock { teardown(userInitiated) }
    }

    private suspend fun teardown(userInitiated: Boolean) {
        val g = graph
        watchJobs.forEach { it.cancel() }
        watchJobs.clear()
        if (running) {
            withContext(Dispatchers.IO) { g.engine.stop() }
            running = false
        }
        if (userInitiated) g.prefs.wantConnected = false
        g.vpnState.value = VpnState.Idle
        monitor.stop()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ---- notification ----

    private fun startInForeground(n: Notification) {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, n, type)
    }

    private fun updateNotification(n: Notification) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, n)
    }

    private fun buildNotification(title: String, text: String?, retry: Boolean = false): Notification {
        val disconnect = PendingIntent.getService(
            this, 1, Intent(this, OpenSaseVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val b = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(openAppIntent(this))
            .addAction(0, getString(R.string.vpn_action_disconnect), disconnect)
        if (retry) {
            val again = PendingIntent.getService(
                this, 2, Intent(this, OpenSaseVpnService::class.java).setAction(ACTION_CONNECT),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            b.addAction(0, getString(R.string.vpn_action_retry), again)
        }
        return b.build()
    }

    companion object {
        private const val TAG = "OpenSaseVpn"
        const val ACTION_CONNECT = "eu.opensase.android.CONNECT"
        const val ACTION_DISCONNECT = "eu.opensase.android.DISCONNECT"
        private const val CHANNEL_ID = "vpn"
        private const val NOTIFICATION_ID = 1
        private const val RETRY_MILLIS = 15_000L
        private const val STATUS_POLL_MILLIS = 3_000L

        fun connect(context: Context) {
            ContextCompat.startForegroundService(
                context, Intent(context, OpenSaseVpnService::class.java).setAction(ACTION_CONNECT),
            )
        }

        fun disconnect(context: Context) {
            context.startService(Intent(context, OpenSaseVpnService::class.java).setAction(ACTION_DISCONNECT))
        }

        fun sumBlocked(statsJson: String): Long = try {
            val a = JSONArray(statsJson)
            (0 until a.length()).sumOf { a.getJSONObject(it).optLong("blocked") }
        } catch (_: Exception) {
            0
        }

        private fun createChannel(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, context.getString(R.string.vpn_channel_name), NotificationManager.IMPORTANCE_LOW).apply {
                    setShowBadge(false)
                },
            )
        }

        fun openAppIntent(context: Context): PendingIntent = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
    }
}
