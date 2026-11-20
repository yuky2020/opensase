package eu.opensase.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import eu.opensase.android.channel.EngineChannel
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow

class MainActivity : FlutterActivity() {
    private var channel: EngineChannel? = null
    private var vpnConsent: CompletableDeferred<Boolean>? = null
    private var saveRequest: Pair<String, CompletableDeferred<Boolean>>? = null

    /** Deep link that launched the activity, until Dart takes it. */
    private var pendingEnrollLink: String? = null
    private val _enrollLinks = MutableSharedFlow<String>(extraBufferCapacity = 4)
    /** Deep links received while running. */
    val enrollLinks: SharedFlow<String> = _enrollLinks

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        pendingEnrollLink = enrollLinkOf(intent)
        super.onCreate(savedInstanceState)
    }

    fun takeEnrollLink(): String? = pendingEnrollLink.also { pendingEnrollLink = null }

    private fun enrollLinkOf(i: Intent?): String? {
        val uri = i?.data ?: return null
        return if (i.action == Intent.ACTION_VIEW && uri.scheme == "opensase" && uri.host == "enroll") uri.toString() else null
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        channel = EngineChannel(this, graph, flutterEngine.dartExecutor.binaryMessenger)
    }

    override fun cleanUpFlutterEngine(flutterEngine: FlutterEngine) {
        channel?.dispose()
        channel = null
        super.cleanUpFlutterEngine(flutterEngine)
    }

    /** Shows the system VPN consent dialog; true if the user accepted. */
    suspend fun requestVpnConsent(intent: Intent): Boolean {
        vpnConsent?.cancel()
        val d = CompletableDeferred<Boolean>()
        vpnConsent = d
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQ_VPN)
        return d.await()
    }

    /** Lets the user pick a location (Storage Access Framework) and writes [content]. */
    suspend fun saveFile(fileName: String, content: String): Boolean {
        val d = CompletableDeferred<Boolean>()
        saveRequest = content to d
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/json")
            .putExtra(Intent.EXTRA_TITLE, fileName)
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQ_SAVE)
        return d.await()
    }

    fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
        }
    }

    @Deprecated("Activity result API is not available on FlutterActivity")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQ_VPN -> {
                vpnConsent?.complete(resultCode == Activity.RESULT_OK)
                vpnConsent = null
            }
            REQ_SAVE -> {
                val req = saveRequest ?: return
                saveRequest = null
                val uri = data?.data
                if (resultCode != Activity.RESULT_OK || uri == null) {
                    req.second.complete(false)
                    return
                }
                val ok = try {
                    contentResolver.openOutputStream(uri)?.use { it.write(req.first.toByteArray()) } != null
                } catch (_: Exception) {
                    false
                }
                req.second.complete(ok)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        enrollLinkOf(intent)?.let { link ->
            pendingEnrollLink = link
            _enrollLinks.tryEmit(link)
        }
    }

    companion object {
        const val EXTRA_CONNECT = "connect"
        private const val REQ_VPN = 4201
        private const val REQ_SAVE = 4202
        private const val REQ_NOTIF = 4203
    }
}
