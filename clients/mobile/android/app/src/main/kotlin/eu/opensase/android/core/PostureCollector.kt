package eu.opensase.android.core

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.os.UserManager
import org.json.JSONObject
import java.time.Instant

/** Collects device posture information for the Go core engine. */
object PostureCollector {
    fun collect(context: Context): String {
        val osVersion = Build.VERSION.RELEASE ?: ""

        val clientVersion = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.PackageInfoFlags.of(0)
                ).versionName ?: ""
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: ""
            }
        } catch (_: Exception) {
            ""
        }

        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        val diskEncrypted: Boolean? = when (dpm?.storageEncryptionStatus) {
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> true
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> false
            else -> null
        }

        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val screenLock: Boolean? = km?.isDeviceSecure

        val managed: Boolean? = run {
            if (dpm != null && (dpm.isProfileOwnerApp(context.packageName) || dpm.isDeviceOwnerApp(context.packageName))) {
                true
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val um = context.getSystemService(Context.USER_SERVICE) as? UserManager
                um?.isManagedProfile
            } else {
                null
            }
        }

        val bootEpochMillis = System.currentTimeMillis() - SystemClock.elapsedRealtime()
        val bootTime = Instant.ofEpochMilli(bootEpochMillis).toString()

        val json = JSONObject().apply {
            put("os", "android")
            put("osVersion", osVersion)
            put("clientVersion", clientVersion)
            if (diskEncrypted != null) put("diskEncrypted", diskEncrypted)
            if (screenLock != null) put("screenLock", screenLock)
            if (managed != null) put("managed", managed)
            put("bootTime", bootTime)
        }
        return json.toString()
    }
}
