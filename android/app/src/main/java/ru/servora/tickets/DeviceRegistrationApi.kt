package ru.servora.tickets

import android.content.Context
import android.os.Build
import android.webkit.CookieManager
import android.util.Base64
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.Executors

class DeviceRegistrationStore(context: Context) {
    private val prefs = context.getSharedPreferences("servora_mobile_push", Context.MODE_PRIVATE)

    val deviceId: String
        get() {
            val existing = prefs.getString(KEY_DEVICE_ID, null)
            if (!existing.isNullOrBlank()) return existing
            val generated = UUID.randomUUID().toString()
            prefs.edit().putString(KEY_DEVICE_ID, generated).apply()
            return generated
        }

    var currentToken: String?
        get() = prefs.getString(KEY_CURRENT_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_CURRENT_TOKEN, value).apply()

    var registeredToken: String?
        get() = prefs.getString(KEY_REGISTERED_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_REGISTERED_TOKEN, value).apply()

    var registeredUserId: String?
        get() = prefs.getString(KEY_REGISTERED_USER_ID, null)
        set(value) = prefs.edit().putString(KEY_REGISTERED_USER_ID, value).apply()

    companion object {
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_CURRENT_TOKEN = "current_token"
        private const val KEY_REGISTERED_TOKEN = "registered_token"
        private const val KEY_REGISTERED_USER_ID = "registered_user_id"
    }
}

class DeviceRegistrationApi(private val context: Context) {
    private val store = DeviceRegistrationStore(context)
    private val executor = Executors.newSingleThreadExecutor()

    fun saveToken(token: String) {
        val normalized = token.trim()
        if (normalized.isNotEmpty()) {
            store.currentToken = normalized
        }
    }

    fun syncIfPossible() {
        val token = store.currentToken?.trim().orEmpty()
        if (token.isEmpty()) return
        val session = sessionSnapshot() ?: return
        if (store.registeredToken == token && store.registeredUserId == session.userId) return

        executor.execute {
            val body = JSONObject()
                .put("token", token)
                .put("device_id", store.deviceId)
                .put("platform", "android")
                .put("app_version", BuildConfig.VERSION_NAME)
                .put("device_name", buildDeviceName())
            if (postJson("/api/mobile/devices/register", session.cookieHeader, body)) {
                store.registeredToken = token
                store.registeredUserId = session.userId
            }
        }
    }

    fun unregisterBestEffort() {
        val session = sessionSnapshot() ?: return
        executor.execute {
            val body = JSONObject()
                .put("device_id", store.deviceId)
                .put("platform", "android")
            if (postJson("/api/mobile/devices/unregister", session.cookieHeader, body)) {
                store.registeredUserId = null
                store.registeredToken = null
            }
        }
    }

    fun clearRegisteredSnapshot() {
        store.registeredUserId = null
        store.registeredToken = null
    }

    private fun sessionSnapshot(): SessionSnapshot? {
        val cookieHeader = CookieManager.getInstance().getCookie(AppConfig.baseUrl()) ?: return null
        if (!cookieHeader.contains("access_token=")) return null
        val token = extractCookieValue(cookieHeader, "access_token") ?: return null
        val userId = decodeJwtSubject(token) ?: return null
        return SessionSnapshot(cookieHeader = cookieHeader, userId = userId)
    }

    private fun postJson(path: String, cookieHeader: String, body: JSONObject): Boolean {
        val connection = (URL(AppConfig.absoluteUrl(path)).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 15000
            readTimeout = 15000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Cookie", cookieHeader)
            setRequestProperty("User-Agent", "ServoraAndroidNative/1.0")
        }
        return try {
            OutputStreamWriter(connection.outputStream, StandardCharsets.UTF_8).use { writer ->
                writer.write(body.toString())
            }
            connection.responseCode in 200..299
        } catch (_: Exception) {
            false
        } finally {
            connection.disconnect()
        }
    }

    private fun buildDeviceName(): String {
        val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
        val model = Build.MODEL?.trim().orEmpty()
        return listOf(manufacturer, model).filter { it.isNotEmpty() }.joinToString(" ").ifBlank { "Android device" }
    }

    private fun extractCookieValue(cookieHeader: String, key: String): String? {
        return cookieHeader
            .split(';')
            .map { it.trim() }
            .firstOrNull { it.startsWith("$key=") }
            ?.substringAfter('=', "")
            ?.takeIf { it.isNotBlank() }
    }

    private fun decodeJwtSubject(token: String): String? {
        val parts = token.split('.')
        if (parts.size < 2) return null
        return try {
            val decoded = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            JSONObject(String(decoded, StandardCharsets.UTF_8)).optString("sub").takeIf { it.isNotBlank() }
        } catch (_: Exception) {
            null
        }
    }

    private data class SessionSnapshot(
        val cookieHeader: String,
        val userId: String,
    )
}
