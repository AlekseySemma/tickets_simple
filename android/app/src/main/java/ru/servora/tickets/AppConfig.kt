package ru.servora.tickets

import android.net.Uri

object AppConfig {
    const val notificationChannelId = "servora_ticket_updates"
    private val normalizedBaseUrl = BuildConfig.SERVORA_BASE_URL.trim().trimEnd('/')
    private val baseUri = Uri.parse(normalizedBaseUrl)

    fun baseUrl(): String = normalizedBaseUrl

    fun absoluteUrl(rawTarget: String?): String {
        val target = rawTarget?.trim().orEmpty()
        if (target.isEmpty()) return "$normalizedBaseUrl/web"
        if (target.startsWith("http://") || target.startsWith("https://")) return target
        if (target.startsWith("/")) return normalizedBaseUrl + target
        return "$normalizedBaseUrl/$target"
    }

    fun isInternalUri(uri: Uri): Boolean {
        val host = uri.host ?: return false
        val scheme = uri.scheme ?: return false
        return (scheme == "http" || scheme == "https") && host.equals(baseUri.host, ignoreCase = true)
    }
}
