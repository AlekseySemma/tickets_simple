package ru.servora.tickets

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class ServoraFirebaseMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        DeviceRegistrationApi(applicationContext).apply {
            saveToken(token)
            syncIfPossible()
        }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        val title = message.data["title"] ?: message.notification?.title ?: getString(R.string.app_name)
        val body = message.data["body"] ?: message.notification?.body ?: ""
        val target = message.data["url"] ?: "/web"
        NotificationHelper.showNotification(this, title, body, target)
    }
}
