package ru.servora.tickets

import android.Manifest
import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.webkit.CookieManager
import android.webkit.PermissionRequest
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.ProgressBar
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import com.google.firebase.messaging.FirebaseMessaging

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private lateinit var loadingIndicator: ProgressBar
    private lateinit var deviceRegistrationApi: DeviceRegistrationApi

    private var fileChooserCallback: ValueCallback<Array<Uri>>? = null
    private var pendingWebPermissionRequest: PermissionRequest? = null
    private var pendingWebPermissionResources: Array<String>? = null

    private val fileChooserLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val callback = fileChooserCallback
        fileChooserCallback = null
        if (callback == null) return@registerForActivityResult

        if (result.resultCode != RESULT_OK) {
            callback.onReceiveValue(null)
            return@registerForActivityResult
        }

        val data = result.data
        val uris = mutableListOf<Uri>()
        data?.data?.let { uris.add(it) }
        val clipData = data?.clipData
        if (clipData != null) {
            for (index in 0 until clipData.itemCount) {
                clipData.getItemAt(index).uri?.let { uris.add(it) }
            }
        }
        callback.onReceiveValue(uris.distinct().toTypedArray())
    }

    private val runtimePermissionsLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { grants ->
        val request = pendingWebPermissionRequest
        val resources = pendingWebPermissionResources
        pendingWebPermissionRequest = null
        pendingWebPermissionResources = null

        if (request == null || resources == null) return@registerForActivityResult
        if (grants.values.all { it }) {
            request.grant(resources)
        } else {
            request.deny()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        webView = findViewById(R.id.webView)
        loadingIndicator = findViewById(R.id.loadingIndicator)
        deviceRegistrationApi = DeviceRegistrationApi(applicationContext)

        NotificationHelper.createChannel(this)
        configureWebView()
        requestNotificationPermissionIfNeeded()
        fetchFirebaseToken()

        if (savedInstanceState == null) {
            webView.loadUrl(initialUrlFromIntent(intent))
        } else {
            webView.restoreState(savedInstanceState)
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) {
                    webView.goBack()
                } else {
                    finish()
                }
            }
        })
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        webView.loadUrl(initialUrlFromIntent(intent))
        deviceRegistrationApi.syncIfPossible()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        webView.saveState(outState)
        super.onSaveInstanceState(outState)
    }

    override fun onDestroy() {
        fileChooserCallback?.onReceiveValue(null)
        fileChooserCallback = null
        pendingWebPermissionRequest?.deny()
        pendingWebPermissionRequest = null
        pendingWebPermissionResources = null
        webView.destroy()
        super.onDestroy()
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun configureWebView() {
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            allowContentAccess = true
            allowFileAccess = true
            mediaPlaybackRequiresUserGesture = false
            mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
            userAgentString = userAgentString + " " + BuildConfig.WEBVIEW_USER_AGENT_SUFFIX
        }

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val uri = request?.url ?: return false
                if (AppConfig.isInternalUri(uri)) return false
                return openExternal(uri)
            }

            override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                super.onPageStarted(view, url, favicon)
                loadingIndicator.isVisible = true
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                loadingIndicator.isVisible = false
                deviceRegistrationApi.syncIfPossible()
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                super.onProgressChanged(view, newProgress)
                loadingIndicator.isVisible = newProgress < 100
            }

            override fun onPermissionRequest(request: PermissionRequest) {
                handleWebPermissionRequest(request)
            }

            override fun onShowFileChooser(
                webView: WebView?,
                filePathCallback: ValueCallback<Array<Uri>>?,
                fileChooserParams: FileChooserParams?,
            ): Boolean {
                fileChooserCallback?.onReceiveValue(null)
                fileChooserCallback = filePathCallback

                val openDocumentIntent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = chooseMimeType(fileChooserParams)
                    putExtra(Intent.EXTRA_ALLOW_MULTIPLE, fileChooserParams?.mode == FileChooserParams.MODE_OPEN_MULTIPLE)
                }
                fileChooserLauncher.launch(Intent.createChooser(openDocumentIntent, getString(R.string.app_name)))
                return true
            }
        }
    }

    private fun handleWebPermissionRequest(request: PermissionRequest) {
        runOnUiThread {
            val requiredPermissions = mutableListOf<String>()
            if (request.resources.contains(PermissionRequest.RESOURCE_AUDIO_CAPTURE) &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED
            ) {
                requiredPermissions += Manifest.permission.RECORD_AUDIO
            }
            if (request.resources.contains(PermissionRequest.RESOURCE_VIDEO_CAPTURE) &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED
            ) {
                requiredPermissions += Manifest.permission.CAMERA
            }

            if (requiredPermissions.isEmpty()) {
                request.grant(request.resources)
                return@runOnUiThread
            }

            pendingWebPermissionRequest?.deny()
            pendingWebPermissionRequest = request
            pendingWebPermissionResources = request.resources
            runtimePermissionsLauncher.launch(requiredPermissions.distinct().toTypedArray())
        }
    }

    private fun chooseMimeType(fileChooserParams: WebChromeClient.FileChooserParams?): String {
        val firstType = fileChooserParams
            ?.acceptTypes
            ?.asSequence()
            ?.map { it.trim() }
            ?.firstOrNull { it.isNotEmpty() && !it.contains(',') }
        return firstType ?: "*/*"
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            return
        }
        runtimePermissionsLauncher.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS))
    }

    private fun fetchFirebaseToken() {
        FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
            if (!task.isSuccessful) return@addOnCompleteListener
            val token = task.result?.trim().orEmpty()
            if (token.isNotEmpty()) {
                deviceRegistrationApi.saveToken(token)
                deviceRegistrationApi.syncIfPossible()
            }
        }
    }

    private fun initialUrlFromIntent(intent: Intent?): String {
        return AppConfig.absoluteUrl(intent?.getStringExtra(EXTRA_TARGET_URL))
    }

    private fun openExternal(uri: Uri): Boolean {
        return try {
            startActivity(Intent(Intent.ACTION_VIEW, uri))
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }

    companion object {
        const val EXTRA_TARGET_URL = "target_url"
    }
}
