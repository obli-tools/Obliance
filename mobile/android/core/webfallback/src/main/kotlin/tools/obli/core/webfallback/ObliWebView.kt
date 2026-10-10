package tools.obli.core.webfallback

import android.annotation.SuppressLint
import android.app.DownloadManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.http.SslError
import android.os.Build
import android.os.Environment
import android.util.Log
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.URLUtil
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.browser.customtabs.CustomTabColorSchemeParams
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.clickable
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.net.toUri
import androidx.webkit.ScriptHandler
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import tools.obli.core.designsystem.ObliCalmState
import tools.obli.core.designsystem.ObliIconButton
import tools.obli.core.designsystem.ObliIcons
import tools.obli.core.designsystem.ObliTheme
import tools.obli.core.designsystem.ObliTypography
import tools.obli.shell.nav.Origins

/**
 * Opens a same-origin page of the active server in the web view, from any
 * screen (the app pushes it full screen on phones, in the detail pane on
 * tablets). Provided by the application; the default does nothing.
 */
fun interface WebPageOpener {
    fun openWeb(path: String, title: String)
}

val LocalWebPageOpener = staticCompositionLocalOf { WebPageOpener { _, _ -> } }

internal object WebIcons {
    val ExternalLink: ImageVector by lazy {
        ObliIcons.lucide("external-link", "M15 3h6v6", "M10 14 21 3", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6")
    }
    val Globe: ImageVector by lazy {
        ObliIcons.lucide("globe", "M2 12a10 10 0 1 0 20 0a10 10 0 1 0-20 0", "M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20", "M2 12h20")
    }
}

/**
 * "Vue web": [path] of [origin] in a WebView sharing the
 * process-wide CookieManager session (signed in, same tenant as the native
 * calls). Native top bar: Fermer, the title with the "Vue web" label,
 * Actualiser, Ouvrir dans le navigateur. JavaScript and DOM storage on; other
 * origins open outside; downloads go to DownloadManager with the cookie;
 * back goes back in the page history, then closes. [onInAppPath] may take a
 * same-origin path the app shows natively (`/devices/12` → the device screen).
 *
 * With [LocalWebDeviceBridge] provided (device-bound validation), the page
 * gets `window.ObliNative.signDeviceChallenge` (bridgeVersion 2, capability
 * `deviceKey`) for [origin] only.
 *
 * [onSsoReauth] (SSO device keys): the page's « Reconfirmer avec Obligate »
 * (`/auth/sso-redirect?reauth=1&return=<path>`) never loads here — it would
 * leave for a Custom Tab without the session. The app runs its native
 * Obligate sheet with the return path, then this view loads
 * `<origin><path>?reauth=ok|failed&reason=…` so the page reports it. Null:
 * refused, the page is told `reason=unsupported`. A [path] that is itself
 * that URL (a notification link…) runs the sheet instead of the first load.
 */
@Composable
fun ObliWebView(
    origin: String,
    path: String,
    title: String,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    onInAppPath: (path: String) -> Boolean = { false },
    onSsoReauth: (suspend (returnPath: String) -> WebReauthOutcome)? = null,
) {
    val context = LocalContext.current
    val start = remember(origin, path) { WebUrlPolicy.startUrl(origin, path) }
    var progress by remember { mutableIntStateOf(0) }
    var pageTitle by remember { mutableStateOf<String?>(null) }
    var currentUrl by remember { mutableStateOf(start) }
    var failed by remember { mutableStateOf(start == null) }
    var webView by remember { mutableStateOf<WebView?>(null) }
    val inApp by rememberUpdatedState(onInAppPath)
    val reauth by rememberUpdatedState(onSsoReauth)
    // The re-authentication lives with the view: leaving the page cancels it.
    val reauthScope = rememberCoroutineScope()
    val reauthRunning = remember { AtomicBoolean(false) }
    val startReauth: (String) -> Unit = { returnPath ->
        if (reauthRunning.compareAndSet(false, true)) {
            reauthScope.launch {
                val outcome = try {
                    reauth?.invoke(returnPath) ?: WebReauthOutcome(false, "unsupported")
                } catch (e: CancellationException) {
                    reauthRunning.set(false)
                    throw e
                } catch (e: RuntimeException) {
                    Log.w(TAG, "re-authentication failed", e)
                    WebReauthOutcome(false, "error")
                }
                reauthRunning.set(false)
                webView?.loadUrl(WebUrlPolicy.reauthResultUrl(origin, returnPath, outcome))
            }
        }
    }

    // The first load, and a reload / retry while nothing loaded yet. `loadUrl` never goes
    // through shouldOverrideUrlLoading, and the server answers a re-authentication start with
    // a 302 (never committed, so never seen by onPageStarted): check it here.
    val loadStart: (WebView) -> Unit = { view ->
        val s = start
        val returnPath = s?.let { WebUrlPolicy.ssoReauthReturn(origin, it) }
        if (returnPath != null) startReauth(returnPath) else if (s != null) view.loadUrl(s)
    }

    BackHandler {
        val view = webView
        if (view != null && view.canGoBack() && !failed) view.goBack() else onClose()
    }

    WebFrame(
        title = title.ifBlank { pageTitle.orEmpty() },
        location = currentUrl?.let { WebUrlPolicy.pathOf(origin, it) }?.let { (Origins.host(origin) ?: origin) + it } ?: Origins.host(origin).orEmpty(),
        progress = progress,
        onClose = onClose,
        onReload = {
            failed = start == null
            val view = webView
            if (view == null || view.url.isNullOrEmpty()) view?.let(loadStart) else view.reload()
        },
        // Never the re-authentication start URL: outside, it has neither the session nor the state.
        onOpenOutside = {
            val here = webView?.url?.takeIf { it.isNotEmpty() } ?: start
            openOutside(context, here?.takeIf { WebUrlPolicy.ssoReauthReturn(origin, it) == null } ?: origin)
        },
        modifier = modifier,
    ) {
        if (start != null) {
            ServerWebView(
                origin = origin,
                bridge = LocalWebDeviceBridge.current,
                onCreated = { webView = it },
                onProgress = { progress = it },
                onTitle = { pageTitle = it },
                onUrl = { currentUrl = it },
                onError = { failed = true },
                inApp = { inApp(it) },
                onSsoReauth = startReauth,
                loadStart = loadStart,
            )
        }
        if (failed) {
            WebError(onRetry = {
                failed = start == null
                webView?.let { v -> if (v.url.isNullOrEmpty()) loadStart(v) else v.reload() }
            })
        }
    }
}

/** Native chrome of the web view (64 dp chrome bar, 2 dp progress line) around [content]. */
@Composable
internal fun WebFrame(
    title: String,
    location: String,
    progress: Int,
    onClose: () -> Unit,
    onReload: () -> Unit,
    onOpenOutside: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    val c = ObliTheme.colors
    Column(modifier.fillMaxSize().background(c.bg)) {
        Row(
            Modifier.fillMaxWidth().height(64.dp).background(c.chrome).padding(horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            ObliIconButton(ObliIcons.X, stringResource(R.string.web_close), onClose, tint = c.text)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    title,
                    style = ObliTypography.cardTitle,
                    color = c.text,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.semantics { heading() },
                )
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(
                        Modifier.clip(RoundedCornerShape(4.dp)).background(c.surface2).padding(horizontal = 6.dp, vertical = 1.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Icon(WebIcons.Globe, contentDescription = null, tint = c.text2, modifier = Modifier.size(11.dp))
                        Text(stringResource(R.string.web_label).uppercase(), style = ObliTypography.overline, color = c.text2, maxLines = 1)
                    }
                    Text(location, style = ObliTypography.monoCaption, color = c.textMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            ObliIconButton(ObliIcons.RefreshCw, stringResource(R.string.web_reload), onReload)
            ObliIconButton(WebIcons.ExternalLink, stringResource(R.string.web_open_browser), onOpenOutside)
        }
        Box(Modifier.fillMaxWidth().height(2.dp).background(c.chrome)) {
            if (progress in 1..99) {
                LinearProgressIndicator(
                    progress = { progress / 100f },
                    modifier = Modifier.fillMaxWidth().height(2.dp),
                    color = c.accentLine,
                    trackColor = Color.Transparent,
                    drawStopIndicator = {},
                )
            }
        }
        Box(Modifier.fillMaxWidth().weight(1f)) { content() }
    }
}

/** "Cette page n'a pas pu être chargée." [Réessayer]. */
@Composable
internal fun WebError(onRetry: () -> Unit) {
    val c = ObliTheme.colors
    Box(Modifier.fillMaxSize().background(c.bg)) {
        ObliCalmState(
            stringResource(R.string.web_error),
            body = stringResource(R.string.web_error_body),
            icon = WebIcons.Globe,
            action = {
                Row(
                    Modifier.heightIn(min = 48.dp).clip(RoundedCornerShape(8.dp)).background(c.accentTint())
                        .clickable(role = Role.Button, onClick = onRetry).padding(horizontal = 20.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.web_retry), style = ObliTypography.label, color = c.accentText)
                }
            },
        )
    }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable
private fun ServerWebView(
    origin: String,
    bridge: WebDeviceBridge?,
    onCreated: (WebView) -> Unit,
    onProgress: (Int) -> Unit,
    onTitle: (String?) -> Unit,
    onUrl: (String?) -> Unit,
    onError: () -> Unit,
    inApp: (String) -> Boolean,
    onSsoReauth: (returnPath: String) -> Unit,
    loadStart: (WebView) -> Unit,
) {
    val bg = ObliTheme.colors.bg.toArgb()
    val progress by rememberUpdatedState(onProgress)
    val titleChanged by rememberUpdatedState(onTitle)
    val urlChanged by rememberUpdatedState(onUrl)
    val error by rememberUpdatedState(onError)
    val native by rememberUpdatedState(inApp)
    val ssoReauth by rememberUpdatedState(onSsoReauth)
    val firstLoad by rememberUpdatedState(loadStart)
    // The bridge's prompts live with the view: leaving the page cancels them.
    val bridgeScope = rememberCoroutineScope()
    val scripts = remember { arrayOfNulls<ScriptHandler>(1) }
    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { context ->
            WebView(context).apply {
                setBackgroundColor(bg)
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                settings.allowFileAccess = false
                settings.allowContentAccess = false
                settings.javaScriptCanOpenWindowsAutomatically = false
                settings.setSupportMultipleWindows(false)
                settings.mediaPlaybackRequiresUserGesture = true
                CookieManager.getInstance().setAcceptCookie(true)
                webChromeClient = object : WebChromeClient() {
                    override fun onProgressChanged(view: WebView?, newProgress: Int) = progress(newProgress)
                    override fun onReceivedTitle(view: WebView?, title: String?) = titleChanged(title)
                }
                webViewClient = ServerClient(origin, { native(it) }, { error() }, { urlChanged(it) }, { ssoReauth(it) })
                setDownloadListener { url, userAgent, contentDisposition, mimeType, _ ->
                    if (WebUrlPolicy.isSameOrigin(origin, url)) {
                        enqueueDownload(context, url, userAgent, contentDisposition, mimeType)
                    } else {
                        openOutside(context, url)
                    }
                }
                onCreated(this)
                // Before the first load, so the first document already has it.
                if (bridge != null) scripts[0] = installDeviceBridge(this, origin, bridge, bridgeScope)
                // [start] itself may be the page's re-authentication (SSO device keys): never loaded then.
                firstLoad(this)
            }
        },
        onRelease = { view ->
            scripts[0]?.let { handler ->
                runCatching { handler.remove() }
                if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                    runCatching { WebViewCompat.removeWebMessageListener(view, DeviceBridgeScript.CHANNEL) }
                }
                scripts[0] = null
            }
            view.stopLoading()
            view.setDownloadListener(null)
            view.destroy()
        },
    )
}

/** Applies [WebUrlPolicy] to every main-frame navigation. */
private class ServerClient(
    private val origin: String,
    private val inApp: (String) -> Boolean,
    private val onError: () -> Unit,
    private val onUrl: (String?) -> Unit,
    /** SSO device keys: the page's `/auth/sso-redirect?reauth=1` — stopped, handed to the app with its return path. */
    private val onSsoReauth: (returnPath: String) -> Unit,
) : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        if (!request.isForMainFrame) return false
        WebUrlPolicy.ssoReauthReturn(origin, request.url.toString())?.let { returnPath ->
            onSsoReauth(returnPath)
            return true
        }
        return when (val nav = WebUrlPolicy.classify(origin, request.url.toString(), inApp)) {
            WebNav.Stay -> false
            is WebNav.InApp -> true
            is WebNav.External -> {
                openOutside(view.context, nav.url)
                true
            }
            is WebNav.System -> {
                openSystem(view.context, nav.url)
                true
            }
            WebNav.Blocked -> true
        }
    }

    override fun onPageStarted(view: WebView, url: String?, favicon: Bitmap?) {
        // Belt and braces only: the server answers a re-authentication start with a 302, which
        // never commits, so this sees it only if a server ever renders that page. The page's own
        // navigation is stopped in shouldOverrideUrlLoading, the start URL before loading
        // (ObliWebView's loadStart), and the Obligate redirect of a missed one leaves as External.
        WebUrlPolicy.ssoReauthReturn(origin, url)?.let { returnPath ->
            view.stopLoading()
            onSsoReauth(returnPath)
            return
        }
        // A server redirect to another origin (never followed with the session).
        if (url != null && !WebUrlPolicy.isSameOrigin(origin, url)) {
            view.stopLoading()
            if (WebUrlPolicy.classify(origin, url) is WebNav.External) openOutside(view.context, url)
            return
        }
        onUrl(url)
    }

    override fun doUpdateVisitedHistory(view: WebView, url: String?, isReload: Boolean) {
        // Single-page app navigations (history.pushState) do not start a page.
        if (WebUrlPolicy.isSameOrigin(origin, url)) onUrl(url)
    }

    override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
        if (request.isForMainFrame) onError()
    }

    @SuppressLint("WebViewClientOnReceivedSslError")
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        // Never proceed on a bad certificate.
        handler.cancel()
        onError()
    }
}

private const val TAG = "ObliWebView"

/** Custom Tab (dark), then any browser; never with the session cookie. */
internal fun openOutside(context: Context, url: String) {
    if (Origins.of(url) == null) return
    val colors = CustomTabColorSchemeParams.Builder().setToolbarColor(TOOLBAR).setNavigationBarColor(TOOLBAR).build()
    val tab = CustomTabsIntent.Builder()
        .setColorScheme(CustomTabsIntent.COLOR_SCHEME_DARK)
        .setDefaultColorSchemeParams(colors)
        .setShowTitle(true)
        .build()
    try {
        tab.launchUrl(context, url.toUri())
    } catch (_: ActivityNotFoundException) {
        openSystem(context, url)
    }
}

private fun openSystem(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, url.toUri()).addCategory(Intent.CATEGORY_BROWSABLE).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(context, R.string.web_no_app, Toast.LENGTH_SHORT).show()
    }
}

/** Same-origin download through DownloadManager, carrying the WebView session cookie and user agent. */
private fun enqueueDownload(context: Context, url: String, userAgent: String?, contentDisposition: String?, mimeType: String?) {
    val dm = context.getSystemService(DownloadManager::class.java) ?: return
    val name = URLUtil.guessFileName(url, contentDisposition, mimeType).replace(Regex("[\\\\/:*?\"<>|]"), "_").ifBlank { "download" }
    val request = DownloadManager.Request(url.toUri())
        .setTitle(name)
        .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
    if (!userAgent.isNullOrBlank()) request.addRequestHeader("User-Agent", userAgent)
    CookieManager.getInstance().getCookie(url)?.takeIf { it.isNotBlank() }?.let { request.addRequestHeader("Cookie", it) }
    if (!mimeType.isNullOrBlank()) request.setMimeType(mimeType)
    // Public Downloads needs no permission from API 29; below, the app's own folder.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, name)
    } else {
        request.setDestinationInExternalFilesDir(context, Environment.DIRECTORY_DOWNLOADS, name)
    }
    try {
        dm.enqueue(request)
        Toast.makeText(context, context.getString(R.string.web_download_started, name), Toast.LENGTH_SHORT).show()
    } catch (e: RuntimeException) {
        Log.w(TAG, "download refused", e)
        Toast.makeText(context, R.string.web_download_failed, Toast.LENGTH_SHORT).show()
    }
}

private const val TOOLBAR = 0xFF0F1220.toInt()
