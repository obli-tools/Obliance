package tools.obli.obliance.remote

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.MutableContextWrapper
import android.graphics.Bitmap
import android.net.Uri
import android.net.http.SslError
import android.util.Log
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.CookieManager
import android.webkit.RenderProcessGoneDetail
import android.webkit.SslErrorHandler
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.net.toUri
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tools.obli.core.designsystem.ObliIconButton
import tools.obli.core.designsystem.ObliIcons
import tools.obli.core.designsystem.ObliTheme
import tools.obli.core.designsystem.ObliTypography
import tools.obli.core.model.ServerId
import tools.obli.core.network.ApiOutcome
import tools.obli.core.security.SsoReauthResult
import tools.obli.core.webfallback.WebReauthOutcome
import tools.obli.core.webfallback.WebUrlPolicy
import tools.obli.obliance.api.Device
import tools.obli.obliance.data.LocalObliServices
import tools.obli.obliance.data.SsoReauthBroker

/**
 * ObliReach through the WEB viewer.
 *
 * The web has no route for the viewer: `ObliReachViewer` is a modal of the
 * device page (`/devices/:id`), opened by the header « Remote › Oblireach »
 * button (or the Remote tab's « Reach »), which itself calls
 * `POST /api/remote/sessions {protocol:'oblireach', sessionId}` and hands the
 * token to the viewer. So this screen opens `/devices/:id?remote=reach` (the
 * page then opens the viewer by itself; older servers ignore the parameter and
 * the hint tells where to tap) of the device's
 * server full screen, in a WebView sharing the process cookie session (the
 * session token then belongs to the same user, as the relay requires), and
 * tells the user where to tap. The WebView is kept by the [SessionManager]:
 * back REDUCES (the stream keeps running, pill + notification), « Terminer »
 * destroys it, which closes the viewer's tunnel (the relay ends the session).
 *
 * SSO device keys: the page's « Reconfirmer avec Obligate » (`/auth/sso-redirect?reauth=1`,
 * a code in a bound session of an Obligate account) never loads in this
 * WebView nor leaves for a browser (neither has the OAuth state): the app's
 * native Obligate sheet runs, then the page is loaded on
 * `<return>?reauth=ok|failed&reason=…`, as in the web bridge.
 */
@Composable
fun ReachScreen(serverId: ServerId, deviceId: Long, onClose: () -> Unit, modifier: Modifier = Modifier) {
    val services = LocalObliServices.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val server = services.sessions.session(serverId)
    val origin = server?.http?.origin
    var label by rememberSaveable { mutableStateOf("#$deviceId") }
    var tenant by rememberSaveable { mutableStateOf<String?>(null) }
    var hintVisible by rememberSaveable { mutableStateOf(true) }

    androidx.compose.runtime.LaunchedEffect(serverId, deviceId) {
        SessionManager.bind(context)
        (services.devices.detail(serverId, deviceId) as? ApiOutcome.Ok<Device>)?.value?.let {
            label = it.label
            tenant = it.tenantName
        }
    }

    val session = remember(serverId, deviceId, origin) {
        if (origin == null) null else ReachSession.obtain(context, serverId, deviceId, origin)
    }
    // Every time: a session kept by the SessionManager gets the app's current broker.
    session?.useSsoReauth(services.ssoReauth)
    androidx.compose.runtime.LaunchedEffect(session, label, tenant) { session?.describe(label, tenant) }

    SecureImmersive()
    // Back reduces: the viewer keeps streaming.
    BackHandler { onClose() }

    ReachFrame(
        deviceLabel = label,
        showHint = hintVisible,
        onDismissHint = { hintVisible = false },
        onMinimize = onClose,
        onEnd = {
            scope.launch {
                session?.terminate()
                onClose()
            }
        },
        modifier = modifier,
    ) {
        when {
            session == null -> Box(Modifier.fillMaxSize().background(ObliTheme.colors.bg))
            LocalInspectionMode.current -> Box(Modifier.fillMaxSize().background(ObliTheme.colors.bg))
            else -> AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx -> session.attach(ctx) },
                onRelease = { session.detach() },
            )
        }
    }
}

/** Chrome of the web viewer screen: « ← PC-COMPTA-03 · Visionneuse web · Terminer », the hint, then the page. */
@Composable
internal fun ReachFrame(
    deviceLabel: String,
    showHint: Boolean,
    onDismissHint: () -> Unit,
    onMinimize: () -> Unit,
    onEnd: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    val c = ObliTheme.colors
    Column(modifier.fillMaxSize().background(c.bg)) {
        Row(
            Modifier.fillMaxWidth().height(56.dp).background(c.chrome).padding(horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            ObliIconButton(ObliIcons.ArrowLeft, stringResource(R.string.remote_minimize), onMinimize, tint = c.text)
            Column(Modifier.weight(1f)) {
                Text(deviceLabel, style = ObliTypography.rowTitle, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(stringResource(R.string.remote_reach_web_viewer), style = ObliTypography.labelSmall, color = c.textMuted, maxLines = 1)
            }
            Box(
                Modifier.heightIn(min = 48.dp).clip(RoundedCornerShape(8.dp)).clickable(role = Role.Button, onClick = onEnd).padding(horizontal = 12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(stringResource(R.string.remote_end), style = ObliTypography.label, color = c.accentText)
            }
        }
        if (showHint) {
            Row(
                Modifier.fillMaxWidth().background(c.surface1).padding(start = 16.dp, end = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(R.string.remote_reach_hint),
                    style = ObliTypography.body,
                    color = c.text2,
                    modifier = Modifier.weight(1f).padding(vertical = 10.dp),
                )
                ObliIconButton(ObliIcons.X, stringResource(R.string.remote_reach_hint_dismiss), onDismissHint)
            }
        }
        Box(Modifier.weight(1f).fillMaxWidth()) { content() }
    }
}

/** FLAG_SECURE (never in screenshots or the recents thumbnail) and immersive system bars while shown. */
@Composable
internal fun SecureImmersive(immersive: Boolean = true) {
    val context = LocalContext.current
    DisposableEffect(context) {
        val activity = context.findActivity()
        val window = activity?.window
        // Only clear what this screen set: the flag may already be on (security setting « Bloquer les
        // captures d'écran partout », another secure screen), and must stay on then.
        val alreadySecure = window != null && window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        if (window != null && !alreadySecure) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val controller = window?.let { WindowCompat.getInsetsController(it, it.decorView) }
        if (immersive) {
            controller?.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            controller?.hide(WindowInsetsCompat.Type.systemBars())
        }
        onDispose {
            if (immersive) controller?.show(WindowInsetsCompat.Type.systemBars())
            if (window != null && !alreadySecure) window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

internal tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

/**
 * The web viewer of one device, kept alive across navigation and rotation:
 * the WebView lives here (on a [MutableContextWrapper] re-pointed at the
 * current activity while shown, at the application otherwise).
 */
internal class ReachSession private constructor(
    override val id: String,
    override val serverId: ServerId,
    override val deviceId: Long,
    private val origin: String,
    private val appContext: Context,
) : RemoteEntry {
    override val protocol: String = "oblireach"
    @Volatile override var deviceLabel: String = "#$deviceId"
        private set
    @Volatile override var tenantName: String? = null
        private set
    private val _phase = MutableStateFlow<SessionPhase>(SessionPhase.Connected(System.currentTimeMillis()))
    override val phase: StateFlow<SessionPhase> = _phase
    private val wrapper = MutableContextWrapper(appContext)
    private var webView: WebView? = null

    /** SSO device keys: the app's Obligate re-authentication; null: the page is told `unsupported`. */
    @Volatile private var ssoReauth: SsoReauthBroker? = null

    /** Lives with the session (a re-authentication survives a reduced viewer), cancelled by [terminate]. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val reauthRunning = AtomicBoolean(false)

    fun useSsoReauth(broker: SsoReauthBroker?) {
        ssoReauth = broker
    }

    /**
     * Main thread. The page's `/auth/sso-redirect?reauth=1&return=[returnPath]`:
     * the native sheet on this session (one at a time), then the page on
     * `<origin>[returnPath]?reauth=ok|failed&reason=…` (its TwoFactorGate reports it).
     */
    private fun startSsoReauth(returnPath: String) {
        if (!reauthRunning.compareAndSet(false, true)) return
        scope.launch {
            val outcome = try {
                when (val r = ssoReauth?.reauthenticate(origin, returnPath)) {
                    null -> WebReauthOutcome(false, "unsupported")
                    SsoReauthResult.Success -> WebReauthOutcome(true)
                    SsoReauthResult.Cancelled -> WebReauthOutcome(false, "cancelled")
                    is SsoReauthResult.Failed -> WebReauthOutcome(false, r.reason)
                }
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

    fun describe(label: String, tenant: String?) {
        deviceLabel = label
        tenantName = tenant
    }

    /** Main thread. */
    @SuppressLint("SetJavaScriptEnabled")
    fun attach(context: Context): WebView {
        wrapper.baseContext = context
        webView?.let { existing ->
            (existing.parent as? ViewGroup)?.removeView(existing)
            return existing
        }
        return WebView(wrapper).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.setSupportMultipleWindows(false)
            settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            CookieManager.getInstance().setAcceptCookie(true)
            webViewClient = ReachClient(origin, onSsoReauth = { startSsoReauth(it) }, onRendererGone = ::rendererGone)
            loadUrl("$origin/devices/$deviceId?remote=reach")
        }.also { webView = it }
    }

    /**
     * Main thread. The page's renderer died (crash, or killed for memory):
     * this WebView is unusable and the viewer's tunnel went with it (the relay
     * ends the session). Handled, so the app is not killed with the renderer.
     */
    private fun rendererGone(view: WebView) {
        if (webView !== view) return
        (view.parent as? ViewGroup)?.removeView(view)
        view.destroy()
        webView = null
        scope.cancel()
        _phase.value = SessionPhase.Ended(EndReason.CONNECTION_LOST)
        SessionManager.remove(id)
    }

    /** The view leaves the screen (reduce, rotation): keep it, forget the activity. */
    fun detach() {
        webView?.let { (it.parent as? ViewGroup)?.removeView(it) }
        wrapper.baseContext = appContext
    }

    override fun lastLine(): String = ""

    override suspend fun terminate(): ApiOutcome<Unit> {
        scope.cancel()
        withContext(Dispatchers.Main) {
            webView?.let { view ->
                (view.parent as? ViewGroup)?.removeView(view)
                view.stopLoading()
                // Unloading the page closes the viewer's tunnel: the relay ends the session.
                view.loadUrl("about:blank")
                view.destroy()
            }
            webView = null
        }
        _phase.value = SessionPhase.Ended(EndReason.ENDED_BY_USER)
        SessionManager.remove(id)
        return ApiOutcome.Ok(Unit)
    }

    companion object {
        fun obtain(context: Context, serverId: ServerId, deviceId: Long, origin: String): ReachSession {
            SessionManager.entries.value.filterIsInstance<ReachSession>()
                .firstOrNull { it.serverId == serverId && it.deviceId == deviceId && it.phase.value.isLive }
                ?.let { return it }
            val session = ReachSession("reach-${serverId.value}-$deviceId-${System.nanoTime()}", serverId, deviceId, origin, context.applicationContext)
            SessionManager.bind(context)
            SessionManager.add(session)
            return session
        }
    }
}

private const val TAG = "ReachScreen"

/**
 * Same-origin pages stay inside; other links open outside, never with the
 * session. The page's Obligate re-authentication (SSO device keys) is stopped and
 * handed to [onSsoReauth] with its return path, BEFORE the same-origin rule:
 * followed, the server's 302 to Obligate would leave for the browser.
 *
 * onRenderProcessGone IS implemented (below); the suppression covers the
 * webkit detector's second report, on the Kotlin supertype call
 * `: WebViewClient()`, which it reads as a plain WebViewClient instance.
 */
@SuppressLint("MissingOnRenderProcessGone")
private class ReachClient(
    private val origin: String,
    private val onSsoReauth: (returnPath: String) -> Unit,
    private val onRendererGone: (WebView) -> Unit,
) : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        if (!request.isForMainFrame) return false
        WebUrlPolicy.ssoReauthReturn(origin, request.url.toString())?.let { returnPath ->
            onSsoReauth(returnPath)
            return true
        }
        val url = request.url
        if (url.scheme == "https" && "${url.scheme}://${url.authority}" == origin) return false
        if (url.scheme == "https" || url.scheme == "http") {
            try {
                view.context.startActivity(Intent(Intent.ACTION_VIEW, url.toString().toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            } catch (_: ActivityNotFoundException) {
                // Nothing to open it with.
            }
        }
        return true
    }

    override fun onPageStarted(view: WebView, url: String?, favicon: Bitmap?) {
        // Belt and braces (a 302 never commits): only if a server ever renders that page.
        WebUrlPolicy.ssoReauthReturn(origin, url)?.let { returnPath ->
            view.stopLoading()
            onSsoReauth(returnPath)
            return
        }
        val u = url?.let(Uri::parse) ?: return
        if (u.scheme != "about" && "${u.scheme}://${u.authority}" != origin) view.stopLoading()
    }

    @SuppressLint("WebViewClientOnReceivedSslError")
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        handler.cancel()
    }

    override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
        onRendererGone(view)
        return true
    }
}
