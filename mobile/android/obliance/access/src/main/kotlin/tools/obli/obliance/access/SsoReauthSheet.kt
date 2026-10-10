package tools.obli.obliance.access

import android.annotation.SuppressLint
import android.content.res.Resources
import android.graphics.Bitmap
import android.net.http.SslError
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import tools.obli.core.designsystem.ObliIcons
import tools.obli.core.designsystem.ObliTheme
import tools.obli.core.designsystem.ObliTokens
import tools.obli.core.designsystem.ObliTypography
import tools.obli.core.designsystem.toColor
import tools.obli.core.network.ApiOutcome
import tools.obli.core.security.SsoReauthResult
import tools.obli.obliance.api.AuthApi
import tools.obli.obliance.data.LocalObliServices
import tools.obli.obliance.data.ObliServices
import tools.obli.shell.nav.Origins

/*
 * SSO device keys: the native Obligate
 * re-authentication sheet. A full-screen WebView (tablet: 720 × 640 dialog,
 * like the Obligate sign-in sheet) on `<origin>/auth/sso-redirect?reauth=1&return=<path>`: Obligate
 * asks for the password and a TOTP code even with a live Obligate session,
 * then `/auth/callback` records the re-authentication on THIS session and
 * redirects to `<path>?reauth=ok` (or `?reauth=failed&reason=<code>`).
 *
 * - The WebView shares the process-wide CookieManager, i.e. the server
 *   session of the native HTTP client (WebCookieJar): the OAuth `state` and
 *   `pendingReauth` live in that session, so the round trip must stay here —
 *   never a Custom Tab.
 * - Only two origins may load in the main frame: the server's and the
 *   Obligate origin the server announces (`/api/auth/sso-config`). Anything
 *   else stops the sheet (`blocked`).
 * - Success is ONLY `<path>?reauth=ok` of the server's origin; that page is
 *   intercepted, never rendered, and the cookies are flushed.
 * - Failures show their reason in formal words, with « Réessayer » when a new
 *   attempt can help, and « Fermer ».
 */

/**
 * Mount ONCE at the app root (ObliNextApp): shows the re-authentications the
 * [tools.obli.obliance.data.SsoReauthBroker] of [LocalObliServices] asks for,
 * one at a time. Without a broker (previews, tests): nothing, and every
 * re-authentication fails closed.
 */
@Composable
fun SsoReauthHost() {
    val broker = LocalObliServices.current.ssoReauth ?: return
    DisposableEffect(broker) {
        val detach = broker.attachHost()
        onDispose { detach() }
    }
    val request by broker.request.collectAsState()
    val r = request ?: return
    key(r) {
        SsoReauthSheet(origin = r.origin, returnPath = r.returnPath, onResult = r::complete)
    }
}

/** Where the sheet is. */
internal sealed interface ReauthPhase {
    /** Reading the server's sso-config (the Obligate origin of the allow-list). */
    data object Preparing : ReauthPhase

    /** The web round trip, allowed on [obligateOrigin] and the server's origin only. */
    data class Web(val obligateOrigin: String) : ReauthPhase

    /** Stopped; [reason] as [SsoReauthResult.Failed] gives it. */
    data class Failed(val reason: String) : ReauthPhase
}

/**
 * The sheet for the session of [origin]. [onResult] is called exactly once:
 * [SsoReauthResult.Success] on `<returnPath>?reauth=ok`, [SsoReauthResult.Cancelled]
 * when the user closes it (or cancelled at Obligate), [SsoReauthResult.Failed]
 * when a failure is closed.
 */
@Composable
internal fun SsoReauthSheet(origin: String, returnPath: String, onResult: (SsoReauthResult) -> Unit) {
    val services = LocalObliServices.current
    var finished by remember { mutableStateOf(false) }
    val finish: (SsoReauthResult) -> Unit = { result ->
        if (!finished) {
            finished = true
            onResult(result)
        }
    }
    val safeReturn = remember(returnPath) { SsoNavigation.reauthReturnPath(returnPath) }
    var attempt by remember { mutableIntStateOf(0) }
    var phase by remember { mutableStateOf<ReauthPhase>(ReauthPhase.Preparing) }
    LaunchedEffect(attempt) {
        phase = ReauthPhase.Preparing
        phase = when (val cfg = SsoNavigation.reauthConfig(origin, readSsoConfig(services, origin))) {
            is ReauthConfig.Ready -> ReauthPhase.Web(cfg.obligateOrigin)
            is ReauthConfig.Refused -> ReauthPhase.Failed(cfg.reason)
        }
    }
    // The session ended meanwhile (`signed_out`, sent to /login): /me tells the app, so the sign-in-again sheet
    // shows when the sheet closes (the runner then reports SessionExpired).
    LaunchedEffect(phase) {
        val p = phase
        if (p is ReauthPhase.Failed && SsoReauthResult.Failed.endsSession(p.reason)) {
            services.sessions.byOrigin(origin)?.probe()
        }
    }
    val cancel = { finish(SsoReauthResult.Cancelled) }
    // Closing (X, back, outside) while a failure is shown reports that failure, never a plain cancel.
    val close = {
        val p = phase
        if (p is ReauthPhase.Failed) finish(SsoReauthResult.Failed(p.reason)) else cancel()
    }
    Dialog(onDismissRequest = close, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        BoxWithConstraints(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            val wide = maxWidth >= 720.dp && maxHeight >= 640.dp
            var progress by remember { mutableIntStateOf(0) }
            var host by remember { mutableStateOf(Origins.host(origin) ?: origin) }
            var webView by remember { mutableStateOf<WebView?>(null) }
            BackHandler {
                val view = webView
                if (phase is ReauthPhase.Web && view != null && view.canGoBack()) view.goBack() else close()
            }
            SsoReauthFrame(
                phase = phase,
                host = host,
                progress = progress,
                onCancel = close,
                onClose = { reason -> finish(SsoReauthResult.Failed(reason)) },
                onRetry = { attempt++ },
                modifier = if (wide) Modifier.size(720.dp, 640.dp).clip(CardShape) else Modifier.fillMaxSize(),
            ) { web ->
                key(attempt) {
                    ReauthWebView(
                        origin = origin,
                        obligateOrigin = web.obligateOrigin,
                        returnPath = safeReturn,
                        onProgress = { progress = it },
                        onHost = { host = it },
                        onStep = { step ->
                            when (step) {
                                ReauthStep.Success -> finish(SsoReauthResult.Success)
                                // Cancelled at Obligate (the server's `cancelled`): a cancel, not an error to explain.
                                is ReauthStep.Failed -> if (step.reason == SsoNavigation.REAUTH_CANCELLED) cancel() else phase = ReauthPhase.Failed(step.reason)
                                ReauthStep.Blocked -> phase = ReauthPhase.Failed(SsoNavigation.REAUTH_BLOCKED)
                                ReauthStep.Continue -> Unit
                            }
                        },
                        onCreated = { webView = it },
                    )
                }
            }
        }
    }
}

/** `GET /api/auth/sso-config` of [origin]'s session; null when it cannot be read. */
private suspend fun readSsoConfig(services: ObliServices, origin: String) =
    services.sessions.byOrigin(origin)?.http?.let { http -> (AuthApi(http).ssoConfig() as? ApiOutcome.Ok)?.value }

/**
 * The sheet's chrome and its non-web states (JVM-captured): [SsoFrame] titled
 * « Reconfirmer avec Obligate », then the preparation, the [web] content, or
 * the failure with its reason (« Réessayer » when it can help, « Fermer »).
 */
@Composable
internal fun SsoReauthFrame(
    phase: ReauthPhase,
    host: String,
    progress: Int,
    onCancel: () -> Unit,
    onClose: (reason: String) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    web: @Composable (ReauthPhase.Web) -> Unit = {},
) {
    SsoFrame(
        host = host,
        progress = if (phase is ReauthPhase.Web) progress else 100,
        onCancel = onCancel,
        modifier = modifier,
        title = stringResource(R.string.access_ssoreauth_title),
    ) {
        when (phase) {
            ReauthPhase.Preparing -> ReauthPreparing()
            is ReauthPhase.Web -> web(phase)
            is ReauthPhase.Failed -> ReauthFailure(phase.reason, onClose = { onClose(phase.reason) }, onRetry = onRetry)
        }
    }
}

@Composable
private fun ReauthPreparing() {
    val c = ObliTheme.colors
    Column(
        Modifier.fillMaxSize().background(c.bg).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator(Modifier.size(28.dp), color = c.text2, strokeWidth = 2.dp)
        Text(stringResource(R.string.access_ssoreauth_preparing), style = ObliTypography.body, color = c.text2, textAlign = TextAlign.Center)
    }
}

@Composable
private fun ReauthFailure(reason: String, onClose: () -> Unit, onRetry: () -> Unit) {
    val c = ObliTheme.colors
    val res = LocalResources.current
    Box(Modifier.fillMaxSize().background(c.bg), contentAlignment = Alignment.TopCenter) {
        Column(
            Modifier.widthIn(max = 480.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Icon(ObliIcons.CircleAlert, contentDescription = null, tint = ObliTokens.Status.WARNING.argb.toColor(), modifier = Modifier.size(28.dp))
            Text(stringResource(R.string.access_ssoreauth_failed_title), style = ObliTypography.dialogTitle, color = c.text, modifier = Modifier.semantics { heading() })
            Text(
                reauthReasonText(res, reason),
                style = ObliTypography.body,
                color = c.text2,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            if (SsoNavigation.canRetryReauth(reason)) {
                PrimaryButton(stringResource(R.string.access_ssoreauth_retry), onRetry, icon = ObliIcons.RefreshCw)
                NeutralButton(stringResource(R.string.access_ssoreauth_close), onClose)
            } else {
                NeutralButton(stringResource(R.string.access_ssoreauth_close), onClose)
            }
        }
    }
}

/** The formal sentence of a failure [reason] (server codes of obligateCallback.routes.ts, and the sheet's own). */
internal fun reauthReasonText(res: Resources, reason: String): String = res.getString(
    when (reason) {
        "no_otp" -> R.string.access_ssoreauth_reason_no_otp
        "identity" -> R.string.access_ssoreauth_reason_identity
        "stale_auth" -> R.string.access_ssoreauth_reason_stale_auth
        "unsupported" -> R.string.access_ssoreauth_reason_unsupported
        "verifier_unavailable" -> R.string.access_ssoreauth_reason_verifier_unavailable
        "unreachable" -> R.string.access_ssoreauth_reason_unreachable
        "origin" -> R.string.access_ssoreauth_reason_origin
        "expired" -> R.string.access_ssoreauth_reason_expired
        "signed_out", SsoNavigation.REAUTH_LOGIN -> R.string.access_ssoreauth_reason_signed_out
        "state" -> R.string.access_ssoreauth_reason_state
        "exchange" -> R.string.access_ssoreauth_reason_exchange
        "not_sso" -> R.string.access_ssoreauth_reason_not_sso
        "misconfigured" -> R.string.access_ssoreauth_reason_misconfigured
        SsoNavigation.REAUTH_BLOCKED -> R.string.access_ssoreauth_reason_blocked
        SsoNavigation.REAUTH_PAGE_ERROR -> R.string.access_ssoreauth_reason_page_error
        SsoNavigation.REAUTH_TLS -> R.string.access_ssoreauth_reason_tls
        SsoNavigation.REAUTH_CONFIG -> R.string.access_ssoreauth_reason_config
        // `error`, `unexpected`, and any code this app does not know yet.
        else -> R.string.access_ssoreauth_reason_generic
    },
)

@SuppressLint("SetJavaScriptEnabled")
@Composable
private fun ReauthWebView(
    origin: String,
    obligateOrigin: String,
    returnPath: String,
    onProgress: (Int) -> Unit,
    onHost: (String) -> Unit,
    onStep: (ReauthStep) -> Unit,
    onCreated: (WebView) -> Unit,
) {
    val step by rememberUpdatedState(onStep)
    val progress by rememberUpdatedState(onProgress)
    val hostChanged by rememberUpdatedState(onHost)
    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { context ->
            WebView(context).apply {
                // Obligate's sign-in page is a JavaScript application; nothing else is loaded here.
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                settings.allowFileAccess = false
                settings.allowContentAccess = false
                settings.javaScriptCanOpenWindowsAutomatically = false
                settings.setSupportMultipleWindows(false)
                // The server session of the native client (WebCookieJar reads this store).
                CookieManager.getInstance().setAcceptCookie(true)
                webChromeClient = object : WebChromeClient() {
                    override fun onProgressChanged(view: WebView?, newProgress: Int) = progress(newProgress)
                }
                webViewClient = ReauthClient(origin, obligateOrigin, returnPath, { step(it) }, { hostChanged(it) })
                onCreated(this)
                loadUrl(SsoNavigation.reauthStartUrl(origin, returnPath))
            }
        },
        onRelease = { view ->
            view.stopLoading()
            view.destroy()
        },
    )
}

/** Applies [SsoNavigation.classifyReauth] to every main-frame navigation; reports the first terminal step once. */
private class ReauthClient(
    private val origin: String,
    private val obligateOrigin: String,
    private val returnPath: String,
    private val onStep: (ReauthStep) -> Unit,
    private val onHost: (String) -> Unit,
) : WebViewClient() {
    private var done = false

    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        if (!request.isForMainFrame) return false
        return intercept(request.url.toString())
    }

    override fun onPageStarted(view: WebView, url: String?, favicon: Bitmap?) {
        if (intercept(url)) {
            view.stopLoading()
            return
        }
        Origins.host(url)?.let(onHost)
    }

    override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
        if (request.isForMainFrame) finish(ReauthStep.Failed(SsoNavigation.REAUTH_PAGE_ERROR))
    }

    @SuppressLint("WebViewClientOnReceivedSslError")
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        // Never proceed on a bad certificate.
        handler.cancel()
        finish(ReauthStep.Failed(SsoNavigation.REAUTH_TLS))
    }

    /** True when the navigation must not load: the flow ended (never rendered), or a page outside the allow-list. */
    private fun intercept(url: String?): Boolean {
        if (done) return true
        return when (val s = SsoNavigation.classifyReauth(origin, url, returnPath, obligateOrigin)) {
            ReauthStep.Continue -> false
            ReauthStep.Success -> {
                // The re-authentication is on the server session: persist its cookie before the native calls.
                runCatching { CookieManager.getInstance().flush() }
                finish(s)
                true
            }
            is ReauthStep.Failed, ReauthStep.Blocked -> {
                finish(s)
                true
            }
        }
    }

    private fun finish(step: ReauthStep) {
        if (done) return
        done = true
        onStep(step)
    }
}
