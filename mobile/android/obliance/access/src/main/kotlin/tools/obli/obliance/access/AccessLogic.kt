package tools.obli.obliance.access

import java.net.URI
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import tools.obli.core.auth.AuthState
import tools.obli.core.auth.ServerRegistry
import tools.obli.core.realtime.ConnectionState
import tools.obli.core.security.SsoReauthResult
import tools.obli.obliance.api.SsoConfig
import tools.obli.obliance.data.FeedStatus
import tools.obli.obliance.data.ServerFeed
import tools.obli.shell.nav.Origins

/*
 * Pure logic of the access screens (no Compose, no Android): unit-tested on the JVM.
 */

/** Display name suggested for a new server ("prérempli par le nom de l'instance ou l'hôte"). */
internal object ServerNames {
    private val ipv4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    /**
     * "https://obliance-dev.example.org" → "Obliance Dev": the first DNS label,
     * split on '-' / '_', each word capitalised. IP addresses and hosts without
     * a usable first label are kept as they are.
     */
    fun suggest(origin: String): String {
        val host = Origins.host(origin) ?: return origin.take(ServerRegistry.MAX_NAME)
        if (host.startsWith("[") || ipv4.matches(host)) return host
        val words = host.substringBefore('.').split('-', '_').filter { it.isNotEmpty() }
        if (words.isEmpty()) return host.take(ServerRegistry.MAX_NAME)
        return words.joinToString(" ") { w -> w.replaceFirstChar { it.uppercaseChar() } }.take(ServerRegistry.MAX_NAME)
    }

    /** Host of an origin for display ("obliance-prod.example.org", port kept when not default). */
    fun hostOf(origin: String): String = origin.substringAfter("://")
}

/** A 6-digit second-factor code found in a pasted text ("482913", "482 913", "Code: 482-913"). */
internal object OtpCodes {
    const val LENGTH = 6

    fun fromText(text: CharSequence?): String? {
        if (text.isNullOrBlank() || text.length > 64) return null
        val digits = text.filter { it.isDigit() }
        return digits.takeIf { it.length == LENGTH }?.toString()
    }

    /** Keeps what a code field accepts: digits only, at most [LENGTH]. */
    fun sanitize(input: String): String = input.filter { it.isDigit() }.take(LENGTH)

    /** "482913" → "482 913" (chip label). */
    fun grouped(code: String): String = if (code.length == LENGTH) code.substring(0, 3) + " " + code.substring(3) else code
}

/** Where the Obligate sign-in WebView is, for one navigation of its main frame. */
internal sealed interface SsoStep {
    /** Let the WebView load it (Obligate pages, `/auth/sso-redirect`, `/auth/callback?code=…`). */
    data object Continue : SsoStep

    /** Back on the server outside `/auth` and `/login`: the session cookie is set, close the sheet. */
    data object SignedIn : SsoStep

    data class Failed(val reason: SsoFailure) : SsoStep

    /** Never loaded (cleartext http, intent:, javascript:, file:…). */
    data object Blocked : SsoStep
}

internal enum class SsoFailure {
    /** `/login?error=sso_failed`, or Obligate came back without a code (cancelled, refused). */
    FAILED,

    /** `/login?error=sso_misconfigured`. */
    MISCONFIGURED,

    /** `/login` without error: Obligate is not configured on this server any more. */
    NOT_CONFIGURED,

    /** The page could not be loaded (network error on the main frame). */
    PAGE_ERROR,

    /** The HTTPS certificate of a page was refused. */
    TLS,
}

/**
 * Navigation rules of the Obligate WebView (server/src/routes/obligateCallback.routes.ts):
 * `/auth/sso-redirect` → Obligate `/authorize` → `/auth/callback?code&state` →
 * (meta refresh) `/` on success, or `/login?error=sso_failed|sso_misconfigured`.
 * The flow must stay in the WebView: the OAuth `state` lives in the server session.
 */
internal object SsoNavigation {
    const val START_PATH = "/auth/sso-redirect"
    private const val CALLBACK_PATH = "/auth/callback"

    fun startUrl(origin: String): String = origin + START_PATH

    fun classify(origin: String, url: String?): SsoStep {
        if (url.isNullOrBlank()) return SsoStep.Continue
        val scheme = Origins.scheme(url)
        if (scheme == "about") return SsoStep.Continue
        if (scheme != "https") return SsoStep.Blocked
        val urlOrigin = Origins.of(url) ?: return SsoStep.Blocked
        if (urlOrigin != origin) return SsoStep.Continue
        val uri = try {
            URI(url.trim())
        } catch (_: Exception) {
            return SsoStep.Continue
        }
        val path = uri.rawPath.orEmpty().ifEmpty { "/" }
        val query = uri.rawQuery.orEmpty()
        return when {
            path == CALLBACK_PATH -> if (param(query, "code").isNullOrEmpty()) SsoStep.Failed(SsoFailure.FAILED) else SsoStep.Continue
            path.startsWith("/auth/") || path == "/auth" -> SsoStep.Continue
            path == "/login" || path.startsWith("/login/") -> when (param(query, "error")) {
                null, "" -> SsoStep.Failed(SsoFailure.NOT_CONFIGURED)
                "sso_misconfigured" -> SsoStep.Failed(SsoFailure.MISCONFIGURED)
                else -> SsoStep.Failed(SsoFailure.FAILED)
            }
            else -> SsoStep.SignedIn
        }
    }

    private fun param(query: String, name: String): String? =
        query.split('&').firstOrNull { it.substringBefore('=') == name }?.substringAfter('=', "")

    // --- SSO device keys: Obligate re-authentication of a signed-in Obligate session ----------------------
    //
    // The sheet (SsoReauthSheet) runs it for the action host (`codeRequiresReauth`), the profile and security screen (SSO
    // enrolment) and the web view. It must NOT reuse [classify]: the server never sends it
    // to /login but back to `<return>?reauth=ok|failed&reason=…`, which [classify] would read
    // as a sign-in (a cancelled or foreign Obligate identity would then look like a success).
    // And unlike the sign-in sheet, only TWO origins may load: the server's and the Obligate
    // origin the server announces (`GET /api/auth/sso-config` → `obligateUrl`).

    /**
     * The Obligate origin of the allow-list, from the server's `obligateUrl`:
     * an https origin that is not the server's own; null otherwise (the
     * re-authentication then does not start).
     */
    fun reauthObligateOrigin(serverOrigin: String, obligateUrl: String?): String? {
        val url = obligateUrl?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        if (Origins.scheme(url) != "https") return null
        val o = Origins.of(url) ?: return null
        return o.takeIf { it != serverOrigin }
    }

    /**
     * The server's `reauthReturnPath` (obligateCallback.routes.ts): a plain
     * same-origin path, else `/`. Stricter than the server on one point: no
     * `.` / `..` segment (`/x/../auth/callback` would pass the prefix test,
     * then be normalised to `/auth/callback` by the WebView, and the success
     * page would never be recognised).
     */
    fun reauthReturnPath(raw: String): String {
        if (raw.length > 200 || !REAUTH_PATH.matches(raw)) return "/"
        if (REAUTH_FORBIDDEN.containsMatchIn(raw) || REAUTH_DOT_SEGMENT.containsMatchIn(raw)) return "/"
        return raw
    }

    /**
     * `/auth/sso-redirect?reauth=1&return=<path>`: the whole round trip stays
     * in the sheet's WebView. The path is [reauthReturnPath]'s (only
     * `A-Za-z0-9-._~/`: nothing to encode in a query).
     */
    fun reauthStartUrl(origin: String, returnPath: String): String =
        "$origin$START_PATH?reauth=1&return=" + reauthReturnPath(returnPath)

    /**
     * Where a re-authentication stands: the pages of [obligateOrigin] and the
     * server's `/auth/…` continue; back on [returnPath] with `reauth=ok` is the
     * only success; `reauth=failed` (with its `reason`), `/login` or any other
     * page of the server is a failure; ANY other origin (or scheme) is
     * [ReauthStep.Blocked] — the sheet then fails (`blocked`), never loads it.
     */
    fun classifyReauth(origin: String, url: String?, returnPath: String, obligateOrigin: String?): ReauthStep {
        if (url.isNullOrBlank()) return ReauthStep.Continue
        val scheme = Origins.scheme(url)
        if (scheme == "about") return if (url.trim().equals("about:blank", ignoreCase = true)) ReauthStep.Continue else ReauthStep.Blocked
        if (scheme != "https") return ReauthStep.Blocked
        val urlOrigin = Origins.of(url) ?: return ReauthStep.Blocked
        if (urlOrigin != origin) return if (obligateOrigin != null && urlOrigin == obligateOrigin) ReauthStep.Continue else ReauthStep.Blocked
        val uri = try {
            URI(url.trim())
        } catch (_: Exception) {
            return ReauthStep.Failed(REAUTH_UNEXPECTED)
        }
        val path = uri.rawPath.orEmpty().ifEmpty { "/" }
        val query = uri.rawQuery.orEmpty()
        return when {
            path.startsWith("/auth/") || path == "/auth" -> ReauthStep.Continue
            path == "/login" || path.startsWith("/login/") -> ReauthStep.Failed(REAUTH_LOGIN)
            path != reauthReturnPath(returnPath) -> ReauthStep.Failed(REAUTH_UNEXPECTED)
            else -> when (param(query, "reauth")) {
                "ok" -> ReauthStep.Success
                "failed" -> ReauthStep.Failed(param(query, "reason")?.takeIf { REASON.matches(it) } ?: "failed")
                else -> ReauthStep.Failed(REAUTH_UNEXPECTED)
            }
        }
    }

    const val REAUTH_UNEXPECTED = "unexpected"

    /** App-side failure reasons of the sheet (the server's are listed in core:security `SsoReauthResult.Failed`). */
    const val REAUTH_BLOCKED = "blocked"
    const val REAUTH_LOGIN = "login"
    const val REAUTH_PAGE_ERROR = "page_error"
    const val REAUTH_TLS = "tls"

    /** `GET /api/auth/sso-config` unreadable, or Obligate not announced: nothing to allow-list. */
    const val REAUTH_CONFIG = "config"

    /** The server's `reason` when Obligate answered with an error (the user cancelled there): a cancel, not a failure. */
    const val REAUTH_CANCELLED = "cancelled"

    /**
     * False for the failures a new attempt cannot fix (the sheet then offers
     * « Fermer » only). One list for the sheet and the profile and security screen:
     * [SsoReauthResult.Failed.canRetry].
     */
    fun canRetryReauth(reason: String): Boolean = SsoReauthResult.Failed.canRetry(reason)

    /**
     * The allow-list of a re-authentication from the server's
     * `/api/auth/sso-config` ([config] null: unreadable): Obligate must be
     * enabled and reachable, at an https origin other than the server's.
     */
    fun reauthConfig(serverOrigin: String, config: SsoConfig?): ReauthConfig = when {
        config == null -> ReauthConfig.Refused(REAUTH_CONFIG)
        !config.obligateEnabled -> ReauthConfig.Refused("unsupported")
        !config.obligateReachable -> ReauthConfig.Refused("unreachable")
        else -> reauthObligateOrigin(serverOrigin, config.obligateUrl)?.let { ReauthConfig.Ready(it) } ?: ReauthConfig.Refused(REAUTH_CONFIG)
    }
    private val REAUTH_PATH = Regex("^/(?![/\\\\])[A-Za-z0-9\\-._~/]*$")
    private val REAUTH_FORBIDDEN = Regex("^/(auth|api|login)(/|$)")
    private val REAUTH_DOT_SEGMENT = Regex("(^|/)\\.{1,2}(/|$)")
    private val REASON = Regex("^[a-z_]{1,32}$")
}

/** Where the Obligate re-authentication of a bound SSO session stands (SSO device keys). */
internal sealed interface ReauthStep {
    /** Obligate's pages, or the server's `/auth/…` steps: keep loading. */
    data object Continue : ReauthStep

    /** Back on the return path with `reauth=ok`: the server recorded the re-authentication. */
    data object Success : ReauthStep

    /** `reauth=failed&reason=…` (cancelled, identity, state…), `/login`, or an unexpected page. */
    data class Failed(val reason: String) : ReauthStep

    /** Never loaded (cleartext http, intent:, javascript:, file:…). */
    data object Blocked : ReauthStep
}

/** What the server's sso-config allows for a re-authentication. */
internal sealed interface ReauthConfig {
    /** Start: only the server's origin and [obligateOrigin] may load. */
    data class Ready(val obligateOrigin: String) : ReauthConfig

    /** Do not start; [reason] as a failure of the sheet. */
    data class Refused(val reason: String) : ReauthConfig
}

/** State line of a server in the scope sheet and the server list. */
internal sealed interface ServerStatus {
    /** Active server, socket connected: "Actif · temps réel connecté". */
    data object Live : ServerStatus

    /** Active server, socket not connected (yet). */
    data object Connecting : ServerStatus

    /** Signed in, last feed refresh at [at] (epoch ms): "Vérifié à 03:20". */
    data class Checked(val at: Long) : ServerStatus

    /** Signed in, no refresh time known. */
    data object SignedIn : ServerStatus

    /** Not probed yet. */
    data object Checking : ServerStatus

    /** "Injoignable depuis 03:02" ([since] null: time unknown). */
    data class Unreachable(val since: Long?) : ServerStatus

    /** "Session expirée · Se reconnecter". */
    data object Expired : ServerStatus

    data object SignedOut : ServerStatus

    /** The user can sign in again from this row. */
    val needsSignIn: Boolean get() = this == Expired || this == SignedOut

    companion object {
        fun of(active: Boolean, auth: AuthState, realtime: ConnectionState?, feed: ServerFeed?): ServerStatus = when {
            auth == AuthState.Expired || feed?.status == FeedStatus.EXPIRED -> Expired
            auth == AuthState.SignedOut || feed?.status == FeedStatus.SIGNED_OUT -> SignedOut
            auth is AuthState.Unreachable -> Unreachable(auth.since)
            feed?.status == FeedStatus.UNREACHABLE -> Unreachable(null)
            auth == AuthState.Unknown -> Checking
            active && realtime == ConnectionState.CONNECTED -> Live
            active -> Connecting
            feed?.updatedAt != null -> Checked(feed.updatedAt!!)
            else -> SignedIn
        }
    }
}

/** "03:20" in the device time zone (24 h). */
internal object Clock24 {
    private val format = DateTimeFormatter.ofPattern("HH:mm")

    fun format(epochMs: Long, zone: ZoneId = ZoneId.systemDefault()): String =
        format.format(Instant.ofEpochMilli(epochMs).atZone(zone))
}
