package tools.obli.core.webfallback

import java.net.URLDecoder
import tools.obli.shell.nav.Origins

/** What the web view does with a main-frame navigation. */
sealed interface WebNav {
    /** Same origin as the server: loads in the web view, with the session cookie. */
    data object Stay : WebNav

    /** Same origin, but the app has a native screen for it (`/devices/12` → the device screen): not loaded. */
    data class InApp(val path: String) : WebNav

    /** An http(s) page of another origin: opened outside (Custom Tab), never with the session. */
    data class External(val url: String) : WebNav

    /** mailto:, tel:: handed to Android. */
    data class System(val url: String) : WebNav

    /** javascript:, file:, content:, data:, intent:… : refused. */
    data object Blocked : WebNav
}

/**
 * URL rules of the web view: only the server's own
 * origin loads inside (the shared CookieManager session goes nowhere else);
 * other origins leave through a Custom Tab; a same-origin path the app shows
 * natively is handed to the app. Pure JVM, unit-tested.
 */
object WebUrlPolicy {
    private val SYSTEM_SCHEMES = setOf("mailto", "tel", "sms", "geo")

    /** Absolute URL of a same-origin [path] ("/manage/users"), or null if [path] would leave [origin]. */
    fun startUrl(origin: String, path: String): String? = Origins.resolveRelativePath(origin, path)

    /** Path + query + fragment of a same-origin [url] ("/devices/12?tab=x"), or null. */
    fun pathOf(origin: String, url: String?): String? {
        if (url == null || Origins.of(url) != origin) return null
        val afterScheme = url.substringAfter("://")
        val slash = afterScheme.indexOfAny(charArrayOf('/', '?', '#'))
        if (slash < 0) return "/"
        val rest = afterScheme.substring(slash)
        return if (rest.startsWith("/")) rest else "/$rest"
    }

    /**
     * Classifies a main-frame navigation of the web view on [origin]. [inApp]
     * receives the same-origin path and returns true when the app opens it
     * natively instead.
     */
    fun classify(origin: String, url: String?, inApp: (String) -> Boolean = { false }): WebNav {
        val scheme = Origins.scheme(url) ?: return WebNav.Blocked
        return when (scheme) {
            "http", "https" -> {
                val target = Origins.of(url) ?: return WebNav.Blocked
                if (target == origin) {
                    val path = pathOf(origin, url) ?: "/"
                    if (inApp(path)) WebNav.InApp(path) else WebNav.Stay
                } else {
                    // Also an http:// downgrade of the same host: a different origin.
                    WebNav.External(url!!.trim())
                }
            }
            in SYSTEM_SCHEMES -> WebNav.System(url!!.trim())
            else -> WebNav.Blocked
        }
    }

    /** Downloads carry the session cookie only to the server's own origin. */
    fun isSameOrigin(origin: String, url: String?): Boolean = Origins.of(url) == origin

    // --- SSO device keys: the page's « Reconfirmer avec Obligate » -----------------------------------
    //
    // The web's 2FA modal does `location.assign('/auth/sso-redirect?reauth=1&return=<path>')`.
    // Followed here, the server's 302 to Obligate would leave for a Custom Tab (another
    // origin), which has neither the session nor the OAuth state: it would always fail.
    // The app stops that navigation, runs its native Obligate sheet (same process cookie
    // store, same session), then loads `<origin><path>?reauth=ok|failed&reason=…` so the
    // page reports it (its TwoFactorGate), as after the web round trip.

    private val REAUTH_PATHS = setOf("/auth/sso-redirect", "/api/auth/sso-redirect")
    private val REAUTH_RETURN = Regex("^/(?![/\\\\])[A-Za-z0-9\\-._~/]*$")
    private val REAUTH_FORBIDDEN = Regex("^/(auth|api|login)(/|$)")
    private val REAUTH_DOT_SEGMENT = Regex("(^|/)\\.{1,2}(/|$)")
    private val REAUTH_REASON = Regex("^[a-z_]{1,32}$")

    /**
     * The return path of a same-origin navigation to `/auth/sso-redirect`
     * (or `/api/auth/…`) with `reauth=1`, sanitised like the server
     * ([reauthReturnPath]); null for any other URL (a plain Obligate sign-in
     * included).
     */
    fun ssoReauthReturn(origin: String, url: String?): String? {
        val full = pathOf(origin, url) ?: return null
        val noFragment = full.substringBefore('#')
        // Express routes ignore case and a trailing slash: so does the match.
        if (noFragment.substringBefore('?').lowercase().trimEnd('/') !in REAUTH_PATHS) return null
        val params = queryParams(noFragment.substringAfter('?', ""))
        if (params["reauth"] != "1") return null
        return reauthReturnPath(params["return"] ?: "/")
    }

    /**
     * The server's `reauthReturnPath` (obligateCallback.routes.ts): a plain
     * same-origin path, never `/auth`, `/api`, `/login`; else `/`. Stricter
     * than the server on one point: no `.` / `..` segment (`/x/../auth/…`
     * would pass the prefix test, then be normalised to `/auth/…` by the
     * WebView).
     */
    fun reauthReturnPath(raw: String): String {
        if (raw.length > 200 || !REAUTH_RETURN.matches(raw)) return "/"
        if (REAUTH_FORBIDDEN.containsMatchIn(raw) || REAUTH_DOT_SEGMENT.containsMatchIn(raw)) return "/"
        return raw
    }

    /**
     * What the page is loaded with after the native re-authentication:
     * `<origin><path>?reauth=ok`, or `?reauth=failed&reason=<code>` (an
     * unexpected code becomes `error`).
     */
    fun reauthResultUrl(origin: String, returnPath: String, outcome: WebReauthOutcome): String {
        val base = origin + reauthReturnPath(returnPath)
        if (outcome.ok) return "$base?reauth=ok"
        val reason = outcome.reason?.takeIf { REAUTH_REASON.matches(it) } ?: "error"
        return "$base?reauth=failed&reason=$reason"
    }

    /** First value of each query parameter, percent-decoded (a malformed one is skipped). */
    private fun queryParams(query: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (part in query.split('&')) {
            if (part.isEmpty()) continue
            val key = decode(part.substringBefore('=')) ?: continue
            val value = decode(part.substringAfter('=', "")) ?: continue
            out.putIfAbsent(key, value)
        }
        return out
    }

    private fun decode(s: String): String? = try {
        URLDecoder.decode(s, Charsets.UTF_8.name())
    } catch (_: IllegalArgumentException) {
        null
    }
}

/** How the app's native Obligate re-authentication ended, for the page (`?reauth=ok|failed&reason=…`). */
data class WebReauthOutcome(val ok: Boolean, val reason: String? = null)
