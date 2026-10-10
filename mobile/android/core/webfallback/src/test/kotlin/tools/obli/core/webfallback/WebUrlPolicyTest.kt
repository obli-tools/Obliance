package tools.obli.core.webfallback

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WebUrlPolicyTest {
    private val origin = "https://obliance.example.org"

    @Test fun startUrlStaysOnTheServer() {
        assertEquals("https://obliance.example.org/manage/users", WebUrlPolicy.startUrl(origin, "/manage/users"))
        assertNull(WebUrlPolicy.startUrl(origin, "//evil.example.net/x"))
        assertNull(WebUrlPolicy.startUrl(origin, "https://evil.example.net/"))
        assertNull(WebUrlPolicy.startUrl(origin, "admin"))
        assertNull(WebUrlPolicy.startUrl(origin, "/\\evil"))
    }

    @Test fun sameOriginLoadsInside() {
        assertEquals(WebNav.Stay, WebUrlPolicy.classify(origin, "https://obliance.example.org/settings?tab=api"))
        assertEquals(WebNav.Stay, WebUrlPolicy.classify(origin, "https://OBLIANCE.example.org:443/"))
    }

    @Test fun otherOriginsOpenOutside() {
        assertEquals(WebNav.External("https://id.example.org/login"), WebUrlPolicy.classify(origin, "https://id.example.org/login"))
        assertEquals(WebNav.External("http://obliance.example.org/"), WebUrlPolicy.classify(origin, "http://obliance.example.org/"))
        assertEquals(WebNav.External("https://obliance.example.org:8443/"), WebUrlPolicy.classify(origin, "https://obliance.example.org:8443/"))
        assertEquals(WebNav.External("https://obliance.example.org.evil.example.net/"), WebUrlPolicy.classify(origin, "https://obliance.example.org.evil.example.net/"))
    }

    @Test fun dangerousSchemesAreBlocked() {
        listOf("javascript:alert(1)", "file:///sdcard/x", "content://x/y", "data:text/html,hi", "intent://x#Intent;end", "about:blank", "", null).forEach {
            assertEquals(it.toString(), WebNav.Blocked, WebUrlPolicy.classify(origin, it))
        }
        assertEquals(WebNav.System("mailto:support@example.org"), WebUrlPolicy.classify(origin, "mailto:support@example.org"))
        assertEquals(WebNav.System("tel:+33100000000"), WebUrlPolicy.classify(origin, "tel:+33100000000"))
    }

    @Test fun nativeScreensTakeTheirPaths() {
        val inApp: (String) -> Boolean = { it.startsWith("/devices/") }
        assertEquals(WebNav.InApp("/devices/12?tab=scripts"), WebUrlPolicy.classify(origin, "https://obliance.example.org/devices/12?tab=scripts", inApp))
        assertEquals(WebNav.Stay, WebUrlPolicy.classify(origin, "https://obliance.example.org/admin", inApp))
        // Another origin's /devices/ path is never taken for ours.
        assertEquals(WebNav.External("https://other.example.org/devices/12"), WebUrlPolicy.classify(origin, "https://other.example.org/devices/12", inApp))
    }

    @Test fun pathOf() {
        assertEquals("/", WebUrlPolicy.pathOf(origin, "https://obliance.example.org"))
        assertEquals("/?x=1", WebUrlPolicy.pathOf(origin, "https://obliance.example.org?x=1"))
        assertEquals("/a/b#c", WebUrlPolicy.pathOf(origin, "https://obliance.example.org/a/b#c"))
        assertNull(WebUrlPolicy.pathOf(origin, "https://other.example.org/a"))
    }

    @Test fun downloadsOnlyCarryTheCookieToTheServer() {
        assertTrue(WebUrlPolicy.isSameOrigin(origin, "https://obliance.example.org/api/reports/1.pdf"))
        assertFalse(WebUrlPolicy.isSameOrigin(origin, "https://cdn.example.net/file.zip"))
    }

    /** SSO device keys: the page's « Reconfirmer avec Obligate » is stopped and handed to the app (never a Custom Tab). */
    @Test fun theObligateReauthenticationOfThePageIsIntercepted() {
        // As the web builds it: encodeURIComponent(location.pathname).
        assertEquals("/devices/12", WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=1&return=%2Fdevices%2F12"))
        assertEquals("/settings", WebUrlPolicy.ssoReauthReturn(origin, "$origin/api/auth/sso-redirect?return=/settings&reauth=1"))
        assertEquals("/", WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=1"))
        // The server's return-path rules: anything odd comes back to '/'.
        assertEquals("/", WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=1&return=%2F%2Fevil.example.net"))
        assertEquals("/", WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=1&return=%2Flogin"))
        assertEquals("/", WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=1&return=https%3A%2F%2Fevil.example.net%2F"))
        assertEquals("/", WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=1&return=%E0%A4%A"))
        // Dot segments: the WebView would normalise /x/../auth/callback to /auth/callback.
        assertEquals("/", WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=1&return=%2Fx%2F..%2Fauth%2Fcallback"))
        assertEquals("/", WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=1&return=%2Fx%2F%2E%2E%2Fauth%2Fsso-redirect"))
        assertEquals("/", WebUrlPolicy.reauthReturnPath("/x/../auth/callback"))
        assertEquals("/", WebUrlPolicy.reauthReturnPath("/./login"))
        assertEquals("/", WebUrlPolicy.reauthReturnPath("/devices/.."))
        assertEquals("/devices/a..b/.hidden", WebUrlPolicy.reauthReturnPath("/devices/a..b/.hidden"))
        // Express ignores case and a trailing slash on the route: so does the interception.
        assertEquals("/devices/12", WebUrlPolicy.ssoReauthReturn(origin, "$origin/Auth/SSO-Redirect/?reauth=1&return=%2Fdevices%2F12"))
        // A plain Obligate sign-in, another origin, another path: not this.
        assertNull(WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect"))
        assertNull(WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect?reauth=0&return=/x"))
        assertNull(WebUrlPolicy.ssoReauthReturn(origin, "https://evil.example.net/auth/sso-redirect?reauth=1"))
        assertNull(WebUrlPolicy.ssoReauthReturn(origin, "$origin/auth/sso-redirect/x?reauth=1"))
        assertNull(WebUrlPolicy.ssoReauthReturn(origin, "$origin/devices?reauth=1"))
        assertNull(WebUrlPolicy.ssoReauthReturn(origin, null))
    }

    @Test fun thePageIsReloadedWithTheOutcomeItExpects() {
        assertEquals("$origin/devices/12?reauth=ok", WebUrlPolicy.reauthResultUrl(origin, "/devices/12", WebReauthOutcome(true)))
        assertEquals("$origin/devices/12?reauth=failed&reason=no_otp", WebUrlPolicy.reauthResultUrl(origin, "/devices/12", WebReauthOutcome(false, "no_otp")))
        assertEquals("$origin/?reauth=failed&reason=cancelled", WebUrlPolicy.reauthResultUrl(origin, "/", WebReauthOutcome(false, "cancelled")))
        // Never a foreign path nor an unexpected reason in what is loaded.
        assertEquals("$origin/?reauth=failed&reason=error", WebUrlPolicy.reauthResultUrl(origin, "//evil.example.net", WebReauthOutcome(false, "<script>")))
        assertEquals("$origin/?reauth=failed&reason=error", WebUrlPolicy.reauthResultUrl(origin, "/auth/x", WebReauthOutcome(false, null)))
        assertEquals("$origin/?reauth=failed&reason=cancelled", WebUrlPolicy.reauthResultUrl(origin, "/x/../auth/sso-redirect", WebReauthOutcome(false, "cancelled")))
    }
}
