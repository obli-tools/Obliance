package tools.obli.obliance.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import tools.obli.core.security.SsoReauthResult
import tools.obli.core.webfallback.WebReauthOutcome

/** Web view paths the app shows natively. */
class WebRoutesTest {
    @Test fun devicesAndRootAreNative() {
        assertEquals(NativeTarget.Device(233), webPathToNative("/devices/233"))
        assertEquals(NativeTarget.Device(233), webPathToNative("/devices/233/?tab=scripts#x"))
        assertEquals(NativeTarget.Fleet, webPathToNative("/"))
        assertEquals(NativeTarget.Fleet, webPathToNative("/?from=login"))
    }

    @Test fun everythingElseStaysInTheWebView() {
        assertNull(webPathToNative("/devices"))
        assertNull(webPathToNative("/devices/abc"))
        assertNull(webPathToNative("/devices/12/terminal"))
        assertNull(webPathToNative("/manage/users"))
    }

    /** SSO device keys: back from the Obligate re-authentication, the page reports it; never popped to a native screen. */
    @Test fun aReauthOutcomeStaysOnThePage() {
        assertNull(webPathToNative("/?reauth=ok"))
        assertNull(webPathToNative("/?reauth=failed&reason=no_otp"))
        assertNull(webPathToNative("/devices/233?reauth=ok"))
        assertNull(webPathToNative("/?x=1&reauth=failed#top"))
        // Only the `reauth` parameter itself counts.
        assertEquals(NativeTarget.Fleet, webPathToNative("/?reauthx=1"))
        assertEquals(NativeTarget.Device(233), webPathToNative("/devices/233?tab=reauth"))
    }

    /** What the page's TwoFactorGate reads after the native sheet. */
    @Test fun theSheetOutcomeIsToldToThePage() {
        assertEquals(WebReauthOutcome(ok = true), webOutcome(SsoReauthResult.Success))
        assertEquals(WebReauthOutcome(ok = false, reason = "cancelled"), webOutcome(SsoReauthResult.Cancelled))
        assertEquals(WebReauthOutcome(ok = false, reason = "no_otp"), webOutcome(SsoReauthResult.Failed("no_otp")))
    }
}
