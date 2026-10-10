package tools.obli.obliance.access

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** SSO device keys: every failure of the Obligate re-authentication has its formal sentence (French, no tutoiement). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "fr-rFR")
class SsoReauthTextsTest {
    private val res get() = ApplicationProvider.getApplicationContext<Context>().resources

    private val serverCodes = listOf(
        "no_otp", "identity", "stale_auth", "unsupported", "verifier_unavailable", "unreachable", "cancelled", "origin",
        "expired", "signed_out", "state", "exchange", "not_sso", "misconfigured", "error",
    )
    private val appCodes = listOf("login", "unexpected", "blocked", "page_error", "tls", "config")

    @Test fun everyReasonHasItsSentence() {
        for (code in serverCodes + appCodes + "a_newer_code") {
            val text = reauthReasonText(res, code)
            assertTrue(code, text.isNotBlank())
            assertFalse("$code: $text", TUTOIEMENT.containsMatchIn(text))
        }
        assertEquals(
            "Activez d'abord la double authentification dans votre compte Obligate : la reconfirmation demande votre mot de passe et un code.",
            reauthReasonText(res, "no_otp"),
        )
        // A code this app does not know yet reads as the generic failure; /login as a signed-out session.
        assertEquals(reauthReasonText(res, "error"), reauthReasonText(res, "a_newer_code"))
        assertEquals(reauthReasonText(res, "signed_out"), reauthReasonText(res, "login"))
        assertEquals("Reconfirmer avec Obligate", res.getString(R.string.access_ssoreauth_title))
    }

    private companion object {
        val TUTOIEMENT = Regex("\\b(tu|toi|ton|ta|tes|te)\\b", RegexOption.IGNORE_CASE)
    }
}
