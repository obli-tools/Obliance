package tools.obli.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.shell.core.obj

/**
 * The recorded reference bodies J1–J8 (a frozen
 * contract, shared with the server tests). Two of these bodies
 * elide parts with "…": J2's `deviceChallenge:{…}` (not JSON) is J1's
 * challenge here, and J7's elided ids and nonce are replaced by well-formed
 * values; every other byte is the reference one.
 */
class DeviceStepUpResponsesTest {
    private val jsonType = "application/json; charset=utf-8"

    private fun raw(status: Int, body: String?, retryAfter: String? = null): ApiOutcome<JsonElement?> =
        ApiResponses.classify(status, jsonType, body, retryAfter) { it }

    private val j1Challenge = """{"v":1,"keyId":"6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f","challengeId":"1b4e28ba-2fa1-41d2-883f-0016d3cca427","purpose":"stepup","userId":42,"tenantId":3,"tenantName":"ACME","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","action":"command.reboot","binding":"42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4","expiresAt":1790000120,"bulkId":null}"""

    private val j1 = """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"command.reboot","currentIp":"203.0.113.21","trustIpAllowed":false,"codeRequiresPassword":true,"deviceKeyStatus":"active","deviceChallenge":$j1Challenge}"""
    private val j2 = """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"command.reboot","deviceKeyStatus":"active","deviceError":"challenge_expired","deviceChallenge":$j1Challenge}"""
    private val j3 = """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"command.reboot","deviceKeyStatus":"active","deviceError":"invalid_assertion","codeRequiresPassword":true,"trustIpAllowed":false}"""
    private val j4 = """{"success":false,"error":"Authentication required","deviceKeyStatus":"revoked"}"""
    private val j5 = """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"command.reboot","currentIp":"…","trustIpAllowed":true,"deviceKeyStatus":"disabled"}"""
    private val j6 = """{"error":"Too many verification attempts","codeLocked":true}"""
    private val j7 = """{"success":true,"data":{"requires2fa":true,"methods":{"totp":true,"email":false,"device":true},"deviceChallenge":{"v":1,"keyId":"6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f","challengeId":"7c9e6679-7425-40de-944b-e07fc1f90ae7","purpose":"login","userId":42,"tenantId":null,"nonce":"zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0","action":"-","binding":"-","expiresAt":1790000120,"bulkId":null}}}"""
    private val j8 = """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"command.reboot","currentIp":"…"}"""

    private val expectedJ1Challenge = DeviceChallenge(
        v = 1,
        keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f",
        challengeId = "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
        purpose = DevicePurpose.STEPUP,
        userId = 42,
        tenantId = 3,
        tenantName = "ACME",
        nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        action = "command.reboot",
        binding = "42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4",
        expiresAt = 1790000120,
        bulkId = null,
    )

    @Test fun j1BoundSessionWithChallenge() {
        assertEquals(
            ApiOutcome.StepUpRequired(
                action = "command.reboot",
                currentIp = "203.0.113.21",
                trustIpAllowed = false,
                codeRequiresPassword = true,
                codeRequiresReauth = false,
                device = DeviceStepUp(DeviceKeyStatus.ACTIVE, expectedJ1Challenge, null),
            ),
            raw(401, j1),
        )
    }

    @Test fun j2ChallengeExpiredCarriesANewChallenge() {
        val out = raw(401, j2) as ApiOutcome.StepUpRequired
        assertEquals(DeviceStepUp(DeviceKeyStatus.ACTIVE, expectedJ1Challenge, DeviceError.CHALLENGE_EXPIRED), out.device)
        assertNull(out.currentIp)
        assertTrue(out.trustIpAllowed) // absent → default
    }

    @Test fun j3InvalidAssertionHasNoChallenge() {
        val out = raw(401, j3) as ApiOutcome.StepUpRequired
        assertEquals(DeviceStepUp(DeviceKeyStatus.ACTIVE, null, DeviceError.INVALID_ASSERTION), out.device)
        assertTrue(out.codeRequiresPassword)
        assertFalse(out.trustIpAllowed)
    }

    @Test fun j4RevokedIsSessionExpired() {
        assertEquals(ApiOutcome.SessionExpired, raw(401, j4))
        assertTrue(ApiResponses.isDeviceKeyRevoked(401, jsonType, j4))
        assertFalse(ApiResponses.isDeviceKeyRevoked(401, jsonType, """{"success":false,"error":"Authentication required"}"""))
        assertFalse(ApiResponses.isDeviceKeyRevoked(401, jsonType, j1))
        assertFalse(ApiResponses.isDeviceKeyRevoked(403, jsonType, j4))
        assertFalse(ApiResponses.isDeviceKeyRevoked(401, "text/html", j4))
    }

    @Test fun j5PolicyDisabled() {
        assertEquals(
            ApiOutcome.StepUpRequired("command.reboot", "…", trustIpAllowed = true, device = DeviceStepUp(DeviceKeyStatus.DISABLED)),
            raw(401, j5),
        )
    }

    @Test fun j6CodeLocked() {
        assertEquals(ApiOutcome.RateLimited(null, codeLocked = true), raw(429, j6))
        // The 15-minute window: Retry-After, code not locked.
        assertEquals(ApiOutcome.RateLimited(600, codeLocked = false), raw(429, """{"error":"Too many verification attempts"}""", "600"))
    }

    @Test fun j7SignInAnswerCarriesALoginChallenge() {
        val out = raw(200, j7) as ApiOutcome.Ok
        val data = ApiResponses.unwrap(out.value) as JsonObject
        val challenge = DeviceChallenge.parse(data.obj("deviceChallenge"))
        assertNotNull(challenge)
        assertEquals(DevicePurpose.LOGIN, challenge!!.purpose)
        assertEquals("-", challenge.action)
        assertEquals("-", challenge.binding)
        assertNull(challenge.tenantId)
        assertNull(challenge.tenantName)
        assertEquals(42L, challenge.userId)
    }

    @Test fun j8OldServerIsUnchanged() {
        assertEquals(ApiOutcome.StepUpRequired("command.reboot", "…"), raw(401, j8))
        val out = raw(401, j8) as ApiOutcome.StepUpRequired
        assertTrue(out.trustIpAllowed)
        assertFalse(out.codeRequiresPassword)
        assertFalse(out.codeRequiresReauth)
        assertNull(out.device)
        assertNull(out.origin)
    }

    @Test fun reauthVariantAndUnknownErrors() {
        val sso = raw(401, """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"command.reboot","trustIpAllowed":false,"codeRequiresReauth":true,"deviceKeyStatus":"throttled"}""") as ApiOutcome.StepUpRequired
        assertTrue(sso.codeRequiresReauth)
        assertEquals(DeviceStepUp(DeviceKeyStatus.THROTTLED), sso.device)
        val odd = raw(401, """{"error":"twoFactorCode required","twoFactorRequired":true,"deviceKeyStatus":"active","deviceError":"something_new"}""") as ApiOutcome.StepUpRequired
        assertEquals(DeviceError.OTHER, odd.device!!.error)
        // An unknown status: no device part at all (the app uses the code).
        assertNull((raw(401, """{"twoFactorRequired":true,"deviceKeyStatus":"frozen","deviceChallenge":$j1Challenge}""") as ApiOutcome.StepUpRequired).device)
    }

    @Test fun aChallengeOnlyCountsWithAnActiveStatus() {
        val disabled = raw(401, """{"twoFactorRequired":true,"deviceKeyStatus":"disabled","deviceChallenge":$j1Challenge}""") as ApiOutcome.StepUpRequired
        assertNull(disabled.device!!.challenge)
        val login = j1Challenge.replace("\"purpose\":\"stepup\"", "\"purpose\":\"login\"")
        val wrongPurpose = raw(401, """{"twoFactorRequired":true,"deviceKeyStatus":"active","deviceChallenge":$login}""") as ApiOutcome.StepUpRequired
        assertNull(wrongPurpose.device!!.challenge)
    }

    @Test fun malformedChallengesAreDropped() {
        fun parse(json: String) = DeviceChallenge.parse(Json.parseToJsonElement(json).jsonObject)
        assertEquals(expectedJ1Challenge, parse(j1Challenge))
        val broken = listOf(
            "\"v\":1" to "\"v\":2",                                           // another version
            "\"v\":1" to "\"v\":\"1\"",
            "\"keyId\":\"6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f\"" to "\"keyId\":\"…\"",
            "\"challengeId\":\"1b4e28ba-2fa1-41d2-883f-0016d3cca427\"" to "\"challengeId\":\"1b4e28ba\"",
            "\"purpose\":\"stepup\"" to "\"purpose\":\"enrol\"",
            "\"userId\":42" to "\"userId\":\"42\"",
            "\"userId\":42" to "\"userId\":0",
            "\"tenantId\":3" to "\"tenantId\":\"3\"",
            "\"nonce\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"" to "\"nonce\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"", // padding
            "\"nonce\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"" to "\"nonce\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd\"",     // 30 bytes
            "\"nonce\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"" to "\"nonce\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+h8\"", // not url-safe
            "\"action\":\"command.reboot\"" to "\"action\":\"command.reboot\\nexp:1\"",
            "\"action\":\"command.reboot\"" to "\"action\":\"-\"",
            "\"binding\":\"42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4\"" to "\"binding\":\"42E94DC1A0B1FCA10FF77A22A2C4EC22AE1FB558FFCD31F9971DA0C3B8C6B5F4\"",
            "\"binding\":\"42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4\"" to "\"binding\":\"-\"",
            "\"expiresAt\":1790000120" to "\"expiresAt\":1790000120.5",
            "\"bulkId\":null" to "\"bulkId\":\"lot-1\"",
        )
        for ((from, to) in broken) {
            val json = j1Challenge.replace(from, to)
            check(json != j1Challenge) { "replacement not applied: $from" }
            assertNull("accepted: $to", parse(json))
        }
        // Optional fields may be absent.
        assertEquals(expectedJ1Challenge.copy(tenantId = null, tenantName = null), parse(j1Challenge.replace("\"tenantId\":3,\"tenantName\":\"ACME\",", "")))
        assertEquals(
            expectedJ1Challenge.copy(bulkId = "0f8fad5b-d9cb-469f-a165-70867728950e"),
            parse(j1Challenge.replace("\"bulkId\":null", "\"bulkId\":\"0f8fad5b-d9cb-469f-a165-70867728950e\"")),
        )
    }

    @Test fun enrolmentErrors() {
        // Mapping of the enrolment answers.
        for (e in listOf("device_keys_disabled", "device_keys_origin_unset", "device_keys_sso_unsupported", "enrol_locked")) {
            assertEquals(ApiOutcome.Forbidden(ForbiddenReason.OTHER, e), raw(403, """{"error":"$e"}"""))
        }
        for (e in listOf("invalid_ticket", "origin_mismatch", "bad_key", "bad_signature")) {
            assertEquals(ApiOutcome.Validation(e, emptyMap()), raw(400, """{"error":"$e"}"""))
        }
        for (e in listOf("too_many_keys", "already_enrolled")) {
            assertEquals(ApiOutcome.Unsupported(e), raw(409, """{"error":"$e"}"""))
        }
        assertEquals(ApiOutcome.Failure(422, FailureKind.CLIENT, "app_signer"), raw(422, """{"error":"attestation_failed","reason":"app_signer"}"""))
        assertEquals(ApiOutcome.Failure(422, FailureKind.CLIENT, "attestation_failed"), raw(422, """{"error":"attestation_failed"}"""))
        assertEquals(ApiOutcome.Failure(422, FailureKind.CLIENT, "other"), raw(422, """{"error":"other","reason":"x"}"""))
        // The envelope text the app recognises when the account has no TOTP.
        val totp = raw(403, """{"error":"This action is marked sensitive — enable TOTP 2FA on your profile before you can use it."}""")
        assertEquals(ForbiddenReason.NO_TOTP, (totp as ApiOutcome.Forbidden).reason)
    }

    @Test fun codeAnswersKeepTheirShape() {
        assertEquals(ApiOutcome.StepUpRejected(), raw(401, """{"error":"Invalid 2FA code"}"""))
        // A right code whose step was already used: same outcome, flagged (the 2FA sheet and the profile security screen say « wait for the next code »).
        assertEquals(ApiOutcome.StepUpRejected(codeUsed = true), raw(401, """{"error":"Invalid 2FA code","codeUsed":true}"""))
        assertEquals(ApiOutcome.StepUpRejected(), raw(401, """{"error":"Invalid 2FA code","codeUsed":false}"""))
        // The enrolment's 401 (enrol/begin) with codeMustBeNew stays a step-up.
        assertTrue(raw(401, """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"device_key.enrol","codeMustBeNew":true,"codeRequiresPassword":true}""") is ApiOutcome.StepUpRequired)
    }

    /** SSO device keys: 503 verifierUnavailable (Obligate could not check the proof) is its own outcome, not an offline agent. */
    @Test fun verifierUnavailableIsNotAnOfflineAgent() {
        val out = raw(503, """{"success":false,"error":"Two-factor verification is temporarily unavailable","verifierUnavailable":true}""")
        assertEquals(ApiOutcome.Failure(503, FailureKind.SERVER, ApiResponses.VERIFIER_UNAVAILABLE), out)
        assertTrue(out.isVerifierUnavailable)
        // Without the flag (or false), a 503 stays AgentOffline, as before.
        val plain = raw(503, """{"success":false,"error":"Device is offline"}""")
        assertEquals(ApiOutcome.AgentOffline("Device is offline"), plain)
        assertFalse(plain.isVerifierUnavailable)
        assertTrue(raw(503, """{"error":"x","verifierUnavailable":false}""") is ApiOutcome.AgentOffline)
        assertTrue(raw(503, null) is ApiOutcome.AgentOffline)
        // Another 5xx with the same text is not it.
        assertFalse(ApiOutcome.Failure(500, FailureKind.SERVER, ApiResponses.VERIFIER_UNAVAILABLE).isVerifierUnavailable)
    }
}
