package tools.obli.obliance.api

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.CookieJar
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceError
import tools.obli.core.network.DeviceKeyHeader
import tools.obli.core.network.DevicePurpose
import tools.obli.core.network.FailureKind
import tools.obli.core.network.ForbiddenReason
import tools.obli.core.network.ObliHttp
import tools.obli.core.security.DeviceAssertion
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.EnrolFinish
import tools.obli.core.security.EnrolProof
import tools.obli.shell.nav.Origins

/**
 * The device-key calls (error mapping,
 * shapes of shared/src/deviceKeys.ts, recorded bodies) through a real ObliHttp.
 */
class DeviceKeysApiTest {
    private val server = MockWebServer().apply { start() }
    private val http = ObliHttp(Origins.of(server.url("/").toString())!!, ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA"))
    private val api = DeviceKeysApi(http)

    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val ticketId = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
    private val nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

    @After fun tearDown() = server.close()

    private fun answer(code: Int, body: String = "") {
        val b = MockResponse.Builder().code(code)
        if (body.isNotEmpty()) b.addHeader("Content-Type", "application/json; charset=utf-8").body(body)
        server.enqueue(b.build())
    }

    private fun bodyOf(request: mockwebserver3.RecordedRequest): JsonObject =
        Json.parseToJsonElement(request.body!!.utf8()).jsonObject

    private val listJson = """{"success":true,"data":{"policy":{"enabled":true,"loginEnabled":true,"requireAttestation":true,"strictSession":true,"originConfigured":true,"ssoSupported":false},
        "allowedOrigins":["https://obliance-qual.example.org"],"boundKeyId":"$keyId","eligibility":{"ok":true},
        "keys":[{"id":"$keyId","label":"Téléphone de John","platform":"android","securityLevel":"strongbox","osPatchLevel":20260905,"createdAt":"2026-09-12T08:14:00.000Z","lastUsedAt":"2026-09-25T01:14:00.000Z","lastUsedIp":"203.0.113.21","useCount":23,"current":true},
                {"id":"0f8fad5b-d9cb-469f-a165-70867728950e","label":null,"platform":"android","securityLevel":"quantum","osPatchLevel":null,"createdAt":"2026-08-30T17:02:00.000Z","lastUsedAt":null,"lastUsedIp":null,"useCount":0,"current":false},
                {"id":"not-a-uuid","securityLevel":"tee"}]}}"""

    @Test fun listDecodesPolicyAndKeys() = runBlocking {
        answer(200, listJson)
        val out = api.list()
        assertTrue(out is ApiOutcome.Ok)
        val list = (out as ApiOutcome.Ok).value
        assertTrue(list.policy.enabled && list.policy.originConfigured && !list.policy.ssoSupported)
        assertEquals(listOf("https://obliance-qual.example.org"), list.allowedOrigins)
        assertEquals(keyId, list.boundKeyId)
        assertTrue(list.eligibility.ok)
        assertEquals(3, list.keys.size)
        // A malformed id is never offered nor compared.
        assertEquals(2, list.validKeys.size)
        assertEquals(DeviceKeyLevel.STRONGBOX, list.keys[0].level)
        // An unknown level is never shown better than unverified.
        assertEquals(DeviceKeyLevel.UNVERIFIED, list.keys[1].level)
        assertTrue(list.isActive(keyId.uppercase()))
        assertFalse(list.isActive("not-a-uuid"))
        val req = server.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/api/profile/device-keys", req.url.encodedPath)
        // The api never adds the header itself (the interceptor does).
        assertNull(req.headers[DeviceKeyHeader.NAME])
    }

    @Test fun missingPolicyIsFailClosed() = runBlocking {
        answer(200, """{"success":true,"data":{"keys":[]}}""")
        val list = (api.list() as ApiOutcome.Ok).value
        assertFalse(list.policy.enabled)
        assertFalse(list.policy.originConfigured)
        assertFalse(list.eligibility.ok)
    }

    @Test fun oldServerAnswers404() = runBlocking {
        answer(404, """{"success":false,"error":"Not found"}""")
        val out = api.list()
        assertEquals(404, (out as ApiOutcome.Failure).status)
        assertEquals(FailureKind.NOT_FOUND, out.kind)
    }

    @Test fun beginSendsThePasswordAndTheCodeAsProofsAndReadsTheTicket() = runBlocking {
        answer(200, """{"success":true,"data":{"ticketId":"$ticketId","nonce":"$nonce","expiresAt":1790000180,"userId":42,"allowedOrigins":["https://obliance-qual.example.org"],"requireAttestation":true}}""")
        val out = api.begin("0123456789abcdef0123456789abcdef", EnrolProof.PasswordAndCode("correct horse", " 482 913 "))
        val ticket = (out as ApiOutcome.Ok).value
        assertEquals(ticketId, ticket.ticketId)
        assertEquals(nonce, ticket.nonce)
        assertEquals(1790000180L, ticket.expiresAt)
        assertEquals(42L, ticket.userId)
        assertEquals(listOf("https://obliance-qual.example.org"), ticket.allowedOrigins)
        assertTrue(ticket.requireAttestation)
        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/api/profile/device-keys/enrol/begin", req.url.encodedPath)
        val body = bodyOf(req)
        assertEquals(setOf("installId", "stepUpPassword", "twoFactorCode"), body.keys)
        assertEquals("0123456789abcdef0123456789abcdef", body["installId"]!!.jsonPrimitive.content)
        assertEquals("correct horse", body["stepUpPassword"]!!.jsonPrimitive.content)
        assertEquals("482913", body["twoFactorCode"]!!.jsonPrimitive.content)
    }

    @Test fun aMalformedTicketIsRefused() = runBlocking {
        // nonce of 31 bytes, then a non-UUID ticket, then a missing user id.
        for (data in listOf(
            """{"ticketId":"$ticketId","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg","expiresAt":1,"userId":42,"allowedOrigins":[]}""",
            """{"ticketId":"t1","nonce":"$nonce","expiresAt":1,"userId":42,"allowedOrigins":[]}""",
            """{"ticketId":"$ticketId","nonce":"$nonce","expiresAt":1,"allowedOrigins":[]}""",
            """{"ticketId":"$ticketId","nonce":"$nonce","expiresAt":1,"userId":42}""",
        )) {
            answer(200, """{"success":true,"data":$data}""")
            val out = api.begin("0123456789abcdef0123456789abcdef", EnrolProof.PasswordAndCode("pw", "123456"))
            assertEquals("for $data", FailureKind.SERVER, (out as ApiOutcome.Failure).kind)
        }
    }

    @Test fun beginRefusalsFollowTheMappingTable() = runBlocking {
        val code = EnrolProof.PasswordAndCode("pw", "123456")
        answer(401, """{"error":"Invalid 2FA code"}""")
        assertEquals(ApiOutcome.StepUpRejected(), api.begin("i", code))
        answer(403, """{"error":"device_keys_disabled"}""")
        assertEquals(ApiOutcome.Forbidden(ForbiddenReason.OTHER, DeviceKeyErrors.DISABLED), api.begin("i", code))
        answer(403, """{"error":"enrol_locked"}""")
        assertEquals(ApiOutcome.Forbidden(ForbiddenReason.OTHER, DeviceKeyErrors.ENROL_LOCKED), api.begin("i", code))
        answer(403, """{"error":"Sensitive actions require 2FA: enable TOTP on your profile"}""")
        assertEquals(ForbiddenReason.NO_TOTP, (api.begin("i", code) as ApiOutcome.Forbidden).reason)
        answer(409, """{"error":"too_many_keys"}""")
        assertEquals(ApiOutcome.Unsupported(DeviceKeyErrors.TOO_MANY_KEYS), api.begin("i", code))
        answer(429, """{"error":"Too many verification attempts","codeLocked":true}""")
        assertEquals(ApiOutcome.RateLimited(null, codeLocked = true), api.begin("i", code))
    }

    /** SSO device keys: an Obligate account begins with {installId} only — never a password nor a code. */
    @Test fun ssoBeginSendsTheInstallIdOnly() = runBlocking {
        answer(200, """{"success":true,"data":{"ticketId":"$ticketId","nonce":"$nonce","expiresAt":1790000180,"userId":42,"allowedOrigins":["https://obliance-qual.example.org"],"requireAttestation":true}}""")
        val out = api.begin("0123456789abcdef0123456789abcdef", EnrolProof.SsoReauth)
        assertEquals(ticketId, (out as ApiOutcome.Ok).value.ticketId)
        val body = bodyOf(server.takeRequest())
        assertEquals(setOf("installId"), body.keys)
        // Without a fresh re-authentication (or the Obligate epoch moved): the step-up 401 asking for it.
        answer(401, """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"device_key.enrol","trustIpAllowed":false,"codeRequiresReauth":true}""")
        val again = api.begin("i", EnrolProof.SsoReauth) as ApiOutcome.StepUpRequired
        assertTrue(again.codeRequiresReauth)
        // Obligate unreachable: 503 verifierUnavailable, not an offline agent.
        answer(503, """{"success":false,"error":"Two-factor verification is temporarily unavailable","verifierUnavailable":true}""")
        assertEquals(ApiOutcome.Failure(503, FailureKind.SERVER, "verifier_unavailable"), api.begin("i", EnrolProof.SsoReauth))
        answer(403, """{"success":false,"error":"device_keys_sso_unsupported"}""")
        assertEquals(ApiOutcome.Forbidden(ForbiddenReason.OTHER, DeviceKeyErrors.SSO_UNSUPPORTED), api.begin("i", EnrolProof.SsoReauth))
    }

    @Test fun finishPostsTheContractShapeAndReadsTheKey() = runBlocking {
        answer(201, """{"success":true,"data":{"keyId":"$keyId","label":"Téléphone de John","securityLevel":"tee","createdAt":"2026-09-26T10:00:00.000Z"}}""")
        val finish = EnrolFinish(ticketId, "https://obliance-qual.example.org", "MFkw", listOf("MIIB", "MIIC"), "MEUC", "Téléphone de John", "0123456789abcdef0123456789abcdef", "0.4.0-alpha")
        val key = (api.finish(finish) as ApiOutcome.Ok).value
        assertEquals(keyId, key.keyId)
        assertEquals(DeviceKeyLevel.TEE, key.securityLevel)
        val req = server.takeRequest()
        assertEquals("/api/profile/device-keys/enrol/finish", req.url.encodedPath)
        val body = bodyOf(req)
        assertEquals(setOf("ticketId", "origin", "publicKey", "attestation", "signature", "label", "installId", "appVersion"), body.keys)
    }

    @Test fun finishRefusals() = runBlocking {
        answer(422, """{"error":"attestation_failed","reason":"bootloader_unlocked"}""")
        val finish = EnrolFinish(ticketId, "https://o.example.org", "k", listOf("c"), "s", "l", "i", "v")
        assertEquals(ApiOutcome.Failure(422, FailureKind.CLIENT, "bootloader_unlocked"), api.finish(finish))
        answer(400, """{"error":"invalid_ticket"}""")
        assertEquals(DeviceKeyErrors.INVALID_TICKET, (api.finish(finish) as ApiOutcome.Validation).message)
        answer(409, """{"error":"already_enrolled"}""")
        assertEquals(ApiOutcome.Unsupported(DeviceKeyErrors.ALREADY_ENROLLED), api.finish(finish))
    }

    @Test fun revokeReportAndRevokeAllPaths() = runBlocking {
        answer(204)
        assertEquals(ApiOutcome.Ok(Unit), api.revoke(keyId))
        server.takeRequest().let { assertEquals("DELETE", it.method); assertEquals("/api/profile/device-keys/$keyId", it.url.encodedPath) }
        answer(204)
        assertEquals(ApiOutcome.Ok(Unit), api.revokeAll())
        server.takeRequest().let { assertEquals("DELETE", it.method); assertEquals("/api/profile/device-keys", it.url.encodedPath) }
        answer(204)
        assertEquals(ApiOutcome.Ok(Unit), api.reportInvalidated(keyId))
        server.takeRequest().let { assertEquals("POST", it.method); assertEquals("/api/profile/device-keys/$keyId/invalidated", it.url.encodedPath) }
        answer(404, """{"error":"Not found"}""")
        assertEquals(404, (api.revoke(keyId) as ApiOutcome.Failure).status)
    }

    @Test fun aMalformedIdNeverReachesAPath() = runBlocking {
        for (bad in listOf("../users", "x", "$keyId/../../x", "")) {
            assertEquals(FailureKind.CLIENT, (api.revoke(bad) as ApiOutcome.Failure).kind)
            assertEquals(FailureKind.CLIENT, (api.reportInvalidated(bad) as ApiOutcome.Failure).kind)
        }
        assertEquals(0, server.requestCount)
    }

    // --- Sign-in and sign-out ------------------------------------------------------------

    /** A recorded login answer carrying a `login` device challenge. */
    private val j7 = """{"success":true,"data":{"requires2fa":true,"methods":{"totp":true,"email":false,"device":true},"deviceChallenge":{"v":1,"keyId":"$keyId","challengeId":"$ticketId","purpose":"login","userId":42,"tenantId":null,"nonce":"$nonce","action":"-","binding":"-","expiresAt":1790000120,"bulkId":null}}}"""

    @Test fun loginSendsTheExplicitHeaderAndReadsJ7() = runBlocking {
        answer(200, j7)
        val out = AuthApi(http).login("john.smith", "secret", keyId)
        val step = out as LoginResult.TwoFactorRequired
        assertTrue(step.methods.device && step.methods.totp)
        val c = step.deviceChallenge!!
        assertEquals(DevicePurpose.LOGIN, c.purpose)
        assertEquals(keyId, c.keyId)
        assertEquals(42L, c.userId)
        assertEquals(keyId, server.takeRequest().headers[DeviceKeyHeader.NAME])
    }

    @Test fun loginWithoutAKeySendsNoHeader() = runBlocking {
        answer(200, """{"success":true,"data":{"requires2fa":true,"methods":{"totp":true,"email":false}}}""")
        assertEquals(LoginResult.TwoFactorRequired(TwoFactorMethods(totp = true)), AuthApi(http).login("john.smith", "secret", null))
        assertNull(server.takeRequest().headers[DeviceKeyHeader.NAME])
        // A value that is not a key id is never sent.
        answer(200, """{"success":true,"data":{"requires2fa":true,"methods":{"totp":true}}}""")
        AuthApi(http).login("john.smith", "secret", "../x")
        assertNull(server.takeRequest().headers[DeviceKeyHeader.NAME])
    }

    @Test fun aMalformedLoginChallengeFallsBackToTheCode() = runBlocking {
        // A stepup challenge in a login answer, and an unknown version: dropped, methods.device false.
        for (bad in listOf(
            j7.replace("\"purpose\":\"login\"", "\"purpose\":\"stepup\""),
            j7.replace("\"v\":1,", "\"v\":2,"),
        )) {
            answer(200, bad)
            val step = AuthApi(http).login("john.smith", "secret", keyId) as LoginResult.TwoFactorRequired
            assertFalse(step.methods.device)
            assertNull(step.deviceChallenge)
        }
    }

    @Test fun verifyDevicePostsTheAssertion() = runBlocking {
        answer(200, """{"success":true,"data":{"user":{"id":42,"username":"john.smith"}}}""")
        val out = AuthApi(http).verifyDevice(DeviceAssertion(keyId, listOf(ticketId), "MEUCIQ=="))
        assertEquals(42L, ((out as DeviceLoginAnswer.Done).result as LoginResult.SignedIn).user.id)
        val body = bodyOf(server.takeRequest())
        assertEquals("device", body["method"]!!.jsonPrimitive.content)
        val a = body["deviceAssertion"]!!.jsonObject
        assertEquals(keyId, a["keyId"]!!.jsonPrimitive.content)
        assertEquals(1, a["v"]!!.jsonPrimitive.content.toInt())
        assertFalse("code" in body)

        answer(401, """{"success":false,"error":"Invalid code","deviceError":"invalid_assertion"}""")
        assertEquals(
            DeviceLoginAnswer.Refused(DeviceError.INVALID_ASSERTION),
            AuthApi(http).verifyDevice(DeviceAssertion(keyId, listOf(ticketId), "MEUCIQ==")),
        )
    }

    @Test fun verifyDeviceReadsTheRenewedChallengeAndTheKeyState() = runBlocking {
        val login = j7.substringAfter("\"deviceChallenge\":").removeSuffix("}}")
        answer(401, """{"success":false,"error":"Invalid code","deviceError":"challenge_expired","deviceChallenge":$login}""")
        val expired = AuthApi(http).verifyDevice(DeviceAssertion(keyId, listOf(ticketId), "MEUCIQ==")) as DeviceLoginAnswer.Refused
        assertEquals(DeviceError.CHALLENGE_EXPIRED, expired.error)
        assertEquals(ticketId, expired.renewed?.challengeId)
        assertFalse(expired.keyRevoked)

        // A step-up challenge is never taken for a login one.
        val stepUp = login.replace("\"purpose\":\"login\"", "\"purpose\":\"stepup\"")
        answer(401, """{"success":false,"error":"Invalid code","deviceError":"challenge_expired","deviceChallenge":$stepUp}""")
        assertNull((AuthApi(http).verifyDevice(DeviceAssertion(keyId, listOf(ticketId), "MEUCIQ==")) as DeviceLoginAnswer.Refused).renewed)

        answer(401, """{"success":false,"error":"Invalid code","deviceKeyStatus":"revoked"}""")
        assertTrue((AuthApi(http).verifyDevice(DeviceAssertion(keyId, listOf(ticketId), "MEUCIQ==")) as DeviceLoginAnswer.Refused).keyRevoked)
        answer(401, """{"success":false,"error":"Invalid code","deviceKeyStatus":"throttled"}""")
        assertTrue((AuthApi(http).verifyDevice(DeviceAssertion(keyId, listOf(ticketId), "MEUCIQ==")) as DeviceLoginAnswer.Refused).keyUnusable)

        answer(400, """{"success":false,"error":"No pending 2FA session"}""")
        assertEquals(DeviceLoginAnswer.Done(LoginResult.TwoFactorSessionLost), AuthApi(http).verifyDevice(DeviceAssertion(keyId, listOf(ticketId), "MEUCIQ==")))
    }

    @Test fun verifyTwoFactorCarriesTheLoginKey() = runBlocking {
        answer(200, """{"success":true,"data":{"user":{"id":42,"username":"john.smith"}}}""")
        AuthApi(http).verifyTwoFactor(TwoFactorMethod.TOTP, "482913", keyId)
        assertEquals(keyId, server.takeRequest().headers[DeviceKeyHeader.NAME])
        answer(200, """{"success":true,"data":{"user":{"id":42,"username":"john.smith"}}}""")
        AuthApi(http).verifyTwoFactor(TwoFactorMethod.TOTP, "482913")
        assertNull(server.takeRequest().headers[DeviceKeyHeader.NAME])
    }

    @Test fun deviceChallengeCarriesTheHeader() = runBlocking {
        answer(200, """{"success":true,"data":{"deviceChallenge":${j7.substringAfter("\"deviceChallenge\":").removeSuffix("}}")}}}""")
        val out = AuthApi(http).deviceChallenge(keyId)
        assertEquals(DevicePurpose.LOGIN, (out as ApiOutcome.Ok).value.purpose)
        val req = server.takeRequest()
        assertEquals("/api/profile/2fa/device-challenge", req.url.encodedPath)
        assertEquals(keyId, req.headers[DeviceKeyHeader.NAME])
        assertEquals(FailureKind.CLIENT, (AuthApi(http).deviceChallenge("x") as ApiOutcome.Failure).kind)
    }

    @Test fun logoutCarriesTheKeyOfTheSession() = runBlocking {
        answer(200, """{"success":true}""")
        assertEquals(ApiOutcome.Ok(Unit), AuthApi(http).logout(keyId))
        assertEquals(keyId, server.takeRequest().headers[DeviceKeyHeader.NAME])
        answer(200, """{"success":true}""")
        AuthApi(http).logout()
        assertNull(server.takeRequest().headers[DeviceKeyHeader.NAME])
    }
}
