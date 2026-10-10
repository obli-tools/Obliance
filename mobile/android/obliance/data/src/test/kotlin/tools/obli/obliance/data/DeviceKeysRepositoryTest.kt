package tools.obli.obliance.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.CookieJar
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.auth.AuthState
import tools.obli.core.auth.ServerRegistry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import tools.obli.core.auth.ServerRegistryState
import tools.obli.core.auth.ServerRegistryStore
import tools.obli.core.auth.ServerSession
import tools.obli.core.auth.ServerSessions
import tools.obli.core.model.ServerColor
import tools.obli.core.model.ServerId
import tools.obli.core.model.ServerProfile
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceKeyHeader
import tools.obli.core.network.FailureKind
import tools.obli.core.network.ForbiddenReason
import tools.obli.core.network.ObliHttp
import tools.obli.core.security.DeviceKeyAlias
import tools.obli.core.security.DeviceKeyHardware
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.DeviceKeyRecord
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.EnrolProof
import tools.obli.core.security.EnrolResult
import tools.obli.core.security.GeneratedKey
import tools.obli.core.security.InMemoryDeviceKeyStore
import tools.obli.core.security.KeyHealth
import tools.obli.core.security.OpenedSignature
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignResult
import tools.obli.core.security.SsoReauthResult
import tools.obli.obliance.api.LoginResult

/**
 * Device-bound validation of the data layer
 * against two fake servers: profile and security states,
 * enrolment, revocation, sign-in header, sign-out, key health, proposal.
 */
class DeviceKeysRepositoryTest {
    private val prod = FakeServer()
    private val qual = FakeServer()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val client = ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA")
    private val cleared = java.util.concurrent.CopyOnWriteArrayList<String>()

    private val prodId = ServerId("prod")
    private val qualId = ServerId("qual")
    private val prodOrigin = "https://obliance-prod.example.org"
    private val qualOrigin = "https://obliance-qual.example.org"
    private val mockOf = mapOf(prodOrigin to prod, qualOrigin to qual)

    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val otherKey = "0f8fad5b-d9cb-469f-a165-70867728950e"
    private val ticketId = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
    private val nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    private val install = "0123456789abcdef0123456789abcdef"

    private val store = InMemoryDeviceKeyStore(newInstallId = { install })
    private val hardware = FakeHardware()
    private var strong = true
    private val prompt = SignPrompt("Activer la validation par empreinte", "Obliance Qual", null, "Annuler")

    private class MemoryStore(var saved: ServerRegistryState?) : ServerRegistryStore {
        override suspend fun load() = saved
        override suspend fun save(state: ServerRegistryState) { saved = state }
    }

    class FakeHardware : DeviceKeyHardware {
        val aliases = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        val deleted = java.util.concurrent.CopyOnWriteArrayList<String>()
        val health = java.util.concurrent.ConcurrentHashMap<String, KeyHealth>()
        override suspend fun generate(alias: String, attestationChallenge: ByteArray): GeneratedKey {
            aliases += alias
            return GeneratedKey(byteArrayOf(0x30, 0x59, 0x30, 0x13), listOf(byteArrayOf(0x30, 1), byteArrayOf(0x30, 2)), DeviceKeyLevel.STRONGBOX)
        }
        override fun delete(alias: String) {
            deleted += alias
            aliases -= alias
        }
        override fun health(alias: String): KeyHealth = if (alias !in aliases) KeyHealth.Missing else health[alias] ?: KeyHealth.Healthy
        override fun openSignature(alias: String): OpenedSignature = OpenedSignature.Failed(health(alias))
        override fun aliases(): Set<String> = aliases.toSet()
    }

    private class FakeSigner(var result: SignResult = SignResult.Signed(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))) : DeviceSigner {
        var calls = 0
        override suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt): SignResult {
            calls++
            return result
        }
    }

    private lateinit var sessions: ServerSessions
    private lateinit var registry: ServerRegistry

    private fun services(reauth: (suspend (String) -> SsoReauthResult)? = null): DefaultObliServices = runBlocking {
        registry = ServerRegistry(
            MemoryStore(
                ServerRegistryState(
                    listOf(
                        ServerProfile(prodId, prodOrigin, "Obliance Prod", ServerColor.VIOLET, "OP", 0),
                        ServerProfile(qualId, qualOrigin, "Obliance Qual", ServerColor.FUCHSIA, "OQ", 1),
                    ),
                    qualId,
                ),
            ),
        )
        registry.load()
        lateinit var services: DefaultObliServices
        val keyed = ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA", deviceKeyHeader = { services.deviceKeyHeader(it) })
        sessions = ServerSessions(registry, { p, now ->
            ServerSession(p.id, now, ObliHttp(mockOf.getValue(p.origin).origin, keyed) { o, k -> services.deviceKeyRevoked(o, k) }, { FakeRealtime() })
        }, scope)
        services = DefaultObliServices(
            registry, sessions,
            httpFor = { origin -> ObliHttp(mockOf[origin]?.origin ?: origin, keyed) },
            clearCookies = { cleared += it },
            scope = scope,
            deviceKeyDeps = DeviceKeyDeps(store, hardware, strongBiometric = { strong }, deviceLabel = { "Téléphone de John" }, appVersion = "0.4.0-alpha", reauth = reauth),
        )
        services
    }

    @After fun tearDown() {
        scope.cancel()
        prod.close()
        qual.close()
    }

    private fun list(
        origin: String = qual.origin,
        enabled: Boolean = true,
        originConfigured: Boolean = true,
        ssoSupported: Boolean = false,
        eligibility: String = """{"ok":true}""",
        keys: String = "",
        bound: String? = null,
    ) = """{"success":true,"data":{"policy":{"enabled":$enabled,"loginEnabled":true,"requireAttestation":true,"strictSession":true,"originConfigured":$originConfigured,"ssoSupported":$ssoSupported},
        "allowedOrigins":["$origin"],"boundKeyId":${bound?.let { "\"$it\"" } ?: "null"},"eligibility":$eligibility,"keys":[$keys]}}"""

    private fun key(id: String = keyId, level: String = "strongbox", current: Boolean = true) =
        """{"id":"$id","label":"Téléphone de John","platform":"android","securityLevel":"$level","createdAt":"2026-09-26T10:00:00.000Z","useCount":0,"current":$current}"""

    private val meLocalTotp = """{"success":true,"data":{"user":{"id":7,"username":"john.smith","displayName":"John Smith","role":"user","totpEnabled":true},"currentTenantId":1}}"""
    private val meLocalNoTotp = """{"success":true,"data":{"user":{"id":7,"username":"john.smith","role":"user","totpEnabled":false},"currentTenantId":1}}"""

    private fun record(origin: String = qual.origin, userId: Long = 7, id: String = keyId): DeviceKeyRecord {
        val alias = DeviceKeyAlias.of(origin, userId, install)
        hardware.aliases += alias
        return DeviceKeyRecord(origin, userId, "john.smith", id, alias, install, DeviceKeyLevel.STRONGBOX, 1)
    }

    private suspend fun signedIn(me: String = meLocalTotp): ServerSession {
        qual.on("GET /api/auth/me", body = me)
        val s = sessions.session(qualId)!!
        assertTrue(s.probe() is AuthState.SignedIn)
        return s
    }

    private suspend fun until(what: String, check: () -> Boolean) {
        withTimeout(5_000) { while (!check()) delay(20) }
        assertTrue(what, check())
    }

    // --- Profile and security states ------------------------------------------------

    @Test fun statesInTheOrderOfTheChecks() = runBlocking {
        val s = services()
        val repo = s.deviceKeys
        // Not signed in.
        assertEquals(DeviceKeyServerState.SignedOut, repo.refresh(qualId).state)
        signedIn()
        qual.on("GET /api/profile/device-keys", 404, """{"error":"Not found"}""")
        assertEquals(DeviceKeyServerState.NotAvailable, repo.refresh(qualId).state)
        qual.on("GET /api/profile/device-keys", body = list(enabled = false))
        assertEquals(DeviceKeyServerState.DisabledByAdmin(null), repo.refresh(qualId).state)
        qual.on("GET /api/profile/device-keys", body = list(originConfigured = false))
        assertEquals(DeviceKeyServerState.OriginUnset, repo.refresh(qualId).state)
        qual.on("GET /api/profile/device-keys", body = list(eligibility = """{"ok":false,"reason":"inactive"}"""))
        assertEquals(DeviceKeyServerState.NotEligible("inactive"), repo.refresh(qualId).state)
        // The reasons the server sends (shared DeviceKeyEligibilityReason).
        qual.on("GET /api/profile/device-keys", body = list(eligibility = """{"ok":false,"reason":"no_totp"}"""))
        assertEquals(DeviceKeyServerState.TotpRequired, repo.refresh(qualId).state)
        qual.on("GET /api/profile/device-keys", body = list(eligibility = """{"ok":false,"reason":"device_keys_sso_unsupported"}"""))
        assertEquals(DeviceKeyServerState.SsoUnsupported, repo.refresh(qualId).state)
        qual.on("GET /api/profile/device-keys", body = list(eligibility = """{"ok":false,"reason":"enrol_locked"}"""))
        assertEquals(DeviceKeyServerState.NotEligible("enrol_locked"), repo.refresh(qualId).state)
        qual.on("GET /api/profile/device-keys", body = list(origin = "https://obliance-qual.example.org"))
        assertEquals(DeviceKeyServerState.OriginMismatch(qual.origin), repo.refresh(qualId).state)
        qual.on("GET /api/profile/device-keys", body = list())
        strong = false
        assertEquals(DeviceKeyServerState.NoStrongBiometric, repo.refresh(qualId).state)
        strong = true
        val view = repo.refresh(qualId)
        assertEquals(DeviceKeyServerState.NotEnrolled, view.state)
        assertTrue(view.state.canEnrol)
        assertNotNull(view.list)
        assertEquals(view, repo.views.value[qualId])
        qual.on("GET /api/profile/device-keys", 500, """{"error":"boom"}""")
        assertTrue(repo.refresh(qualId).state is DeviceKeyServerState.Failed)
    }

    /** SSO device keys: an Obligate account may enrol only where the server supports it AND the app has its sheet. */
    @Test fun obligateAndTotpLessAccounts() = runBlocking {
        val s = services(reauth = { SsoReauthResult.Success })
        signedIn(ME_ADMIN)
        // SSO device keys off on the server (DEVICE_KEYS_SSO_ENABLED unset, Obligate without the capabilities, older server).
        qual.on("GET /api/profile/device-keys", body = list())
        val off = s.deviceKeys.refresh(qualId)
        assertEquals(DeviceKeyServerState.SsoUnsupported, off.state)
        assertTrue(off.sso)
        // SSO device keys on: « Activer », through Obligate — no TOTP of this server needed (ME_ADMIN has none).
        qual.on("GET /api/profile/device-keys", body = list(ssoSupported = true))
        val on = s.deviceKeys.refresh(qualId)
        assertEquals(DeviceKeyServerState.NotEnrolled, on.state)
        assertTrue(on.state.canEnrol)
        assertTrue(on.sso)
        // The server's own refusal still wins.
        qual.on("GET /api/profile/device-keys", body = list(ssoSupported = true, eligibility = """{"ok":false,"reason":"device_keys_sso_unsupported"}"""))
        assertEquals(DeviceKeyServerState.SsoUnsupported, s.deviceKeys.refresh(qualId).state)
        // A local account without TOTP: TOTP first.
        signedIn(meLocalNoTotp)
        qual.on("GET /api/profile/device-keys", body = list(ssoSupported = true))
        val local = s.deviceKeys.refresh(qualId)
        assertEquals(DeviceKeyServerState.TotpRequired, local.state)
        assertFalse(local.sso)
    }

    /** Without the app's re-authentication sheet (fakes, previews), an Obligate account is never offered « Activer ». */
    @Test fun obligateAccountsWithoutTheSheetStayUnsupported() = runBlocking {
        val s = services()
        signedIn(ME_ADMIN)
        qual.on("GET /api/profile/device-keys", body = list(ssoSupported = true))
        val sso = s.deviceKeys.refresh(qualId).state
        assertEquals(DeviceKeyServerState.SsoUnsupported, sso)
        assertFalse(sso.canEnrol)
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.SSO_UNSUPPORTED), s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt))
        assertEquals(0, qual.count("POST /api/profile/device-keys/enrol/begin"))
    }

    @Test fun anActiveKeyAndAKeyRevokedElsewhere() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        signedIn()
        qual.on("GET /api/profile/device-keys", body = list(keys = key(level = "tee"), bound = keyId))
        assertEquals(DeviceKeyServerState.Active(rec, DeviceKeyLevel.TEE, bound = true), s.deviceKeys.refresh(qualId).state)
        assertEquals(rec, s.deviceKeys.localKey(qualId))
        // The web revoked it: gone from the list → forgotten here, alias deleted, « Activer » again.
        qual.on("GET /api/profile/device-keys", body = list(keys = key(otherKey, current = false)))
        assertEquals(DeviceKeyServerState.NotEnrolled, s.deviceKeys.refresh(qualId).state)
        assertNull(store.find(qual.origin, 7))
        assertTrue(rec.alias in hardware.deleted)
    }

    // --- Enrolment ----------------------------------------------------------------------------

    private fun enrolRoutes() {
        qual.on("POST /api/profile/device-keys/enrol/begin", body = """{"success":true,"data":{"ticketId":"$ticketId","nonce":"$nonce","expiresAt":1790000180,"userId":7,"allowedOrigins":["${qual.origin}"],"requireAttestation":true}}""")
        qual.on("POST /api/profile/device-keys/enrol/finish", 201, """{"success":true,"data":{"keyId":"$keyId","label":"Téléphone de John","securityLevel":"strongbox","createdAt":"2026-09-26T10:00:00.000Z"}}""")
    }

    @Test fun enrolStoresTheKeyAndTheRowTurnsActive() = runBlocking {
        val s = services()
        signedIn()
        enrolRoutes()
        qual.on("GET /api/profile/device-keys", body = list(keys = key(), bound = keyId))
        val signer = FakeSigner()
        val out = s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("correct horse", "482913"), signer, prompt)
        assertTrue("got $out", out is DeviceKeyEnrolOutcome.Enrolled)
        val rec = store.find(qual.origin, 7)!!
        assertEquals(keyId, rec.keyId)
        assertEquals("john.smith", rec.username)
        assertEquals(1, signer.calls)
        assertTrue(s.deviceKeys.views.value.getValue(qualId).state is DeviceKeyServerState.Active)
        // begin carried the proofs, finish the contract fields; the label and version are the app's.
        val finish = qual.recorded.first { it.first == "POST /api/profile/device-keys/enrol/finish" }.second.body!!.utf8()
        assertTrue(finish.contains("\"label\":\"Téléphone de John\"") && finish.contains("\"appVersion\":\"0.4.0-alpha\""))
        // The session is bound now: later requests carry the header of this key.
        qual.on("GET /api/devices/summary", body = """{"success":true,"data":{}}""")
        s.devices.summary(qualId)
        assertEquals(keyId, qual.recorded.last { it.first == "GET /api/devices/summary" }.second.headers[DeviceKeyHeader.NAME])
    }

    @Test fun wrongCredentialsAndRefusals() = runBlocking {
        val s = services()
        signedIn()
        qual.on("POST /api/profile/device-keys/enrol/begin", 401, """{"error":"Invalid 2FA code"}""")
        assertEquals(DeviceKeyEnrolOutcome.WrongCredentials, s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("pw", "123456"), FakeSigner(), prompt))
        // The code of the sign-in, still on the authenticator: right, but its step was used (not counted).
        qual.on("POST /api/profile/device-keys/enrol/begin", 401, """{"error":"Invalid 2FA code","codeUsed":true}""")
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.CODE_USED), s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("pw", "123456"), FakeSigner(), prompt))
        // Another 401 wording: /me still answers, so it was the password, not the session.
        qual.on("POST /api/profile/device-keys/enrol/begin", 401, """{"error":"Invalid password"}""")
        assertEquals(DeviceKeyEnrolOutcome.WrongCredentials, s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("pw", "123456"), FakeSigner(), prompt))
        assertTrue(sessions.session(qualId)!!.auth.value is AuthState.SignedIn)
        qual.on("POST /api/profile/device-keys/enrol/begin", 403, """{"error":"enrol_locked"}""")
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.LOCKED), s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("pw", "123456"), FakeSigner(), prompt))
        // No strong biometric: nothing is sent.
        strong = false
        val before = qual.count("POST /api/profile/device-keys/enrol/begin")
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.BIOMETRIC_UNAVAILABLE), s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("pw", "123456"), FakeSigner(), prompt))
        assertEquals(before, qual.count("POST /api/profile/device-keys/enrol/begin"))
        strong = true
        // The session really expired.
        qual.on("POST /api/profile/device-keys/enrol/begin", 401, EXPIRED)
        qual.on("GET /api/auth/me", 401, EXPIRED)
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.SESSION_EXPIRED), s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("pw", "123456"), FakeSigner(), prompt))
        assertEquals(AuthState.Expired, sessions.session(qualId)!!.auth.value)
    }

    /**
     * SSO device keys: the Obligate re-authentication of THIS session, then
     * begin with {installId} only, then the same key flow; never a password.
     */
    @Test fun anObligateAccountEnrolsThroughTheReauthentication() = runBlocking {
        val asked = mutableListOf<String>()
        var answer: SsoReauthResult = SsoReauthResult.Success
        val s = services(reauth = { origin -> asked += origin; answer })
        signedIn(ME_ADMIN)
        qual.on("POST /api/profile/device-keys/enrol/begin", body = """{"success":true,"data":{"ticketId":"$ticketId","nonce":"$nonce","expiresAt":1790000180,"userId":3,"allowedOrigins":["${qual.origin}"],"requireAttestation":true}}""")
        qual.on("POST /api/profile/device-keys/enrol/finish", 201, """{"success":true,"data":{"keyId":"$keyId","label":"Téléphone de John","securityLevel":"strongbox","createdAt":"2026-09-26T10:00:00.000Z"}}""")
        qual.on("GET /api/profile/device-keys", body = list(ssoSupported = true, keys = key(), bound = keyId))
        val out = s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt)
        assertTrue("got $out", out is DeviceKeyEnrolOutcome.Enrolled)
        assertEquals(listOf(qual.origin), asked)
        assertEquals("og_john.smith", store.find(qual.origin, 3)!!.username)
        val begin = qual.recorded.first { it.first == "POST /api/profile/device-keys/enrol/begin" }.second.body!!.utf8()
        assertEquals(setOf("installId"), Json.parseToJsonElement(begin).jsonObject.keys)

        val begins = { qual.count("POST /api/profile/device-keys/enrol/begin") }
        val sent = begins()
        // Never a local password for an Obligate account: refused before any call (no sheet either).
        assertEquals(
            DeviceKeyEnrolOutcome.Failed(EnrolProblem.SSO_UNSUPPORTED, DefaultDeviceKeysRepository.PROOF_MISMATCH),
            s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("pw", "123456"), FakeSigner(), prompt),
        )
        // Sheet closed: cancelled; refused: reported with its reason. Nothing sent either way.
        answer = SsoReauthResult.Cancelled
        assertEquals(DeviceKeyEnrolOutcome.Cancelled, s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt))
        answer = SsoReauthResult.Failed("no_otp")
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.REAUTH_FAILED, "no_otp"), s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt))
        assertEquals(sent, begins())
        // The sheet was asked for the first enrolment, the cancel and the refusal — not for the local password.
        assertEquals(3, asked.size)
        // begin wants a NEW re-authentication (older than 5 min, already used, or the Obligate epoch moved).
        answer = SsoReauthResult.Success
        qual.on("POST /api/profile/device-keys/enrol/begin", 401, """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"device_key.enrol","trustIpAllowed":false,"codeRequiresReauth":true}""")
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.REAUTH_REQUIRED), s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt))
        // Obligate unreachable at begin.
        qual.on("POST /api/profile/device-keys/enrol/begin", 503, """{"success":false,"error":"Two-factor verification is temporarily unavailable","verifierUnavailable":true}""")
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.VERIFIER_UNAVAILABLE), s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt))
        // The sheet says the session ended: /me decides. Still signed in → the reason; gone → sign-in-again.
        answer = SsoReauthResult.Failed("signed_out")
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.REAUTH_FAILED, "signed_out"), s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt))
        qual.on("GET /api/auth/me", 401, EXPIRED)
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.SESSION_EXPIRED), s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt))
        assertEquals(AuthState.Expired, sessions.session(qualId)!!.auth.value)
    }

    @Test fun aLocalAccountNeverTakesTheObligatePath() = runBlocking {
        val asked = mutableListOf<String>()
        val s = services(reauth = { origin -> asked += origin; SsoReauthResult.Success })
        signedIn()
        assertEquals(
            DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED, DefaultDeviceKeysRepository.PROOF_MISMATCH),
            s.deviceKeys.enrol(qualId, EnrolProof.SsoReauth, FakeSigner(), prompt),
        )
        assertTrue(asked.isEmpty())
        assertEquals(0, qual.count("POST /api/profile/device-keys/enrol/begin"))
    }

    @Test fun aCancelledFingerprintLeavesNoKey() = runBlocking {
        val s = services()
        signedIn()
        enrolRoutes()
        val out = s.deviceKeys.enrol(qualId, EnrolProof.PasswordAndCode("pw", "123456"), FakeSigner(SignResult.UseCode), prompt)
        assertEquals(DeviceKeyEnrolOutcome.Cancelled, out)
        assertNull(store.find(qual.origin, 7))
        assertTrue(hardware.aliases.isEmpty())
        assertEquals(0, qual.count("POST /api/profile/device-keys/enrol/finish"))
    }

    @Test fun enrolmentOutcomesFollowTheMappingTable() {
        fun r(o: ApiOutcome<Nothing>) = DefaultDeviceKeysRepository.outcomeOf(EnrolResult.Refused(o))
        assertEquals(DeviceKeyEnrolOutcome.WrongCredentials, r(ApiOutcome.StepUpRejected()))
        // A right code already used (the sign-in code): « attendez le code suivant », not « mot de passe ou code incorrect ».
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.CODE_USED), r(ApiOutcome.StepUpRejected(codeUsed = true)))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.DISABLED), r(ApiOutcome.Forbidden(ForbiddenReason.OTHER, "device_keys_disabled")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.ORIGIN_UNSET), r(ApiOutcome.Forbidden(ForbiddenReason.OTHER, "device_keys_origin_unset")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.SSO_UNSUPPORTED), r(ApiOutcome.Forbidden(ForbiddenReason.OTHER, "device_keys_sso_unsupported")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.NO_TOTP), r(ApiOutcome.Forbidden(ForbiddenReason.NO_TOTP, "enable TOTP")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.TICKET), r(ApiOutcome.Validation("invalid_ticket", emptyMap())))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.ORIGIN_MISMATCH), r(ApiOutcome.Validation("origin_mismatch", emptyMap())))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED, "bad_signature"), r(ApiOutcome.Validation("bad_signature", emptyMap())))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.TOO_MANY_KEYS), r(ApiOutcome.Unsupported("too_many_keys")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.ALREADY_ENROLLED), r(ApiOutcome.Unsupported("already_enrolled")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.ATTESTATION, "app_signer"), r(ApiOutcome.Failure(422, FailureKind.CLIENT, "app_signer")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.CODE_LOCKED), r(ApiOutcome.RateLimited(null, codeLocked = true)))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.RATE_LIMITED), r(ApiOutcome.RateLimited(60)))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.NETWORK), r(ApiOutcome.Failure(null, FailureKind.NETWORK)))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.NOT_AVAILABLE), r(ApiOutcome.Failure(404, FailureKind.NOT_FOUND)))
        // An Obligate account needs a (new) re-authentication (401 twoFactorRequired + codeRequiresReauth): « Reconfirmer » again.
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.REAUTH_REQUIRED), r(ApiOutcome.StepUpRequired("device_key.enrol", null, trustIpAllowed = false, codeRequiresReauth = true)))
        // 503 verifierUnavailable (Obligate could not confirm the account right now).
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.VERIFIER_UNAVAILABLE), r(ApiOutcome.Failure(503, FailureKind.SERVER, "verifier_unavailable")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED, "boom"), r(ApiOutcome.Failure(500, FailureKind.SERVER, "boom")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED), r(ApiOutcome.StepUpRequired("device_key.enrol", null, codeRequiresPassword = true)))
        val o = DefaultDeviceKeysRepository::outcomeOf
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.NOT_HARDWARE_BACKED), o(EnrolResult.NotHardwareBacked))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.BUSY), o(EnrolResult.KeyGenerationFailed("busy")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.KEY_FAILED, "ProviderException"), o(EnrolResult.KeyGenerationFailed("ProviderException")))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.ORIGIN_MISMATCH), o(EnrolResult.OriginNotAllowed))
        assertEquals(DeviceKeyEnrolOutcome.Failed(EnrolProblem.BIOMETRIC_LOCKED), o(EnrolResult.NotSigned(SignResult.LockedOut)))
        assertEquals(DeviceKeyEnrolOutcome.Cancelled, o(EnrolResult.NotSigned(SignResult.Cancelled)))
    }

    // --- Revocation --------------------------------------------------------------------------

    @Test fun revokingThisPhonesKeyForgetsItAndEndsTheSession() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        signedIn()
        qual.on("DELETE /api/profile/device-keys/$keyId", 204, "")
        // The server ended the bound session.
        qual.on("GET /api/auth/me", 401, EXPIRED)
        assertEquals(ApiOutcome.Ok(Unit), s.deviceKeys.revoke(qualId, keyId))
        assertNull(store.find(qual.origin, 7))
        assertTrue(rec.alias in hardware.deleted)
        assertEquals(AuthState.Expired, sessions.session(qualId)!!.auth.value)
    }

    @Test fun revokingAnotherPhoneKeepsThisOne() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        signedIn()
        qual.on("DELETE /api/profile/device-keys/$otherKey", 204, "")
        qual.on("GET /api/profile/device-keys", body = list(keys = key(), bound = keyId))
        assertEquals(ApiOutcome.Ok(Unit), s.deviceKeys.revoke(qualId, otherKey))
        assertEquals(rec, store.find(qual.origin, 7))
        assertTrue(sessions.session(qualId)!!.auth.value is AuthState.SignedIn)
        // The DELETE carried this phone's header (bound session).
        assertEquals(keyId, qual.recorded.last { it.first == "DELETE /api/profile/device-keys/$otherKey" }.second.headers[DeviceKeyHeader.NAME])
    }

    @Test fun revokeAllForgetsThisPhoneToo() = runBlocking {
        val s = services()
        store.put(record())
        signedIn()
        qual.on("DELETE /api/profile/device-keys", 204, "")
        qual.on("GET /api/auth/me", 401, EXPIRED)
        assertEquals(ApiOutcome.Ok(Unit), s.deviceKeys.revokeAll(qualId))
        assertNull(store.find(qual.origin, 7))
    }

    @Test fun a401RevokedPurgesTheKeyTheRequestCarried() = runBlocking {
        val s = services()
        store.put(record())
        signedIn()
        qual.on("GET /api/devices/summary", 401, """{"success":false,"error":"Authentication required","deviceKeyStatus":"revoked"}""")
        assertEquals(ApiOutcome.SessionExpired, s.devices.summary(qualId))
        until("purged") { store.find(qual.origin, 7) == null }
    }

    // --- Sign-in, sign-out ------------------------------------------------------------------------

    @Test fun signInSendsTheKeyOfTheTypedUsername() = runBlocking {
        val s = services()
        store.put(record())
        qual.on("POST /api/auth/login", body = """{"success":true,"data":{"requires2fa":true,"methods":{"totp":true,"email":false}}}""")
        val out = s.auth.login(qualOrigin, "JOHN.SMITH", "secret")
        assertEquals(LoginResult.TwoFactorRequired(tools.obli.obliance.api.TwoFactorMethods(totp = true)), out)
        assertEquals(keyId, qual.recorded.last().second.headers[DeviceKeyHeader.NAME])
        s.auth.login(qualOrigin, "someone.else", "secret")
        assertNull(qual.recorded.last().second.headers[DeviceKeyHeader.NAME])
    }

    @Test fun aKeyRevokedWhileSignedOutIsForgottenBeforeTheNewSessionUsesIt() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        qual.on("GET /api/auth/me", body = meLocalTotp)
        qual.on("GET /api/profile/device-keys", body = list(keys = key(otherKey, current = false)))
        val done = s.auth.completeSignIn(qualOrigin)
        assertTrue(done is SignInResult.Done)
        assertNull(store.find(qual.origin, 7))
        // Neither the check nor the probe carried the dead key's header.
        assertTrue(qual.recorded.filter { it.first == "GET /api/auth/me" || it.first == "GET /api/profile/device-keys" }.all { it.second.headers[DeviceKeyHeader.NAME] == null })
    }

    @Test fun aKeyStillActiveIsKeptAtSignIn() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        qual.on("GET /api/auth/me", body = meLocalTotp)
        qual.on("GET /api/profile/device-keys", body = list(keys = key()))
        s.auth.completeSignIn(qualOrigin)
        assertEquals(rec, store.find(qual.origin, 7))
    }

    @Test fun signOutRevokesWithTheHeaderThenForgets() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        signedIn()
        qual.on("POST /api/auth/logout", body = """{"success":true}""")
        s.auth.signOut(qualId)
        assertEquals(keyId, qual.recorded.last { it.first == "POST /api/auth/logout" }.second.headers[DeviceKeyHeader.NAME])
        assertNull(store.find(qual.origin, 7))
        assertTrue(rec.alias in hardware.deleted)
        assertEquals(AuthState.SignedOut, sessions.session(qualId)!!.auth.value)
    }

    @Test fun signOutOfAnExpiredSessionStillForgetsTheKey() = runBlocking {
        val s = services()
        store.put(record())
        signedIn()
        sessions.session(qualId)!!.markExpired()
        qual.on("POST /api/auth/logout", 503, """{"error":"unavailable"}""") // the server cannot revoke: forgotten anyway
        s.auth.signOut(qualId)
        assertNull(store.find(qual.origin, 7))
    }

    /**
     * Cold start with the server unreachable: `/me` never answered, the user is
     * unknown in this process, yet « Se déconnecter » is offered. The key goes
     * anyway (offline too), with its header in case the server hears it.
     */
    @Test fun signOutAfterAnUnreachableFirstProbeStillForgetsTheKey() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        qual.on("GET /api/auth/me", 503, """{"error":"unavailable"}""")
        val session = sessions.session(qualId)!!
        assertTrue(session.probe() is AuthState.Unreachable)
        assertNull(session.lastUserId)
        qual.on("POST /api/auth/logout", 503, """{"error":"unavailable"}""")
        s.auth.signOut(qualId)
        assertEquals(keyId, qual.recorded.last { it.first == "POST /api/auth/logout" }.second.headers[DeviceKeyHeader.NAME])
        assertNull(store.find(qual.origin, 7))
        assertTrue(rec.alias in hardware.deleted)
        assertEquals(AuthState.SignedOut, session.auth.value)
    }

    /** Never probed and two accounts' keys on that server: both go, no header (it could be the wrong one), other servers untouched. */
    @Test fun signOutOfAnUnknownUserForgetsEveryKeyOfThatServerOnly() = runBlocking {
        val s = services()
        val mine = record(userId = 7)
        val other = record(userId = 9, id = otherKey)
        val prodKey = record(origin = prod.origin, userId = 7)
        store.put(mine)
        store.put(other)
        store.put(prodKey)
        qual.on("POST /api/auth/logout", body = """{"success":true}""")
        s.auth.signOut(qualId)
        assertNull(qual.recorded.last { it.first == "POST /api/auth/logout" }.second.headers[DeviceKeyHeader.NAME])
        assertNull(store.find(qual.origin, 7))
        assertNull(store.find(qual.origin, 9))
        assertTrue(mine.alias in hardware.deleted && other.alias in hardware.deleted)
        assertEquals(prodKey, store.find(prod.origin, 7))
    }

    /**
     * The runner's session info: the session tenant `/me` last gave for
     * an origin and the server's name; a challenge of another tenant makes the
     * app read the session again.
     */
    @Test fun actionSessionsReadTheProbeAndTheProfile() = runBlocking {
        val s = services()
        signedIn()
        val info = s.actionSessions
        assertEquals(1L, info.tenantOf(qual.origin))
        assertEquals("Obliance Qual", info.serverNameOf(qual.origin))
        assertNull(info.tenantOf("https://elsewhere.example.org"))
        assertNull(info.serverNameOf("https://elsewhere.example.org"))
        // The web view switched the session tenant behind the native screen.
        qual.on("GET /api/auth/me", body = meLocalTotp.replace("\"currentTenantId\":1", "\"currentTenantId\":4"))
        info.tenantChanged(qual.origin)
        until("probed again") { info.tenantOf(qual.origin) == 4L }
    }

    @Test fun removingAServerForgetsEveryKeyOfItsOrigin() = runBlocking {
        val s = services()
        store.put(DeviceKeyRecord(prodOrigin, 3, "og_john", keyId, DeviceKeyAlias.of(prodOrigin, 3, install), install, DeviceKeyLevel.TEE, 1))
        store.put(DeviceKeyRecord(prodOrigin, 9, "john.local", otherKey, DeviceKeyAlias.of(prodOrigin, 9, install), install, DeviceKeyLevel.TEE, 1))
        registry.remove(prodId)
        assertTrue(store.records.value.none { it.origin == prodOrigin })
    }

    // --- Key health ---------------------------------------------------------------------------------

    @Test fun anInvalidatedKeyIsReportedPurgedAndEndsThatSession() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        signedIn()
        hardware.health[rec.alias] = KeyHealth.Invalidated
        qual.on("POST /api/profile/device-keys/$keyId/invalidated", 204, "")
        s.start() // always in the foreground in tests: the health check runs
        until("session ended") { sessions.session(qualId)!!.auth.value == AuthState.Expired }
        assertEquals(1, qual.count("POST /api/profile/device-keys/$keyId/invalidated"))
        assertNull(store.find(qual.origin, 7))
        assertTrue(qualOrigin in cleared)
        assertTrue(qualId in s.deviceKeys.invalidatedServers.value)
        // The sign-in-again sheet says why the session ended…
        assertTrue(qualId in s.deviceKeys.reauthNotices.value)
        // …until the user signs in again (password + code); the profile screen then offers « Réactiver ».
        qual.on("GET /api/auth/me", body = meLocalTotp)
        qual.on("GET /api/profile/device-keys", body = list())
        assertTrue(s.auth.completeSignIn(qualOrigin) is SignInResult.Done)
        assertFalse(qualId in s.deviceKeys.reauthNotices.value)
        assertEquals(DeviceKeyServerState.Invalidated, s.deviceKeys.refresh(qualId).state)
    }

    @Test fun aKeyThatIsMerelyUnavailableIsKept() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        signedIn()
        hardware.health[rec.alias] = KeyHealth.Unavailable("KeyStoreException")
        s.start()
        delay(300)
        assertEquals(rec, store.find(qual.origin, 7))
        assertTrue(sessions.session(qualId)!!.auth.value is AuthState.SignedIn)
        assertTrue(cleared.isEmpty())
    }

    // --- First-2FA proposal ------------------------------------------------------------------------

    @Test fun aCodeOnAnEligibleServerProposesOnceAndLaterIsRemembered() = runBlocking {
        val s = services()
        signedIn()
        qual.on("GET /api/profile/device-keys", body = list())
        s.deviceKeys.codeAccepted(qual.origin)
        until("proposed") { s.deviceKeys.proposal.value != null }
        assertEquals(DeviceKeyProposal(qualId, "Obliance Qual"), s.deviceKeys.proposal.value)
        s.deviceKeys.answerProposal(accepted = false)
        assertNull(s.deviceKeys.proposal.value)
        s.deviceKeys.codeAccepted(qual.origin)
        delay(300)
        assertNull(s.deviceKeys.proposal.value)
    }

    @Test fun noProposalWhereItCannotBeEnabled() = runBlocking {
        val s = services()
        signedIn(ME_ADMIN) // Obligate account, no SSO device keys
        qual.on("GET /api/profile/device-keys", body = list())
        s.deviceKeys.codeAccepted(qual.origin)
        delay(300)
        assertNull(s.deviceKeys.proposal.value)
        assertFalse(s.deviceKeys.views.value.getValue(qualId).state.canEnrol)
    }
}
