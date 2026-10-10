package tools.obli.obliance.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.CookieJar
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.auth.ServerRegistry
import tools.obli.core.auth.ServerRegistryState
import tools.obli.core.auth.ServerRegistryStore
import tools.obli.core.auth.ServerSession
import tools.obli.core.auth.ServerSessions
import tools.obli.core.model.ServerColor
import tools.obli.core.model.ServerId
import tools.obli.core.model.ServerProfile
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceKeyHeader
import tools.obli.core.network.DevicePurpose
import tools.obli.core.network.ObliHttp
import tools.obli.core.security.DeviceKeyAlias
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.DeviceKeyRecord
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.InMemoryDeviceKeyStore
import tools.obli.core.security.KeyHealth
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignResult
import tools.obli.obliance.api.LoginResult
import tools.obli.obliance.api.TwoFactorMethod

/**
 * The fingerprint sign-in of a local account through the data layer
 * against a fake server: the key of
 * the typed username, the `login` payload, a renewed challenge, a dead or
 * revoked key, and the code of the same login.
 */
class DeviceSignInRepositoryTest {
    private val qual = FakeServer()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val cleared = java.util.concurrent.CopyOnWriteArrayList<String>()
    private val qualId = ServerId("qual")
    private val qualOrigin = "https://obliance-qual.example.org"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val c1 = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
    private val c2 = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
    private val nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    private val install = "0123456789abcdef0123456789abcdef"
    private val store = InMemoryDeviceKeyStore(newInstallId = { install })
    private val hardware = DeviceKeysRepositoryTest.FakeHardware()
    private var now = 1_000_000L
    private val prompt = SignPrompt("Connexion à Obliance Qual", "john.smith", null, "Utiliser un code")

    private class MemoryStore(var saved: ServerRegistryState?) : ServerRegistryStore {
        override suspend fun load() = saved
        override suspend fun save(state: ServerRegistryState) { saved = state }
    }

    /** Records each payload; [onSign] runs before answering (to change the server's next answer). */
    private class Signer(val results: ArrayDeque<SignResult>, val onSign: (Int) -> Unit = {}) : DeviceSigner {
        val payloads = mutableListOf<String>()
        override suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt): SignResult {
            payloads += String(payload, Charsets.UTF_8)
            onSign(payloads.size)
            return results.removeFirstOrNull() ?: SignResult.Cancelled
        }
    }

    private fun signed() = SignResult.Signed(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))

    private fun services(): DefaultObliServices = runBlocking {
        val registry = ServerRegistry(MemoryStore(ServerRegistryState(listOf(ServerProfile(qualId, qualOrigin, "Obliance Qual", ServerColor.FUCHSIA, "OQ", 0)), qualId)))
        registry.load()
        lateinit var services: DefaultObliServices
        val keyed = ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA", deviceKeyHeader = { services.deviceKeyHeader(it) })
        val sessions = ServerSessions(registry, { p, n -> ServerSession(p.id, n, ObliHttp(qual.origin, keyed) { o, k -> services.deviceKeyRevoked(o, k) }, { FakeRealtime() }) }, scope)
        services = DefaultObliServices(
            registry, sessions,
            httpFor = { origin -> ObliHttp(if (origin == qualOrigin) qual.origin else origin, keyed) },
            clearCookies = { cleared += it },
            scope = scope,
            clock = { now },
            deviceKeyDeps = DeviceKeyDeps(store, hardware, strongBiometric = { true }, deviceLabel = { "Pixel" }, appVersion = "0.4.0-alpha"),
        )
        services
    }

    private fun record(): DeviceKeyRecord {
        val alias = DeviceKeyAlias.of(qual.origin, 7, install)
        hardware.aliases += alias
        return DeviceKeyRecord(qual.origin, 7, "john.smith", keyId, alias, install, DeviceKeyLevel.STRONGBOX, 1)
    }

    private fun challengeJson(id: String = c1, user: Long = 7) =
        """{"v":1,"keyId":"$keyId","challengeId":"$id","purpose":"login","userId":$user,"tenantId":null,"nonce":"$nonce","action":"-","binding":"-","expiresAt":1790000120,"bulkId":null}"""

    private fun challenge(id: String = c1, user: Long = 7) =
        DeviceChallenge(1, keyId, id, DevicePurpose.LOGIN, user, null, null, nonce, "-", "-", 1790000120, null)

    private val signedInBody = """{"success":true,"data":{"user":{"id":7,"username":"john.smith"}}}"""

    private fun bodyOf(route: String, index: Int = -1): JsonObject {
        val list = qual.recorded.filter { it.first == route }
        val r = if (index < 0) list.last() else list[index]
        return Json.parseToJsonElement(r.second.body!!.utf8()).jsonObject
    }

    private suspend fun loginWithKey(s: DefaultObliServices): LoginResult {
        qual.on("POST /api/auth/login", body = """{"success":true,"data":{"requires2fa":true,"methods":{"totp":true,"email":false,"device":true},"deviceChallenge":${challengeJson()}}}""")
        return s.auth.login(qualOrigin, "John.Smith", "secret")
    }

    @After fun tearDown() {
        scope.cancel()
        qual.close()
    }

    @Test fun theLoginChallengeOfTheLoginKeyIsSignedAndSent() = runBlocking {
        val s = services()
        store.put(record())
        val step = loginWithKey(s) as LoginResult.TwoFactorRequired
        assertEquals(keyId, qual.recorded.last().second.headers[DeviceKeyHeader.NAME])
        qual.on("POST /api/profile/2fa/verify", body = signedInBody)
        val signer = Signer(ArrayDeque(listOf(signed())))
        val out = s.auth.signInWithDevice(qualOrigin, "john.smith", step.deviceChallenge!!, signer, prompt)
        assertEquals(7L, ((out as DeviceSignInResult.Finished).result as LoginResult.SignedIn).user.id)
        assertEquals(
            "obli-devkey-v1\npurpose:login\norigin:${qual.origin}\nuser:7\nkey:$keyId\ncount:1\nchallenge:$c1\nnonce:$nonce\naction:-\nbinding:-\nexp:1790000120",
            signer.payloads.single(),
        )
        val body = bodyOf("POST /api/profile/2fa/verify")
        assertEquals("device", body["method"]!!.jsonPrimitive.content)
        assertEquals(keyId, body["deviceAssertion"]!!.jsonObject["keyId"]!!.jsonPrimitive.content)
        assertTrue("no code travels with it", "code" !in body)
    }

    @Test fun anExpiredChallengeIsSignedOnceMoreNeverTwice() = runBlocking {
        val s = services()
        store.put(record())
        loginWithKey(s)
        qual.on("POST /api/profile/2fa/verify", 401, """{"success":false,"error":"Invalid code","deviceError":"challenge_expired","deviceChallenge":${challengeJson(c2)}}""")
        val signer = Signer(ArrayDeque(listOf(signed(), signed(), signed())))
        val out = s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), signer, prompt)
        assertEquals(DeviceSignInResult.Refused, out)
        assertEquals(2, signer.payloads.size)
        assertTrue(signer.payloads[1].contains("challenge:$c2"))

        // Renewed, then accepted.
        val signer2 = Signer(ArrayDeque(listOf(signed(), signed()))) { n -> if (n == 2) qual.on("POST /api/profile/2fa/verify", body = signedInBody) }
        qual.on("POST /api/profile/2fa/verify", 401, """{"success":false,"error":"Invalid code","deviceError":"challenge_expired","deviceChallenge":${challengeJson(c2)}}""")
        val ok = s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), signer2, prompt)
        assertTrue((ok as DeviceSignInResult.Finished).result is LoginResult.SignedIn)
    }

    @Test fun aPromptOpenPastTheChallengeLifeAsksANewChallenge() = runBlocking {
        val s = services()
        store.put(record())
        loginWithKey(s)
        qual.on("POST /api/profile/2fa/device-challenge", body = """{"success":true,"data":{"deviceChallenge":${challengeJson(c2)}}}""")
        qual.on("POST /api/profile/2fa/verify", body = signedInBody)
        val signer = Signer(ArrayDeque(listOf(signed(), signed()))) { n -> if (n == 1) now += 116_000 }
        val out = s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), signer, prompt)
        assertTrue((out as DeviceSignInResult.Finished).result is LoginResult.SignedIn)
        assertEquals(1, qual.count("POST /api/profile/2fa/verify"))
        assertTrue("the stale signature was never sent", bodyOf("POST /api/profile/2fa/verify")["deviceAssertion"]!!.jsonObject["challengeIds"].toString().contains(c2))
        assertEquals(keyId, qual.recorded.last { it.first == "POST /api/profile/2fa/device-challenge" }.second.headers[DeviceKeyHeader.NAME])
    }

    @Test fun aStaleChallengeIsRenewedBeforeThePrompt() = runBlocking {
        val s = services()
        store.put(record())
        loginWithKey(s)
        qual.on("POST /api/profile/2fa/device-challenge", body = """{"success":true,"data":{"deviceChallenge":${challengeJson(c2)}}}""")
        qual.on("POST /api/profile/2fa/verify", body = signedInBody)
        val signer = Signer(ArrayDeque(listOf(signed())))
        s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), signer, prompt, challengeStale = true)
        assertTrue(signer.payloads.single().contains("challenge:$c2"))
    }

    @Test fun aRevokedKeyIsForgottenAndTheCodeRemains() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        loginWithKey(s)
        qual.on("POST /api/profile/2fa/verify", 401, """{"success":false,"error":"Invalid code","deviceKeyStatus":"revoked"}""")
        val out = s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), Signer(ArrayDeque(listOf(signed()))), prompt)
        assertEquals(DeviceSignInResult.KeyLost, out)
        assertNull(store.find(qual.origin, 7))
        assertTrue(rec.alias in hardware.deleted)
        assertTrue("the pending login keeps its cookie", cleared.isEmpty())
        // The code of the same login no longer names the forgotten key.
        qual.on("POST /api/profile/2fa/verify", body = signedInBody)
        s.auth.verifyTwoFactor(qualOrigin, TwoFactorMethod.TOTP, "482913")
        assertNull(qual.recorded.last().second.headers[DeviceKeyHeader.NAME])
    }

    @Test fun anInvalidatedKeyAtThePromptIsForgottenWithoutEndingTheLogin() = runBlocking {
        val s = services()
        store.put(record())
        loginWithKey(s)
        val out = s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), Signer(ArrayDeque(listOf(SignResult.Invalidated))), prompt)
        assertEquals(DeviceSignInResult.KeyLost, out)
        assertNull(store.find(qual.origin, 7))
        assertTrue(cleared.isEmpty())
        assertEquals("nothing reported: there is no session yet", 0, qual.count("POST /api/profile/device-keys/$keyId/invalidated"))
    }

    @Test fun aDeadKeyIsNotSentAtLogin() = runBlocking {
        val s = services()
        val rec = record()
        store.put(rec)
        hardware.health[rec.alias] = KeyHealth.Invalidated
        qual.on("POST /api/auth/login", body = """{"success":true,"data":{"requires2fa":true,"methods":{"totp":true,"email":false}}}""")
        s.auth.login(qualOrigin, "john.smith", "secret")
        assertNull(qual.recorded.last().second.headers[DeviceKeyHeader.NAME])
        assertNull(store.find(qual.origin, 7))
        assertTrue(s.deviceKeys.invalidatedServers.value.contains(qualId))
    }

    @Test fun theCodeOfTheSameLoginCarriesItsKey() = runBlocking {
        val s = services()
        store.put(record())
        loginWithKey(s)
        qual.on("POST /api/profile/2fa/verify", body = signedInBody)
        s.auth.verifyTwoFactor(qualOrigin, TwoFactorMethod.TOTP, "482913")
        assertEquals(keyId, qual.recorded.last().second.headers[DeviceKeyHeader.NAME])
    }

    @Test fun aChallengeForAnotherUserOrAnotherNameIsNeverSigned() = runBlocking {
        val s = services()
        store.put(record())
        loginWithKey(s)
        val signer = Signer(ArrayDeque(listOf(signed())))
        assertEquals(DeviceSignInResult.UseCode, s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(user = 8), signer, prompt))
        assertEquals(DeviceSignInResult.UseCode, s.auth.signInWithDevice(qualOrigin, "someone.else", challenge(), signer, prompt))
        assertTrue(signer.payloads.isEmpty())
    }

    @Test fun withoutALoginKeyTheFingerprintIsNotTried() = runBlocking {
        val s = services()
        qual.on("POST /api/auth/login", body = """{"success":true,"data":{"requires2fa":true,"methods":{"totp":true,"email":false}}}""")
        s.auth.login(qualOrigin, "john.smith", "secret")
        val signer = Signer(ArrayDeque(listOf(signed())))
        assertEquals(DeviceSignInResult.UseCode, s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), signer, prompt))
        assertTrue(signer.payloads.isEmpty())
    }

    @Test fun useCodeAndCancelAreReportedAsSuch() = runBlocking {
        val s = services()
        store.put(record())
        loginWithKey(s)
        assertEquals(DeviceSignInResult.UseCode, s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), Signer(ArrayDeque(listOf(SignResult.UseCode))), prompt))
        assertEquals(DeviceSignInResult.UseCode, s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), Signer(ArrayDeque(listOf(SignResult.LockedOut))), prompt))
        assertEquals(DeviceSignInResult.Cancelled, s.auth.signInWithDevice(qualOrigin, "john.smith", challenge(), Signer(ArrayDeque(listOf(SignResult.Cancelled))), prompt))
        assertEquals(0, qual.count("POST /api/profile/2fa/verify"))
    }
}
