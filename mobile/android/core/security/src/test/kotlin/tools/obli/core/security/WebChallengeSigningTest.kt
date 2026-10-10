package tools.obli.core.security

import java.util.Base64
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The native side of the web view bridge `signDeviceChallenge`. */
class WebChallengeSigningTest {
    private val origin = "https://obliance.example.com"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val record = DeviceKeyRecord(origin, 42, "john.smith", keyId, DeviceKeyAlias.of(origin, 42, "install"), "install", DeviceKeyLevel.STRONGBOX, 1)
    private val keys = DeviceKeyResolver { if (it == origin) record else null }
    private val sig = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)

    /** J1's deviceChallenge, as the page relays it. */
    private fun challengeJson(
        purpose: String = "stepup",
        userId: Long = 42,
        key: String = keyId,
        v: Int = 1,
        action: String = "command.reboot",
        binding: String = "42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4",
    ) = """{"v":$v,"keyId":"$key","challengeId":"1b4e28ba-2fa1-41d2-883f-0016d3cca427","purpose":"$purpose","userId":$userId,"tenantId":${if (purpose == "login") "null" else "3"},"tenantName":"ACME","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","action":"$action","binding":"$binding","expiresAt":1790000120,"bulkId":null}"""

    private class Calls {
        val log = mutableListOf<String>()
        val specs = mutableListOf<ActionSpec>()
        val requests = mutableListOf<DeviceSignRequest>()
    }

    private suspend fun sign(
        json: String,
        result: SignResult = SignResult.Signed(sig),
        page: String = origin,
        active: String? = origin,
        k: DeviceKeyResolver? = keys,
        calls: Calls = Calls(),
        tenants: (Long) -> WebChallengeSigning.TenantLookup = { if (it == 3L) WebChallengeSigning.TenantLookup.Known("ACME") else WebChallengeSigning.TenantLookup.NotMine },
    ) = WebChallengeSigning.sign(
        pageOrigin = page,
        activeOrigin = active,
        serverName = "Obliance Prod",
        challengeJson = json,
        keys = k,
        tenants = tenants,
        sign = { spec, request -> calls.log += "sign"; calls.specs += spec; calls.requests += request; result },
        invalidated = { o, id -> calls.log += "invalidated:$o:$id" },
    )

    @Test fun aChallengeOfThisPhoneIsSignedWithTheNativePrompt() = runBlocking {
        val calls = Calls()
        val answer = sign(challengeJson(), calls = calls) as WebChallengeSigning.Answer.Assertion
        val json = answer.toJson()[DeviceAssertion.FIELD]!!.jsonObject
        assertEquals(JsonPrimitive(keyId), json["keyId"])
        assertEquals(JsonPrimitive(Base64.getEncoder().encodeToString(sig)), json["signature"])
        assertEquals("[\"1b4e28ba-2fa1-41d2-883f-0016d3cca427\"]", json["challengeIds"].toString())
        val spec = calls.specs.single()
        assertEquals("command.reboot", spec.target)
        assertEquals("Obliance Prod › ACME", spec.scope)
        assertEquals("Obliance Prod", spec.serverName)
        assertEquals(3L, spec.tenantId)
        // The payload is DeviceProofPayload's, with the app's origin (never the page's text).
        assertTrue(String(calls.requests.single().payload, Charsets.UTF_8).startsWith("obli-devkey-v1\npurpose:stepup\norigin:$origin\nuser:42\nkey:$keyId\ncount:1\n"))
        assertEquals("Assertion(<redacted>)", answer.toString())
    }

    /** The page relays the JSON: its `tenantName` is page text, never shown; the app names `tenantId` itself. */
    @Test fun theTenantShownIsTheAppsNeverThePages() = runBlocking {
        val calls = Calls()
        val forged = challengeJson().replace("\"tenantName\":\"ACME\"", "\"tenantName\":\"Autre client ‮\"")
        sign(forged, calls = calls)
        assertEquals("Obliance Prod › ACME", calls.specs.single().scope)
        assertEquals("ACME", calls.requests.single().tenantName)
        // Tenants not loaded: « #id », still signed.
        val unknown = Calls()
        sign(forged, calls = unknown, tenants = { WebChallengeSigning.TenantLookup.Unknown })
        assertEquals("Obliance Prod › #3", unknown.specs.single().scope)
        assertEquals("#3", unknown.requests.single().tenantName)
        // A blank name from the list is not an empty subtitle.
        val blank = Calls()
        sign(forged, calls = blank, tenants = { WebChallengeSigning.TenantLookup.Known(" ") })
        assertEquals("#3", blank.requests.single().tenantName)
    }

    @Test fun aTenantThatIsNotTheUsersIsRefusedWithoutAPrompt() = runBlocking {
        val calls = Calls()
        val answer = sign(challengeJson(), calls = calls, tenants = { WebChallengeSigning.TenantLookup.NotMine })
        assertEquals(WebChallengeSigning.Answer.Error("bad_challenge"), answer)
        assertTrue(calls.log.isEmpty())
        // The lookup failing is not a refusal: « #id ».
        val odd = Calls()
        sign(challengeJson(), calls = odd, tenants = { error("tenants store not ready") })
        assertEquals("#3", odd.requests.single().tenantName)
    }

    @Test fun onlyTheActiveServersPageMaySign() = runBlocking {
        val calls = Calls()
        assertEquals(WebChallengeSigning.Answer.Error("not_active_server"), sign(challengeJson(), page = "https://evil.example.org", calls = calls))
        assertEquals(WebChallengeSigning.Answer.Error("not_active_server"), sign(challengeJson(), active = "https://obliance-dev.example.org", calls = calls))
        assertEquals(WebChallengeSigning.Answer.Error("not_active_server"), sign(challengeJson(), active = null, calls = calls))
        assertTrue(calls.log.isEmpty())
    }

    @Test fun onlyAStepUpChallengeOfThisKeyAndUserIsSigned() = runBlocking {
        val calls = Calls()
        assertEquals(WebChallengeSigning.Answer.Error("wrong_purpose"), sign(challengeJson(purpose = "login", action = "-", binding = "-"), calls = calls))
        assertEquals(WebChallengeSigning.Answer.Error("key_mismatch"), sign(challengeJson(userId = 43), calls = calls))
        assertEquals(WebChallengeSigning.Answer.Error("key_mismatch"), sign(challengeJson(key = "7c9e6679-7425-40de-944b-e07fc1f90ae7"), calls = calls))
        assertEquals(WebChallengeSigning.Answer.Error("no_key"), sign(challengeJson(), k = DeviceKeyResolver { null }, calls = calls))
        assertEquals(WebChallengeSigning.Answer.Error("no_key"), sign(challengeJson(), k = null, calls = calls))
        assertTrue(calls.log.isEmpty())
    }

    @Test fun malformedChallengesAreRefusedUnread() = runBlocking {
        val calls = Calls()
        for (bad in listOf("", "null", "[]", "{", challengeJson(v = 2), challengeJson(binding = "-"), challengeJson(action = "a\nb"), "x".repeat(9_000))) {
            assertEquals(bad.take(40), WebChallengeSigning.Answer.Error("bad_challenge"), sign(bad, calls = calls))
        }
        assertTrue(calls.log.isEmpty())
    }

    @Test fun promptOutcomesMapToTheBridgeAnswers() = runBlocking {
        assertEquals(WebChallengeSigning.Answer.UseCode, sign(challengeJson(), SignResult.UseCode))
        assertEquals(WebChallengeSigning.Answer.UseCode, sign(challengeJson(), SignResult.LockedOut))
        assertEquals(WebChallengeSigning.Answer.UseCode, sign(challengeJson(), SignResult.Unavailable("x")))
        assertEquals(WebChallengeSigning.Answer.Cancelled, sign(challengeJson(), SignResult.Cancelled))
        val calls = Calls()
        assertEquals(WebChallengeSigning.Answer.Error("invalidated"), sign(challengeJson(), SignResult.Invalidated, calls = calls))
        assertEquals(listOf("sign", "invalidated:$origin:$keyId"), calls.log)
    }

    @Test fun answersSerialiseAsTheContractSays() {
        assertEquals("""{"cancelled":true}""", WebChallengeSigning.Answer.Cancelled.toJson().toString())
        assertEquals("""{"useCode":true}""", WebChallengeSigning.Answer.UseCode.toJson().toString())
        assertEquals("""{"error":"busy"}""", WebChallengeSigning.Answer.Error("busy").toJson().toString())
    }
}
