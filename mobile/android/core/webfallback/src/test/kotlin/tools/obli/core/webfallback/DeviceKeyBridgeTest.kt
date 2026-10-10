package tools.obli.core.webfallback

import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** The web view bridge `signDeviceChallenge` (bridgeVersion 2): script and transport. */
class DeviceKeyBridgeTest {
    private val info = WebBridgeInfo(app = "obliance", appVersion = "0.4.0-alpha", versionCode = 5)
    private val script = DeviceBridgeScript.build(info)

    @Test fun theScriptAnnouncesBridgeVersion2WithTheDeviceKeyCapabilityOnly() {
        assertTrue(script.contains("\"platform\":\"android\""))
        assertTrue(script.contains("\"app\":\"obliance\""))
        assertTrue(script.contains("\"appVersion\":\"0.4.0-alpha\""))
        assertTrue(script.contains("\"versionCode\":5"))
        assertTrue(script.contains("\"bridgeVersion\":2"))
        assertTrue(script.contains("\"capabilities\":[\"deviceKey\"]"))
        assertTrue(script.contains("var CHANNEL = \"__obliBridge\";"))
        assertFalse(script.contains("__INFO__"))
        assertFalse("never the desktop shell's flags", script.contains("_is_native_app"))
        assertFalse("no other bridge method here", script.contains("saveFile"))
    }

    @Test fun valuesAreJsonEscaped() {
        val s = DeviceBridgeScript.build(WebBridgeInfo("x\"</script>", "1'", 1))
        assertTrue(s.contains("\"app\":\"x\\\"</script>\""))
    }

    @Test fun requestsAreParsedStrictly() {
        assertEquals(
            DeviceBridgeProtocol.Parsed.Request(3, "signDeviceChallenge", "{\"v\":1}"),
            DeviceBridgeProtocol.parse("""{"id":3,"method":"signDeviceChallenge","params":{"challengeJson":"{\"v\":1}"}}"""),
        )
        assertEquals(DeviceBridgeProtocol.Parsed.Request(4, "signDeviceChallenge", null), DeviceBridgeProtocol.parse("""{"id":4,"method":"signDeviceChallenge","params":{}}"""))
        assertEquals(DeviceBridgeProtocol.Parsed.Invalid(null, "invalid message"), DeviceBridgeProtocol.parse("garbage"))
        assertEquals(DeviceBridgeProtocol.Parsed.Invalid(null, "invalid message"), DeviceBridgeProtocol.parse(null))
        assertEquals(DeviceBridgeProtocol.Parsed.Invalid(null, "invalid id"), DeviceBridgeProtocol.parse("""{"id":"3","method":"x"}"""))
        assertEquals(DeviceBridgeProtocol.Parsed.Invalid(5, "invalid method"), DeviceBridgeProtocol.parse("""{"id":5}"""))
        assertEquals(DeviceBridgeProtocol.Parsed.Invalid(null, "invalid message"), DeviceBridgeProtocol.parse("x".repeat(DeviceBridgeProtocol.MAX_MESSAGE_LENGTH + 1)))
    }

    @Test fun answersHaveTheTransportShape() {
        val ok = Json.parseToJsonElement(DeviceBridgeProtocol.success(7, DeviceBridgeProtocol.refusal("busy"))).jsonObject
        assertEquals(JsonPrimitive(7), ok["id"])
        assertEquals(JsonPrimitive(true), ok["ok"])
        assertEquals("""{"error":"busy"}""", ok["result"].toString())
        val ko = Json.parseToJsonElement(DeviceBridgeProtocol.failure(8, "unknown method")).jsonObject
        assertEquals(JsonPrimitive(false), ko["ok"])
        assertEquals(JsonPrimitive("unknown method"), ko["error"])
    }

    // --- The gate: no prompt loop from a page (MFA fatigue) -------------------------------------

    private var now = 1_790_000_000_000L
    private fun gate() = DeviceBridgeGate { now }
    private fun challenge(id: String = "1b4e28ba-2fa1-41d2-883f-0016d3cca427", expiresAt: Long = 1_790_000_120) =
        """{"v":1,"keyId":"6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f","challengeId":"$id","purpose":"stepup","userId":42,"tenantId":3,"tenantName":"ACME","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","action":"command.reboot","binding":"42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4","expiresAt":$expiresAt,"bulkId":null}"""
    private val signed = Json.parseToJsonElement("""{"deviceAssertion":{"v":1,"keyId":"k","challengeIds":["c"],"signature":"MEU="}}""").jsonObject
    private val cancelled = Json.parseToJsonElement("""{"cancelled":true}""").jsonObject
    private val useCode = Json.parseToJsonElement("""{"useCode":true}""").jsonObject

    @Test fun aChallengeIsPromptedOnceNeverAgain() {
        val g = gate()
        assertEquals(null, g.admit(challenge()))
        g.answered(signed)
        // The same challenge JSON again (re-sent by a script): refused without a prompt.
        assertEquals("rate_limited", g.admit(challenge()))
        // A new challenge (`challenge_expired` renewed it): allowed.
        assertEquals(null, g.admit(challenge(id = "7c9e6679-7425-40de-944b-e07fc1f90ae7")))
    }

    @Test fun rightAfterACancelOrACodeThePageGetsTheCode() {
        for (answer in listOf(cancelled, useCode, DeviceBridgeProtocol.refusal("key_mismatch"))) {
            val g = gate()
            assertEquals(null, g.admit(challenge()))
            g.answered(answer)
            assertEquals("rate_limited", g.admit(challenge(id = "7c9e6679-7425-40de-944b-e07fc1f90ae7")))
            now += DeviceBridgeGate.COOLDOWN_MS - 1
            assertEquals("rate_limited", g.admit(challenge(id = "0f8fad5b-d9cb-469f-a165-70867728950e", expiresAt = now / 1000 + 120)))
            now += 1
            assertEquals(null, g.admit(challenge(id = "0f8fad5b-d9cb-469f-a165-70867728950e", expiresAt = now / 1000 + 120)))
        }
    }

    @Test fun anExpiredChallengeIsNeverPrompted() {
        val g = gate()
        // Expired 31 s ago (beyond the 30 s clock allowance).
        assertEquals("expired", g.admit(challenge(expiresAt = now / 1000 - 31)))
        // Within the allowance: the server decides (challenge_expired renews it).
        assertEquals(null, g.admit(challenge(expiresAt = now / 1000 - 29)))
    }

    @Test fun atMostAFewPromptsAMinute() {
        val g = gate()
        repeat(DeviceBridgeGate.MAX_PER_MINUTE) { n ->
            assertEquals(null, g.admit(challenge(id = "00000000-0000-4000-8000-%012d".format(n))))
            g.answered(signed)
            now += 1_000
        }
        assertEquals("rate_limited", g.admit(challenge(id = "00000000-0000-4000-8000-000000000099")))
        now += 60_000
        assertEquals(null, g.admit(challenge(id = "00000000-0000-4000-8000-000000000099", expiresAt = now / 1000 + 120)))
    }

    @Test fun whatIsNotAChallengeIsRefusedUnread() {
        val g = gate()
        for (bad in listOf("", "{", "[]", """{"challengeId":"x"}""", """{"expiresAt":1}""", """{"challengeId":"x","expiresAt":"1790000120"}""")) {
            assertEquals(bad, "bad_challenge", g.admit(bad))
        }
    }

    /**
     * The generated script in Node (when available) against a fake
     * `__obliBridge`: the web client's detection (`canUseNative`), the request
     * shape, id correlation, resolve with the answer OBJECT, reject on a
     * transport error, frozen globals, and no channel.
     */
    @Test fun behavesInAJavaScriptEngine() {
        val node = findNode()
        assumeTrue("node not available", node != null)
        val outDir = File(System.getProperty("obli.test.out") ?: "build/test-out").apply { mkdirs() }
        val scriptFile = File(outDir, "obli-devkey-bridge.js").apply { writeText(script) }
        val harness = File(outDir, "obli-devkey-bridge-harness.js").apply { writeText(HARNESS) }
        val proc = ProcessBuilder(node, harness.absolutePath, scriptFile.absolutePath).redirectErrorStream(true).start()
        val finished = proc.waitFor(60, TimeUnit.SECONDS)
        val output = proc.inputStream.bufferedReader().readText()
        assertTrue("node timed out", finished)
        assertEquals("node harness failed:\n$output", 0, proc.exitValue())
        assertTrue(output, output.contains("DEVKEY BRIDGE OK"))
    }

    private fun findNode(): String? {
        for (c in listOf("node", "node.exe", "C:\\Program Files\\nodejs\\node.exe")) {
            try {
                val p = ProcessBuilder(c, "--version").redirectErrorStream(true).start()
                if (p.waitFor(20, TimeUnit.SECONDS) && p.exitValue() == 0) return c
            } catch (_: Exception) {
                // next
            }
        }
        return null
    }

    private companion object {
        val HARNESS = """
            'use strict';
            const fs = require('fs');
            const src = fs.readFileSync(process.argv[2], 'utf8');
            function fail(m) { console.error('FAIL: ' + m); process.exit(1); }
            function assert(c, m) { if (!c) fail(m); }
            const sent = [];
            let listener = null;
            const channel = {
              postMessage(m) { assert(typeof m === 'string', 'postMessage takes a string'); sent.push(JSON.parse(m)); },
              addEventListener(type, l) { if (type === 'message') listener = l; },
            };
            const win = { __obliBridge: channel };
            new Function('window', src)(win);
            const n = win.__obli_native;
            assert(n && n.platform === 'android' && n.app === 'obliance' && n.bridgeVersion === 2, '__obli_native');
            assert(n.capabilities.length === 1 && n.capabilities[0] === 'deviceKey', 'capabilities');
            assert(Object.isFrozen(n) && Object.isFrozen(win.ObliNative), 'frozen');
            // The web client's canUseNative('signDeviceChallenge') (client/src/native/bridge.ts).
            const canUse = n.platform === 'android' && typeof win.ObliNative.signDeviceChallenge === 'function' && n.capabilities.includes('deviceKey');
            assert(canUse, 'canUseNative');
            new Function('window', src)(win); // twice: nothing redefined

            (async () => {
              const challenge = JSON.stringify({ v: 1, keyId: 'k', challengeId: 'c', purpose: 'stepup' });
              const p1 = win.ObliNative.signDeviceChallenge(challenge);
              assert(sent.length === 1 && sent[0].method === 'signDeviceChallenge' && sent[0].params.challengeJson === challenge, 'request shape');
              const p2 = win.ObliNative.signDeviceChallenge(challenge);
              assert(sent[1].id !== sent[0].id, 'distinct ids');
              listener({ data: 'noise' });
              listener({ data: JSON.stringify({ id: sent[1].id, ok: true, result: { error: 'busy' } }) });
              listener({ data: JSON.stringify({ id: sent[0].id, ok: true, result: { deviceAssertion: { v: 1, keyId: 'k', challengeIds: ['c'], signature: 'MEU=' } } }) });
              const r1 = await p1;
              assert(r1.deviceAssertion && r1.deviceAssertion.challengeIds[0] === 'c', 'resolved with the answer object');
              const r2 = await p2;
              assert(r2.error === 'busy', 'a refusal resolves');
              const p3 = win.ObliNative.signDeviceChallenge(challenge);
              listener({ data: JSON.stringify({ id: sent[2].id, ok: false, error: 'unknown method' }) });
              let rejected = null;
              try { await p3; } catch (e) { rejected = e; }
              assert(rejected instanceof Error && rejected.message === 'unknown method', 'transport errors reject');
              let typeErr = null;
              try { await win.ObliNative.signDeviceChallenge({ v: 1 }); } catch (e) { typeErr = e; }
              assert(typeErr && sent.length === 3, 'a non-string is refused before sending');
              const bare = {};
              new Function('window', src)(bare);
              let err = null;
              try { await bare.ObliNative.signDeviceChallenge(challenge); } catch (e) { err = e; }
              assert(err && /unavailable/.test(err.message), 'rejects without a channel');
              console.log('DEVKEY BRIDGE OK');
            })().catch((e) => fail(e && e.stack || String(e)));
        """.trimIndent()
    }
}
