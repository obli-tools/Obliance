package tools.obli.core.security

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DevicePurpose

/**
 * The payload `obli-devkey-v1` against the reference vectors V1 and V2
 * (a frozen contract shared with the server tests): same bytes,
 * same sha256, and the reference signatures verify with JCA (what the server does
 * with `crypto.verify`).
 */
class DeviceProofPayloadTest {
    private fun sha256(s: ByteArray) = MessageDigest.getInstance("SHA-256").digest(s).joinToString("") { "%02x".format(it) }

    private fun verifies(spkiB64: String, payload: ByteArray, sigB64: String): Boolean {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(spkiB64)))
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(payload)
            verify(Base64.getDecoder().decode(sigB64))
        }
    }

    private val v1Text = """
        obli-devkey-v1
        purpose:stepup
        origin:https://obliance.example.com
        user:42
        key:6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f
        count:1
        challenge:1b4e28ba-2fa1-41d2-883f-0016d3cca427
        nonce:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
        action:command.reboot
        binding:50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c
        exp:1790000120
    """.trimIndent()

    private val v1Challenge = PayloadChallenge(
        "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "command.reboot",
        "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
        1790000120,
    )
    private val key = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val v1Spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO6H1i3djvlx3Y3QnxD9qrYXeL/aREhQFgpFHkpHxU8Mmx2pp9AyQNrB//ENPMpE+Ve5VvKU0+5kXma3m+toVxg=="
    private val v1Sig = "MEYCIQC/VWdsOwkNPoBmjkWg/yJWksa7HvMYqrJbp19TJefv4gIhALhNJMRDnHhOwotAVnDT6eLY+aR/Siq6JMZ1VCBD56OJ"

    @Test fun v1SingleChallenge() {
        val text = DeviceProofPayload.build(DevicePurpose.STEPUP, "https://obliance.example.com", 42, key, listOf(v1Challenge))
        assertEquals(v1Text, text)
        assertFalse(text.endsWith("\n"))
        val bytes = DeviceProofPayload.bytes(DevicePurpose.STEPUP, "https://obliance.example.com", 42, key, listOf(v1Challenge))
        assertEquals("5d75a9e6d6cb5dfcc0d2d9ef7fc7348a5c59fa428ece8b07f11d769fe7695fc2", sha256(bytes))
        assertTrue(verifies(v1Spki, bytes, v1Sig))
        // The nonce is 0x00..0x1f, the binding sha256("example").
        assertTrue(Base64.getUrlDecoder().decode(v1Challenge.nonce).contentEquals(ByteArray(32) { it.toByte() }))
        assertEquals(v1Challenge.binding, sha256("example".toByteArray()))
        // public_key_fp and the enrolment key line.
        val spki = Base64.getDecoder().decode(v1Spki)
        assertEquals("6145231539132278683d273815557b66512d14d4fb6b093867122cc38b2b5770", sha256(spki))
        assertEquals("spki-sha256:6145231539132278683d273815557b66512d14d4fb6b093867122cc38b2b5770", DeviceProofPayload.enrolKeyRef(spki))
        // One byte changed: the signature no longer verifies.
        val tampered = DeviceProofPayload.bytes(DevicePurpose.STEPUP, "https://obliance.example.com", 43, key, listOf(v1Challenge))
        assertFalse(verifies(v1Spki, tampered, v1Sig))
    }

    @Test fun v2BatchOnANonStandardPort() {
        val challenges = listOf(
            PayloadChallenge("0f8fad5b-d9cb-469f-a165-70867728950e", "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s", "command.reboot", "42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4", 1790000200),
            PayloadChallenge("7c9e6679-7425-40de-944b-e07fc1f90ae7", "zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0", "command.reboot", "d1cfff2ae8c88d7fadb9f02e95153f8c71d8d29d9cf4b86ec41247da70908405", 1790000201),
        )
        val bytes = DeviceProofPayload.bytes(DevicePurpose.STEPUP, "https://obliance.example.com:8443", 42, key, challenges)
        assertEquals("eeb4ef7a7d8eb846fbb7aa67afe62d280c71810f5cfd54106395f16f878b7cfb", sha256(bytes))
        assertTrue(
            verifies(
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC8l1DDFcl+02mbjMgVVJGGAfDvqE7NZdjWWbj0n1v9A29R/hz0CAPWnt9UNheUOo+m3Cm62qxTOPALLXVW0npg==",
                bytes,
                "MEUCIBUBAT1EvUVDSgblSbU7jfUCDVzhzoxgvJ+CRpp+l4rRAiEAlgDjiTKua6d6K55etd0ygmMnyC8jP4xwLZQgklo2vPU=",
            ),
        )
        assertTrue(Base64.getUrlDecoder().decode(challenges[0].nonce).all { it == 0xab.toByte() })
        assertTrue(Base64.getUrlDecoder().decode(challenges[1].nonce).all { it == 0xcd.toByte() })
    }

    @Test fun refusals() {
        val o = "https://obliance.example.com"
        fun build(origin: String = o, user: Long = 42, keyRef: String = key, cs: List<PayloadChallenge> = listOf(v1Challenge)) =
            DeviceProofPayload.build(DevicePurpose.STEPUP, origin, user, keyRef, cs)
        build() // sanity
        val bad = listOf<() -> Unit>(
            { build(cs = listOf(v1Challenge.copy(action = "command.reboot\nexp:1"))) },
            { build(cs = listOf(v1Challenge.copy(action = "command.reboot\r"))) },
            { build(cs = listOf(v1Challenge.copy(binding = "a\u0000b"))) },
            { build(cs = listOf(v1Challenge.copy(challengeId = ""))) },
            { build(cs = listOf(v1Challenge.copy(exp = 0))) },
            { build(keyRef = "k\n") },
            { build(cs = emptyList()) },                                     // count 0
            { build(cs = List(51) { v1Challenge.copy(challengeId = "c$it") }) }, // count 51
            { build(origin = "https://obliancé.example.com") },              // IDN: refused
            { build(origin = "https://Obliance.Example.com") },              // not normalised
            { build(origin = "https://obliance.example.com:443") },
            { build(origin = "https://obliance.example.com/") },
            { build(user = 0) },
        )
        bad.forEachIndexed { i, f -> assertThrows("case $i", IllegalArgumentException::class.java) { f() } }
        // 50 challenges is the maximum accepted.
        assertEquals(6 + 5 * 50, build(cs = List(50) { v1Challenge.copy(challengeId = "c$it") }).lines().size)
    }

    @Test fun aliasAndInstallIds() {
        val a = DeviceKeyAlias.of("https://obliance.example.com", 42, "0123456789abcdef0123456789abcdef")
        assertTrue(a.startsWith("obli.devkey.v1."))
        assertEquals(15 + 16, a.length)
        val expected = sha256("https://obliance.example.com\n42\n0123456789abcdef0123456789abcdef".toByteArray()).take(16)
        assertEquals("obli.devkey.v1.$expected", a)
        assertTrue(DeviceKeyAlias.isOurs(a))
        assertFalse(DeviceKeyAlias.isOurs("obli.devkey.v1.XYZ"))
        assertFalse(DeviceKeyAlias.isOurs("other.alias"))
        // Another user, origin or install: another alias.
        assertFalse(a == DeviceKeyAlias.of("https://obliance.example.com", 43, "0123456789abcdef0123456789abcdef"))
        assertFalse(a == DeviceKeyAlias.of("https://obliance.example.com:8443", 42, "0123456789abcdef0123456789abcdef"))
        val id = randomInstallId()
        assertEquals(32, id.length)
        assertTrue(id.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test fun signRequestsAreBuiltFromCheckedChallenges() {
        val record = DeviceKeyRecord("https://obliance.example.com", 42, "john.smith", key, DeviceKeyAlias.of("https://obliance.example.com", 42, "i"), "i", DeviceKeyLevel.STRONGBOX, 1)
        val c = DeviceChallenge(1, key, v1Challenge.challengeId, DevicePurpose.STEPUP, 42, 3, "ACME", v1Challenge.nonce, v1Challenge.action, v1Challenge.binding, v1Challenge.exp, null)
        val request = DeviceSignRequest.stepUp(record.origin, record, listOf(c))
        assertEquals(v1Text, String(request.payload, Charsets.UTF_8))
        val assertion = request.assertion(Base64.getDecoder().decode(v1Sig))
        assertEquals(v1Sig, assertion.signature)
        assertEquals(listOf(c.challengeId), assertion.challengeIds)
        assertEquals(
            """{"v":1,"keyId":"$key","challengeIds":["${c.challengeId}"],"signature":"$v1Sig"}""",
            assertion.toJson().toString(),
        )
        assertFalse(assertion.toString().contains(v1Sig))
        // Another key, user, origin or purpose: refused.
        assertThrows(IllegalArgumentException::class.java) { DeviceSignRequest.stepUp(record.origin, record, listOf(c.copy(keyId = "0f8fad5b-d9cb-469f-a165-70867728950e"))) }
        assertThrows(IllegalArgumentException::class.java) { DeviceSignRequest.stepUp(record.origin, record, listOf(c.copy(userId = 43))) }
        assertThrows(IllegalArgumentException::class.java) { DeviceSignRequest.stepUp("https://other.example.com", record, listOf(c)) }
        assertThrows(IllegalArgumentException::class.java) { DeviceSignRequest.stepUp(record.origin, record, listOf(c.copy(purpose = DevicePurpose.LOGIN))) }
        // A batch needs one bulk id, one action, one tenant.
        val c2 = c.copy(challengeId = "7c9e6679-7425-40de-944b-e07fc1f90ae7")
        assertThrows(IllegalArgumentException::class.java) { DeviceSignRequest.stepUp(record.origin, record, listOf(c, c2)) }
        val bulk = "0f8fad5b-d9cb-469f-a165-70867728950e"
        assertEquals(2, DeviceSignRequest.stepUp(record.origin, record, listOf(c.copy(bulkId = bulk), c2.copy(bulkId = bulk))).count)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSignRequest.stepUp(record.origin, record, listOf(c.copy(bulkId = bulk), c2.copy(bulkId = bulk, action = "command.shutdown")))
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSignRequest.stepUp(record.origin, record, listOf(c.copy(bulkId = bulk), c2.copy(bulkId = bulk, tenantId = 4)))
        }
        // Sign-in payload: purpose login, action and binding "-".
        val login = DeviceChallenge(1, key, c2.challengeId, DevicePurpose.LOGIN, 42, null, null, v1Challenge.nonce, "-", "-", 1790000120, null)
        val text = String(DeviceSignRequest.login(record.origin, record, login).payload, Charsets.UTF_8)
        assertTrue(text.startsWith("obli-devkey-v1\npurpose:login\norigin:https://obliance.example.com\nuser:42\nkey:$key\ncount:1\n"))
        assertTrue(text.endsWith("\naction:-\nbinding:-\nexp:1790000120"))
    }

    @Test fun secretsAreNeverPrinted() {
        assertFalse(TwoFactorAnswer("482913", false, "hunter2").toString().contains("hunter2"))
        assertFalse(TwoFactorAnswer("482913", false, "hunter2").toString().contains("482913"))
        assertFalse(SignResult.Signed(byteArrayOf(1, 2, 3)).toString().contains("1"))
    }
}
