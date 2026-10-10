package tools.obli.core.security

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.FailureKind
import tools.obli.core.network.ForbiddenReason

/** Enrolment orchestration: every failure deletes the alias. */
class DeviceKeyEnrolmentTest {
    private val origin = "https://obliance.example.com"
    private val ticketId = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
    private val nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val prompt = SignPrompt("Activer la validation par empreinte", "Obliance Prod", null, "Annuler")

    private class FakeApi(
        var begin: ApiOutcome<EnrolTicket>,
        var finish: ApiOutcome<EnrolledKey>,
    ) : DeviceKeyEnrolmentApi {
        val calls = mutableListOf<String>()
        var finished: EnrolFinish? = null
        override suspend fun begin(installId: String, proof: EnrolProof): ApiOutcome<EnrolTicket> {
            calls += when (proof) {
                is EnrolProof.PasswordAndCode -> "begin:$installId:${proof.code}"
                EnrolProof.SsoReauth -> "begin:$installId:sso"
            }
            return begin
        }
        override suspend fun finish(request: EnrolFinish): ApiOutcome<EnrolledKey> {
            calls += "finish"
            finished = request
            return finish
        }
    }

    /** A software EC key standing for the Keystore (the device side is core:devicekey's). */
    private class FakeGenerator(var failure: Exception? = null) : DeviceKeyGenerator {
        val generated = mutableListOf<String>()
        val deleted = mutableListOf<String>()
        var challenge: ByteArray? = null
        var pair: KeyPair? = null
        override suspend fun generate(alias: String, attestationChallenge: ByteArray): GeneratedKey {
            generated += alias
            challenge = attestationChallenge
            failure?.let { throw it }
            val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            pair = kp
            return GeneratedKey(kp.public.encoded, listOf(byteArrayOf(1, 2), byteArrayOf(3, 4)), DeviceKeyLevel.STRONGBOX)
        }
        override fun delete(alias: String) {
            deleted += alias
        }
    }

    private class FakeSigner(private val generator: FakeGenerator, var result: SignResult? = null) : DeviceSigner {
        var signedPayload: ByteArray? = null
        var alias: String? = null
        override suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt): SignResult {
            this.alias = alias
            signedPayload = payload
            result?.let { return it }
            val s = Signature.getInstance("SHA256withECDSA").apply { initSign(generator.pair!!.private); update(payload) }
            return SignResult.Signed(s.sign())
        }
    }

    private fun ticket(userId: Long = 42, allowed: List<String> = listOf("https://lan.example.com", origin)) =
        EnrolTicket(ticketId, nonce, 1790000180, userId, allowed, true)

    private val enrolled = EnrolledKey(keyId, "Samsung SM-S911B", DeviceKeyLevel.STRONGBOX, "2026-09-26T10:00:00.000Z")

    private class Setup(val api: FakeApi, val generator: FakeGenerator, val signer: FakeSigner, val store: InMemoryDeviceKeyStore, val enrolment: DeviceKeyEnrolment)

    private fun setup(begin: ApiOutcome<EnrolTicket> = ApiOutcome.Ok(ticket()), finish: ApiOutcome<EnrolledKey> = ApiOutcome.Ok(enrolled)): Setup {
        val api = FakeApi(begin, finish)
        val generator = FakeGenerator()
        val signer = FakeSigner(generator)
        val store = InMemoryDeviceKeyStore(newInstallId = { "0123456789abcdef0123456789abcdef" })
        return Setup(api, generator, signer, store, DeviceKeyEnrolment(api, generator, signer, store, clock = { 1_790_000_000_000 }))
    }

    private suspend fun Setup.enrol(o: String = origin, proof: EnrolProof = EnrolProof.PasswordAndCode("correct horse", "482913")) =
        enrolment.enrol(o, 42, "John.Smith ", proof, "Samsung SM-S911B", "0.4.0-alpha", prompt)

    private val alias = DeviceKeyAlias.of(origin, 42, "0123456789abcdef0123456789abcdef")

    @Test fun success() = runBlocking {
        val s = setup()
        val r = s.enrol() as EnrolResult.Enrolled
        assertEquals(DeviceKeyRecord(origin, 42, "John.Smith", keyId, alias, "0123456789abcdef0123456789abcdef", DeviceKeyLevel.STRONGBOX, 1_790_000_000_000), r.record)
        assertEquals(r.record, s.store.find(origin, 42))
        assertEquals(r.record, s.store.findByUsername(origin, "john.smith"))
        assertEquals(listOf("begin:0123456789abcdef0123456789abcdef:482913", "finish"), s.api.calls)
        assertEquals(listOf(alias), s.generator.generated)
        assertTrue(s.generator.deleted.isEmpty())
        assertEquals(alias, s.signer.alias)
        // The attestation challenge is the ticket's nonce (32 bytes).
        assertTrue(s.generator.challenge!!.contentEquals(Base64.getUrlDecoder().decode(nonce)))
        // The enrolment payload, verified with the public key sent to finish.
        val f = s.api.finished!!
        val spki = Base64.getDecoder().decode(f.publicKey)
        val expected = """
            obli-devkey-v1
            purpose:enrol
            origin:$origin
            user:42
            key:${DeviceProofPayload.enrolKeyRef(spki)}
            count:1
            challenge:$ticketId
            nonce:$nonce
            action:device_key.enrol
            binding:-
            exp:1790000180
        """.trimIndent()
        assertEquals(expected, String(s.signer.signedPayload!!, Charsets.UTF_8))
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(s.signer.signedPayload!!); verify(Base64.getDecoder().decode(f.signature)) })
        assertEquals(listOf("AQI=", "AwQ="), f.attestation)
        assertEquals(origin, f.origin)
        assertEquals(ticketId, f.ticketId)
        assertEquals("0.4.0-alpha", f.appVersion)
        assertEquals(setOf("ticketId", "origin", "publicKey", "attestation", "signature", "label", "installId", "appVersion"), f.toJson().keys)
    }

    @Test fun nonAsciiOrNonNormalisedOriginIsRefusedBeforeAnyCall() = runBlocking {
        for (o in listOf("https://obliancé.example.com", "https://Obliance.example.com", "https://obliance.example.com/")) {
            val s = setup()
            assertEquals(EnrolResult.OriginNotAllowed, s.enrol(o))
            assertTrue(s.api.calls.isEmpty())
            assertTrue(s.generator.generated.isEmpty())
        }
    }

    @Test fun aRefusedBeginGeneratesNothing() = runBlocking {
        for (out in listOf<ApiOutcome<EnrolTicket>>(
            ApiOutcome.Forbidden(ForbiddenReason.OTHER, "device_keys_origin_unset"),
            ApiOutcome.StepUpRejected(),
            ApiOutcome.Unsupported("too_many_keys"),
        )) {
            val s = setup(begin = out)
            assertEquals(EnrolResult.Refused(out as ApiOutcome<Nothing>), s.enrol())
            assertTrue(s.generator.generated.isEmpty())
        }
    }

    @Test fun ticketChecks() = runBlocking {
        val otherUser = setup(begin = ApiOutcome.Ok(ticket(userId = 43)))
        assertEquals(EnrolResult.InvalidTicket, otherUser.enrol())
        val notAllowed = setup(begin = ApiOutcome.Ok(ticket(allowed = listOf("https://lan.example.com"))))
        assertEquals(EnrolResult.OriginNotAllowed, notAllowed.enrol())
        val shortNonce = setup(begin = ApiOutcome.Ok(ticket().copy(nonce = "AAECAwQF")))
        assertEquals(EnrolResult.InvalidTicket, shortNonce.enrol())
        for (s in listOf(otherUser, notAllowed, shortNonce)) assertTrue(s.generator.generated.isEmpty())
    }

    @Test fun everyLaterFailureDeletesTheAlias() = runBlocking {
        val hw = setup().apply { generator.failure = HardwareNotSecureException("software") }
        assertEquals(EnrolResult.NotHardwareBacked, hw.enrol())
        val gen = setup().apply { generator.failure = java.security.ProviderException("keystore") }
        assertEquals(EnrolResult.KeyGenerationFailed("ProviderException"), gen.enrol())
        val cancelled = setup().apply { signer.result = SignResult.Cancelled }
        assertEquals(EnrolResult.NotSigned(SignResult.Cancelled), cancelled.enrol())
        val locked = setup().apply { signer.result = SignResult.LockedOut }
        assertEquals(EnrolResult.NotSigned(SignResult.LockedOut), locked.enrol())
        val attestation = ApiOutcome.Failure(422, FailureKind.CLIENT, "boot_state")
        val refused = setup(finish = attestation)
        assertEquals(EnrolResult.Refused(attestation), refused.enrol())
        val badId = setup(finish = ApiOutcome.Ok(enrolled.copy(keyId = "not-a-uuid")))
        assertTrue(badId.enrol() is EnrolResult.Refused)
        for (s in listOf(hw, gen, cancelled, locked, refused, badId)) {
            assertEquals(listOf(alias), s.generator.deleted)
            assertEquals(null, s.store.find(origin, 42))
        }
        // Finish is never called when the signature is missing.
        assertEquals(listOf("begin:0123456789abcdef0123456789abcdef:482913"), cancelled.api.calls)
    }

    @Test fun aSecondEnrolmentOfTheSameKeyWaitsItsTurn() = runBlocking {
        val s = setup()
        assertTrue(DeviceKeyLocks.reserve(alias))
        try {
            assertEquals(EnrolResult.KeyGenerationFailed(DeviceKeyEnrolment.BUSY), s.enrol())
            assertTrue(s.generator.generated.isEmpty())
            assertTrue(s.generator.deleted.isEmpty())   // never the other enrolment's key
        } finally {
            DeviceKeyLocks.release(alias)
        }
        assertTrue(s.enrol() is EnrolResult.Enrolled)
        assertTrue(DeviceKeyLocks.reserve(alias))          // released after the enrolment
        DeviceKeyLocks.release(alias)
    }

    @Test fun aLeftoverRecordOfThisInstallIsReplaced() = runBlocking {
        val s = setup()
        val old = DeviceKeyRecord(origin, 42, "john.smith", "0f8fad5b-d9cb-469f-a165-70867728950e", alias, "0123456789abcdef0123456789abcdef", DeviceKeyLevel.TEE, 1)
        s.store.put(old)
        val r = s.enrol() as EnrolResult.Enrolled
        assertEquals(listOf(r.record), s.store.records.value)
    }

    /** SSO device keys: an Obligate account begins with the re-authentication only (no password, no code), then the same key flow. */
    @Test fun ssoProofBeginsWithoutPasswordNorCode() = runBlocking {
        val s = setup()
        val r = s.enrol(proof = EnrolProof.SsoReauth) as EnrolResult.Enrolled
        assertEquals(listOf("begin:0123456789abcdef0123456789abcdef:sso", "finish"), s.api.calls)
        assertEquals(r.record, s.store.find(origin, 42))
        // The password never shows in logs.
        assertTrue(!EnrolProof.PasswordAndCode("correct horse", "482913").toString().contains("horse"))
    }
}
