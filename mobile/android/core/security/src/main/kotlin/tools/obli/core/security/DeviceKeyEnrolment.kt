package tools.obli.core.security

import java.util.Base64
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceKeyHeader
import tools.obli.core.network.DevicePurpose
import tools.obli.core.network.FailureKind

/** `POST …/enrol/begin` answer: `{ticketId, nonce, expiresAt, userId, allowedOrigins, requireAttestation}`. */
data class EnrolTicket(
    val ticketId: String,
    /** base64url without padding, 32 bytes: the attestation challenge AND the payload nonce. */
    val nonce: String,
    val expiresAt: Long,
    val userId: Long,
    val allowedOrigins: List<String>,
    val requireAttestation: Boolean,
)

/** `POST …/enrol/finish` body. Base64 is standard base64 of DER. */
class EnrolFinish(
    val ticketId: String,
    val origin: String,
    val publicKey: String,
    val attestation: List<String>,
    val signature: String,
    val label: String,
    val installId: String,
    val appVersion: String,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("ticketId", JsonPrimitive(ticketId))
        put("origin", JsonPrimitive(origin))
        put("publicKey", JsonPrimitive(publicKey))
        put("attestation", JsonArray(attestation.map(::JsonPrimitive)))
        put("signature", JsonPrimitive(signature))
        put("label", JsonPrimitive(label))
        put("installId", JsonPrimitive(installId))
        put("appVersion", JsonPrimitive(appVersion))
    }

    override fun toString(): String = "EnrolFinish(ticket=$ticketId, origin=$origin, chain=${attestation.size}, signature=<redacted>)"
}

/** `201 {data:{keyId, label, securityLevel, createdAt}}`. */
data class EnrolledKey(val keyId: String, val label: String?, val securityLevel: DeviceKeyLevel, val createdAt: String?)

/** What proves the account at `enrol/begin` (an Obligate re-authentication for an Obligate account). */
sealed interface EnrolProof {
    /** Local account: the account password and a NEW code. Never kept beyond the call, never printed. */
    class PasswordAndCode(val password: String, val code: String) : EnrolProof {
        override fun toString(): String = "PasswordAndCode(password=<redacted>, code=<redacted>)"
    }

    /**
     * Obligate account (SSO device keys): the session was re-authenticated at Obligate
     * just before (less than 5 min, single use: one re-authentication opens
     * one ticket). The body carries `{installId}` only — never a password.
     */
    data object SsoReauth : EnrolProof
}

/**
 * The two enrolment calls of ONE server (implemented over its session by
 * `:obliance:api` DeviceKeysApi). The proofs (`stepUpPassword`,
 * `twoFactorCode`) are body fields removed by the server before anything else.
 */
interface DeviceKeyEnrolmentApi {
    suspend fun begin(installId: String, proof: EnrolProof): ApiOutcome<EnrolTicket>
    suspend fun finish(request: EnrolFinish): ApiOutcome<EnrolledKey>
}

sealed interface EnrolResult {
    /** Stored; the server bound the current session to the key. [localLevel] is the local KeyInfo reading. */
    data class Enrolled(val record: DeviceKeyRecord, val localLevel: DeviceKeyLevel) : EnrolResult

    /** begin/finish refused (403 disabled / origin unset / SSO / locked, 401 wrong code, 409, 422 attestation…). */
    data class Refused(val outcome: ApiOutcome<Nothing>) : EnrolResult

    /** Non-ASCII or non-normalised origin, or not among the server's `allowedOrigins`. Nothing generated. */
    data object OriginNotAllowed : EnrolResult

    /** The ticket's user is not the session's user, or its nonce / id is malformed. Nothing generated. */
    data object InvalidTicket : EnrolResult

    /** KeyInfo says the key is not in secure hardware ("non protégée par le matériel"). */
    data object NotHardwareBacked : EnrolResult
    data class KeyGenerationFailed(val reason: String) : EnrolResult

    /** The biometric did not sign (cancelled, "Utiliser un code", locked out, invalidated, unavailable). */
    data class NotSigned(val result: SignResult) : EnrolResult
}

/**
 * Enrolment of this phone on one server, pure orchestration:
 * begin (password + NEW code, or a fresh Obligate re-authentication for an
 * Obligate account) → checks → key generation with the nonce as attestation
 * challenge → biometric signature of the enrolment payload → finish →
 * record. On any failure after the generation, the alias is deleted. Never
 * keeps the password.
 */
class DeviceKeyEnrolment(
    private val api: DeviceKeyEnrolmentApi,
    private val generator: DeviceKeyGenerator,
    private val signer: DeviceSigner,
    private val store: DeviceKeyStore,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    /**
     * @param origin the ObliHttp origin of the server (the app's, never a server answer).
     * @param sessionUserId the user of the session (from `/api/auth/me`); the ticket must name the same.
     * @param proof the password + NEW code, or [EnrolProof.SsoReauth] right after the Obligate re-authentication.
     * @param prompt texts of the biometric prompt ("Activer la validation par empreinte…").
     */
    suspend fun enrol(
        origin: String,
        sessionUserId: Long,
        username: String,
        proof: EnrolProof,
        label: String,
        appVersion: String,
        prompt: SignPrompt,
    ): EnrolResult {
        if (!DeviceProofPayload.isAsciiOrigin(origin)) return EnrolResult.OriginNotAllowed
        val installId = store.installId(origin)

        val ticket = when (val out = api.begin(installId, proof)) {
            is ApiOutcome.Ok -> out.value
            is ApiOutcome.Accepted -> out.value
            else -> {
                @Suppress("UNCHECKED_CAST")
                return EnrolResult.Refused(out as ApiOutcome<Nothing>)
            }
        }
        if (ticket.userId != sessionUserId || !DeviceKeyHeader.isValidKeyId(ticket.ticketId) || !DeviceChallenge.isNonce(ticket.nonce) || ticket.expiresAt <= 0) {
            return EnrolResult.InvalidTicket
        }
        if (origin !in ticket.allowedOrigins) return EnrolResult.OriginNotAllowed

        val alias = DeviceKeyAlias.of(origin, sessionUserId, installId)
        // The alias is reserved from its generation to its record: never taken for an orphan.
        if (!DeviceKeyLocks.reserve(alias)) return EnrolResult.KeyGenerationFailed(BUSY)
        try {
            return generateSignFinish(ticket, origin, sessionUserId, username, label, appVersion, prompt, installId, alias)
        } finally {
            DeviceKeyLocks.release(alias)
        }
    }

    private suspend fun generateSignFinish(
        ticket: EnrolTicket,
        origin: String,
        sessionUserId: Long,
        username: String,
        label: String,
        appVersion: String,
        prompt: SignPrompt,
        installId: String,
        alias: String,
    ): EnrolResult {
        // Same (origin, user, install) = same alias: a leftover record is replaced
        // (finish revokes the server's older key of this install: `replaced`).
        store.find(origin, sessionUserId)?.let { store.remove(it.origin, it.userId) }
        val nonce = Base64.getUrlDecoder().decode(ticket.nonce)

        val key = try {
            generator.generate(alias, nonce)
        } catch (_: HardwareNotSecureException) {
            generator.safeDelete(alias)
            return EnrolResult.NotHardwareBacked
        } catch (e: Exception) {
            generator.safeDelete(alias)
            if (e is CancellationException) throw e
            return EnrolResult.KeyGenerationFailed(e.javaClass.simpleName)
        }

        try {
            val payload = DeviceProofPayload.bytes(
                DevicePurpose.ENROL,
                origin,
                sessionUserId,
                DeviceProofPayload.enrolKeyRef(key.spki),
                listOf(PayloadChallenge(ticket.ticketId, ticket.nonce, ENROL_ACTION, "-", ticket.expiresAt)),
            )
            val der = when (val signed = signer.signWith(alias, payload, prompt)) {
                is SignResult.Signed -> signed.der
                else -> {
                    generator.safeDelete(alias)
                    return EnrolResult.NotSigned(signed)
                }
            }
            val b64 = Base64.getEncoder()
            val finish = EnrolFinish(
                ticketId = ticket.ticketId,
                origin = origin,
                publicKey = b64.encodeToString(key.spki),
                attestation = key.chain.map(b64::encodeToString),
                signature = b64.encodeToString(der),
                label = label,
                installId = installId,
                appVersion = appVersion,
            )
            val enrolled = when (val out = api.finish(finish)) {
                is ApiOutcome.Ok -> out.value
                is ApiOutcome.Accepted -> out.value
                else -> {
                    generator.safeDelete(alias)
                    @Suppress("UNCHECKED_CAST")
                    return EnrolResult.Refused(out as ApiOutcome<Nothing>)
                }
            }
            if (!DeviceKeyHeader.isValidKeyId(enrolled.keyId)) {
                generator.safeDelete(alias)
                return EnrolResult.Refused(ApiOutcome.Failure(null, FailureKind.SERVER, "bad key id"))
            }
            val record = DeviceKeyRecord(origin, sessionUserId, username.trim(), enrolled.keyId, alias, installId, enrolled.securityLevel, clock())
            store.put(record)
            return EnrolResult.Enrolled(record, key.securityLevel)
        } catch (e: Exception) {
            generator.safeDelete(alias)
            if (e is CancellationException) throw e
            return EnrolResult.KeyGenerationFailed(e.javaClass.simpleName)
        }
    }

    private fun DeviceKeyGenerator.safeDelete(alias: String) {
        runCatching { delete(alias) }
    }

    companion object {
        /** `action` line of the enrolment payload. */
        const val ENROL_ACTION = "device_key.enrol"

        /** [EnrolResult.KeyGenerationFailed] reason: an enrolment of the same key is already running. */
        const val BUSY = "busy"
    }
}
