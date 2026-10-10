package tools.obli.obliance.api

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.ApiResponses
import tools.obli.core.network.DeviceKeyHeader
import tools.obli.core.network.FailureKind
import tools.obli.core.network.ObliHttp
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.security.DeviceKeyEnrolmentApi
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.EnrolFinish
import tools.obli.core.security.EnrolProof
import tools.obli.core.security.EnrolTicket
import tools.obli.core.security.EnrolledKey
import tools.obli.shell.core.bool
import tools.obli.shell.core.str
import tools.obli.shell.core.strictLong

/*
 * Device-bound validation, Obliance paths (shapes of
 * shared/src/deviceKeys.ts). The
 * protocol itself (payload, challenges, assertions) is core:security's.
 */

/** `policy` of `GET /api/profile/device-keys`. Fail-closed defaults: a field the server leaves out disables. */
@Serializable
data class DeviceKeyPolicy(
    val enabled: Boolean = false,
    val loginEnabled: Boolean = false,
    val requireAttestation: Boolean = true,
    val strictSession: Boolean = true,
    val originConfigured: Boolean = false,
    val ssoSupported: Boolean = false,
)

/** `eligibility` of the list: may THIS account enrol a phone now, and if not why (free text of the server). */
@Serializable
data class DeviceKeyEligibility(val ok: Boolean = false, val reason: String? = null)

/** One ACTIVE key of the account, as the server lists it to its owner (`DeviceKeyInfo`). */
@Serializable
data class DeviceKeyInfo(
    val id: String = "",
    val label: String? = null,
    val platform: String = "",
    /** `strongbox` | `tee` | `unverified` (kept as text: [level] reads it). */
    val securityLevel: String = "",
    val osPatchLevel: Long? = null,
    val createdAt: String? = null,
    val lastUsedAt: String? = null,
    val lastUsedIp: String? = null,
    val useCount: Long = 0,
    /** The key bound to the session that asked (this phone, when it is enrolled and bound). */
    val current: Boolean = false,
) {
    /** Unknown or missing level → [DeviceKeyLevel.UNVERIFIED] (never shown better than it is). */
    val level: DeviceKeyLevel get() = DeviceKeyLevel.of(securityLevel) ?: DeviceKeyLevel.UNVERIFIED
}

/** `GET /api/profile/device-keys` → `data` (`DeviceKeyListResponse`). */
@Serializable
data class DeviceKeyList(
    val policy: DeviceKeyPolicy = DeviceKeyPolicy(),
    val allowedOrigins: List<String> = emptyList(),
    val boundKeyId: String? = null,
    val eligibility: DeviceKeyEligibility = DeviceKeyEligibility(),
    val keys: List<DeviceKeyInfo> = emptyList(),
) {
    /** Only well-formed key ids (a malformed row is never offered for revocation nor compared). */
    val validKeys: List<DeviceKeyInfo> get() = keys.filter { DeviceKeyHeader.isValidKeyId(it.id) }

    fun isActive(keyId: String): Boolean = validKeys.any { it.id.equals(keyId, ignoreCase = true) }
}

/**
 * Server error codes of the enrolment and key endpoints:
 * table): carried as the `error` text of [ApiOutcome.Forbidden] (403),
 * [ApiOutcome.Validation] (400), [ApiOutcome.Unsupported] (409); `422
 * attestation_failed` is `Failure(422, CLIENT, reason)`.
 */
object DeviceKeyErrors {
    const val DISABLED = "device_keys_disabled"
    const val ORIGIN_UNSET = "device_keys_origin_unset"
    const val SSO_UNSUPPORTED = "device_keys_sso_unsupported"
    const val ENROL_LOCKED = "enrol_locked"
    const val INVALID_TICKET = "invalid_ticket"
    const val ORIGIN_MISMATCH = "origin_mismatch"
    const val BAD_KEY = "bad_key"
    const val BAD_SIGNATURE = "bad_signature"
    const val TOO_MANY_KEYS = "too_many_keys"
    const val ALREADY_ENROLLED = "already_enrolled"
}

/**
 * The phone's calls about its keys on ONE server,
 * over that server's session. Also the [DeviceKeyEnrolmentApi] of
 * core:security's `DeviceKeyEnrolment` ([begin] / [finish]).
 *
 * The proofs of enrol/begin (`stepUpPassword`, `twoFactorCode`) are body
 * fields the server removes before anything else; they are never logged here.
 * No call of this class sends `X-Obli-Device-Key` itself: the interceptor
 * does, for the key of the session's user.
 */
class DeviceKeysApi(private val http: ObliHttp) : DeviceKeyEnrolmentApi {
    /** `GET /api/profile/device-keys`. `Failure(404, NOT_FOUND)` = a server without device-bound validation. */
    suspend fun list(): ApiOutcome<DeviceKeyList> =
        http.call(ObliHttp.Method.GET, PATH, decode = ApiJson.unwrapped(DeviceKeyList.serializer()))

    /**
     * `POST …/enrol/begin`:
     * - local account: `{installId, stepUpPassword, twoFactorCode}`, the account
     *   password and a NEW code; a wrong one of either answers `401 Invalid
     *   2FA code` ([ApiOutcome.StepUpRejected]);
     * - Obligate account (SSO device keys, [EnrolProof.SsoReauth]): `{installId}` only,
     *   right after the Obligate re-authentication of this session (the
     *   server checks it: less than 5 min, single use). Without it, or when the
     *   Obligate MFA epoch moved: `401 twoFactorRequired + codeRequiresReauth`;
     *   Obligate unreachable: `503 verifierUnavailable`.
     */
    override suspend fun begin(installId: String, proof: EnrolProof): ApiOutcome<EnrolTicket> {
        val body = buildJsonObject {
            put("installId", JsonPrimitive(installId))
            when (proof) {
                is EnrolProof.PasswordAndCode -> {
                    put(STEP_UP_PASSWORD, JsonPrimitive(proof.password))
                    put(TWO_FACTOR_CODE, JsonPrimitive(proof.code.filter { !it.isWhitespace() }))
                }
                // Never a password nor a code for an Obligate account.
                EnrolProof.SsoReauth -> Unit
            }
        }
        return http.call(ObliHttp.Method.POST, "$PATH/enrol/begin", body, decode = ::decodeTicket)
    }

    /** `POST …/enrol/finish` → `201 {keyId, label, securityLevel, createdAt}`; the server binds the session. */
    override suspend fun finish(request: EnrolFinish): ApiOutcome<EnrolledKey> =
        http.call(ObliHttp.Method.POST, "$PATH/enrol/finish", request.toJson(), decode = ::decodeEnrolled)

    /** `DELETE …/:id` (no step-up): 204, or 404 when it is not a key of the caller. */
    suspend fun revoke(keyId: String): ApiOutcome<Unit> {
        if (!DeviceKeyHeader.isValidKeyId(keyId)) return BAD_ID
        return http.call(ObliHttp.Method.DELETE, "$PATH/$keyId", decode = ApiJson.ignoreBody)
    }

    /** `DELETE …` : every key of the caller (this phone's included: its session ends). */
    suspend fun revokeAll(): ApiOutcome<Unit> = http.call(ObliHttp.Method.DELETE, PATH, decode = ApiJson.ignoreBody)

    /** `POST …/:id/invalidated`: the key is dead on this phone; the server revokes it and kills its sessions. */
    suspend fun reportInvalidated(keyId: String): ApiOutcome<Unit> {
        if (!DeviceKeyHeader.isValidKeyId(keyId)) return BAD_ID
        return http.call(ObliHttp.Method.POST, "$PATH/$keyId/invalidated", decode = ApiJson.ignoreBody)
    }

    companion object {
        const val PATH = "/api/profile/device-keys"
        const val STEP_UP_PASSWORD = "stepUpPassword"
        const val TWO_FACTOR_CODE = "twoFactorCode"

        private val BAD_ID: ApiOutcome<Nothing> = ApiOutcome.Failure(null, FailureKind.CLIENT, "bad key id")

        /** The ticket, strictly: any missing or malformed field → null (the enrolment stops, nothing is generated). */
        internal fun decodeTicket(element: JsonElement?): EnrolTicket? {
            val o = ApiResponses.unwrap(element) as? JsonObject ?: return null
            val ticketId = o.str("ticketId")?.takeIf(DeviceKeyHeader::isValidKeyId) ?: return null
            val nonce = o.str("nonce")?.takeIf { DeviceChallenge.isNonce(it) } ?: return null
            val expiresAt = o.strictLong("expiresAt")?.takeIf { it > 0 } ?: return null
            val userId = o.strictLong("userId")?.takeIf { it > 0 } ?: return null
            val origins = (o["allowedOrigins"] as? kotlinx.serialization.json.JsonArray)
                ?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content } ?: return null
            val requireAttestation = o.bool("requireAttestation") ?: true
            return EnrolTicket(ticketId, nonce, expiresAt, userId, origins, requireAttestation)
        }

        /** `{keyId, label, securityLevel, createdAt}`; an unknown level reads as unverified (never better). */
        internal fun decodeEnrolled(element: JsonElement?): EnrolledKey? {
            val o = ApiResponses.unwrap(element) as? JsonObject ?: return null
            val keyId = o.str("keyId") ?: return null
            val label = o["label"]?.takeIf { it !is JsonNull }?.let { o.str("label") }
            val level = DeviceKeyLevel.of(o.str("securityLevel")) ?: DeviceKeyLevel.UNVERIFIED
            return EnrolledKey(keyId, label, level, o.str("createdAt"))
        }
    }
}
