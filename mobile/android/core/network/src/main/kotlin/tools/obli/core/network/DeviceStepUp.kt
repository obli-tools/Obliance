package tools.obli.core.network

import java.util.Base64
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import tools.obli.shell.core.obj
import tools.obli.shell.core.str
import tools.obli.shell.core.strictLong

/*
 * Device-bound validation, network side.
 * Pure JVM and app-agnostic: the protocol
 * "obli-devkey-v1" is common to every Obli app; only the API paths are
 * Obliance's. Nothing here signs: the app only copies what the server sent.
 */

/** The header naming this phone's key for (origin, user of the session). */
object DeviceKeyHeader {
    const val NAME = "X-Obli-Device-Key"

    private val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    /** Key ids and challenge ids are server UUIDs; anything else is never sent nor signed. */
    fun isValidKeyId(value: String?): Boolean = value != null && UUID.matches(value)
}

/** `purpose` of a challenge and of the signed payload. */
enum class DevicePurpose(val wire: String) {
    ENROL("enrol"),
    LOGIN("login"),
    STEPUP("stepup"),
    ;

    companion object {
        fun of(wire: String?): DevicePurpose? = entries.firstOrNull { it.wire == wire }
    }
}

/** `deviceKeyStatus` of a step-up 401. `revoked` never reaches here: it comes with `Authentication required`. */
enum class DeviceKeyStatus(val wire: String) {
    ACTIVE("active"),
    DISABLED("disabled"),
    THROTTLED("throttled"),
    ;

    companion object {
        fun of(wire: String?): DeviceKeyStatus? = entries.firstOrNull { it.wire == wire }
    }
}

/** `deviceError` of a step-up 401 (the server's reject reasons). */
enum class DeviceError {
    /** A challenge of the SAME binding exists: a new `deviceChallenge` comes with it (one more signature at most). */
    CHALLENGE_EXPIRED,

    /** Signature, binding, session, tenant, batch, origin or purpose refused: fall back on the code. */
    INVALID_ASSERTION,

    /** A value this app does not know: handled like [INVALID_ASSERTION] (code). */
    OTHER,
    ;

    companion object {
        fun of(wire: String): DeviceError = when (wire) {
            "challenge_expired" -> CHALLENGE_EXPIRED
            "invalid_assertion" -> INVALID_ASSERTION
            else -> OTHER
        }
    }
}

/** The device-key part of a step-up 401: present only when the session is bound or the header was sent. */
data class DeviceStepUp(
    val status: DeviceKeyStatus,
    /** Present only with [DeviceKeyStatus.ACTIVE] on a site that accepts the fingerprint, and only if well formed. */
    val challenge: DeviceChallenge? = null,
    val error: DeviceError? = null,
)

/**
 * A challenge as the server sends it (401 step-up, login answer, device-challenge):
 * `{v, keyId, challengeId, purpose, userId, tenantId, tenantName, nonce, action,
 * binding, expiresAt, bulkId}`. [parse] is strict: a challenge of an unknown
 * version or with one malformed field is dropped, and the app falls back on
 * the code (a peer ignores a version it does not know).
 */
data class DeviceChallenge(
    val v: Int,
    val keyId: String,
    val challengeId: String,
    val purpose: DevicePurpose,
    val userId: Long,
    /** Binding tenant (covered by `binding`); null for a login and for tenant-less routes. */
    val tenantId: Long?,
    /** DISPLAY ONLY (the prompt's "server › tenant"). */
    val tenantName: String?,
    /** base64url without padding, 32 bytes. Copied as is into the payload. */
    val nonce: String,
    /** Action key, `-` for a login. */
    val action: String,
    /** Hex sha256 of the request binding, `-` for a login. The app never computes it. */
    val binding: String,
    /** Unix seconds, database clock. */
    val expiresAt: Long,
    val bulkId: String?,
) {
    companion object {
        const val VERSION = 1
        const val NONCE_BYTES = 32
        const val MAX_ACTION_LENGTH = 120

        private val BASE64URL = Regex("^[A-Za-z0-9_-]+$")
        private val HEX64 = Regex("^[0-9a-f]{64}$")

        /** The challenge in [obj], or null when absent, of another version or malformed. */
        fun parse(obj: JsonObject?): DeviceChallenge? {
            if (obj == null) return null
            if (obj.strictLong("v") != VERSION.toLong()) return null
            val keyId = obj.str("keyId")?.takeIf(DeviceKeyHeader::isValidKeyId) ?: return null
            val challengeId = obj.str("challengeId")?.takeIf(DeviceKeyHeader::isValidKeyId) ?: return null
            val purpose = DevicePurpose.of(obj.str("purpose")) ?: return null
            val userId = obj.strictLong("userId")?.takeIf { it > 0 } ?: return null
            val tenantId = when (obj["tenantId"]) {
                null, JsonNull -> null
                else -> obj.strictLong("tenantId")?.takeIf { it > 0 } ?: return null
            }
            val tenantName = when (obj["tenantName"]) {
                null, JsonNull -> null
                else -> obj.str("tenantName") ?: return null
            }
            val nonce = obj.str("nonce")?.takeIf(::isNonce) ?: return null
            val action = obj.str("action")?.takeIf { it.isNotEmpty() && it.length <= MAX_ACTION_LENGTH && it.none(Char::isISOControl) } ?: return null
            val binding = obj.str("binding")?.takeIf { it == "-" || HEX64.matches(it) } ?: return null
            val expiresAt = obj.strictLong("expiresAt")?.takeIf { it > 0 } ?: return null
            val bulkId = when (obj["bulkId"]) {
                null, JsonNull -> null
                else -> obj.str("bulkId")?.takeIf(DeviceKeyHeader::isValidKeyId) ?: return null
            }
            // A login has no action, binding nor tenant; a step-up always has an action and a binding.
            when (purpose) {
                DevicePurpose.LOGIN -> if (action != "-" || binding != "-" || tenantId != null) return null
                DevicePurpose.STEPUP -> if (action == "-" || binding == "-") return null
                DevicePurpose.ENROL -> return null // enrolment tickets are not challenges of this shape
            }
            return DeviceChallenge(VERSION, keyId, challengeId, purpose, userId, tenantId, tenantName, nonce, action, binding, expiresAt, bulkId)
        }

        /** base64url without padding decoding to exactly [NONCE_BYTES] bytes. */
        fun isNonce(value: String): Boolean {
            if (!BASE64URL.matches(value)) return false
            return try {
                Base64.getUrlDecoder().decode(value).size == NONCE_BYTES
            } catch (_: IllegalArgumentException) {
                false
            }
        }

        /** The device part of a step-up 401 body, or null when the body carries none. */
        fun stepUpOf(body: JsonObject): DeviceStepUp? {
            val status = DeviceKeyStatus.of(body.str("deviceKeyStatus")) ?: return null
            val error = body.str("deviceError")?.let(DeviceError::of)
            val challenge = if (status == DeviceKeyStatus.ACTIVE) {
                parse(body.obj("deviceChallenge"))?.takeIf { it.purpose == DevicePurpose.STEPUP }
            } else {
                null
            }
            return DeviceStepUp(status, challenge, error)
        }
    }
}
