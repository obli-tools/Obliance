package tools.obli.core.security

import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceKeyHeader
import tools.obli.core.network.DevicePurpose
import tools.obli.shell.nav.Origins

/*
 * Device-bound validation, security side.
 * Pure JVM and app-agnostic ("obli-devkey-v1" is
 * shared by every Obli app). RULES: a payload is only ever built by
 * [DeviceProofPayload]; an assertion, a signature or a password is never
 * logged (the toString of every type that carries one is redacted).
 */

/** One challenge of a payload (its 5 repeated lines). */
data class PayloadChallenge(
    val challengeId: String,
    /** base64url without padding, copied as the server sent it. */
    val nonce: String,
    /** Action key, or `-`. */
    val action: String,
    /** Hex sha256 copied from the challenge (the app NEVER computes it), or `-`. */
    val binding: String,
    /** `expires_at` of the challenge, unix seconds, database clock. */
    val exp: Long,
) {
    companion object {
        fun of(c: DeviceChallenge) = PayloadChallenge(c.challengeId, c.nonce, c.action, c.binding, c.expiresAt)
    }
}

/**
 * The canonical signed payload `obli-devkey-v1`: UTF-8, lines joined by
 * `\n`, fixed order, no final newline. Checked against the reference vectors V1 and V2.
 */
object DeviceProofPayload {
    const val VERSION_LINE = "obli-devkey-v1"
    const val MAX_CHALLENGES = 50

    /**
     * @param keyRef the key id, or, for an enrolment, `spki-sha256:` + the hex
     *   sha256 of the SPKI DER ([enrolKeyRef]).
     * @throws IllegalArgumentException for a field with `\r`, `\n` (or any
     *   control character), an empty field, a count outside 1..50, a non-ASCII
     *   or non-normalised origin, a user id ≤ 0.
     */
    fun build(purpose: DevicePurpose, origin: String, userId: Long, keyRef: String, challenges: List<PayloadChallenge>): String {
        require(isAsciiOrigin(origin)) { "origin must be a normalised ASCII origin" }
        require(userId > 0) { "user id must be positive" }
        require(challenges.size in 1..MAX_CHALLENGES) { "count must be in 1..$MAX_CHALLENGES" }
        field(keyRef)
        val lines = ArrayList<String>(6 + 5 * challenges.size)
        lines += VERSION_LINE
        lines += "purpose:${purpose.wire}"
        lines += "origin:$origin"
        lines += "user:$userId"
        lines += "key:$keyRef"
        lines += "count:${challenges.size}"
        for (c in challenges) {
            require(c.exp > 0) { "exp must be positive" }
            lines += "challenge:${field(c.challengeId)}"
            lines += "nonce:${field(c.nonce)}"
            lines += "action:${field(c.action)}"
            lines += "binding:${field(c.binding)}"
            lines += "exp:${c.exp}"
        }
        return lines.joinToString("\n")
    }

    fun bytes(purpose: DevicePurpose, origin: String, userId: Long, keyRef: String, challenges: List<PayloadChallenge>): ByteArray =
        build(purpose, origin, userId, keyRef, challenges).toByteArray(Charsets.UTF_8)

    /** `spki-sha256:<hex sha256 of the SPKI DER>`: the `key` line of an enrolment. */
    fun enrolKeyRef(spki: ByteArray): String = "spki-sha256:" + sha256Hex(spki)

    /**
     * An origin both sides write the same way: what [Origins.of] gives,
     * printable ASCII only. IDN hosts are refused (`new URL` would punycode them).
     */
    fun isAsciiOrigin(origin: String): Boolean =
        origin.isNotEmpty() && origin.all { it.code in 0x21..0x7E } && Origins.of(origin) == origin

    private fun field(value: String): String {
        require(value.isNotEmpty()) { "empty payload field" }
        require(value.none { it == '\r' || it == '\n' || it.isISOControl() }) { "control character in a payload field" }
        return value
    }
}

internal fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

/** `deviceAssertion` body field: `{v, keyId, challengeIds, signature}`. */
class DeviceAssertion(
    val keyId: String,
    val challengeIds: List<String>,
    /** Standard base64 of the DER ECDSA signature. */
    val signature: String,
    val v: Int = VERSION,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("v", JsonPrimitive(v))
        put("keyId", JsonPrimitive(keyId))
        put("challengeIds", JsonArray(challengeIds.map(::JsonPrimitive)))
        put("signature", JsonPrimitive(signature))
    }

    override fun equals(other: Any?): Boolean =
        other is DeviceAssertion && other.v == v && other.keyId == keyId && other.challengeIds == challengeIds && other.signature == signature

    override fun hashCode(): Int = listOf(v, keyId, challengeIds, signature).hashCode()

    override fun toString(): String = "DeviceAssertion(keyId=$keyId, count=${challengeIds.size}, signature=<redacted>)"

    companion object {
        const val VERSION = 1
        const val FIELD = "deviceAssertion"
    }
}

/** Where the key lives (server `security_level`): StrongBox, TEE, or not verified by attestation. */
enum class DeviceKeyLevel(val wire: String) {
    STRONGBOX("strongbox"),
    TEE("tee"),
    UNVERIFIED("unverified"),
    ;

    companion object {
        fun of(wire: String?): DeviceKeyLevel? = entries.firstOrNull { it.wire == wire }
    }
}

/**
 * What the phone remembers of one key: indexed by (origin, server user
 * id). [alias] is the Keystore alias ([DeviceKeyAlias]); [keyId] the server's
 * UUID sent in `X-Obli-Device-Key`.
 */
data class DeviceKeyRecord(
    val origin: String,
    val userId: Long,
    val username: String,
    val keyId: String,
    val alias: String,
    val installId: String,
    val securityLevel: DeviceKeyLevel,
    /** Epoch milliseconds (local clock) of the enrolment. */
    val createdAt: Long,
) {
    init {
        require(userId > 0) { "user id must be positive" }
        require(DeviceKeyHeader.isValidKeyId(keyId)) { "key id must be a UUID" }
        require(DeviceKeyAlias.isOurs(alias)) { "not a device-key alias" }
    }
}

/** Keystore alias of a key: `obli.devkey.v1.` + 16 hex of sha256(origin \n userId \n installId). */
object DeviceKeyAlias {
    const val PREFIX = "obli.devkey.v1."

    fun of(origin: String, userId: Long, installId: String): String =
        PREFIX + sha256Hex("$origin\n$userId\n$installId".toByteArray(Charsets.UTF_8)).take(16)

    fun isOurs(alias: String): Boolean = alias.length == PREFIX.length + 16 && alias.startsWith(PREFIX) &&
        alias.substring(PREFIX.length).all { it in '0'..'9' || it in 'a'..'f' }
}

/** Texts of the system biometric prompt (built by the host from the action and the challenge). */
data class SignPrompt(
    val title: String,
    val subtitle: String?,
    val description: String?,
    /** The negative button ("Utiliser un code"): mandatory, the device credential is never offered. */
    val negative: String,
)

/** Outcome of one signature. */
sealed interface SignResult {
    /** DER ECDSA signature of the payload. */
    class Signed(val der: ByteArray) : SignResult {
        override fun toString(): String = "Signed(<redacted>)"
    }

    /** "Utiliser un code" (the prompt's negative button). */
    data object UseCode : SignResult
    data object Cancelled : SignResult

    /** The key was invalidated (new biometric, screen lock removed) or is gone. */
    data object Invalidated : SignResult

    /** Too many failed attempts: the biometric is locked out. */
    data object LockedOut : SignResult
    data class Unavailable(val reason: String) : SignResult
}

/**
 * What the host signs for a step-up or a sign-in: built ONLY by the factories
 * below, which check the challenges against the record and build the payload
 * with [DeviceProofPayload]. [payload] is a copy.
 */
class DeviceSignRequest private constructor(
    val purpose: DevicePurpose,
    val origin: String,
    val record: DeviceKeyRecord,
    val challenges: List<DeviceChallenge>,
    private val payloadBytes: ByteArray,
) {
    val payload: ByteArray get() = payloadBytes.copyOf()
    val count: Int get() = challenges.size

    /** Action key of the challenges (the same for all of them). */
    val action: String get() = challenges.first().action

    /** DISPLAY ONLY: the tenant named by the server in the challenge. */
    val tenantName: String? get() = challenges.first().tenantName

    /** The body field once [der] is obtained. */
    fun assertion(der: ByteArray): DeviceAssertion =
        DeviceAssertion(record.keyId, challenges.map { it.challengeId }, Base64.getEncoder().encodeToString(der))

    override fun toString(): String = "DeviceSignRequest(${purpose.wire}, $origin, key=${record.keyId}, count=$count)"

    companion object {
        /**
         * Step-up over 1..50 challenges of [record] on [origin]. For a batch
         * (count > 1) all challenges must share the action, the tenant and a
         * non-null bulk id; the server checks it again.
         */
        fun stepUp(origin: String, record: DeviceKeyRecord, challenges: List<DeviceChallenge>): DeviceSignRequest {
            require(challenges.size in 1..DeviceProofPayload.MAX_CHALLENGES) { "count must be in 1..${DeviceProofPayload.MAX_CHALLENGES}" }
            require(origin == record.origin) { "the key belongs to another origin" }
            require(challenges.all { it.purpose == DevicePurpose.STEPUP && it.keyId == record.keyId && it.userId == record.userId }) {
                "challenge of another purpose, key or user"
            }
            require(challenges.map { it.challengeId }.toSet().size == challenges.size) { "duplicate challenge" }
            if (challenges.size > 1) {
                val first = challenges.first()
                require(first.bulkId != null && challenges.all { it.bulkId == first.bulkId && it.action == first.action && it.tenantId == first.tenantId }) {
                    "a batch needs one bulk id, one action and one tenant"
                }
            }
            val payload = DeviceProofPayload.bytes(DevicePurpose.STEPUP, origin, record.userId, record.keyId, challenges.map(PayloadChallenge::of))
            return DeviceSignRequest(DevicePurpose.STEPUP, origin, record, challenges.toList(), payload)
        }

        /** Sign-in with the fingerprint: one `login` challenge of [record]. */
        fun login(origin: String, record: DeviceKeyRecord, challenge: DeviceChallenge): DeviceSignRequest {
            require(origin == record.origin) { "the key belongs to another origin" }
            require(challenge.purpose == DevicePurpose.LOGIN && challenge.keyId == record.keyId && challenge.userId == record.userId) {
                "challenge of another purpose, key or user"
            }
            val payload = DeviceProofPayload.bytes(DevicePurpose.LOGIN, origin, record.userId, record.keyId, listOf(PayloadChallenge.of(challenge)))
            return DeviceSignRequest(DevicePurpose.LOGIN, origin, record, listOf(challenge), payload)
        }
    }
}
