package tools.obli.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import tools.obli.shell.core.bool
import tools.obli.shell.core.obj
import tools.obli.shell.core.str
import tools.obli.shell.core.strictLong

/**
 * Maps a raw HTTP answer of an Obli server to an [ApiOutcome]. Pure JVM: the
 * transport (OkHttp) only hands over status, headers and body text, so every
 * server shape is covered by unit tests with recorded bodies.
 *
 * Server shapes (server/src): errors are `{success:false, error}` (AppError) or
 * `{error, ...}`; restriction outcomes come from restriction.service.ts.
 */
object ApiResponses {
    private val json = Json { ignoreUnknownKeys = true; isLenient = false }

    /**
     * @param decode maps the JSON body (null for an empty body) to the payload;
     *   returning null means "unexpected shape" and yields [FailureKind.SERVER].
     */
    fun <T> classify(
        status: Int,
        contentType: String?,
        body: String?,
        retryAfter: String? = null,
        decode: (JsonElement?) -> T?,
    ): ApiOutcome<T> {
        val text = body?.takeIf { it.isNotBlank() }
        val isJson = contentType?.substringBefore(';')?.trim()?.lowercase()?.let { it == "application/json" || it.endsWith("+json") } == true
        val element: JsonElement? = if (text != null && isJson) parse(text) else null

        if (status in 200..299) {
            if (text != null && (!isJson || element == null)) return ApiOutcome.Failure(status, FailureKind.NOT_JSON)
            if (status == 202) {
                val data = (element as? JsonObject)?.obj("data")
                if (data?.str("status") == "pending_approval") {
                    val id = data.strictLong("approvalId") ?: return ApiOutcome.Failure(status, FailureKind.SERVER)
                    return ApiOutcome.PendingApproval(id)
                }
                return decode(element)?.let { ApiOutcome.Accepted(it) } ?: ApiOutcome.Failure(status, FailureKind.SERVER)
            }
            return decode(element)?.let { ApiOutcome.Ok(it) } ?: ApiOutcome.Failure(status, FailureKind.SERVER)
        }

        val obj = element as? JsonObject
        val message = obj?.str("error") ?: obj?.str("message") ?: ""
        return when (status) {
            400 -> ApiOutcome.Validation(message, fieldErrors(obj?.obj("details")))
            // 401 twoFactorRequired → StepUpRequired (+ device fields); `Invalid 2FA code`
            // → StepUpRejected; anything else, `deviceKeyStatus:'revoked'` included → SessionExpired.
            401 -> when {
                obj?.bool("twoFactorRequired") == true -> stepUp(obj)
                message.equals("Invalid 2FA code", ignoreCase = true) -> ApiOutcome.StepUpRejected(codeUsed = obj?.bool("codeUsed") == true)
                else -> ApiOutcome.SessionExpired
            }
            403 -> forbidden(message)
            404 -> ApiOutcome.Failure(404, FailureKind.NOT_FOUND, message.ifEmpty { null })
            409 -> ApiOutcome.Unsupported(message)
            // Enrolment: `422 {error:'attestation_failed', reason}` → Failure(CLIENT, reason).
            422 -> ApiOutcome.Failure(
                422,
                FailureKind.CLIENT,
                (if (message == ATTESTATION_FAILED) obj?.str("reason") else null) ?: message.ifEmpty { null },
            )
            423 -> ApiOutcome.PrivacyLocked(
                feature = FEATURE.find(message)?.groupValues?.get(1),
                passwordSet = message.contains("password is set", ignoreCase = true),
                message = message,
            )
            429 -> ApiOutcome.RateLimited(
                retryAfter?.trim()?.toIntOrNull()?.takeIf { it >= 0 },
                codeLocked = obj?.bool("codeLocked") == true,
            )
            // `503 {verifierUnavailable:true}` (step-up of an Obligate account, SSO enrolment):
            // Obligate could not check the proof — not an offline agent, nothing was run.
            503 -> if (obj?.bool("verifierUnavailable") == true) {
                ApiOutcome.Failure(503, FailureKind.SERVER, VERIFIER_UNAVAILABLE)
            } else {
                ApiOutcome.AgentOffline(message)
            }
            in 500..599 -> ApiOutcome.Failure(status, FailureKind.SERVER, message.ifEmpty { null })
            else -> ApiOutcome.Failure(status, FailureKind.CLIENT, message.ifEmpty { null })
        }
    }

    /** For a call that never got an HTTP answer. */
    fun network(message: String? = null): ApiOutcome<Nothing> = ApiOutcome.Failure(null, FailureKind.NETWORK, message)

    /**
     * True for `401 {error:'Authentication required', deviceKeyStatus:'revoked'}`:
     * the server destroyed the session because this phone's key was revoked.
     * The outcome itself is [ApiOutcome.SessionExpired]; the caller
     * purges the local key when it is the one of the session's user.
     */
    fun isDeviceKeyRevoked(status: Int, contentType: String?, body: String?): Boolean {
        if (status != 401 || body.isNullOrBlank()) return false
        val isJson = contentType?.substringBefore(';')?.trim()?.lowercase()?.let { it == "application/json" || it.endsWith("+json") } == true
        if (!isJson) return false
        val obj = parse(body) as? JsonObject ?: return false
        return obj.bool("twoFactorRequired") != true && obj.str("deviceKeyStatus") == "revoked"
    }

    /** The JSON object of an answer body, or null (not JSON, not an object, empty). */
    fun errorObject(contentType: String?, body: String?): JsonObject? {
        if (body.isNullOrBlank()) return null
        val isJson = contentType?.substringBefore(';')?.trim()?.lowercase()?.let { it == "application/json" || it.endsWith("+json") } == true
        if (!isJson) return null
        return parse(body) as? JsonObject
    }

    private fun stepUp(obj: JsonObject): ApiOutcome.StepUpRequired = ApiOutcome.StepUpRequired(
        action = obj.str("action"),
        currentIp = obj.str("currentIp"),
        trustIpAllowed = obj.bool("trustIpAllowed") ?: true,
        codeRequiresPassword = obj.bool("codeRequiresPassword") ?: false,
        codeRequiresReauth = obj.bool("codeRequiresReauth") ?: false,
        device = DeviceChallenge.stepUpOf(obj),
    )

    /** Payload of `{success, data}` / `{data}` envelopes, or the element itself (raw endpoints). */
    fun unwrap(element: JsonElement?): JsonElement? {
        val obj = element as? JsonObject ?: return element
        return if ("data" in obj && (obj.size == 1 || "success" in obj)) obj["data"] else obj
    }

    private fun forbidden(message: String): ApiOutcome<Nothing> {
        CAPABILITY.find(message)?.let { return ApiOutcome.Forbidden(ForbiddenReason.CAPABILITY, message, it.groupValues[1]) }
        val reason = when {
            message.contains("enable TOTP", ignoreCase = true) -> ForbiddenReason.NO_TOTP
            message.contains("no approval path", ignoreCase = true) -> ForbiddenReason.NO_APPROVAL_PATH
            else -> ForbiddenReason.OTHER
        }
        return ApiOutcome.Forbidden(reason, message)
    }

    private fun fieldErrors(details: JsonObject?): Map<String, List<String>> =
        details?.mapNotNull { (field, value) ->
            val msgs = (value as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            msgs?.takeIf { it.isNotEmpty() }?.let { field to it }
        }?.toMap().orEmpty()

    private fun parse(text: String): JsonElement? = try {
        json.parseToJsonElement(text)
    } catch (_: Exception) {
        null
    }

    /**
     * [ApiOutcome.Failure] message of `503 {verifierUnavailable:true}`: the
     * second factor could not be verified right now (Obligate unreachable for
     * an Obligate account, SSO device keys); see [isVerifierUnavailable].
     */
    const val VERIFIER_UNAVAILABLE = "verifier_unavailable"

    private const val ATTESTATION_FAILED = "attestation_failed"
    private val CAPABILITY = Regex("Capability '([a-z_]+)' not permitted")
    private val FEATURE = Regex("feature '([^']+)'")
}
