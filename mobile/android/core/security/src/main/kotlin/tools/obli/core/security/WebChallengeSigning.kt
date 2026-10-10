package tools.obli.core.security

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DevicePurpose

/**
 * The native checks of `window.ObliNative.signDeviceChallenge(challengeJson)`
 * (bridgeVersion 2), as a pure function: the web page of the app (the web
 * view) hands over the
 * `deviceChallenge` of a step-up 401 it received; nothing is signed unless
 *
 *  - the page's origin is the origin of the ACTIVE server;
 *  - the challenge parses strictly (`DeviceChallenge.parse`: known `v`, every
 *    field well formed), its purpose is `stepup`, and it names ONE challenge;
 *  - its `userId` and `keyId` are those of this phone's key of (origin, user
 *    of the session signed in there).
 *
 * The prompt is built natively ([promptSpec]) from the challenge's action and
 * the tenant the APP names for `challenge.tenantId` ([TenantLookup]): the
 * page relays the JSON, so its `tenantName` is page text and is dropped; a
 * tenant id that is not one of the user's tenants is refused. The payload is
 * [DeviceProofPayload]'s, through [DeviceSignRequest.stepUp]. The page never
 * receives anything but the assertion or a short error code.
 */
object WebChallengeSigning {
    /** A challenge JSON longer than this is refused unread. */
    const val MAX_JSON_LENGTH = 8_192

    /** What the bridge answers the page (`{deviceAssertion}` / `{cancelled:true}` / `{useCode:true}` / `{error}`). */
    sealed interface Answer {
        class Assertion(val assertion: DeviceAssertion) : Answer {
            override fun toString(): String = "Assertion(<redacted>)"
        }

        data object Cancelled : Answer
        data object UseCode : Answer
        data class Error(val code: String) : Answer

        /** The result object of the bridge call. */
        fun toJson(): JsonObject = when (this) {
            is Assertion -> buildJsonObject { put(DeviceAssertion.FIELD, assertion.toJson()) }
            Cancelled -> buildJsonObject { put("cancelled", JsonPrimitive(true)) }
            UseCode -> buildJsonObject { put("useCode", JsonPrimitive(true)) }
            is Error -> buildJsonObject { put("error", JsonPrimitive(code)) }
        }
    }

    /** Error codes returned to the page (never a detail of the key or of the session). */
    object Errors {
        const val BAD_CHALLENGE = "bad_challenge"
        const val NOT_ACTIVE_SERVER = "not_active_server"
        const val WRONG_PURPOSE = "wrong_purpose"
        const val NO_KEY = "no_key"
        const val KEY_MISMATCH = "key_mismatch"
        const val INVALIDATED = "invalidated"
        const val BUSY = "busy"
        const val UNAVAILABLE = "unavailable"

        /** Too many prompts, the same challenge again, or right after a declined prompt (the bridge's gate). */
        const val RATE_LIMITED = "rate_limited"

        /** The challenge's `expiresAt` is past (beyond the clock-skew allowance). */
        const val EXPIRED = "expired"

        /** The web view is not on screen (app in the background, another window on top). */
        const val NOT_VISIBLE = "not_visible"
    }

    /** How the prompt names the tenant of `challenge.tenantId` — from the app's own data, never the page's. */
    sealed interface TenantLookup {
        /** One of the user's tenants, by the name the app loaded. */
        data class Known(val name: String) : TenantLookup

        /** The app does not know the user's tenants (not loaded): shown as « #id ». */
        data object Unknown : TenantLookup

        /** Not one of the user's tenants: nothing is signed ([Errors.BAD_CHALLENGE]). */
        data object NotMine : TenantLookup
    }

    private val json = Json { isLenient = false }

    /**
     * @param pageOrigin origin of the page that called (checked against the
     *   web view's own origin by the bridge before this is reached).
     * @param activeOrigin ObliHttp origin of the active server, null if none.
     * @param serverName display name of that server (the prompt's « serveur › tenant »).
     * @param tenants names `challenge.tenantId` from the app's tenant list of the
     *   active server (the page's `tenantName` is never shown).
     * @param sign shows the fingerprint prompt for the request (the action host's signer).
     * @param invalidated the invalidation flow, when the key turned out dead.
     */
    suspend fun sign(
        pageOrigin: String,
        activeOrigin: String?,
        serverName: String?,
        challengeJson: String,
        keys: DeviceKeyResolver?,
        tenants: (tenantId: Long) -> TenantLookup = { TenantLookup.Unknown },
        spec: (DeviceChallenge) -> ActionSpec = { promptSpec(it, serverName) },
        sign: suspend (ActionSpec, DeviceSignRequest) -> SignResult,
        invalidated: suspend (origin: String, keyId: String) -> Unit,
    ): Answer {
        if (activeOrigin == null || pageOrigin != activeOrigin) return Answer.Error(Errors.NOT_ACTIVE_SERVER)
        if (challengeJson.length > MAX_JSON_LENGTH) return Answer.Error(Errors.BAD_CHALLENGE)
        val obj = try {
            json.parseToJsonElement(challengeJson) as? JsonObject
        } catch (_: Exception) {
            null
        } ?: return Answer.Error(Errors.BAD_CHALLENGE)
        // parse() drops a challenge of another version or with one malformed field.
        val relayed = DeviceChallenge.parse(obj) ?: return Answer.Error(Errors.BAD_CHALLENGE)
        if (relayed.purpose != DevicePurpose.STEPUP) return Answer.Error(Errors.WRONG_PURPOSE)
        // The tenant NAME comes from the app, never from the page (it is not covered by the binding).
        val tenantLabel = relayed.tenantId?.let { id ->
            when (val t = try { tenants(id) } catch (_: RuntimeException) { TenantLookup.Unknown }) {
                is TenantLookup.Known -> t.name.takeIf { it.isNotBlank() } ?: "#$id"
                TenantLookup.Unknown -> "#$id"
                TenantLookup.NotMine -> return Answer.Error(Errors.BAD_CHALLENGE)
            }
        }
        val challenge = relayed.copy(tenantName = tenantLabel)
        val record = try {
            keys?.keyFor(pageOrigin)
        } catch (_: RuntimeException) {
            null
        } ?: return Answer.Error(Errors.NO_KEY)
        if (record.origin != pageOrigin || record.userId != challenge.userId || record.keyId != challenge.keyId) return Answer.Error(Errors.KEY_MISMATCH)
        val request = try {
            DeviceSignRequest.stepUp(pageOrigin, record, listOf(challenge))
        } catch (_: IllegalArgumentException) {
            return Answer.Error(Errors.BAD_CHALLENGE)
        }
        return when (val signed = sign(spec(challenge), request)) {
            is SignResult.Signed -> Answer.Assertion(request.assertion(signed.der))
            SignResult.UseCode, SignResult.LockedOut, is SignResult.Unavailable -> Answer.UseCode
            SignResult.Cancelled -> Answer.Cancelled
            SignResult.Invalidated -> {
                invalidated(record.origin, record.keyId)
                Answer.Error(Errors.INVALIDATED)
            }
        }
    }

    /**
     * The prompt of a web action: the app has no label for the page's
     * action, so the title names it by its key (« Action protégée :
     * command.reboot »); the subtitle is « serveur › tenant », the tenant as
     * [sign] resolved it natively (display only: the binding covers the id).
     * T0: the description is « Double authentification, pour cette action
     * uniquement ».
     */
    fun promptSpec(challenge: DeviceChallenge, serverName: String?, title: String = DEFAULT_TITLE): ActionSpec = ActionSpec(
        key = challenge.action,
        tier = Tier.T0,
        title = title,
        target = challenge.action,
        scope = listOfNotNull(serverName, challenge.tenantName).joinToString(" › "),
        tenantId = challenge.tenantId,
        serverName = serverName,
    )

    /** Overridden by the app with its localised « Action protégée : ». */
    const val DEFAULT_TITLE = "Action protégée :"
}
