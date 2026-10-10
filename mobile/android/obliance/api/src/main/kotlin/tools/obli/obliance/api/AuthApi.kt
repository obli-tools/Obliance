package tools.obli.obliance.api

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import tools.obli.core.model.ObliUser
import tools.obli.core.model.SessionProbe
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.ApiResponses
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceError
import tools.obli.core.network.DeviceKeyHeader
import tools.obli.core.network.DevicePurpose
import tools.obli.core.network.FailureKind
import tools.obli.core.network.ObliHttp
import tools.obli.core.security.DeviceAssertion
import tools.obli.shell.core.obj
import tools.obli.shell.core.str

/** `GET /health` (server/src/app.ts, public, not enveloped). */
@Serializable
data class Health(
    val status: String = "",
    val version: String? = null,
    val timestamp: String? = null,
) {
    val isOk: Boolean get() = status == "ok"
}

/** `GET /api/auth/sso-config` → `data` (obligate.service.ts getSsoConfig). */
@Serializable
data class SsoConfig(
    val obligateUrl: String? = null,
    val obligateReachable: Boolean = false,
    val obligateEnabled: Boolean = false,
) {
    /** The "Se connecter avec Obligate" button is offered only when both are true. */
    val offersObligate: Boolean get() = obligateEnabled && obligateReachable && !obligateUrl.isNullOrBlank()
}

/** Second factors of the account, from `data.methods` of a login that needs 2FA. */
@Serializable
data class TwoFactorMethods(
    val totp: Boolean = false,
    val email: Boolean = false,
    /**
     * Device-bound validation: the login carried the header of
     * an eligible key of this account; the answer has a `login` challenge and
     * the server did NOT send the automatic e-mail code.
     */
    val device: Boolean = false,
)

enum class TwoFactorMethod(val wire: String) { TOTP("totp"), EMAIL("email") }

@Serializable
internal data class LoginPayload(
    val requires2fa: Boolean = false,
    val methods: TwoFactorMethods = TwoFactorMethods(),
    val user: ObliUser? = null,
    /** A `login` challenge when `methods.device` (read strictly by [DeviceChallenge.parse]). */
    val deviceChallenge: JsonObject? = null,
)

/** Outcome of `POST /api/auth/login` and of its 2FA continuation. */
sealed interface LoginResult {
    /** The session cookie is set; the account is signed in. */
    data class SignedIn(val user: ObliUser) : LoginResult

    /**
     * Step 1 done (`pendingMfaUserId` in the session): send the code with
     * [AuthApi.verifyTwoFactor], or, when [deviceChallenge] is set
     * (`methods.device`), sign it with the fingerprint and send it
     * with [AuthApi.verifyDevice]. A malformed challenge is dropped and
     * `methods.device` reads false: the code is used.
     */
    data class TwoFactorRequired(val methods: TwoFactorMethods, val deviceChallenge: DeviceChallenge? = null) : LoginResult

    /** 401 on login: `Invalid username or password`. */
    data object InvalidCredentials : LoginResult

    /** 401 on 2FA verify: `Invalid code` (the pending session is kept, try again). */
    data object InvalidCode : LoginResult

    /** 400 `No pending 2FA session`: the pending login expired, start again. */
    data object TwoFactorSessionLost : LoginResult

    /** 429 from authLimiter / mfaLimiter. */
    data class RateLimited(val retryAfterSec: Int?) : LoginResult

    /** Anything else (validation, network, 5xx…), for the screen to explain. */
    data class Failed(val outcome: ApiOutcome<Nothing>) : LoginResult
}

/** Answer of [AuthApi.verifyDevice] (the fingerprint sign-in). */
sealed interface DeviceLoginAnswer {
    /** Signed in, or an answer that is not about the fingerprint (pending login lost, rate limit, network…). */
    data class Done(val result: LoginResult) : DeviceLoginAnswer

    /**
     * `401 {error:'Invalid code', …}`: the assertion was refused. [renewed] is
     * the new `login` challenge that comes with `challenge_expired` (strictly
     * parsed; null otherwise); [keyRevoked] when `deviceKeyStatus:'revoked'`
     * (the key is dead server side: forget it here).
     */
    data class Refused(
        val error: DeviceError?,
        val renewed: DeviceChallenge? = null,
        val keyRevoked: Boolean = false,
        /** `deviceKeyStatus` `throttled` or `disabled`: no signature now, the code. */
        val keyUnusable: Boolean = false,
    ) : DeviceLoginAnswer

    companion object {
        internal fun refusedBy(body: JsonObject?): Refused {
            val error = body?.str("deviceError")?.let(DeviceError::of)
            val status = body?.str("deviceKeyStatus")
            val renewed = if (error == DeviceError.CHALLENGE_EXPIRED) {
                DeviceChallenge.parse(body.obj("deviceChallenge"))?.takeIf { it.purpose == DevicePurpose.LOGIN }
            } else {
                null
            }
            return Refused(error, renewed, keyRevoked = status == "revoked", keyUnusable = status == "throttled" || status == "disabled")
        }
    }
}

/**
 * Sign-in calls of ONE server (server/src/controllers/auth.controller.ts,
 * twoFactor.controller.ts, routes/obligateCallback.routes.ts).
 *
 * Flow: [login] → either [LoginResult.SignedIn], or [LoginResult.TwoFactorRequired]
 * (the server keeps `pendingMfaUserId` in the session cookie and, for e-mail
 * OTP, has already sent a code) → [verifyTwoFactor] with `{code, method}`
 * ([resendEmailCode] sends a new e-mail code). The cookie jar carries the
 * session between the two steps: use the same origin and client.
 */
class AuthApi(private val http: ObliHttp) {
    suspend fun health(): ApiOutcome<Health> = http.call(ObliHttp.Method.GET, "/health", decode = ApiJson.unwrapped(Health.serializer()))

    suspend fun ssoConfig(): ApiOutcome<SsoConfig> =
        http.call(ObliHttp.Method.GET, "/api/auth/sso-config", decode = ApiJson.unwrapped(SsoConfig.serializer()))

    /** `GET /api/auth/me` (also done by ServerSession.probe()). */
    suspend fun me(): ApiOutcome<SessionProbe> =
        http.call(ObliHttp.Method.GET, "/api/auth/me", decode = ApiJson.unwrapped(SessionProbe.serializer()))

    /**
     * `POST /api/auth/login`. [deviceKeyId]: this phone's key for the typed
     * username on this origin (`DeviceKeyStore.findByUsername`), sent as the
     * explicit `X-Obli-Device-Key`: the server then offers the
     * fingerprint when that key is eligible, and binds the new session to it.
     */
    suspend fun login(username: String, password: String, deviceKeyId: String? = null): LoginResult {
        val out = http.call(
            ObliHttp.Method.POST,
            "/api/auth/login",
            ApiJson.body("username" to username.trim(), "password" to password),
            headers = deviceKeyHeaders(deviceKeyId),
            decode = ApiJson.unwrapped(LoginPayload.serializer()),
        )
        return when (out) {
            is ApiOutcome.Ok -> step(out.value)
            is ApiOutcome.Accepted -> step(out.value)
            // Any 401 here is the credentials: there is no session to expire yet.
            ApiOutcome.SessionExpired, is ApiOutcome.StepUpRejected, is ApiOutcome.StepUpRequired -> LoginResult.InvalidCredentials
            else -> failure(out)
        }
    }

    /**
     * `POST /api/profile/2fa/verify {code, method}`. [deviceKeyId]: the key
     * whose header the login carried (the regenerated session is bound
     * to it when it is an active key of this user).
     */
    suspend fun verifyTwoFactor(method: TwoFactorMethod, code: String, deviceKeyId: String? = null): LoginResult {
        val out = http.call(
            ObliHttp.Method.POST,
            "/api/profile/2fa/verify",
            ApiJson.body("code" to code.filter { !it.isWhitespace() }, "method" to method.wire),
            headers = deviceKeyHeaders(deviceKeyId),
            decode = ApiJson.unwrapped(LoginPayload.serializer()),
        )
        return when (out) {
            is ApiOutcome.Ok -> out.value.user?.let { LoginResult.SignedIn(it) } ?: LoginResult.Failed(ApiResponses.network("no user"))
            is ApiOutcome.Accepted -> out.value.user?.let { LoginResult.SignedIn(it) } ?: LoginResult.Failed(ApiResponses.network("no user"))
            ApiOutcome.SessionExpired, is ApiOutcome.StepUpRejected, is ApiOutcome.StepUpRequired -> LoginResult.InvalidCode
            is ApiOutcome.Validation ->
                if (out.message.contains("pending 2FA", ignoreCase = true)) LoginResult.TwoFactorSessionLost else LoginResult.Failed(out)
            else -> failure(out)
        }
    }

    /** `POST /api/profile/2fa/resend-email` (only while a login is pending). */
    suspend fun resendEmailCode(): ApiOutcome<Unit> =
        http.call(ObliHttp.Method.POST, "/api/profile/2fa/resend-email", decode = ApiJson.ignoreBody)

    /**
     * `POST /api/profile/2fa/verify {method:'device', deviceAssertion}`:
     * the assertion of the `login` challenge. A refused one answers `401
     * {error:'Invalid code', deviceError?, deviceChallenge?, deviceKeyStatus?}`
     * → [DeviceLoginAnswer.Refused] (the pending login is kept: the code, or
     * one more signature of the renewed challenge after `challenge_expired`).
     */
    suspend fun verifyDevice(assertion: DeviceAssertion): DeviceLoginAnswer {
        val body = buildJsonObject {
            put("method", JsonPrimitive(DEVICE_METHOD))
            put(DeviceAssertion.FIELD, assertion.toJson())
        }
        var refusal: JsonObject? = null
        val out = http.call(
            ObliHttp.Method.POST,
            "/api/profile/2fa/verify",
            body,
            errorBody = { status, obj -> if (status == 401) refusal = obj },
            decode = ApiJson.unwrapped(LoginPayload.serializer()),
        )
        return when (out) {
            is ApiOutcome.Ok -> DeviceLoginAnswer.Done(out.value.user?.let { LoginResult.SignedIn(it) } ?: LoginResult.Failed(ApiResponses.network("no user")))
            is ApiOutcome.Accepted -> DeviceLoginAnswer.Done(out.value.user?.let { LoginResult.SignedIn(it) } ?: LoginResult.Failed(ApiResponses.network("no user")))
            ApiOutcome.SessionExpired, is ApiOutcome.StepUpRejected, is ApiOutcome.StepUpRequired -> DeviceLoginAnswer.refusedBy(refusal)
            is ApiOutcome.Validation -> DeviceLoginAnswer.Done(
                if (out.message.contains("pending 2FA", ignoreCase = true)) LoginResult.TwoFactorSessionLost else LoginResult.Failed(out),
            )
            else -> DeviceLoginAnswer.Done(failure(out))
        }
    }

    /**
     * `POST /api/profile/2fa/device-challenge`: a new `login`
     * challenge for the pending login, when the prompt stayed open past 120 s.
     * Needs the explicit header of the key ([deviceKeyId]).
     */
    suspend fun deviceChallenge(deviceKeyId: String): ApiOutcome<DeviceChallenge> {
        if (!DeviceKeyHeader.isValidKeyId(deviceKeyId)) return ApiOutcome.Failure(null, FailureKind.CLIENT, "bad key id")
        return http.call(
            ObliHttp.Method.POST,
            "/api/profile/2fa/device-challenge",
            headers = deviceKeyHeaders(deviceKeyId),
            decode = ::decodeLoginChallenge,
        )
    }

    /**
     * `POST /api/auth/logout`: destroys the server session (the cookie is
     * cleared by the server). With [deviceKeyId] (this phone's key of the
     * session's user) the server also revokes that key (`logout`).
     */
    suspend fun logout(deviceKeyId: String? = null): ApiOutcome<Unit> =
        http.call(ObliHttp.Method.POST, "/api/auth/logout", headers = deviceKeyHeaders(deviceKeyId), decode = ApiJson.ignoreBody)

    private fun step(payload: LoginPayload): LoginResult = when {
        payload.requires2fa -> {
            val challenge = if (payload.methods.device) DeviceChallenge.parse(payload.deviceChallenge)?.takeIf { it.purpose == DevicePurpose.LOGIN } else null
            LoginResult.TwoFactorRequired(payload.methods.copy(device = challenge != null), challenge)
        }
        payload.user != null -> LoginResult.SignedIn(payload.user)
        else -> LoginResult.Failed(ApiResponses.network("unexpected login answer"))
    }

    private fun deviceKeyHeaders(keyId: String?): Map<String, String> =
        if (DeviceKeyHeader.isValidKeyId(keyId)) mapOf(DeviceKeyHeader.NAME to keyId!!) else emptyMap()

    companion object {
        /** `method` of the fingerprint sign-in. */
        const val DEVICE_METHOD = "device"

        /** `{data:{deviceChallenge}}` → a `login` challenge, or null (strict). */
        internal fun decodeLoginChallenge(element: JsonElement?): DeviceChallenge? {
            val data = ApiResponses.unwrap(element) as? JsonObject ?: return null
            return DeviceChallenge.parse(data.obj("deviceChallenge"))?.takeIf { it.purpose == DevicePurpose.LOGIN }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun failure(out: ApiOutcome<*>): LoginResult = when (out) {
        is ApiOutcome.RateLimited -> LoginResult.RateLimited(out.retryAfterSec)
        else -> LoginResult.Failed(out as ApiOutcome<Nothing>)
    }
}
