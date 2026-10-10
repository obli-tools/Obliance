package tools.obli.core.network

/**
 * Typed result of one call to an Obli server. The server
 * guard rails (step-up 2FA, two-person approval, privacy lock) are states, not
 * errors: [tools.obli.core.network.ApiResponses] maps each of them here, and
 * the action runner turns them into sheets (2FA, approval pending, privacy unlock).
 */
sealed interface ApiOutcome<out T> {
    /** 2xx with a decoded payload (204 decodes `null`). */
    data class Ok<T>(val value: T) : ApiOutcome<T>

    /** 202 carrying a payload that is NOT an approval (e.g. scripts/execute: the executions). */
    data class Accepted<T>(val value: T) : ApiOutcome<T>

    /** 202 `{data:{approvalId, status:'pending_approval'}}`: a two-person approval was created. */
    data class PendingApproval(val approvalId: Long) : ApiOutcome<Nothing>

    /**
     * 401 `{twoFactorRequired:true, action, currentIp}`: resend the SAME body with
     * a proof (`twoFactorCode`, or `deviceAssertion` on a bound session). The
     * optional fields come from servers with device-bound validation;
     * older servers leave them out and
     * the defaults keep the old behaviour.
     */
    data class StepUpRequired(
        val action: String?,
        val currentIp: String?,
        /** False on a bound session (and on sites without the shortcut): no "trust this IP" box. */
        val trustIpAllowed: Boolean = true,
        /** Bound session, local account: a code is accepted only with `stepUpPassword`. */
        val codeRequiresPassword: Boolean = false,
        /** Bound session, Obligate account (SSO device keys): re-authenticate with Obligate, then the code. */
        val codeRequiresReauth: Boolean = false,
        val device: DeviceStepUp? = null,
        /**
         * The client's origin, set by [ObliHttp] ONLY when the answer came from
         * that origin; null otherwise (and when classified without a transport).
         * A challenge is never signed without it.
         */
        val origin: String? = null,
    ) : ApiOutcome<Nothing>

    /**
     * 401 `Invalid 2FA code` after a step-up: the code (or the password with
     * it) was refused, the session is fine. [codeUsed] (`codeUsed:true`): the
     * code was right but its 30 s step was already used (the sign-in code, or
     * the same code twice); not counted by the server — wait for the next code.
     */
    data class StepUpRejected(val codeUsed: Boolean = false) : ApiOutcome<Nothing>

    /** 423: privacy mode blocks [feature]; [passwordSet] = unlock goes through the privacy password. */
    data class PrivacyLocked(val feature: String?, val passwordSet: Boolean, val message: String) : ApiOutcome<Nothing>

    /** 409: legacy agent, already handled, not applicable. [message] is the server text. */
    data class Unsupported(val message: String) : ApiOutcome<Nothing>

    data class Forbidden(val reason: ForbiddenReason, val message: String, val capability: String? = null) : ApiOutcome<Nothing>

    /** 503: the agent (or the server-side dependency) is not reachable. */
    data class AgentOffline(val message: String) : ApiOutcome<Nothing>

    /** 401 `Authentication required`: the session cookie is gone or expired (sign in again). */
    data object SessionExpired : ApiOutcome<Nothing>

    /**
     * 429. [codeLocked]: too many wrong codes in 24 h, code entry is locked
     * until a full sign-in (`{error:'Too many verification attempts', codeLocked:true}`).
     */
    data class RateLimited(val retryAfterSec: Int?, val codeLocked: Boolean = false) : ApiOutcome<Nothing>

    /** 400 with `details` (zod `fieldErrors`). */
    data class Validation(val message: String, val fields: Map<String, List<String>>) : ApiOutcome<Nothing>

    data class Failure(val status: Int?, val kind: FailureKind, val message: String? = null) : ApiOutcome<Nothing>
}

enum class ForbiddenReason {
    /** `Capability 'x' not permitted for your team…` (remembered per device and capability). */
    CAPABILITY,

    /** A sensitive action needs TOTP on the profile first. */
    NO_TOTP,

    /** Restricted action with no approval path configured. */
    NO_APPROVAL_PATH,
    OTHER,
}

enum class FailureKind {
    NOT_FOUND,
    SERVER,

    /** A 2xx on an /api/… route that is not JSON (the SPA fallback may answer index.html). */
    NOT_JSON,

    /** Any other 4xx. */
    CLIENT,

    /** No HTTP answer at all (DNS, TLS, timeout, reset). */
    NETWORK,
}

/** Never an automatic replay after these. */
val ApiOutcome<*>.isSuccess: Boolean get() = this is ApiOutcome.Ok || this is ApiOutcome.Accepted

/**
 * `503 {verifierUnavailable:true}`: the second factor could not be checked
 * right now (Obligate unreachable for an Obligate account, SSO device keys). Not an
 * offline agent: « La vérification Obligate est momentanément indisponible ».
 */
val ApiOutcome<*>.isVerifierUnavailable: Boolean
    get() = this is ApiOutcome.Failure && status == 503 && message == ApiResponses.VERIFIER_UNAVAILABLE
