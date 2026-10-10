package tools.obli.core.security

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceError
import tools.obli.core.network.DeviceKeyStatus

/** Safety tiers of a mutating action. */
enum class Tier {
    /** Immediate, no confirmation. */
    T0,

    /** Compact sheet naming the target, one button, no delay. */
    T1,

    /** Sheet + biometric prompt naming the target. */
    T2,

    /** Hold 1.5 s + biometric; bulk ≥ 10 also asks to type the count. */
    T3,
}

/** What a confirmation shows: action, target and where it runs (server › tenant). */
data class ActionSpec(
    val key: String,
    val tier: Tier,
    val title: String,
    val target: String,
    val scope: String,
    val consequence: String? = null,
    /** > 1 for bulk actions: disables the trust window. */
    val targetCount: Int = 1,
    /**
     * Calls the prompts may make on the ITEM'S server (approval pending "Annuler la
     * demande", privacy unlock). Null: those buttons are not offered.
     */
    val endpoints: ActionEndpoints? = null,
    /**
     * Session tenant the action is meant for (device-bound validation): a
     * challenge naming another tenant is never signed (`TENANT_CHANGED`).
     * Null: not checked.
     */
    val tenantId: Long? = null,
    /** Server name, always shown in the fingerprint prompt ("Obliance Prod › ACME"), even with one server. */
    val serverName: String? = null,
)

/**
 * Server calls a prompt may need, bound to the server (and device) the action
 * targets. Built by the app over that server's session, never another origin.
 */
interface ActionEndpoints {
    /** Approval pending: the requester withdraws their own pending approval. */
    suspend fun cancelApproval(approvalId: Long): ApiOutcome<Unit>

    /** Privacy unlock: unlocks [feature] (`scripts`, `remote`, `processes`, `files`) with the device's privacy password. */
    suspend fun unlockPrivacy(feature: String, password: String): PrivacyUnlockResult
}

sealed interface PrivacyUnlockResult {
    data class Unlocked(val ttlSeconds: Int) : PrivacyUnlockResult
    data object WrongPassword : PrivacyUnlockResult

    /** The device has no privacy password: only an administrator can disable privacy mode. */
    data object NoPasswordSet : PrivacyUnlockResult
    data object TooManyAttempts : PrivacyUnlockResult
    data object DeviceOffline : PrivacyUnlockResult
    data object SessionExpired : PrivacyUnlockResult
    data class Failed(val outcome: ApiOutcome<Nothing>) : PrivacyUnlockResult
}

sealed interface Preflight {
    data object Ok : Preflight

    /** Shown as is (offline, privacy, legacy agent, missing right…); nothing is sent. */
    data class Blocked(val reason: String) : Preflight

    /** Action routes are bound to the session tenant: switch first ("Basculer et continuer"). */
    data class NeedsTenantSwitch(val tenantName: String, val switch: suspend () -> Boolean) : Preflight
}

/**
 * The 2FA sheet's answer. [password] (`stepUpPassword`) only in the "password + code"
 * variant of a bound session; it is never kept beyond the action and never
 * printed.
 */
data class TwoFactorAnswer(val code: String, val trustIp: Boolean, val password: String? = null) {
    override fun toString(): String = "TwoFactorAnswer(code=<redacted>, trustIp=$trustIp, password=${if (password == null) "null" else "<redacted>"})"
}

/** How the 2FA sheet must look for this step-up. */
data class TwoFactorOptions(
    /** False: no "trust this IP" box (bound session, or a site without the shortcut). */
    val trustIpAllowed: Boolean = true,
    /** Bound session, local account: a password field above the 6 boxes. */
    val passwordRequired: Boolean = false,
    /**
     * Bound session, Obligate account (`codeRequiresReauth`): the Obligate
     * re-authentication already happened; the 2FA sheet says « Identité reconfirmée,
     * saisissez un NOUVEAU code » (Obligate consumed the step used at its
     * sign-in: that code would get `codeUsed`).
     */
    val reauthRequired: Boolean = false,
    /**
     * The previous code was right but its 30 s step was already used
     * (`401 Invalid 2FA code` + `codeUsed`): the 2FA sheet says « wait for the next
     * code » instead of « wrong code ».
     */
    val previousCodeUsed: Boolean = false,
)

/**
 * What the app knows of the session an answer came from (device-bound
 * validation), for the
 * [ActionSpec]s that leave [ActionSpec.tenantId] / [ActionSpec.serverName]
 * unset: a challenge naming another tenant than the one the app last read for
 * that session is never signed (`TENANT_CHANGED`), and the fingerprint prompt
 * always names the server. Read at the step-up, on the origin of the answer.
 */
interface ActionSessionInfo {
    /** Session tenant of [origin] as the app last read it (`/api/auth/me` `currentTenantId`); null when unknown. */
    fun tenantOf(origin: String): Long?

    /** Display name of the server whose origin is [origin]; null when unknown. */
    fun serverNameOf(origin: String): String?

    /**
     * A challenge of [origin] named another tenant (the session was switched
     * behind the screen: web view, notification): the app reads the session
     * again. Must return at once (launch any work elsewhere).
     */
    fun tenantChanged(origin: String) {}
}

/**
 * Outcome of an Obligate re-authentication (SSO device keys):
 * `/auth/sso-redirect?reauth=1` → Obligate (password + TOTP,
 * even with an Obligate session) → `/auth/callback` → `<return>?reauth=…`,
 * the whole round trip in an in-app web view sharing the session cookie.
 */
sealed interface SsoReauthResult {
    /** Back on `<return>?reauth=ok`: the server recorded a fresh re-authentication of THIS session (5 min, single use for an enrolment). */
    data object Success : SsoReauthResult

    /**
     * Refused. [reason]: the server's code (`no_otp`, `identity`, `stale_auth`,
     * `unsupported`, `verifier_unavailable`, `unreachable`, `origin`, `expired`,
     * `signed_out`, `state`, `exchange`, `not_sso`, `misconfigured`, `error`…)
     * or the app's (`blocked`, `login`, `unexpected`, `page_error`, `tls`, `config`).
     */
    data class Failed(val reason: String) : SsoReauthResult {
        /** The server session ended meanwhile: sign in again (sign-in-again screen), not an Obligate problem. */
        val endsSession: Boolean get() = endsSession(reason)

        companion object {
            /** The server's `signed_out`; the app's `login` (the server sent the sheet to /login: no session). */
            fun endsSession(reason: String): Boolean = reason == SIGNED_OUT || reason == LOGIN

            /**
             * False for the failures a new attempt cannot fix: no OTP at
             * Obligate, not an Obligate account, SSO device keys off, a misconfigured
             * server, the wrong address, a foreign page, a bad certificate,
             * an ended session. The sheet then offers « Fermer » only, and
             * the profile security screen no « Reconfirmer ».
             */
            fun canRetry(reason: String): Boolean = reason !in FINAL

            const val SIGNED_OUT = "signed_out"
            const val LOGIN = "login"
            private val FINAL = setOf("no_otp", "not_sso", "unsupported", "misconfigured", "origin", SIGNED_OUT, LOGIN, "blocked", "tls")
        }
    }

    /** Closed by the user, or nothing can show the sheet (fail closed): nothing happened. */
    data object Cancelled : SsoReauthResult
}

/** The UI host (root Compose host) implements the prompts: confirmation, 2FA, approval pending and privacy unlock sheets, the sign-in-again screen, the fingerprint. */
interface ActionPrompter {
    suspend fun confirmTenantSwitch(spec: ActionSpec, tenantName: String): Boolean

    /** Tier-appropriate confirmation (T1 sheet, T2 biometric, T3 hold + biometric). */
    suspend fun confirm(spec: ActionSpec): Boolean

    /** The 2FA sheet; [previousWasWrong] after a rejected code. Null = cancelled. */
    suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean): TwoFactorAnswer?

    /**
     * The 2FA sheet in the variant [options] asks for. The default serves the
     * prompters written before device-bound validation: they cannot ask for a
     * password, so a "password + code" step-up is cancelled, and the IP box
     * answer is dropped when it is not allowed.
     */
    suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean, options: TwoFactorOptions): TwoFactorAnswer? {
        if (options.passwordRequired) return null
        val answer = askTwoFactor(spec, currentIp, previousWasWrong) ?: return null
        return if (options.trustIpAllowed) answer else answer.copy(trustIp = false)
    }

    /** Approval pending: the request is waiting for a second person. */
    suspend fun approvalRequested(spec: ActionSpec, approvalId: Long)

    /** Privacy unlock: returns true when the device was unlocked and one retry may be made. */
    suspend fun unlockPrivacy(spec: ActionSpec, feature: String?, passwordSet: Boolean): Boolean

    /** The sign-in-again screen over the current screen. The action is NEVER replayed afterwards. */
    suspend fun sessionExpired()

    /**
     * The fingerprint prompt for [request] (one or N challenges), whose texts
     * the host builds from [spec] and the challenge (action, target, "server ›
     * tenant"). Default: no signer ([SignResult.Unavailable]), the code is used.
     */
    suspend fun signStepUp(spec: ActionSpec, request: DeviceSignRequest): SignResult = SignResult.Unavailable("no signer")

    /**
     * The key of [origin] was invalidated (new biometric, screen lock removed):
     * report it to the server, purge the key, clear the origin's cookie, show
     * the sign-in-again screen. The runner then returns [ActionResult.SessionExpired].
     */
    suspend fun deviceKeyInvalidated(origin: String, keyId: String) {}

    /**
     * SSO device keys: re-authenticates the
     * session of [origin] with Obligate (password + TOTP there), before a
     * code in a bound session of an Obligate account. [spec]: the action it
     * is for (the host may name it). The default fails closed: no prompt,
     * [SsoReauthResult.Cancelled].
     */
    suspend fun reauthenticateSso(origin: String, spec: ActionSpec? = null): SsoReauthResult = SsoReauthResult.Cancelled

    /**
     * A 6-digit code was accepted on [origin] (the action went through) while
     * the session is not bound to a key of this phone (the step-up carried no
     * device part): the host may propose « Utiliser l'empreinte la prochaine
     * fois ? ». Informative, called once per run, never blocks the result;
     * must return at once (launch any work elsewhere).
     */
    fun codeAccepted(spec: ActionSpec, origin: String) {}
}

sealed interface ActionResult<out T> {
    data class Done<T>(val value: T) : ActionResult<T>
    data class AwaitingApproval(val approvalId: Long) : ActionResult<Nothing>
    data object Cancelled : ActionResult<Nothing>
    data class Blocked(val reason: String) : ActionResult<Nothing>
    data object SessionExpired : ActionResult<Nothing>

    /** Any other server answer (403, 409, 503, network…), to be explained by the screen. */
    data class Failed(val outcome: ApiOutcome<Nothing>) : ActionResult<Nothing>
}

/**
 * The single path of every call that changes something:
 * preflight → local tier → call → server guard rails, in this order:
 * `401 twoFactorRequired` → the fingerprint when the server sent a challenge
 * for this phone's key (at most 2 signatures), else the 2FA sheet, and the SAME body
 * again with the proof (3 codes); `202 pending_approval` → approval pending sheet, never a
 * success; `423` → privacy unlock sheet and one retry; `401` session → sign in again, never replayed.
 * No automatic retry otherwise.
 *
 * Proofs: each resend carries ONE kind
 * of proof — an assertion never travels with a code; `deviceBulkId` is
 * kept; the password lives only in the local `extra` of this run.
 */
class ActionRunner(
    private val prompter: ActionPrompter,
    /** The key of (origin, user of the session on that origin). Null: never sign, always the code. */
    private val deviceKeys: DeviceKeyResolver?,
    private val clock: () -> Long = System::currentTimeMillis,
    /** Session tenant and server name per origin, for specs that do not set them. Null: not checked. */
    private val sessionInfo: ActionSessionInfo? = null,
) {
    /**
     * Without device keys (the code only). Keeps the source of every existing
     * call: `ActionRunner(prompter)`, `ActionRunner(prompter, clock)` and
     * `ActionRunner(prompter) { now }` (the trailing lambda is the clock).
     */
    constructor(prompter: ActionPrompter, clock: () -> Long = System::currentTimeMillis) : this(prompter, null, clock)

    @Volatile private var lastStrongConfirmAt: Long? = null

    suspend fun <T> run(
        spec: ActionSpec,
        preflight: suspend () -> Preflight = { Preflight.Ok },
        call: suspend (extra: JsonObject) -> ApiOutcome<T>,
    ): ActionResult<T> {
        when (val p = preflight()) {
            is Preflight.Blocked -> return ActionResult.Blocked(p.reason)
            is Preflight.NeedsTenantSwitch -> {
                if (!prompter.confirmTenantSwitch(spec, p.tenantName)) return ActionResult.Cancelled
                if (!p.switch()) return ActionResult.Blocked(TENANT_SWITCH_FAILED)
            }
            Preflight.Ok -> Unit
        }

        if (spec.tier != Tier.T0 && !withinTrustWindow(spec)) {
            if (!prompter.confirm(spec)) return ActionResult.Cancelled
            if (spec.tier == Tier.T2) lastStrongConfirmAt = clock()
        }

        var extra = JsonObject(emptyMap())
        var codeAttempts = 0
        var wrongCode = false
        var codeUsed = false
        var privacyRetried = false
        var signAttempts = 0
        var preferCode = false
        var lastStepUp: ApiOutcome.StepUpRequired? = null
        while (true) {
            when (val out = call(extra)) {
                is ApiOutcome.Ok -> {
                    codeWasAccepted(spec, extra, lastStepUp)
                    return ActionResult.Done(out.value)
                }
                is ApiOutcome.Accepted -> {
                    codeWasAccepted(spec, extra, lastStepUp)
                    return ActionResult.Done(out.value)
                }
                is ApiOutcome.PendingApproval -> {
                    prompter.approvalRequested(spec, out.approvalId)
                    return ActionResult.AwaitingApproval(out.approvalId)
                }
                is ApiOutcome.StepUpRequired, is ApiOutcome.StepUpRejected -> {
                    var askReauth = false
                    if (out is ApiOutcome.StepUpRequired) {
                        lastStepUp = out
                        askReauth = out.codeRequiresReauth
                        val device = out.device
                        // A refused assertion or a throttled session → the code.
                        if (device != null && (device.status == DeviceKeyStatus.THROTTLED || device.error == DeviceError.INVALID_ASSERTION || device.error == DeviceError.OTHER)) {
                            preferCode = true
                        }
                        val challenge = device?.challenge?.takeIf { device.status == DeviceKeyStatus.ACTIVE }
                        if (challenge != null && !preferCode && signAttempts < MAX_SIGN_ATTEMPTS) {
                            when (val d = signable(spec, out.origin, challenge)) {
                                Signable.TenantChanged -> {
                                    tenantChanged(out.origin)
                                    return ActionResult.Blocked(TENANT_CHANGED)
                                }
                                Signable.No -> preferCode = true
                                is Signable.Yes -> {
                                    signAttempts++
                                    val request = try {
                                        DeviceSignRequest.stepUp(d.origin, d.record, listOf(challenge))
                                    } catch (_: IllegalArgumentException) {
                                        null
                                    }
                                    val promptSpec = sessionInfo.promptSpec(spec, d.origin)
                                    when (val signed = request?.let { prompter.signStepUp(promptSpec, it) } ?: SignResult.Unavailable("payload")) {
                                        is SignResult.Signed -> {
                                            extra = buildJsonObject {
                                                withoutProofs(extra).forEach { (k, v) -> put(k, v) }
                                                put(DeviceAssertion.FIELD, request!!.assertion(signed.der).toJson())
                                            }
                                            continue
                                        }
                                        SignResult.UseCode, SignResult.LockedOut, is SignResult.Unavailable -> preferCode = true
                                        SignResult.Cancelled -> return ActionResult.Cancelled
                                        SignResult.Invalidated -> {
                                            prompter.deviceKeyInvalidated(d.origin, d.record.keyId)
                                            return ActionResult.SessionExpired
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        wrongCode = true
                        codeUsed = (out as? ApiOutcome.StepUpRejected)?.codeUsed == true
                    }

                    // The code (2FA sheet), in the variant the last step-up asked for.
                    if (codeAttempts >= MAX_CODE_ATTEMPTS) return ActionResult.Failed(ApiOutcome.StepUpRejected(codeUsed))
                    val step = lastStepUp
                    val options = TwoFactorOptions(
                        trustIpAllowed = step?.trustIpAllowed ?: true,
                        passwordRequired = step?.codeRequiresPassword ?: false,
                        reauthRequired = step?.codeRequiresReauth ?: false,
                        previousCodeUsed = codeUsed,
                    )
                    if (askReauth) {
                        // Re-authentication happens on the client's origin only.
                        val origin = step?.origin ?: return ActionResult.Failed(step ?: ApiOutcome.StepUpRejected())
                        when (val r = prompter.reauthenticateSso(origin, spec)) {
                            SsoReauthResult.Success -> Unit
                            SsoReauthResult.Cancelled -> return ActionResult.Cancelled
                            is SsoReauthResult.Failed -> {
                                // The session ended meanwhile: sign in again, as every expired session (never replayed).
                                if (r.endsSession) {
                                    prompter.sessionExpired()
                                    return ActionResult.SessionExpired
                                }
                                // Reported (the sheet already said why), never a silent cancel; nothing was sent.
                                return ActionResult.Blocked(SSO_REAUTH_FAILED)
                            }
                        }
                    }
                    val ip = (out as? ApiOutcome.StepUpRequired)?.currentIp
                    val answer = prompter.askTwoFactor(spec, ip, wrongCode, options) ?: return ActionResult.Cancelled
                    codeAttempts++
                    val password = answer.password?.takeIf { options.passwordRequired && it.isNotEmpty() }
                    extra = buildJsonObject {
                        withoutProofs(extra).forEach { (k, v) -> put(k, v) }
                        put(CODE, JsonPrimitive(answer.code.trim()))
                        if (password != null) put(PASSWORD, JsonPrimitive(password))
                        if (answer.trustIp && options.trustIpAllowed && !options.passwordRequired) put(TRUST_IP, JsonPrimitive(true))
                    }
                }
                is ApiOutcome.PrivacyLocked -> {
                    if (privacyRetried || !prompter.unlockPrivacy(spec, out.feature, out.passwordSet)) {
                        return ActionResult.Failed(out)
                    }
                    privacyRetried = true
                }
                ApiOutcome.SessionExpired -> {
                    prompter.sessionExpired()
                    return ActionResult.SessionExpired
                }
                is ApiOutcome.Unsupported -> return ActionResult.Failed(out)
                is ApiOutcome.Forbidden -> return ActionResult.Failed(out)
                is ApiOutcome.AgentOffline -> return ActionResult.Failed(out)
                is ApiOutcome.RateLimited -> return ActionResult.Failed(out)
                is ApiOutcome.Validation -> return ActionResult.Failed(out)
                is ApiOutcome.Failure -> return ActionResult.Failed(out)
            }
        }
    }

    /**
     * A loop of ONE request per target with the SAME action:
     * preflight and the local tier
     * once, then [BulkStepUp] — first pass with `deviceBulkId`, ONE
     * fingerprint for up to 50 challenges, second pass with the same
     * assertion; else ONE code for the rest of the loop. [call] builds the
     * SAME body for a target on every send and merges `extra` into it. Give
     * [spec] the loop's `targetCount`. Per-target answers (including
     * `202 pending_approval` and `423`, which get no approval / privacy sheet here) are in
     * the [BulkReport]; an expired session ends the run (sign in again, never replayed).
     */
    suspend fun <K, T> runBulk(
        spec: ActionSpec,
        targets: List<K>,
        preflight: suspend () -> Preflight = { Preflight.Ok },
        bulkId: String = java.util.UUID.randomUUID().toString(),
        call: suspend (target: K, extra: JsonObject) -> ApiOutcome<T>,
    ): ActionResult<BulkReport<K, T>> {
        if (targets.isEmpty()) return ActionResult.Done(BulkReport(emptyMap()))
        when (val p = preflight()) {
            is Preflight.Blocked -> return ActionResult.Blocked(p.reason)
            is Preflight.NeedsTenantSwitch -> {
                if (!prompter.confirmTenantSwitch(spec, p.tenantName)) return ActionResult.Cancelled
                if (!p.switch()) return ActionResult.Blocked(TENANT_SWITCH_FAILED)
            }
            Preflight.Ok -> Unit
        }
        if (spec.tier != Tier.T0 && !withinTrustWindow(spec)) {
            if (!prompter.confirm(spec)) return ActionResult.Cancelled
            if (spec.tier == Tier.T2) lastStrongConfirmAt = clock()
        }
        return BulkStepUp(prompter, deviceKeys, { bulkId }, sessionInfo).run(spec, targets, call)
    }

    private fun tenantChanged(origin: String?) {
        if (origin == null) return
        try {
            sessionInfo?.tenantChanged(origin)
        } catch (_: RuntimeException) {
            // Informative: the action is refused either way.
        }
    }

    private sealed interface Signable {
        data class Yes(val origin: String, val record: DeviceKeyRecord) : Signable
        data object No : Signable
        data object TenantChanged : Signable
    }

    /**
     * The answer came from the client's origin, the challenge
     * names the key of (origin, user of the session), and its tenant is the
     * action's (or, when the spec does not say, the session tenant the app
     * last read for that origin) when both are known.
     */
    private fun signable(spec: ActionSpec, origin: String?, challenge: DeviceChallenge): Signable {
        if (origin == null) return Signable.No
        val record = try {
            deviceKeys?.keyFor(origin)
        } catch (_: RuntimeException) {
            null
        } ?: return Signable.No
        if (record.origin != origin || challenge.userId != record.userId || challenge.keyId != record.keyId) return Signable.No
        val expected = sessionInfo.expectedTenant(spec, origin)
        if (expected != null && challenge.tenantId != null && expected != challenge.tenantId) return Signable.TenantChanged
        return Signable.Yes(origin, record)
    }

    /**
     * The first-2FA proposal (A3): the success followed a code, on an answer
     * of the client's origin whose step-up had no device part (session not
     * bound, no header of a key of this phone), and no key is known locally.
     */
    private fun codeWasAccepted(spec: ActionSpec, extra: JsonObject, step: ApiOutcome.StepUpRequired?) {
        if (CODE !in extra || step == null || step.device != null) return
        val origin = step.origin ?: return
        val known = try {
            deviceKeys?.keyFor(origin)
        } catch (_: RuntimeException) {
            null
        }
        if (known != null) return
        try {
            prompter.codeAccepted(spec, origin)
        } catch (_: RuntimeException) {
            // Informative only: never changes the result of the action.
        }
    }

    /** 60 s after a successful T2 biometric, later T2 on single targets skip the prompt. */
    private fun withinTrustWindow(spec: ActionSpec): Boolean {
        if (spec.tier != Tier.T2 || spec.targetCount > 1) return false
        val at = lastStrongConfirmAt ?: return false
        return clock() - at in 0 until TRUST_WINDOW_MS
    }

    companion object {
        const val MAX_CODE_ATTEMPTS = 3

        /** One signature, and one more after `challenge_expired` (2 contacts per action at most). */
        const val MAX_SIGN_ATTEMPTS = 2
        const val TRUST_WINDOW_MS = 60_000L

        /** [ActionResult.Blocked] reason when "Basculer et continuer" could not switch the tenant. */
        const val TENANT_SWITCH_FAILED = "tenant switch failed"

        /** [ActionResult.Blocked] reason when the challenge names another tenant than the action's. */
        const val TENANT_CHANGED = "tenant changed"

        /**
         * [ActionResult.Blocked] reason (and, in a bulk report, the failure of
         * the targets not sent) when the Obligate re-authentication a code
         * needed was refused (SSO device keys). The action was not run.
         */
        const val SSO_REAUTH_FAILED = "sso reauth failed"

        const val CODE = "twoFactorCode"
        const val TRUST_IP = "trustIp"
        const val PASSWORD = "stepUpPassword"
        const val BULK_ID = "deviceBulkId"

        /** The proof fields a resend replaces (`deviceBulkId` is kept: it is not a proof of the user). */
        val PROOF_FIELDS = setOf(CODE, TRUST_IP, PASSWORD, DeviceAssertion.FIELD)

        /** `base`: [extra] without any proof. */
        fun withoutProofs(extra: JsonObject): JsonObject = JsonObject(extra.filterKeys { it !in PROOF_FIELDS })
    }
}

/**
 * The tenant a challenge must name for [spec] on [origin]: the spec's own
 * ([ActionSpec.tenantId], e.g. the item's tenant), else the session tenant
 * the app last read there; null when neither is known (not checked).
 */
internal fun ActionSessionInfo?.expectedTenant(spec: ActionSpec, origin: String): Long? {
    spec.tenantId?.let { return it }
    return try {
        this?.tenantOf(origin)
    } catch (_: RuntimeException) {
        null
    }
}

/**
 * [spec] as the fingerprint prompt shows it: the server always named
 * ([ActionSpec.serverName], else the server of [origin]) and the expected
 * tenant filled in. The tenant NAME of the prompt is the server's (the
 * challenge's), never the screen's.
 */
internal fun ActionSessionInfo?.promptSpec(spec: ActionSpec, origin: String): ActionSpec {
    val server = spec.serverName ?: try {
        this?.serverNameOf(origin)
    } catch (_: RuntimeException) {
        null
    }
    return spec.copy(serverName = server, tenantId = expectedTenant(spec, origin))
}
