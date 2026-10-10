package tools.obli.core.security.ui

import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import tools.obli.core.network.ApiOutcome
import tools.obli.core.security.ActionPrompter
import tools.obli.core.security.ActionSpec
import tools.obli.core.security.DeviceSignPrompts
import tools.obli.core.security.DeviceSignRequest
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.PrivacyUnlockResult
import tools.obli.core.security.SignPromptTexts
import tools.obli.core.security.SignResult
import tools.obli.core.security.SsoReauthResult
import tools.obli.core.security.Tier
import tools.obli.core.security.TwoFactorAnswer
import tools.obli.core.security.TwoFactorOptions

/**
 * The strong authentication step of T2 and T3: biometric
 * (BIOMETRIC_STRONG) or the device credential, whose subtitle names the
 * target and the scope. [isAvailable] is false when the device has no screen
 * lock: the confirmation sheet is then the only step, and it says so.
 */
interface StrongAuthenticator {
    fun isAvailable(): Boolean

    /** True when the user authenticated; false when cancelled or failed. */
    suspend fun authenticate(spec: ActionSpec): Boolean

    /** No screen lock / no activity able to host the prompt. */
    object None : StrongAuthenticator {
        override fun isAvailable() = false
        override suspend fun authenticate(spec: ActionSpec) = false
    }
}

/**
 * One prompt of the [ActionPrompter] waiting for the user (confirmation, 2FA, approval pending, privacy unlock and the
 * tenant switch). Each carries its answer as a [CompletableDeferred]; the
 * observable fields are the sheet's own state (typed count, code…), hoisted
 * here so the state machine is unit-testable without a UI.
 */
sealed class ActionPrompt(val spec: ActionSpec) {
    /** "Pour agir sur X, Obliance doit passer sur le tenant Y." */
    class TenantSwitch internal constructor(spec: ActionSpec, val tenantName: String) : ActionPrompt(spec) {
        internal val reply = CompletableDeferred<Boolean>()
    }

    /** Confirmation sheet per tier: T1 sheet, T2 sheet + biometric, T3 hold (or two buttons) + biometric, bulk ≥ 10 types the count. */
    class Confirm internal constructor(
        spec: ActionSpec,
        /** False when no screen lock is set: the sheet alone confirms, and says so. */
        val strongAuthAvailable: Boolean,
        /** TalkBack or switch access: the 1.5 s hold becomes a second "Confirmer définitivement" button. */
        val accessible: Boolean,
    ) : ActionPrompt(spec) {
        internal val reply = CompletableDeferred<Boolean>()
        var typedCount by mutableStateOf("")
        var armed by mutableStateOf(false)
            internal set
        var authenticating by mutableStateOf(false)
            internal set
        var authFailed by mutableStateOf(false)
            internal set

        val strong: Boolean get() = spec.tier == Tier.T2 || spec.tier == Tier.T3
        val needsCount: Boolean get() = spec.tier == Tier.T3 && spec.targetCount >= BULK_COUNT_THRESHOLD
        val countOk: Boolean get() = !needsCount || typedCount.trim() == spec.targetCount.toString()
        val usesHold: Boolean get() = spec.tier == Tier.T3 && !accessible
    }

    /**
     * 2FA sheet: 6-digit code, "trust this IP", error after a wrong code. In the
     * "password + code" variant of a bound session ([options]
     * `passwordRequired`) the account password is asked above the boxes and
     * the IP box is never shown; it is also hidden when the server does not
     * allow the shortcut (`trustIpAllowed` false).
     */
    class TwoFactor internal constructor(
        spec: ActionSpec,
        val currentIp: String?,
        val previousWasWrong: Boolean,
        val options: TwoFactorOptions = TwoFactorOptions(),
    ) : ActionPrompt(spec) {
        internal val reply = CompletableDeferred<TwoFactorAnswer?>()
        var code by mutableStateOf("")
        var trustIp by mutableStateOf(false)

        /** The account password (`stepUpPassword`): only in the password variant, cleared once answered. */
        var password by mutableStateOf("")

        val passwordRequired: Boolean get() = options.passwordRequired

        /** The previous code was right but already used (`codeUsed`): « wait for the next code », not « wrong code ». */
        val codeUsed: Boolean get() = previousWasWrong && options.previousCodeUsed
        val showTrustIp: Boolean get() = options.trustIpAllowed && !options.passwordRequired
        val codeComplete: Boolean get() = code.trim().let { it.length == ActionHostState.CODE_LENGTH && it.all(Char::isDigit) }
        val canSubmit: Boolean get() = codeComplete && (!passwordRequired || password.isNotEmpty())
    }

    /**
     * 2FA sheet, Obligate variant (SSO device keys, `codeRequiresReauth`): before a code, the
     * user re-confirms with Obligate. « Sur ce téléphone, la validation se
     * fait par empreinte… » + « Reconfirmer avec Obligate » (true) / Annuler.
     */
    class SsoReauth internal constructor(spec: ActionSpec) : ActionPrompt(spec) {
        internal val reply = CompletableDeferred<Boolean>()
    }

    /** Approval pending: waiting for a second person; never shown as a success. */
    class ApprovalSent internal constructor(spec: ActionSpec, val approvalId: Long) : ActionPrompt(spec) {
        internal val reply = CompletableDeferred<Unit>()
        var cancel by mutableStateOf(CancelState.IDLE)
            internal set
    }

    /** Privacy unlock: privacy mode blocks [feature]; unlock with the device's privacy password. */
    class PrivacyUnlock internal constructor(spec: ActionSpec, val feature: String?, val passwordSet: Boolean) : ActionPrompt(spec) {
        internal val reply = CompletableDeferred<Boolean>()
        var selectedFeature by mutableStateOf(feature ?: PRIVACY_FEATURES.first())
        var password by mutableStateOf("")
        var busy by mutableStateOf(false)
            internal set
        var error by mutableStateOf<PrivacyUnlockResult?>(null)
            internal set

        /**
         * The unlock route needs a feature and an endpoint on the item's server.
         * Without a feature (raw "disable privacy mode" refused because a
         * password is set) there is nothing to unlock here.
         */
        val canUnlock: Boolean get() = spec.endpoints != null && feature != null && error != PrivacyUnlockResult.NoPasswordSet
    }

    enum class CancelState { IDLE, CANCELLING, CANCELLED, FAILED }

    companion object {
        /** Bulk T3 actions on this many targets or more ask to type the count. */
        const val BULK_COUNT_THRESHOLD = 10

        /** Features of the server privacy gate (privacyGate.service.ts featureForCommand). */
        val PRIVACY_FEATURES = listOf("scripts", "remote", "processes", "files")
    }
}

/**
 * The [ActionPrompter] of the root host: each prompt is
 * published on [prompt] (a StateFlow, i.e. a SharedFlow replaying the current
 * prompt) and suspends on its [CompletableDeferred] until the sheet answers.
 * Prompts are serialised: two actions never show two sheets at once. A
 * prompt whose action is cancelled (screen left) disappears.
 */
@Stable
class ActionHostState(
    private val authenticator: StrongAuthenticator = StrongAuthenticator.None,
    private val accessibilityMode: () -> Boolean = { false },
    private val onSessionExpired: suspend () -> Unit = {},
    /**
     * Device-bound validation: the
     * fingerprint signer ([BiometricDeviceSigner]) and the texts of its prompt.
     * Without them, a step-up challenge is never signed: the code is used.
     */
    private val deviceSigner: DeviceSigner? = null,
    private val signTexts: SignPromptTexts? = null,
    /**
     * A signature found this phone's key of [origin] dead: the app
     * reports it, purges the key, clears the origin's cookie and shows the sign-in-again screen
     * (core:security `DeviceKeyMaintenance.invalidated`).
     */
    private val onDeviceKeyInvalidated: suspend (origin: String, keyId: String) -> Unit = { _, _ -> },
    /**
     * SSO device keys: the Obligate re-authentication sheet of [origin] (before a code
     * in a bound session of an Obligate account). Null (previews, tests, an
     * app without the sheet): fail closed, [SsoReauthResult.Cancelled] and no prompt.
     */
    private val onReauthenticateSso: (suspend (origin: String) -> SsoReauthResult)? = null,
    /**
     * A code went through on [origin] while this phone has no key there: the
     * app may propose « Utiliser l'empreinte la prochaine fois ? ».
     * Must return at once.
     */
    private val onCodeAccepted: (origin: String) -> Unit = {},
) : ActionPrompter {
    private val mutex = Mutex()
    private val _prompt = MutableStateFlow<ActionPrompt?>(null)

    /** The prompt on screen, null when none. */
    val prompt: StateFlow<ActionPrompt?> = _prompt.asStateFlow()

    /** The step-up IP of the last 2FA prompt: the retry after a wrong code does not carry it. */
    private var lastIp: Pair<ActionSpec, String>? = null

    private suspend fun <R> show(p: ActionPrompt, reply: CompletableDeferred<R>, abort: R): R = mutex.withLock {
        _prompt.value = p
        try {
            reply.await()
        } finally {
            reply.complete(abort)
            _prompt.compareAndSet(p, null)
        }
    }

    override suspend fun confirmTenantSwitch(spec: ActionSpec, tenantName: String): Boolean =
        TenantSwitch(spec, tenantName).let { show(it, it.reply, false) }

    override suspend fun confirm(spec: ActionSpec): Boolean =
        ActionPrompt.Confirm(spec, authenticator.isAvailable(), accessibilityMode()).let { show(it, it.reply, false) }

    override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean): TwoFactorAnswer? =
        askTwoFactor(spec, currentIp, previousWasWrong, TwoFactorOptions())

    /** The 2FA sheet in the variant the step-up asked for: password + code on a bound session, no IP box when not allowed. */
    override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean, options: TwoFactorOptions): TwoFactorAnswer? {
        val ip = currentIp ?: lastIp?.takeIf { it.first == spec }?.second
        if (ip != null) lastIp = spec to ip
        val p = ActionPrompt.TwoFactor(spec, ip, previousWasWrong, options)
        return try {
            show(p, p.reply, null)
        } finally {
            p.password = "" // never kept by the sheet beyond its answer
        }
    }

    /**
     * The fingerprint for [request]: a system BiometricPrompt
     * (BIOMETRIC_STRONG only, "Utiliser un code" as negative button) whose
     * texts are built here from the action and the challenge. One prompt at a
     * time, like the sheets.
     */
    override suspend fun signStepUp(spec: ActionSpec, request: DeviceSignRequest): SignResult {
        val signer = deviceSigner ?: return SignResult.Unavailable(NO_SIGNER)
        val texts = signTexts ?: return SignResult.Unavailable(NO_SIGNER)
        val prompt = DeviceSignPrompts.stepUp(spec, request, texts)
        return mutex.withLock { signer.sign(request.record, request.payload, prompt) }
    }

    override suspend fun deviceKeyInvalidated(origin: String, keyId: String) = onDeviceKeyInvalidated(origin, keyId)

    /**
     * SSO device keys: the 2FA sheet explains first (« …reconfirmez d'abord votre identité auprès
     * d'Obligate », [ActionPrompt.SsoReauth]), then the app's Obligate sheet.
     * Without a sheet: [SsoReauthResult.Cancelled] at once.
     */
    override suspend fun reauthenticateSso(origin: String, spec: ActionSpec?): SsoReauthResult {
        val sheet = onReauthenticateSso ?: return SsoReauthResult.Cancelled
        if (spec != null) {
            val intro = ActionPrompt.SsoReauth(spec)
            if (!show(intro, intro.reply, false)) return SsoReauthResult.Cancelled
        }
        return sheet(origin)
    }

    override fun codeAccepted(spec: ActionSpec, origin: String) = onCodeAccepted(origin)

    override suspend fun approvalRequested(spec: ActionSpec, approvalId: Long) =
        ActionPrompt.ApprovalSent(spec, approvalId).let { show(it, it.reply, Unit) }

    override suspend fun unlockPrivacy(spec: ActionSpec, feature: String?, passwordSet: Boolean): Boolean =
        ActionPrompt.PrivacyUnlock(spec, feature, passwordSet).let { show(it, it.reply, false) }

    override suspend fun sessionExpired() = onSessionExpired()

    // --- Answers from the sheets ----------------------------------------------

    /** Annuler / back / swipe down: the negative answer of the current prompt. */
    fun cancel() {
        when (val p = _prompt.value) {
            is TenantSwitch -> p.reply.complete(false)
            is ActionPrompt.Confirm -> if (!p.authenticating) p.reply.complete(false)
            is ActionPrompt.TwoFactor -> {
                p.password = ""
                p.reply.complete(null)
            }
            is ActionPrompt.SsoReauth -> p.reply.complete(false)
            is ActionPrompt.ApprovalSent -> p.reply.complete(Unit)
            is ActionPrompt.PrivacyUnlock -> p.reply.complete(false)
            null -> Unit
        }
    }

    fun switchTenant(p: TenantSwitch) {
        p.reply.complete(true)
    }

    /** « Reconfirmer avec Obligate »: the app's Obligate sheet opens next. */
    fun startSsoReauth(p: ActionPrompt.SsoReauth) {
        p.reply.complete(true)
    }

    /**
     * The confirm button (T1, T2), the end of the hold (T3), or "Confirmer
     * définitivement" (T3 accessible). A strong tier then asks for the
     * biometric; a cancelled biometric keeps the sheet open (retry or cancel).
     */
    suspend fun accept(p: ActionPrompt.Confirm) {
        if (p.reply.isCompleted || p.authenticating || !p.countOk) return
        if (p.spec.tier == Tier.T3 && p.accessible && !p.armed) {
            p.armed = true
            return
        }
        if (p.strong && p.strongAuthAvailable) {
            p.authenticating = true
            p.authFailed = false
            val ok = try {
                authenticator.authenticate(p.spec)
            } finally {
                p.authenticating = false
            }
            if (!ok) {
                p.authFailed = true
                return
            }
        }
        p.reply.complete(true)
    }

    /**
     * "Valider" (or the 6th digit): the code, the IP box only where it is
     * shown, the password only in the password variant (then required).
     */
    fun submitCode(p: ActionPrompt.TwoFactor) {
        if (!p.canSubmit) return
        val answer = TwoFactorAnswer(
            code = p.code.trim(),
            trustIp = p.trustIp && p.showTrustIp,
            password = p.password.takeIf { p.passwordRequired },
        )
        p.password = ""
        p.reply.complete(answer)
    }

    fun acknowledge(p: ActionPrompt.ApprovalSent) {
        p.reply.complete(Unit)
    }

    /** "Annuler la demande" of the approval pending sheet, on the item's server. */
    suspend fun cancelApproval(p: ActionPrompt.ApprovalSent) {
        val endpoints = p.spec.endpoints ?: return
        if (p.cancel == ActionPrompt.CancelState.CANCELLING || p.cancel == ActionPrompt.CancelState.CANCELLED) return
        p.cancel = ActionPrompt.CancelState.CANCELLING
        p.cancel = when (endpoints.cancelApproval(p.approvalId)) {
            is ApiOutcome.Ok, is ApiOutcome.Accepted -> ActionPrompt.CancelState.CANCELLED
            else -> ActionPrompt.CancelState.FAILED
        }
    }

    /** "Déverrouiller" of the privacy unlock sheet: one unlock request; true answer (one retry of the action) only once unlocked. */
    suspend fun unlock(p: ActionPrompt.PrivacyUnlock) {
        val endpoints = p.spec.endpoints ?: return
        if (p.busy || p.password.isEmpty() || !p.canUnlock) return
        p.busy = true
        p.error = null
        val result = try {
            endpoints.unlockPrivacy(p.selectedFeature, p.password)
        } finally {
            p.busy = false
        }
        if (result is PrivacyUnlockResult.Unlocked) {
            p.reply.complete(true)
            return
        }
        p.error = result
        if (result == PrivacyUnlockResult.WrongPassword) p.password = ""
        if (result == PrivacyUnlockResult.SessionExpired) {
            p.reply.complete(false)
            onSessionExpired()
        }
    }

    companion object {
        const val CODE_LENGTH = 6

        /** [SignResult.Unavailable] reason when the host has no fingerprint signer. */
        const val NO_SIGNER = "no signer"
    }
}

private typealias TenantSwitch = ActionPrompt.TenantSwitch
