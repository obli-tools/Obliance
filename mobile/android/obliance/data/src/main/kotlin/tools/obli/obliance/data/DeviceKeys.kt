package tools.obli.obliance.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import tools.obli.core.model.ServerId
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.FailureKind
import tools.obli.core.security.DeviceKeyHardware
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.DeviceKeyRecord
import tools.obli.core.security.DeviceKeyResolver
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.EnrolProof
import tools.obli.core.security.SignPrompt
import tools.obli.obliance.api.DeviceKeyList

// ---------------------------------------------------------------------------
// « Validation par empreinte »:
// the state of THIS phone on each server, one key per (server, user).
// ---------------------------------------------------------------------------

/** What the profile and security screen shows for one server, in the order the checks are made. */
sealed interface DeviceKeyServerState {
    /** Not read yet. */
    data object Loading : DeviceKeyServerState

    /** Nobody is signed in on this server (or the session expired): sign in first. */
    data object SignedOut : DeviceKeyServerState

    /** `GET /api/profile/device-keys` 404: the server predates the feature (state `notAvailable`). */
    data object NotAvailable : DeviceKeyServerState

    /** `policy.enabled` false (state `disabledByAdmin`). A key of this phone may still exist: « Désactiver sur ce téléphone ». */
    data class DisabledByAdmin(val record: DeviceKeyRecord? = null) : DeviceKeyServerState

    /** `policy.originConfigured` false: no APP_URL / DEVICE_KEY_ORIGINS (state `originUnset`). */
    data object OriginUnset : DeviceKeyServerState

    /** The app's address of this server is not among the server's allowed origins (or is not ASCII). */
    data class OriginMismatch(val origin: String) : DeviceKeyServerState

    /**
     * Obligate account, and the server does not support it (SSO device keys off:
     * `policy.ssoSupported` false; state `ssoUnsupported`) or this app
     * cannot re-authenticate with Obligate (no re-authentication sheet).
     */
    data object SsoUnsupported : DeviceKeyServerState

    /** Local account without an authenticator app: TOTP first (the enrolment needs a new code). */
    data object TotpRequired : DeviceKeyServerState

    /** `eligibility.ok` false for another reason (the server's text, never trusted for anything but display). */
    data class NotEligible(val reason: String?) : DeviceKeyServerState

    /** No BIOMETRIC_STRONG enrolled on this phone (state `noStrongBiometric`). */
    data object NoStrongBiometric : DeviceKeyServerState

    /** Eligible, no key here → « Activer ». */
    data object NotEnrolled : DeviceKeyServerState

    /** The key of this phone was invalidated or lost → « Réactiver » (reason `invalidated`). */
    data object Invalidated : DeviceKeyServerState

    /** Enrolled: [level] as the server attested it; [bound] = this session is bound to the key. */
    data class Active(val record: DeviceKeyRecord, val level: DeviceKeyLevel, val bound: Boolean) : DeviceKeyServerState

    /** The list could not be read (network, 5xx…): the last known state is not assumed. */
    data class Failed(val outcome: ApiOutcome<Nothing>) : DeviceKeyServerState

    /** « Activer » / « Réactiver » are offered. */
    val canEnrol: Boolean get() = this == NotEnrolled || this == Invalidated
}

/** One server's row: its state and, when read, the account's keys (the phones list). */
data class DeviceKeyView(
    val serverId: ServerId,
    val state: DeviceKeyServerState,
    /** The last list read (null before, and for an old server). */
    val list: DeviceKeyList? = null,
    /**
     * The account of this row signs in with Obligate (SSO device keys): « Activer »
     * then goes through the Obligate re-authentication, never a password nor
     * a code (SSO variant of the profile and security screen).
     */
    val sso: Boolean = false,
)

/** Why an enrolment did not end with a key (each maps to its own user-facing text). */
enum class EnrolProblem {
    DISABLED,
    ORIGIN_UNSET,
    ORIGIN_MISMATCH,
    SSO_UNSUPPORTED,
    NO_TOTP,

    /**
     * Obligate account: `enrol/begin` wants a (new) Obligate re-authentication
     * (`401 codeRequiresReauth`: none, older than 5 min, already used, or the
     * Obligate MFA epoch moved). The profile and security screen offers « Reconfirmer » again.
     */
    REAUTH_REQUIRED,

    /** Obligate account: the re-authentication was refused (detail: the sheet's reason code). */
    REAUTH_FAILED,

    /** `503 verifierUnavailable`: Obligate could not confirm the account right now. */
    VERIFIER_UNAVAILABLE,

    /** `403 enrol_locked`: 3 failures in 24 h. */
    LOCKED,

    /** `429 codeLocked`: too many wrong codes, a full sign-in unlocks it. */
    CODE_LOCKED,

    /** `429` without codeLocked. */
    RATE_LIMITED,

    /** `401 Invalid 2FA code` + `codeUsed`: a right code already used (the sign-in code): wait for the next one. */
    CODE_USED,
    TOO_MANY_KEYS,
    ALREADY_ENROLLED,

    /** `422 attestation_failed` (detail: the server's reason). */
    ATTESTATION,

    /** KeyInfo: the key is not in secure hardware. */
    NOT_HARDWARE_BACKED,

    /** The ticket expired or was refused (180 s): start again. */
    TICKET,

    /** Another enrolment of the same key is running. */
    BUSY,

    /** The Keystore could not create the key (detail: the exception class). */
    KEY_FAILED,

    /** The biometric is locked out after too many attempts. */
    BIOMETRIC_LOCKED,

    /** The biometric could not be shown (detail: why). */
    BIOMETRIC_UNAVAILABLE,

    /** A server without the feature (404). */
    NOT_AVAILABLE,
    SESSION_EXPIRED,
    NETWORK,

    /** Anything else (bad_key, bad_signature, 5xx…; detail: the server text). */
    FAILED,
}

sealed interface DeviceKeyEnrolOutcome {
    /** Stored and bound; [level] as the server attested it. */
    data class Enrolled(val record: DeviceKeyRecord, val level: DeviceKeyLevel) : DeviceKeyEnrolOutcome

    /** `401 Invalid 2FA code`: the password or the code is wrong (the server does not say which). Retry. */
    data object WrongCredentials : DeviceKeyEnrolOutcome

    /** The biometric prompt was cancelled: nothing happened server side that matters (the ticket expires). */
    data object Cancelled : DeviceKeyEnrolOutcome
    data class Failed(val problem: EnrolProblem, val detail: String? = null) : DeviceKeyEnrolOutcome
}

/** « Utiliser l'empreinte la prochaine fois ? » after a code on [serverId]. */
data class DeviceKeyProposal(val serverId: ServerId, val serverName: String)

/**
 * Device-bound validation of every configured server. The phone holds
 * at most one key per (server origin, server user); every call goes to the
 * server's OWN session. Never logs a password, a code or a signature.
 */
interface DeviceKeysRepository {
    /** False when the app has no Keystore (previews, tests): the profile screen says it is not available on this phone. */
    val supported: Boolean

    /** The last state read per server (only servers [refresh]ed so far). */
    val views: StateFlow<Map<ServerId, DeviceKeyView>>

    /**
     * Reads `GET /api/profile/device-keys` on [serverId] (with the session's
     * user and this phone's record) and publishes its [DeviceKeyView]. A local
     * key the server no longer lists as active is purged (revoked elsewhere).
     */
    suspend fun refresh(serverId: ServerId): DeviceKeyView

    /**
     * Begin → key → fingerprint ([signer] with [prompt]) → finish →
     * record. [proof]: a local account's password + NEW code (they live only
     * in this call), or, for an Obligate account (SSO device keys),
     * [EnrolProof.SsoReauth]: the Obligate re-authentication sheet first,
     * then `begin` at once with `{installId}` only (the re-authentication is
     * single use and lasts 5 min). A proof that does not match the account is
     * refused without any call (never a local password for an `og_` account).
     */
    suspend fun enrol(serverId: ServerId, proof: EnrolProof, signer: DeviceSigner, prompt: SignPrompt): DeviceKeyEnrolOutcome

    /**
     * `DELETE /api/profile/device-keys/:id` (no step-up). When it is
     * THIS phone's key, the local key is purged too and the server has ended
     * the session bound to it (sign-in-again follows).
     */
    suspend fun revoke(serverId: ServerId, keyId: String): ApiOutcome<Unit>

    /** `DELETE /api/profile/device-keys`: every phone of the account, this one included. */
    suspend fun revokeAll(serverId: ServerId): ApiOutcome<Unit>

    /** This phone's key for the user signed in on [serverId], if any. */
    fun localKey(serverId: ServerId): DeviceKeyRecord?

    /** For the action host: the key of (origin, user of the session there). */
    val resolver: DeviceKeyResolver?

    /** For the fingerprint signer (core:security-ui `BiometricDeviceSigner`). */
    val hardware: DeviceKeyHardware?

    /** Host hook: a signature found the key of [origin] dead. Report, purge, end that session. */
    suspend fun invalidated(origin: String, keyId: String) {}

    /** Servers whose key was invalidated on this phone since the app started (the profile screen says so and offers « Réactiver »). */
    val invalidatedServers: StateFlow<Set<ServerId>>

    /**
     * Servers whose session was ended BECAUSE their key was invalidated, until
     * the next sign-in there: the sign-in-again sheet says why (reason `invalidated`).
     */
    val reauthNotices: StateFlow<Set<ServerId>> get() = invalidatedServers

    /** Host hook: a code went through on [origin] (ActionPrompter.codeAccepted). Returns at once. */
    fun codeAccepted(origin: String) {}

    /** The pending « Utiliser l'empreinte la prochaine fois ? », if any. */
    val proposal: StateFlow<DeviceKeyProposal?>

    /** Answer of the proposal: « Activer » (true) opens the profile and security screen; « Plus tard » is remembered 30 days. */
    fun answerProposal(accepted: Boolean) {}

    /** No device-bound validation at all (default of test fakes). */
    object None : DeviceKeysRepository {
        private val empty = MutableStateFlow<Map<ServerId, DeviceKeyView>>(emptyMap()).asStateFlow()
        private val noServers = MutableStateFlow<Set<ServerId>>(emptySet()).asStateFlow()
        private val noProposal = MutableStateFlow<DeviceKeyProposal?>(null).asStateFlow()
        private val unsupported: ApiOutcome<Nothing> = ApiOutcome.Failure(null, FailureKind.CLIENT, "device keys not supported")

        override val supported: Boolean get() = false
        override val views: StateFlow<Map<ServerId, DeviceKeyView>> get() = empty
        override suspend fun refresh(serverId: ServerId) = DeviceKeyView(serverId, DeviceKeyServerState.NotAvailable)
        override suspend fun enrol(serverId: ServerId, proof: EnrolProof, signer: DeviceSigner, prompt: SignPrompt): DeviceKeyEnrolOutcome =
            DeviceKeyEnrolOutcome.Failed(EnrolProblem.NOT_AVAILABLE)
        override suspend fun revoke(serverId: ServerId, keyId: String): ApiOutcome<Unit> = unsupported
        override suspend fun revokeAll(serverId: ServerId): ApiOutcome<Unit> = unsupported
        override fun localKey(serverId: ServerId): DeviceKeyRecord? = null
        override val resolver: DeviceKeyResolver? get() = null
        override val hardware: DeviceKeyHardware? get() = null
        override val invalidatedServers: StateFlow<Set<ServerId>> get() = noServers
        override val proposal: StateFlow<DeviceKeyProposal?> get() = noProposal
    }
}
