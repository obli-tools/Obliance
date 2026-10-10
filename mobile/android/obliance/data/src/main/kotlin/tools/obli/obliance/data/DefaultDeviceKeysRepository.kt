package tools.obli.obliance.data

import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tools.obli.core.auth.AuthState
import tools.obli.core.auth.ServerRegistry
import tools.obli.core.auth.ServerSession
import tools.obli.core.auth.ServerSessions
import tools.obli.core.model.ObliUser
import tools.obli.core.model.ServerId
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.FailureKind
import tools.obli.core.network.ForbiddenReason
import tools.obli.core.network.isVerifierUnavailable
import tools.obli.core.security.DeviceKeyEnrolment
import tools.obli.core.security.DeviceKeyHardware
import tools.obli.core.security.DeviceKeyMaintenance
import tools.obli.core.security.DeviceKeyRecord
import tools.obli.core.security.DeviceKeyResolver
import tools.obli.core.security.DeviceKeyStore
import tools.obli.core.security.DeviceProofPayload
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.EnrolProof
import tools.obli.core.security.EnrolResult
import tools.obli.core.security.KeyHealth
import tools.obli.core.security.SessionDeviceKeys
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignResult
import tools.obli.core.security.SsoReauthResult
import tools.obli.obliance.api.AuthApi
import tools.obli.obliance.api.DeviceKeyErrors
import tools.obli.obliance.api.DeviceKeyList
import tools.obli.obliance.api.DeviceKeysApi

/**
 * What the application gives for device-bound validation (AppGraph): the
 * Keystore (core:devicekey `KeystoreDeviceKeys`), the records
 * (`DataStoreDeviceKeyStore`), the biometric check and the key's label.
 */
class DeviceKeyDeps(
    val store: DeviceKeyStore,
    val hardware: DeviceKeyHardware,
    /** `BiometricManager.canAuthenticate(BIOMETRIC_STRONG) == BIOMETRIC_SUCCESS` (a secure lock screen included). */
    val strongBiometric: () -> Boolean,
    /** Label of the key in the account's phone list ("samsung SM-S911B"). */
    val deviceLabel: () -> String,
    /** The app's versionName, sent with the enrolment. */
    val appVersion: String,
    /** Where « Plus tard » of the first-2FA proposal is remembered. */
    val proposals: DeviceKeyProposalMemory = DeviceKeyProposalMemory.InMemory(),
    /** Reads the persisted records (DataStoreDeviceKeyStore.load); run before the first key check. */
    val load: suspend () -> Unit = {},
    /**
     * SSO device keys: the Obligate re-authentication of the session of an origin (the
     * app's sheet, obliance:access `SsoReauthHost` through [SsoReauthBroker]).
     * Null (fakes, previews): Obligate accounts stay `SsoUnsupported` (fail closed).
     */
    val reauth: (suspend (origin: String) -> SsoReauthResult)? = null,
)

/** « Plus tard » of the proposal, per (origin, user): no second proposal for [DefaultDeviceKeysRepository.DECLINE_MS]. */
interface DeviceKeyProposalMemory {
    fun declinedAt(key: String): Long?
    fun decline(key: String, at: Long)

    class InMemory : DeviceKeyProposalMemory {
        private val map = ConcurrentHashMap<String, Long>()
        override fun declinedAt(key: String): Long? = map[key]
        override fun decline(key: String, at: Long) {
            map[key] = at
        }
    }
}

/**
 * The link between sign-in / sign-out and the phone's keys
 * used by [DefaultAuthRepository].
 */
internal interface DeviceKeyLink {
    /**
     * The explicit header of the sign-in: the key remembered for [username]
     * on [origin], only while its Keystore key is alive. A dead key (new
     * biometric, lock removed) is forgotten here and not sent: there is no
     * session to report it with (`…/invalidated` ends the caller's session),
     * so the server row waits for a revocation or the 180-day expiry — nobody
     * can sign with it any more.
     */
    suspend fun loginKey(origin: String, username: String): DeviceKeyRecord?

    /** The record of [keyId] on [origin], if this phone still has it. */
    fun record(origin: String, keyId: String): DeviceKeyRecord?

    /** A sign-in found the key dead or revoked: forgotten here only (the pending login keeps its cookie). */
    suspend fun loginKeyGone(origin: String, keyId: String)

    /** The key of (origin, user): the header of the sign-out. */
    fun keyIdOf(origin: String, userId: Long): String?

    /**
     * Every key this phone holds for [origin] (any account): the sign-out of a
     * session whose user is not known in this process (cold start offline).
     */
    fun recordsOf(origin: String): List<DeviceKeyRecord>

    /**
     * Just signed in, BEFORE the session is marked signed in (so no request
     * carries the header yet): a local key the server no longer lists as
     * active is purged — otherwise its header would end the new session at once.
     */
    suspend fun beforeSignedIn(session: ServerSession)

    /** After the sign-out call (or offline anyway), forget the key of (origin, user). */
    suspend fun forget(origin: String, userId: Long)
}

/**
 * The production [DeviceKeysRepository]:
 * one key per (server origin, server user), each call on the
 * server's own session, key health through core:security `DeviceKeyMaintenance`
 * (invalidated or lost → report, purge, cookie cleared, sign-in-again sheet).
 */
internal class DefaultDeviceKeysRepository(
    private val registry: ServerRegistry,
    private val sessions: ServerSessions,
    private val deps: DeviceKeyDeps,
    /** Expires the cookies of an origin (WebCookieJar.clearOrigin). */
    private val clearCookies: (origin: String) -> Unit,
    private val scope: CoroutineScope,
    private val clock: () -> Long = System::currentTimeMillis,
) : DeviceKeysRepository, DeviceKeyLink {
    private val store: DeviceKeyStore get() = deps.store

    /** The key of (origin, user of the session signed in there) — the interceptor's and the runner's source. */
    val sessionKeys = SessionDeviceKeys(deps.store) { origin -> sessions.byOrigin(origin)?.userId }

    val maintenance = DeviceKeyMaintenance(deps.store, deps.hardware, ::reportInvalidated, ::endSession)

    private val _views = MutableStateFlow<Map<ServerId, DeviceKeyView>>(emptyMap())
    private val _invalidated = MutableStateFlow<Set<ServerId>>(emptySet())
    private val _reauthNotices = MutableStateFlow<Set<ServerId>>(emptySet())
    private val _proposal = MutableStateFlow<DeviceKeyProposal?>(null)

    /** ObliHttp origin of each server met (a removed server has no session left to ask). */
    private val origins = ConcurrentHashMap<ServerId, String>()

    /** (origin, user) already considered for the proposal in this process. */
    private val asked = ConcurrentHashMap.newKeySet<String>()
    @Volatile private var proposalKey: String? = null

    init {
        registry.addRemovalListener { profile -> forgetServer(profile.id, profile.origin) }
    }

    override val supported: Boolean get() = true
    override val views: StateFlow<Map<ServerId, DeviceKeyView>> = _views.asStateFlow()
    override val resolver: DeviceKeyResolver get() = sessionKeys
    override val hardware: DeviceKeyHardware get() = deps.hardware
    override val invalidatedServers: StateFlow<Set<ServerId>> = _invalidated.asStateFlow()
    override val reauthNotices: StateFlow<Set<ServerId>> = _reauthNotices.asStateFlow()
    override val proposal: StateFlow<DeviceKeyProposal?> = _proposal.asStateFlow()

    // --- Lifecycle ---------------------------------------------------------------

    /** Start-up: the persisted records, before anything reads them. */
    suspend fun load() = deps.load()

    /**
     * On each return to the foreground (and at start-up): orphan aliases
     * deleted, every record's key health read; a dead key (new biometric,
     * screen lock removed) goes through the invalidation flow for its server.
     */
    suspend fun checkKeys() {
        withContext(Dispatchers.IO) { maintenance.reconcile() }
    }

    /** ObliHttp's `onDeviceKeyRevoked`: 401 `revoked` for the key the request carried. */
    fun deviceKeyRevoked(origin: String, keyId: String?) {
        scope.launch { maintenance.revoked(origin, keyId) }
    }

    // --- Profile and security screen ---------------------------------------------------

    override suspend fun refresh(serverId: ServerId): DeviceKeyView {
        val session = sessions.session(serverId) ?: return publish(DeviceKeyView(serverId, DeviceKeyServerState.SignedOut))
        val probe = (session.auth.value as? AuthState.SignedIn)?.probe
            ?: return publish(DeviceKeyView(serverId, DeviceKeyServerState.SignedOut))
        val origin = session.http.origin.also { origins[serverId] = it }
        val list = when (val out = DeviceKeysApi(session.http).list().watchedBy(session)) {
            is ApiOutcome.Ok -> out.value
            is ApiOutcome.Accepted -> out.value
            ApiOutcome.SessionExpired -> return publish(DeviceKeyView(serverId, DeviceKeyServerState.SignedOut))
            is ApiOutcome.Failure -> return if (out.status == 404) {
                publish(DeviceKeyView(serverId, DeviceKeyServerState.NotAvailable))
            } else {
                publish(DeviceKeyView(serverId, DeviceKeyServerState.Failed(out)))
            }
            else -> return publish(DeviceKeyView(serverId, DeviceKeyServerState.Failed(out.failureAs())))
        }
        var record = store.find(origin, probe.user.id)
        if (record != null && list.policy.enabled && !list.isActive(record.keyId)) {
            // Revoked elsewhere (web, administrator, password change, stale): forget it here too.
            maintenance.revoked(origin, record.keyId)
            record = null
        }
        val sso = isSso(probe.user)
        return publish(DeviceKeyView(serverId, stateOf(serverId, origin, probe.user, list, record), list, sso = sso))
    }

    private fun stateOf(serverId: ServerId, origin: String, user: ObliUser, list: DeviceKeyList, record: DeviceKeyRecord?): DeviceKeyServerState {
        val policy = list.policy
        val sso = isSso(user)
        return when {
            !policy.enabled -> DeviceKeyServerState.DisabledByAdmin(record)
            record != null -> DeviceKeyServerState.Active(
                record,
                list.validKeys.firstOrNull { it.id.equals(record.keyId, ignoreCase = true) }?.level ?: record.securityLevel,
                bound = list.boundKeyId?.equals(record.keyId, ignoreCase = true) == true,
            )
            !policy.originConfigured -> DeviceKeyServerState.OriginUnset
            // SSO device keys: an Obligate account enrols through the Obligate
            // re-authentication. Not offered while the server does not support
            // it (DEVICE_KEYS_SSO_ENABLED off, Obligate without the capabilities,
            // an older server: ssoSupported false) or without the app's sheet.
            sso && (!policy.ssoSupported || deps.reauth == null) -> DeviceKeyServerState.SsoUnsupported
            // A local account needs an authenticator app (the enrolment asks a NEW code).
            !sso && !user.totpEnabled -> DeviceKeyServerState.TotpRequired
            !list.eligibility.ok -> eligibilityState(list.eligibility.reason, record)
            !DeviceProofPayload.isAsciiOrigin(origin) || origin !in list.allowedOrigins -> DeviceKeyServerState.OriginMismatch(origin)
            !deps.strongBiometric() -> DeviceKeyServerState.NoStrongBiometric
            serverId in _invalidated.value -> DeviceKeyServerState.Invalidated
            else -> DeviceKeyServerState.NotEnrolled
        }
    }

    /** The server's free `eligibility.reason`, read for display only (fail closed: never « Activer »). */
    private fun eligibilityState(reason: String?, record: DeviceKeyRecord?): DeviceKeyServerState {
        val r = reason.orEmpty().lowercase()
        return when {
            "totp" in r -> DeviceKeyServerState.TotpRequired
            "sso" in r || "obligate" in r -> DeviceKeyServerState.SsoUnsupported
            "origin" in r -> DeviceKeyServerState.OriginUnset
            "disabled" in r -> DeviceKeyServerState.DisabledByAdmin(record)
            // enrol_locked and anything new: shown by the profile and security screen from the reason (never « Activer »).
            else -> DeviceKeyServerState.NotEligible(reason)
        }
    }

    private fun publish(view: DeviceKeyView): DeviceKeyView {
        _views.update { it + (view.serverId to view) }
        return view
    }

    override suspend fun enrol(serverId: ServerId, proof: EnrolProof, signer: DeviceSigner, prompt: SignPrompt): DeviceKeyEnrolOutcome {
        val session = sessions.session(serverId) ?: return DeviceKeyEnrolOutcome.Failed(EnrolProblem.SESSION_EXPIRED)
        val user = (session.auth.value as? AuthState.SignedIn)?.probe?.user ?: return DeviceKeyEnrolOutcome.Failed(EnrolProblem.SESSION_EXPIRED)
        val sso = isSso(user)
        // The proof must be the account's: never a local password for an Obligate
        // account, never the Obligate path for a local one. Nothing is sent.
        if (sso != (proof is EnrolProof.SsoReauth)) return DeviceKeyEnrolOutcome.Failed(if (sso) EnrolProblem.SSO_UNSUPPORTED else EnrolProblem.FAILED, PROOF_MISMATCH)
        if (!deps.strongBiometric()) return DeviceKeyEnrolOutcome.Failed(EnrolProblem.BIOMETRIC_UNAVAILABLE)
        val origin = session.http.origin.also { origins[serverId] = it }
        if (sso) {
            // SSO device keys: the Obligate re-authentication of THIS session first (the app's
            // sheet), then begin at once: it is single use and lasts 5 min, and the 180 s
            // ticket must still fit the fingerprint prompt.
            val reauth = deps.reauth ?: return DeviceKeyEnrolOutcome.Failed(EnrolProblem.SSO_UNSUPPORTED)
            when (val r = reauth(origin)) {
                SsoReauthResult.Success -> Unit
                SsoReauthResult.Cancelled -> return DeviceKeyEnrolOutcome.Cancelled
                is SsoReauthResult.Failed -> {
                    // The session ended meanwhile: the profile screen says so (sign-in-again follows), as for begin.
                    if (r.endsSession && session.probe() !is AuthState.SignedIn) return DeviceKeyEnrolOutcome.Failed(EnrolProblem.SESSION_EXPIRED)
                    return DeviceKeyEnrolOutcome.Failed(EnrolProblem.REAUTH_FAILED, r.reason)
                }
            }
        }
        val enrolment = DeviceKeyEnrolment(DeviceKeysApi(session.http), deps.hardware, signer, store, clock)
        val label = deps.deviceLabel().trim().take(MAX_LABEL).ifEmpty { "Android" }
        val result = enrolment.enrol(origin, user.id, user.username, proof, label, deps.appVersion, prompt)
        if (result.isSessionExpired()) {
            // enrol/begin answers `401 Invalid 2FA code` for a wrong password or code; another 401
            // wording would read as an expired session: ask /me before telling the user so.
            val signedIn = session.probe() is AuthState.SignedIn
            return when {
                !signedIn -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.SESSION_EXPIRED)
                // An Obligate account has no password nor code to be wrong: re-authenticate again.
                sso -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.REAUTH_REQUIRED)
                else -> DeviceKeyEnrolOutcome.WrongCredentials
            }
        }
        val outcome = outcomeOf(result)
        if (outcome is DeviceKeyEnrolOutcome.Enrolled) {
            _invalidated.update { it - serverId }
            proposalKey?.let { key -> if (key == proposalKeyOf(origin, user.id)) _proposal.value = null }
        }
        refresh(serverId)
        return outcome
    }

    private fun EnrolResult.isSessionExpired(): Boolean = this is EnrolResult.Refused && outcome == ApiOutcome.SessionExpired

    override suspend fun revoke(serverId: ServerId, keyId: String): ApiOutcome<Unit> {
        val session = sessions.session(serverId) ?: return noServer
        val out = DeviceKeysApi(session.http).revoke(keyId).watchedBy(session)
        // 404: not (or no longer) an active key of this account — ours is dead either way.
        if (out is ApiOutcome.Ok || (out is ApiOutcome.Failure && out.status == 404)) afterRevoke(session, setOf(keyId))
        return out
    }

    override suspend fun revokeAll(serverId: ServerId): ApiOutcome<Unit> {
        val session = sessions.session(serverId) ?: return noServer
        val out = DeviceKeysApi(session.http).revokeAll().watchedBy(session)
        if (out is ApiOutcome.Ok) afterRevoke(session, null)
        return out
    }

    /**
     * After a revocation: this phone's key among them → purged here too; the
     * server ended the sessions bound to it — /me tells (sign-in-again follows) — then
     * the row is read again.
     */
    private suspend fun afterRevoke(session: ServerSession, keyIds: Set<String>?) {
        val origin = session.http.origin
        val record = session.userId?.let { store.find(origin, it) }
        if (record != null && (keyIds == null || keyIds.any { it.equals(record.keyId, ignoreCase = true) })) {
            maintenance.revoked(origin, record.keyId)
            session.probe()
        }
        if (session.auth.value is AuthState.SignedIn) refresh(session.id) else publish(DeviceKeyView(session.id, DeviceKeyServerState.SignedOut))
    }

    override fun localKey(serverId: ServerId): DeviceKeyRecord? {
        val session = sessions.session(serverId) ?: return null
        val userId = session.userId ?: return null
        return store.find(session.http.origin, userId)
    }

    // --- Invalidation ----------------------------------------------------------------------

    override suspend fun invalidated(origin: String, keyId: String) {
        maintenance.invalidated(origin, keyId)
    }

    private suspend fun reportInvalidated(origin: String, keyId: String) {
        val session = sessions.byOrigin(origin) ?: return
        DeviceKeysApi(session.http).reportInvalidated(keyId)
    }

    /** Invalidation step 3: the cookie of that origin goes (even offline), the session ends, the sign-in-again sheet shows. */
    private suspend fun endSession(origin: String) {
        val session = sessions.byOrigin(origin) ?: run {
            clearCookies(origin)
            return
        }
        _invalidated.update { it + session.id }
        _reauthNotices.update { it + session.id }
        clearCookies(session.profile.origin)
        if (registry.state.value.activeId == session.id) runCatching { session.realtime.disconnect() }
        session.markExpired()
        publish(DeviceKeyView(session.id, DeviceKeyServerState.SignedOut))
    }

    // --- First-2FA proposal ----------------------------------------------------------------

    override fun codeAccepted(origin: String) {
        scope.launch {
            try {
                propose(origin)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // A proposal is a convenience: never an error.
            }
        }
    }

    private suspend fun propose(origin: String) {
        val session = sessions.byOrigin(origin) ?: return
        val userId = session.userId ?: return
        if (store.find(origin, userId) != null) return
        val key = proposalKeyOf(origin, userId)
        if (!asked.add(key)) return
        deps.proposals.declinedAt(key)?.let { if (clock() - it in 0 until DECLINE_MS) return }
        if (!deps.strongBiometric()) return
        val view = refresh(session.id)
        if (view.state.canEnrol && _proposal.value == null) {
            proposalKey = key
            _proposal.value = DeviceKeyProposal(session.id, session.profile.displayName)
        }
    }

    override fun answerProposal(accepted: Boolean) {
        val key = proposalKey
        _proposal.value = null
        proposalKey = null
        if (!accepted && key != null) deps.proposals.decline(key, clock())
    }

    private fun proposalKeyOf(origin: String, userId: Long) = "$origin|$userId"

    // --- DeviceKeyLink (sign-in, sign-out) ------------------------------------------------------

    override suspend fun loginKey(origin: String, username: String): DeviceKeyRecord? {
        val record = store.findByUsername(origin, username) ?: return null
        val health = withContext(Dispatchers.IO) { runCatching { deps.hardware.health(record.alias) }.getOrElse { KeyHealth.Unavailable(it.javaClass.simpleName) } }
        if (health.isDead) {
            maintenance.revoked(origin, record.keyId)
            // The profile and security screen then offers « Réactiver » once signed in (with the code).
            sessions.byOrigin(origin)?.let { s -> _invalidated.update { it + s.id } }
            return null
        }
        return record
    }

    override fun record(origin: String, keyId: String): DeviceKeyRecord? =
        store.records.value.firstOrNull { it.origin == origin && it.keyId.equals(keyId, ignoreCase = true) }

    override suspend fun loginKeyGone(origin: String, keyId: String) {
        maintenance.revoked(origin, keyId)
    }

    override fun keyIdOf(origin: String, userId: Long): String? = store.find(origin, userId)?.keyId

    override fun recordsOf(origin: String): List<DeviceKeyRecord> = store.records.value.filter { it.origin == origin }

    override suspend fun beforeSignedIn(session: ServerSession) {
        val origin = session.http.origin.also { origins[session.id] = it }
        _reauthNotices.update { it - session.id }
        if (store.records.value.none { it.origin == origin }) return
        // Raw calls: the session is not "signed in" yet, so the interceptor adds no header.
        val user = (AuthApi(session.http).me() as? ApiOutcome.Ok)?.value?.user ?: return
        val record = store.find(origin, user.id) ?: return
        val list = (DeviceKeysApi(session.http).list() as? ApiOutcome.Ok)?.value ?: return
        if (list.policy.enabled && !list.isActive(record.keyId)) maintenance.revoked(origin, record.keyId)
    }

    override suspend fun forget(origin: String, userId: Long) {
        maintenance.forget(origin, userId)
    }

    /** A removed server: every key of its origin goes (all accounts), no server call is possible any more. */
    private suspend fun forgetServer(id: ServerId, profileOrigin: String) {
        val known = setOfNotNull(profileOrigin, origins.remove(id))
        store.records.value.filter { it.origin in known }.forEach { maintenance.forget(it.origin, it.userId) }
        _views.update { it - id }
        _invalidated.update { it - id }
        _reauthNotices.update { it - id }
        if (_proposal.value?.serverId == id) {
            _proposal.value = null
            proposalKey = null
        }
    }

    companion object {
        /** « Plus tard »: no second proposal for this long. */
        const val DECLINE_MS = 30L * 24 * 3600 * 1000

        /** Label length sent to the server. */
        const val MAX_LABEL = 64

        /** [DeviceKeyEnrolOutcome.Failed] detail: the proof given does not match the account (nothing sent). */
        const val PROOF_MISMATCH = "proof"

        /**
         * An account that signs in with Obligate (SSO device keys): `foreignSource ==
         * 'obligate'`, the `og_` prefix as a fallback (a /me without it).
         */
        fun isSso(user: ObliUser): Boolean = user.isObligate || user.username.startsWith("og_")

        /** The outcome of core's enrolment, as the profile and security screen explains it (pure, JVM-tested). */
        fun outcomeOf(result: EnrolResult): DeviceKeyEnrolOutcome = when (result) {
            is EnrolResult.Enrolled -> DeviceKeyEnrolOutcome.Enrolled(result.record, result.record.securityLevel)
            is EnrolResult.Refused -> refusal(result.outcome)
            EnrolResult.OriginNotAllowed -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.ORIGIN_MISMATCH)
            EnrolResult.InvalidTicket -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.TICKET)
            EnrolResult.NotHardwareBacked -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.NOT_HARDWARE_BACKED)
            is EnrolResult.KeyGenerationFailed ->
                if (result.reason == DeviceKeyEnrolment.BUSY) DeviceKeyEnrolOutcome.Failed(EnrolProblem.BUSY) else DeviceKeyEnrolOutcome.Failed(EnrolProblem.KEY_FAILED, result.reason)
            is EnrolResult.NotSigned -> when (val s = result.result) {
                SignResult.UseCode, SignResult.Cancelled -> DeviceKeyEnrolOutcome.Cancelled
                SignResult.LockedOut -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.BIOMETRIC_LOCKED)
                SignResult.Invalidated -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.KEY_FAILED, "invalidated")
                is SignResult.Unavailable -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.BIOMETRIC_UNAVAILABLE, s.reason)
                is SignResult.Signed -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED)
            }
        }

        /** Refusal table, enrolment rows. */
        fun refusal(out: ApiOutcome<Nothing>): DeviceKeyEnrolOutcome = when (out) {
            // `codeUsed`: a right code whose step was already used (enrol/begin wants a NEW one).
            is ApiOutcome.StepUpRejected -> if (out.codeUsed) DeviceKeyEnrolOutcome.Failed(EnrolProblem.CODE_USED) else DeviceKeyEnrolOutcome.WrongCredentials
            // 401 twoFactorRequired: a proof was missing, or an Obligate account needs a (new)
            // Obligate re-authentication (codeRequiresReauth: none, expired, already used, or the
            // Obligate MFA epoch moved): the profile and security screen offers « Reconfirmer » again.
            is ApiOutcome.StepUpRequired ->
                DeviceKeyEnrolOutcome.Failed(if (out.codeRequiresReauth) EnrolProblem.REAUTH_REQUIRED else EnrolProblem.FAILED)
            ApiOutcome.SessionExpired -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.SESSION_EXPIRED)
            is ApiOutcome.Forbidden -> when {
                out.reason == ForbiddenReason.NO_TOTP -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.NO_TOTP)
                out.message == DeviceKeyErrors.DISABLED -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.DISABLED)
                out.message == DeviceKeyErrors.ORIGIN_UNSET -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.ORIGIN_UNSET)
                out.message == DeviceKeyErrors.SSO_UNSUPPORTED -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.SSO_UNSUPPORTED)
                out.message == DeviceKeyErrors.ENROL_LOCKED -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.LOCKED)
                else -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED, out.message.ifEmpty { null })
            }
            is ApiOutcome.Validation -> when (out.message) {
                DeviceKeyErrors.INVALID_TICKET -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.TICKET)
                DeviceKeyErrors.ORIGIN_MISMATCH -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.ORIGIN_MISMATCH)
                else -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED, out.message.ifEmpty { null })
            }
            is ApiOutcome.Unsupported -> when (out.message) {
                DeviceKeyErrors.TOO_MANY_KEYS -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.TOO_MANY_KEYS)
                DeviceKeyErrors.ALREADY_ENROLLED -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.ALREADY_ENROLLED)
                else -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED, out.message.ifEmpty { null })
            }
            is ApiOutcome.RateLimited ->
                DeviceKeyEnrolOutcome.Failed(if (out.codeLocked) EnrolProblem.CODE_LOCKED else EnrolProblem.RATE_LIMITED)
            is ApiOutcome.Failure -> when {
                // 503 verifierUnavailable (Obligate account): Obligate could not confirm it right now.
                out.isVerifierUnavailable -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.VERIFIER_UNAVAILABLE)
                out.status == 422 -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.ATTESTATION, out.message)
                out.status == 404 -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.NOT_AVAILABLE)
                out.kind == FailureKind.NETWORK -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.NETWORK)
                else -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED, out.message)
            }
            else -> DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED)
        }
    }
}
