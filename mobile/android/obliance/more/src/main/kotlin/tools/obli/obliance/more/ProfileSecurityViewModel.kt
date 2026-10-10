package tools.obli.obliance.more

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import tools.obli.core.auth.AuthState
import tools.obli.core.auth.ServerRegistryState
import tools.obli.core.model.ObliUser
import tools.obli.core.model.ServerId
import tools.obli.core.model.ServerProfile
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.EnrolProof
import tools.obli.core.security.SignPrompt
import tools.obli.obliance.api.DeviceKeyInfo
import tools.obli.obliance.data.DeviceKeyEnrolOutcome
import tools.obli.obliance.data.DeviceKeyServerState
import tools.obli.obliance.data.DeviceKeyView
import tools.obli.obliance.data.EnrolProblem
import tools.obli.obliance.data.ObliServices

/** One server of the « Validation par empreinte » section. */
internal data class DeviceKeyRow(
    val profile: ServerProfile,
    val state: DeviceKeyServerState,
    /** Active keys of the account on that server (the phones list), when read. */
    val keys: List<DeviceKeyInfo>? = null,
    /** The account on that server signs in with Obligate: « Activer » goes through Obligate (SSO device keys). */
    val sso: Boolean = false,
)

internal data class ProfileSecurityUi(
    /** The ACTIVE server's account (the header of « Profil et sécurité »). */
    val server: ServerProfile? = null,
    val user: ObliUser? = null,
    val multiServer: Boolean = false,
    /** False: this build has no Keystore wiring (never in the app). */
    val supported: Boolean = true,
    val rows: List<DeviceKeyRow> = emptyList(),
) {
    val obligate: Boolean get() = user?.let { it.isObligate || it.username.startsWith("og_") } == true
    fun row(id: ServerId): DeviceKeyRow? = rows.firstOrNull { it.profile.id == id }
}

/**
 * The device-key enrolment as « Profil et sécurité » walks it: explanation, then password + NEW
 * code, then the fingerprint. SSO variant ([sso], SSO device keys): explanation,
 * then « Reconfirmer avec Obligate » (the Obligate sheet, then `begin` at
 * once, then the fingerprint); no password nor code field.
 */
internal sealed interface EnrolStep {
    val serverId: ServerId
    val serverName: String
    val sso: Boolean

    data class Explain(override val serverId: ServerId, override val serverName: String, override val sso: Boolean = false) : EnrolStep

    /**
     * [wrong]: the last password or code was refused; [problem]: another
     * refusal to explain; [busy]: in flight. For [sso], the step of
     * « Reconfirmer avec Obligate » (again after a refusal).
     */
    data class Credentials(
        override val serverId: ServerId,
        override val serverName: String,
        val busy: Boolean = false,
        val wrong: Boolean = false,
        val problem: EnrolProblem? = null,
        val detail: String? = null,
        override val sso: Boolean = false,
    ) : EnrolStep
}

internal object ProfileSecurityMapper {
    fun map(registry: ServerRegistryState, activeAuth: AuthState?, views: Map<ServerId, DeviceKeyView>, supported: Boolean): ProfileSecurityUi =
        ProfileSecurityUi(
            server = registry.active,
            user = (activeAuth as? AuthState.SignedIn)?.probe?.user,
            multiServer = registry.isMultiServer,
            supported = supported,
            rows = registry.profiles.map { p ->
                val view = views[p.id]
                DeviceKeyRow(p, view?.state ?: DeviceKeyServerState.Loading, view?.list?.validKeys, sso = view?.sso == true)
            },
        )
}

/**
 * « Profil et sécurité »:
 * the account of the active server and « Validation par empreinte », one row
 * per server. The enrolment runs here; revocations run through the app's
 * ActionRunner (T1 / T2) from the screen. The password and the code live in
 * [password] / [code] only until they are sent (then cleared).
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal class ProfileSecurityViewModel(
    private val services: ObliServices,
    /** Texts of the enrolment's biometric prompt for a server name. */
    private val enrolPrompt: (serverName: String) -> SignPrompt,
) : ViewModel() {
    val ui: StateFlow<ProfileSecurityUi> = combine(
        services.registry.state,
        services.sessions.active.flatMapLatest { it?.auth ?: flowOf(null) },
        services.deviceKeys.views,
    ) { registry, auth, views -> ProfileSecurityMapper.map(registry, auth, views, services.deviceKeys.supported) }
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            ProfileSecurityMapper.map(
                services.registry.state.value,
                services.sessions.active.value?.auth?.value,
                services.deviceKeys.views.value,
                services.deviceKeys.supported,
            ),
        )

    private val _enrol = MutableStateFlow<EnrolStep?>(null)
    val enrol: StateFlow<EnrolStep?> = _enrol.asStateFlow()

    /** Result of the last enrolment, for the snackbar (consumed by the screen). */
    private val _enrolled = MutableStateFlow<DeviceKeyEnrolOutcome.Enrolled?>(null)
    val enrolled: StateFlow<DeviceKeyEnrolOutcome.Enrolled?> = _enrolled.asStateFlow()

    var password by mutableStateOf("")
    var code by mutableStateOf("")

    /** Reads every server's row (on open, on resume, after an action). */
    fun refreshAll() {
        if (!services.deviceKeys.supported) return
        services.registry.state.value.profiles.forEach { p -> viewModelScope.launch { services.deviceKeys.refresh(p.id) } }
    }

    fun refresh(serverId: ServerId) {
        viewModelScope.launch { services.deviceKeys.refresh(serverId) }
    }

    private var requestTaken = false

    /**
     * The enrolment asked by the screen's opener (the proposal), taken ONCE
     * per ViewModel: a recomposition after a rotation does not restart it.
     */
    fun takeEnrolRequest(serverId: ServerId) {
        if (requestTaken) return
        requestTaken = true
        startEnrol(serverId)
    }

    /** « Activer » / « Réactiver » (or the proposal's « Activer »): the explanation first. */
    fun startEnrol(serverId: ServerId) {
        val profile = services.registry.state.value.byId(serverId) ?: return
        clearSecrets()
        _enrol.value = EnrolStep.Explain(serverId, profile.displayName, sso = isSso(serverId))
    }

    /**
     * Whether the account signed in on [serverId] is an Obligate one: the
     * row's (read with the list), else the session user's (`og_` fallback).
     */
    private fun isSso(serverId: ServerId): Boolean {
        if (services.deviceKeys.views.value[serverId]?.sso == true) return true
        val user = (services.sessions.session(serverId)?.auth?.value as? AuthState.SignedIn)?.probe?.user ?: return false
        return user.isObligate || user.username.startsWith("og_")
    }

    /** « Continuer » of a local account: the password + code step. (An Obligate account goes straight to [submit].) */
    fun continueEnrol() {
        val step = _enrol.value as? EnrolStep.Explain ?: return
        if (step.sso) return
        _enrol.value = EnrolStep.Credentials(step.serverId, step.serverName)
    }

    /** Local account: the password and a 6-digit code are there. */
    val canSubmit: Boolean get() = password.isNotEmpty() && code.length == CODE_LENGTH && code.all(Char::isDigit)

    /** What the sheet's main button may do now, per variant (SSO: nothing to type). */
    fun canSubmit(step: EnrolStep): Boolean = when (step) {
        is EnrolStep.Explain -> step.sso
        is EnrolStep.Credentials -> !step.busy && (step.sso || canSubmit)
    }

    /**
     * « Activer »: begin → key → fingerprint → finish. The secrets are cleared
     * as soon as they are sent. [signer] is the CURRENT activity's (passed by
     * the screen at the tap): this ViewModel outlives a rotation, an activity
     * captured when it was created would be a destroyed one. Null (previews,
     * no FragmentActivity): « Activer » explains why it cannot.
     *
     * Obligate account (« Reconfirmer avec Obligate », from the explanation or
     * after a refusal): the repository opens the Obligate sheet, then calls
     * `begin` at once with the installation id only — never a password.
     */
    fun submit(signer: DeviceSigner?) {
        when (val step = _enrol.value) {
            is EnrolStep.Explain -> if (step.sso) submitSso(EnrolStep.Credentials(step.serverId, step.serverName, sso = true), signer)
            is EnrolStep.Credentials -> if (step.sso) submitSso(step, signer) else submitLocal(step, signer)
            null -> Unit
        }
    }

    private fun submitLocal(step: EnrolStep.Credentials, signer: DeviceSigner?) {
        if (step.busy || !canSubmit) return
        signer ?: run {
            _enrol.value = step.copy(problem = EnrolProblem.BIOMETRIC_UNAVAILABLE, wrong = false, detail = null)
            return
        }
        val proof = EnrolProof.PasswordAndCode(password, code)
        clearSecrets()
        _enrol.value = step.copy(busy = true, wrong = false, problem = null, detail = null)
        viewModelScope.launch {
            val out = services.deviceKeys.enrol(step.serverId, proof, signer, enrolPrompt(step.serverName))
            _enrol.value = when (out) {
                is DeviceKeyEnrolOutcome.Enrolled -> {
                    _enrolled.value = out
                    null
                }
                DeviceKeyEnrolOutcome.WrongCredentials -> step.copy(busy = false, wrong = true)
                DeviceKeyEnrolOutcome.Cancelled -> step.copy(busy = false)
                is DeviceKeyEnrolOutcome.Failed -> step.copy(busy = false, problem = out.problem, detail = out.detail)
            }
        }
    }

    private fun submitSso(step: EnrolStep.Credentials, signer: DeviceSigner?) {
        if (step.busy) return
        clearSecrets()
        val base = step.copy(busy = false, wrong = false, problem = null, detail = null)
        signer ?: run {
            _enrol.value = base.copy(problem = EnrolProblem.BIOMETRIC_UNAVAILABLE)
            return
        }
        _enrol.value = base.copy(busy = true)
        viewModelScope.launch {
            val out = services.deviceKeys.enrol(step.serverId, EnrolProof.SsoReauth, signer, enrolPrompt(step.serverName))
            _enrol.value = when (out) {
                is DeviceKeyEnrolOutcome.Enrolled -> {
                    _enrolled.value = out
                    null
                }
                // No password nor code to be wrong for an Obligate account: confirm again.
                DeviceKeyEnrolOutcome.WrongCredentials -> base.copy(problem = EnrolProblem.REAUTH_REQUIRED)
                // Sheet or fingerprint closed: « Reconfirmer avec Obligate » is offered again.
                DeviceKeyEnrolOutcome.Cancelled -> base
                is DeviceKeyEnrolOutcome.Failed -> base.copy(problem = out.problem, detail = out.detail)
            }
        }
    }

    fun cancelEnrol() {
        if ((_enrol.value as? EnrolStep.Credentials)?.busy == true) return
        clearSecrets()
        _enrol.value = null
    }

    fun enrolledShown() {
        _enrolled.value = null
    }

    private fun clearSecrets() {
        password = ""
        code = ""
    }

    override fun onCleared() {
        clearSecrets()
    }

    companion object {
        const val CODE_LENGTH = 6
    }
}
