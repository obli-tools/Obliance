package tools.obli.obliance.data.sample

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import tools.obli.core.model.ServerId
import tools.obli.core.network.ApiOutcome
import tools.obli.core.security.DeviceKeyAlias
import tools.obli.core.security.DeviceKeyHardware
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.DeviceKeyRecord
import tools.obli.core.security.DeviceKeyResolver
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.EnrolProof
import tools.obli.core.security.SignPrompt
import tools.obli.obliance.api.DeviceKeyEligibility
import tools.obli.obliance.api.DeviceKeyInfo
import tools.obli.obliance.api.DeviceKeyList
import tools.obli.obliance.api.DeviceKeyPolicy
import tools.obli.obliance.data.DeviceKeyEnrolOutcome
import tools.obli.obliance.data.DeviceKeyProposal
import tools.obli.obliance.data.DeviceKeyServerState
import tools.obli.obliance.data.DeviceKeyView
import tools.obli.obliance.data.DeviceKeysRepository
import tools.obli.obliance.data.EnrolProblem

/**
 * In-memory [DeviceKeysRepository] over the sample data, for previews
 * and screenshot tests: Obliance Prod and Dev are Obligate accounts
 * (« Pas encore disponible pour les comptes Obligate », before SSO device keys), Obliance
 * Qual is a local account whose phone is enrolled (StrongBox), with a second
 * phone in its list. [views] may be replaced by a test; enrol succeeds with any
 * 6-digit code and password "secret".
 */
class SampleDeviceKeys(
    initial: Map<ServerId, DeviceKeyView> = defaultViews(),
    invalidated: Set<ServerId> = emptySet(),
    proposal: DeviceKeyProposal? = null,
) : DeviceKeysRepository {
    private val _views = MutableStateFlow(initial)
    private val _invalidated = MutableStateFlow(invalidated)
    private val _proposal = MutableStateFlow(proposal)

    override val supported: Boolean get() = true
    override val views: StateFlow<Map<ServerId, DeviceKeyView>> = _views.asStateFlow()
    override val invalidatedServers: StateFlow<Set<ServerId>> = _invalidated.asStateFlow()
    override val proposal: StateFlow<DeviceKeyProposal?> = _proposal.asStateFlow()
    override val resolver: DeviceKeyResolver? get() = null
    override val hardware: DeviceKeyHardware? get() = null

    override suspend fun refresh(serverId: ServerId): DeviceKeyView =
        _views.value[serverId] ?: DeviceKeyView(serverId, DeviceKeyServerState.NotAvailable).also { v -> _views.update { it + (serverId to v) } }

    override suspend fun enrol(serverId: ServerId, proof: EnrolProof, signer: DeviceSigner, prompt: SignPrompt): DeviceKeyEnrolOutcome {
        val sso = _views.value[serverId]?.sso == true
        when (proof) {
            is EnrolProof.PasswordAndCode -> if (sso || proof.password != "secret" || proof.code.length != 6) return DeviceKeyEnrolOutcome.WrongCredentials
            // No Obligate sheet here: the sample re-authentication always succeeds.
            EnrolProof.SsoReauth -> if (!sso) return DeviceKeyEnrolOutcome.Failed(EnrolProblem.FAILED, "proof")
        }
        val record = record(serverId)
        _views.update { it + (serverId to DeviceKeyView(serverId, DeviceKeyServerState.Active(record, DeviceKeyLevel.STRONGBOX, bound = true), list(record.keyId, origin(serverId), ssoSupported = sso), sso = sso)) }
        _invalidated.update { it - serverId }
        return DeviceKeyEnrolOutcome.Enrolled(record, DeviceKeyLevel.STRONGBOX)
    }

    override suspend fun revoke(serverId: ServerId, keyId: String): ApiOutcome<Unit> {
        _views.update { views ->
            val view = views[serverId] ?: return@update views
            val list = view.list?.let { l -> l.copy(keys = l.keys.filterNot { it.id == keyId }) }
            val state = (view.state as? DeviceKeyServerState.Active)?.takeIf { it.record.keyId == keyId }?.let { DeviceKeyServerState.NotEnrolled } ?: view.state
            views + (serverId to view.copy(state = state, list = list))
        }
        return ApiOutcome.Ok(Unit)
    }

    override suspend fun revokeAll(serverId: ServerId): ApiOutcome<Unit> {
        _views.update { views ->
            val view = views[serverId] ?: return@update views
            views + (serverId to view.copy(state = DeviceKeyServerState.NotEnrolled, list = view.list?.copy(keys = emptyList())))
        }
        return ApiOutcome.Ok(Unit)
    }

    override fun localKey(serverId: ServerId): DeviceKeyRecord? = (_views.value[serverId]?.state as? DeviceKeyServerState.Active)?.record

    override fun answerProposal(accepted: Boolean) {
        _proposal.value = null
    }

    companion object {
        const val THIS_PHONE_KEY = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
        const val OTHER_PHONE_KEY = "0f8fad5b-d9cb-469f-a165-70867728950e"

        private fun origin(serverId: ServerId) = SampleData.profiles.first { it.id == serverId }.origin

        fun record(serverId: ServerId = SampleData.QUAL): DeviceKeyRecord {
            val origin = origin(serverId)
            val user = SampleData.probe(serverId).user
            return DeviceKeyRecord(origin, user.id, user.username, THIS_PHONE_KEY, DeviceKeyAlias.of(origin, user.id, "0123456789abcdef0123456789abcdef"), "0123456789abcdef0123456789abcdef", DeviceKeyLevel.STRONGBOX, 1_790_000_000_000)
        }

        /** The account's phones on Obliance Qual: this one (StrongBox, this session) and a tablet (TEE). */
        fun list(currentKey: String? = THIS_PHONE_KEY, origin: String = origin(SampleData.QUAL), ssoSupported: Boolean = false): DeviceKeyList = DeviceKeyList(
            policy = DeviceKeyPolicy(enabled = true, loginEnabled = true, requireAttestation = true, strictSession = true, originConfigured = true, ssoSupported = ssoSupported),
            allowedOrigins = listOf(origin),
            boundKeyId = currentKey,
            eligibility = DeviceKeyEligibility(ok = true),
            keys = listOfNotNull(
                currentKey?.let {
                    DeviceKeyInfo(it, "Téléphone de John", "android", "strongbox", 20260905, "2026-09-12T08:14:00Z", "2026-09-25T01:14:00Z", "203.0.113.21", 23, current = true)
                },
                DeviceKeyInfo(OTHER_PHONE_KEY, "Tablette de John", "android", "tee", 20260801, "2026-08-30T17:02:00Z", "2026-09-20T09:41:00Z", "10.0.0.24", 4, current = false),
            ),
        )

        fun defaultViews(): Map<ServerId, DeviceKeyView> = mapOf(
            SampleData.PROD to DeviceKeyView(SampleData.PROD, DeviceKeyServerState.SsoUnsupported, sso = true),
            SampleData.DEV to DeviceKeyView(SampleData.DEV, DeviceKeyServerState.SsoUnsupported, sso = true),
            SampleData.QUAL to DeviceKeyView(SampleData.QUAL, DeviceKeyServerState.Active(record(), DeviceKeyLevel.STRONGBOX, bound = true), list()),
        )

        /**
         * SSO device keys on (servers with `DEVICE_KEYS_SSO_ENABLED`): Obliance Prod's
         * Obligate account not enrolled yet (« Activer » through Obligate), Obliance
         * Dev's Obligate account enrolled (StrongBox, bound), Obliance Qual unchanged.
         */
        fun ssoViews(): Map<ServerId, DeviceKeyView> {
            val devRecord = record(SampleData.DEV)
            return mapOf(
                SampleData.PROD to DeviceKeyView(SampleData.PROD, DeviceKeyServerState.NotEnrolled, list(null, origin(SampleData.PROD), ssoSupported = true), sso = true),
                SampleData.DEV to DeviceKeyView(
                    SampleData.DEV,
                    DeviceKeyServerState.Active(devRecord, DeviceKeyLevel.STRONGBOX, bound = true),
                    list(devRecord.keyId, origin(SampleData.DEV), ssoSupported = true),
                    sso = true,
                ),
                SampleData.QUAL to DeviceKeyView(SampleData.QUAL, DeviceKeyServerState.Active(record(), DeviceKeyLevel.STRONGBOX, bound = true), list()),
            )
        }
    }
}
