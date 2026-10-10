package tools.obli.core.security

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceKeyStatus
import tools.obli.core.network.DeviceStepUp

/**
 * The first-2FA proposal hook: [ActionPrompter.codeAccepted] after a
 * code went through on an unbound session of the client's origin, never
 * otherwise, and never changing the result.
 */
class ActionRunnerCodeAcceptedTest {
    private val origin = "https://obliance.example.com"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val record = DeviceKeyRecord(origin, 42, "john.smith", keyId, DeviceKeyAlias.of(origin, 42, "install"), "install", DeviceKeyLevel.TEE, 1)
    private val spec = ActionSpec("device.reboot", Tier.T0, "Redémarrer", "SRV-DEMO01", "Obliance Prod › ACME")

    private class Prompter(private val throwOnAccepted: Boolean = false) : ActionPrompter {
        val accepted = mutableListOf<String>()
        val codes = ArrayDeque<TwoFactorAnswer?>()
        override suspend fun confirmTenantSwitch(spec: ActionSpec, tenantName: String) = true
        override suspend fun confirm(spec: ActionSpec) = true
        override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean): TwoFactorAnswer? = codes.removeFirstOrNull()
        override suspend fun approvalRequested(spec: ActionSpec, approvalId: Long) {}
        override suspend fun unlockPrivacy(spec: ActionSpec, feature: String?, passwordSet: Boolean) = false
        override suspend fun sessionExpired() {}
        override fun codeAccepted(spec: ActionSpec, origin: String) {
            accepted += origin
            if (throwOnAccepted) throw IllegalStateException("host failed")
        }
    }

    private fun <T> scripted(vararg answers: ApiOutcome<T>): suspend (JsonObject) -> ApiOutcome<T> {
        val queue = ArrayDeque(answers.toList())
        return { queue.removeFirst() }
    }

    private fun stepUp(from: String? = origin, device: DeviceStepUp? = null) =
        ApiOutcome.StepUpRequired("command.reboot", "203.0.113.21", origin = from, device = device)

    @Test fun aCodeOnAnUnboundSessionOfTheClientsOriginIsReported() = runBlocking {
        val p = Prompter().apply { codes += TwoFactorAnswer("482913", false) }
        val r = ActionRunner(p, DeviceKeyResolver { null }).run(spec, call = scripted(stepUp(), ApiOutcome.Ok(Unit)))
        assertEquals(ActionResult.Done(Unit), r)
        assertEquals(listOf(origin), p.accepted)
    }

    @Test fun acceptedWithABodyToo() = runBlocking {
        val p = Prompter().apply { codes += TwoFactorAnswer("482913", false) }
        val r = ActionRunner(p).run(spec, call = scripted(stepUp(), ApiOutcome.Accepted("x")))
        assertEquals(ActionResult.Done("x"), r)
        assertEquals(listOf(origin), p.accepted)
    }

    @Test fun noStepUpNoProposal() = runBlocking {
        val p = Prompter()
        ActionRunner(p).run(spec, call = scripted(ApiOutcome.Ok(Unit)))
        assertTrue(p.accepted.isEmpty())
    }

    @Test fun anAnswerOfAnotherOriginIsNeverReported() = runBlocking {
        val p = Prompter().apply { codes += TwoFactorAnswer("482913", false) }
        ActionRunner(p).run(spec, call = scripted(stepUp(from = null), ApiOutcome.Ok(Unit)))
        assertTrue(p.accepted.isEmpty())
    }

    @Test fun aSessionWithADevicePartIsNotProposedAgain() = runBlocking {
        // Policy off (disabled) or a bound session: the server already knows a key of this phone.
        val p = Prompter().apply { codes += TwoFactorAnswer("482913", false) }
        ActionRunner(p).run(spec, call = scripted(stepUp(device = DeviceStepUp(DeviceKeyStatus.DISABLED)), ApiOutcome.Ok(Unit)))
        assertTrue(p.accepted.isEmpty())
    }

    @Test fun aKeyKnownLocallyIsNotProposed() = runBlocking {
        val p = Prompter().apply { codes += TwoFactorAnswer("482913", false) }
        ActionRunner(p, DeviceKeyResolver { record }).run(spec, call = scripted(stepUp(), ApiOutcome.Ok(Unit)))
        assertTrue(p.accepted.isEmpty())
    }

    @Test fun aFailureAfterTheCodeIsNotReported() = runBlocking {
        val p = Prompter().apply { codes += TwoFactorAnswer("482913", false) }
        val r = ActionRunner(p).run(spec, call = scripted(stepUp(), ApiOutcome.AgentOffline("offline")))
        assertEquals(ActionResult.Failed(ApiOutcome.AgentOffline("offline")), r)
        assertTrue(p.accepted.isEmpty())
    }

    @Test fun aFailingHostNeverChangesTheResult() = runBlocking {
        val p = Prompter(throwOnAccepted = true).apply { codes += TwoFactorAnswer("482913", false) }
        val r = ActionRunner(p).run(spec, call = scripted(stepUp(), ApiOutcome.Ok(7)))
        assertEquals(ActionResult.Done(7), r)
        assertEquals(listOf(origin), p.accepted)
    }
}
