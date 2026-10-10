package tools.obli.core.security

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceKeyStatus
import tools.obli.core.network.DevicePurpose
import tools.obli.core.network.DeviceStepUp

/**
 * The runner fills what the screens' specs leave out:
 * the session tenant the app last read for the answer's origin
 * (a challenge of another tenant is never signed) and the server's name (always
 * in the fingerprint prompt); and a right code already used (`codeUsed`) is told
 * apart from a wrong one.
 */
class ActionRunnerSessionInfoTest {
    private val origin = "https://obliance.example.com"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val bulkId = "0f8fad5b-d9cb-469f-a165-70867728950e"
    private val record = DeviceKeyRecord(origin, 42, "john.smith", keyId, DeviceKeyAlias.of(origin, 42, "install"), "install", DeviceKeyLevel.STRONGBOX, 1)
    private val keys = DeviceKeyResolver { if (it == origin) record else null }
    private val sig = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)

    /** What a device screen builds today: scope text only, no tenant id, no server name. */
    private val reboot = ActionSpec("device.reboot", Tier.T0, "Redémarrer", "SRV-DEMO06", "ACME")

    private fun challenge(n: Int = 1, tenantId: Long? = 3, bulk: String? = null) = DeviceChallenge(
        1, keyId, "00000000-0000-4000-8000-%012d".format(n), DevicePurpose.STEPUP, 42, tenantId, "Default",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "command.reboot",
        "42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4", 1790000120, bulk,
    )

    private fun stepUp(c: DeviceChallenge? = challenge()) = ApiOutcome.StepUpRequired(
        "command.reboot", null, trustIpAllowed = false, codeRequiresPassword = true,
        device = DeviceStepUp(DeviceKeyStatus.ACTIVE, c), origin = origin,
    )

    private class Info(var tenant: Long? = 3, var name: String? = "Obliance Prod") : ActionSessionInfo {
        val changed = mutableListOf<String>()
        override fun tenantOf(origin: String): Long? = tenant
        override fun serverNameOf(origin: String): String? = name
        override fun tenantChanged(origin: String) {
            changed += origin
        }
    }

    private class Prompter : ActionPrompter {
        val log = mutableListOf<String>()
        val specs = mutableListOf<ActionSpec>()
        val signs = ArrayDeque<SignResult>()
        val codes = ArrayDeque<TwoFactorAnswer?>()
        val options = mutableListOf<TwoFactorOptions>()
        override suspend fun confirmTenantSwitch(spec: ActionSpec, tenantName: String) = true
        override suspend fun confirm(spec: ActionSpec) = true
        override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean): TwoFactorAnswer? = error("4-argument variant")
        override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean, options: TwoFactorOptions): TwoFactorAnswer? {
            log += "2fa:$previousWasWrong"
            this.options += options
            return codes.removeFirstOrNull()
        }
        override suspend fun approvalRequested(spec: ActionSpec, approvalId: Long) {}
        override suspend fun unlockPrivacy(spec: ActionSpec, feature: String?, passwordSet: Boolean) = false
        override suspend fun sessionExpired() {}
        override suspend fun signStepUp(spec: ActionSpec, request: DeviceSignRequest): SignResult {
            log += "sign:${request.count}"
            specs += spec
            return signs.removeFirstOrNull() ?: SignResult.Cancelled
        }
    }

    private fun <T> scripted(vararg answers: ApiOutcome<T>): suspend (JsonObject) -> ApiOutcome<T> {
        val queue = ArrayDeque(answers.toList())
        return { queue.removeFirst() }
    }

    @Test fun theSessionTenantAndTheServerNameReachThePrompt() = runBlocking {
        val p = Prompter().apply { signs += SignResult.Signed(sig) }
        val info = Info()
        assertEquals(ActionResult.Done(Unit), ActionRunner(p, keys, sessionInfo = info).run(reboot, call = scripted(stepUp(), ApiOutcome.Ok(Unit))))
        val shown = p.specs.single()
        assertEquals("Obliance Prod", shown.serverName)
        assertEquals(3L, shown.tenantId)
        assertEquals("the rest of the spec is the screen's", reboot, shown.copy(serverName = null, tenantId = null))
        assertTrue(info.changed.isEmpty())
    }

    /** The session tenant moved behind the screen (web view, notification) → « Le tenant a changé ». */
    @Test fun aChallengeOfAnotherSessionTenantIsNeverSigned() = runBlocking {
        val p = Prompter()
        val info = Info(tenant = 4)
        val r = ActionRunner(p, keys, sessionInfo = info).run(reboot, call = scripted<Unit>(stepUp(challenge(tenantId = 1))))
        assertEquals(ActionResult.Blocked(ActionRunner.TENANT_CHANGED), r)
        assertTrue("no prompt at all", p.log.isEmpty())
        assertEquals("the app reads that session again", listOf(origin), info.changed)
    }

    @Test fun theSpecsOwnTenantAndServerWin() = runBlocking {
        val p = Prompter().apply { signs += SignResult.Signed(sig) }
        val spec = reboot.copy(tenantId = 3, serverName = "Prod (écran)")
        assertEquals(ActionResult.Done(Unit), ActionRunner(p, keys, sessionInfo = Info(tenant = 9, name = "Autre")).run(spec, call = scripted(stepUp(), ApiOutcome.Ok(Unit))))
        assertEquals("Prod (écran)", p.specs.single().serverName)
        assertEquals(3L, p.specs.single().tenantId)
        val blocked = ActionRunner(Prompter(), keys, sessionInfo = Info(tenant = 3)).run(spec.copy(tenantId = 4), call = scripted<Unit>(stepUp()))
        assertEquals(ActionResult.Blocked(ActionRunner.TENANT_CHANGED), blocked)
    }

    @Test fun anUnknownSessionTenantIsNotChecked() = runBlocking {
        val p = Prompter().apply { signs += SignResult.Signed(sig) }
        val info = Info(tenant = null, name = null)
        assertEquals(ActionResult.Done(Unit), ActionRunner(p, keys, sessionInfo = info).run(reboot, call = scripted(stepUp(challenge(tenantId = 7)), ApiOutcome.Ok(Unit))))
        assertEquals(null, p.specs.single().serverName)
        // Without any session info: as before.
        val p2 = Prompter().apply { signs += SignResult.Signed(sig) }
        assertEquals(ActionResult.Done(Unit), ActionRunner(p2, keys).run(reboot, call = scripted(stepUp(challenge(tenantId = 7)), ApiOutcome.Ok(Unit))))
    }

    @Test fun aBulkRunChecksTheSessionTenantToo() = runBlocking {
        val p = Prompter()
        val info = Info(tenant = 3)
        val targets = listOf(1, 2)
        val answers = mapOf(1 to stepUp(challenge(1, tenantId = 3, bulk = bulkId)), 2 to stepUp(challenge(2, tenantId = 5, bulk = bulkId)))
        val r = ActionRunner(p, keys, sessionInfo = info).runBulk(reboot.copy(targetCount = 2), targets, bulkId = bulkId) { t, _ -> answers.getValue(t) }
        assertEquals(ActionResult.Blocked(ActionRunner.TENANT_CHANGED), r)
        assertTrue(p.log.isEmpty())
        assertEquals(listOf(origin), info.changed)

        // Same tenant: one prompt, naming the server.
        val ok = Prompter().apply { signs += SignResult.Signed(sig) }
        val sent = mutableMapOf<Int, Int>()
        val done = ActionRunner(ok, keys, sessionInfo = Info()).runBulk(reboot.copy(targetCount = 2), targets, bulkId = bulkId) { t, _ ->
            val n = (sent[t] ?: 0) + 1
            sent[t] = n
            if (n == 1) stepUp(challenge(t, tenantId = 3, bulk = bulkId)) else ApiOutcome.Ok("ok")
        }
        assertTrue(done is ActionResult.Done)
        assertEquals("Obliance Prod", ok.specs.single().serverName)
        assertEquals(2, ok.specs.single().targetCount)
    }

    @Test fun aCodeAlreadyUsedIsToldApartFromAWrongOne() = runBlocking {
        val p = Prompter().apply {
            codes += TwoFactorAnswer("482913", false)
            codes += TwoFactorAnswer("482913", false)
            codes += TwoFactorAnswer("517204", false)
        }
        val stepNoDevice = ApiOutcome.StepUpRequired("command.reboot", null)
        val r = ActionRunner(p, keys).run(
            reboot,
            call = scripted(stepNoDevice, ApiOutcome.StepUpRejected(codeUsed = true), ApiOutcome.StepUpRejected(), ApiOutcome.Ok(Unit)),
        )
        assertEquals(ActionResult.Done(Unit), r)
        assertEquals(listOf("2fa:false", "2fa:true", "2fa:true"), p.log)
        assertEquals(listOf(false, true, false), p.options.map { it.previousCodeUsed })
    }

    @Test fun theLastCodeUsedIsKeptInTheFailure() = runBlocking {
        val p = Prompter().apply { repeat(3) { codes += TwoFactorAnswer("482913", false) } }
        val r = ActionRunner(p, keys).run(
            reboot,
            call = scripted<Unit>(
                ApiOutcome.StepUpRequired("command.reboot", null),
                ApiOutcome.StepUpRejected(codeUsed = true),
                ApiOutcome.StepUpRejected(codeUsed = true),
                ApiOutcome.StepUpRejected(codeUsed = true),
            ),
        )
        assertEquals(ActionResult.Failed(ApiOutcome.StepUpRejected(codeUsed = true)), r)
        assertFalse(p.options.first().previousCodeUsed)
        assertTrue(p.options.drop(1).all { it.previousCodeUsed })
    }

    @Test fun aBulkCodeAlreadyUsedIsFlaggedForTheNextPrompt() = runBlocking {
        val p = Prompter().apply {
            codes += TwoFactorAnswer("482913", false)
            codes += TwoFactorAnswer("517204", false)
        }
        val queues = mapOf(
            1 to ArrayDeque(listOf<ApiOutcome<String>>(ApiOutcome.StepUpRequired("command.reboot", null), ApiOutcome.StepUpRejected(codeUsed = true), ApiOutcome.Ok("a"))),
        )
        val r = ActionRunner(p, keys).runBulk(reboot, listOf(1), bulkId = bulkId) { t, _ -> queues.getValue(t).removeFirst() }
        assertEquals(mapOf(1 to "a"), (r as ActionResult.Done).value.values())
        assertEquals(listOf(false, true), p.options.map { it.previousCodeUsed })
    }
}
