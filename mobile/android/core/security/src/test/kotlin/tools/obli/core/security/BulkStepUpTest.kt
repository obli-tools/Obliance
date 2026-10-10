package tools.obli.core.security

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceError
import tools.obli.core.network.DeviceKeyStatus
import tools.obli.core.network.DevicePurpose
import tools.obli.core.network.DeviceStepUp
import tools.obli.core.network.FailureKind

/** One fingerprint for a per-device loop. */
class BulkStepUpTest {
    private val origin = "https://obliance.example.com"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val bulkId = "0f8fad5b-d9cb-469f-a165-70867728950e"
    private val record = DeviceKeyRecord(origin, 42, "john.smith", keyId, DeviceKeyAlias.of(origin, 42, "install"), "install", DeviceKeyLevel.STRONGBOX, 1)
    private val keys = DeviceKeyResolver { if (it == origin) record else null }
    private val sig = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)
    private val spec = ActionSpec("device.reboot", Tier.T0, "Redémarrer", "3 appareils", "Obliance Prod › ACME", targetCount = 3, tenantId = 3, serverName = "Obliance Prod")

    private fun id(n: Int) = "00000000-0000-4000-8000-%012d".format(n)

    private fun challenge(n: Int, tenantId: Long? = 3, bulk: String? = bulkId, action: String = "command.reboot") = DeviceChallenge(
        1, keyId, id(n), DevicePurpose.STEPUP, 42, tenantId, "ACME",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", action,
        "42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4", 1790000120, bulk,
    )

    private fun stepUp(c: DeviceChallenge? = null, error: DeviceError? = null, status: DeviceKeyStatus? = DeviceKeyStatus.ACTIVE, password: Boolean = true) =
        ApiOutcome.StepUpRequired(
            "command.reboot", "203.0.113.21", trustIpAllowed = !password, codeRequiresPassword = password,
            device = status?.let { DeviceStepUp(it, c, error) }, origin = origin,
        )

    private class FakePrompter : ActionPrompter {
        val log = mutableListOf<String>()
        val signs = ArrayDeque<SignResult>()
        val codes = ArrayDeque<TwoFactorAnswer?>()
        val signed = mutableListOf<DeviceSignRequest>()
        val specs = mutableListOf<ActionSpec>()
        val options = mutableListOf<TwoFactorOptions>()
        override suspend fun confirmTenantSwitch(spec: ActionSpec, tenantName: String) = true
        override suspend fun confirm(spec: ActionSpec) = true.also { log += "confirm" }
        override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean): TwoFactorAnswer? = error("4-argument variant")
        override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean, options: TwoFactorOptions): TwoFactorAnswer? {
            log += "2fa:$previousWasWrong"
            this.options += options
            return codes.removeFirstOrNull()
        }
        override suspend fun approvalRequested(spec: ActionSpec, approvalId: Long) {}
        override suspend fun unlockPrivacy(spec: ActionSpec, feature: String?, passwordSet: Boolean) = false
        override suspend fun sessionExpired() { log += "expired" }
        override suspend fun signStepUp(spec: ActionSpec, request: DeviceSignRequest): SignResult {
            log += "sign:${request.count}"
            signed += request
            specs += spec
            return signs.removeFirstOrNull() ?: SignResult.Cancelled
        }
        override suspend fun deviceKeyInvalidated(origin: String, keyId: String) { log += "invalidated" }
        var reauth: SsoReauthResult = SsoReauthResult.Success
        override suspend fun reauthenticateSso(origin: String, spec: ActionSpec?): SsoReauthResult = reauth.also { log += "reauth" }
    }

    /** Answers per target, in order; records every (target, extra). */
    private class Script(vararg answers: Pair<Int, List<ApiOutcome<String>>>) {
        val queues = answers.associate { (t, list) -> t to ArrayDeque(list) }
        val sent = mutableListOf<Pair<Int, JsonObject>>()
        val call: suspend (Int, JsonObject) -> ApiOutcome<String> = { t, extra ->
            sent += t to extra
            queues.getValue(t).removeFirst()
        }
        fun of(t: Int) = sent.filter { it.first == t }.map { it.second }
    }

    private fun runner(p: ActionPrompter, k: DeviceKeyResolver? = keys) = ActionRunner(p, k)

    @Test fun oneFingerprintForTheWholeLoop() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Signed(sig) }
        val s = Script(
            1 to listOf(stepUp(challenge(1)), ApiOutcome.Ok("a")),
            2 to listOf(stepUp(challenge(2)), ApiOutcome.Ok("b")),
            3 to listOf(stepUp(challenge(3)), ApiOutcome.Ok("c")),
        )
        val r = runner(p).runBulk(spec, listOf(1, 2, 3), bulkId = bulkId, call = s.call)
        val report = (r as ActionResult.Done).value
        assertEquals(mapOf(1 to "a", 2 to "b", 3 to "c"), report.values())
        assertEquals(listOf("sign:3"), p.log)
        assertEquals("Redémarrer", p.specs.single().title)
        assertEquals(3, p.specs.single().targetCount)
        // First pass: only the bulk id. Second pass: the SAME assertion, covering the 3 challenges.
        for (t in 1..3) {
            val (first, second) = s.of(t)
            assertEquals(setOf(ActionRunner.BULK_ID), first.keys)
            assertEquals(JsonPrimitive(bulkId), first[ActionRunner.BULK_ID])
            assertEquals(JsonPrimitive(bulkId), second[ActionRunner.BULK_ID])
            val a = second[DeviceAssertion.FIELD]!!.jsonObject
            assertEquals(JsonArray(listOf(id(1), id(2), id(3)).map(::JsonPrimitive)), a["challengeIds"])
            assertNull(second[ActionRunner.CODE])
        }
        assertEquals(s.of(1)[1], s.of(3)[1])
        val payload = String(p.signed.single().payload, Charsets.UTF_8)
        assertTrue(payload.contains("\ncount:3\n"))
    }

    @Test fun targetsWithoutAStepUpAreDoneInTheFirstPass() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Signed(sig) }
        val s = Script(
            1 to listOf(ApiOutcome.Ok("a")),
            2 to listOf(stepUp(challenge(2)), ApiOutcome.Ok("b")),
            3 to listOf(ApiOutcome.AgentOffline("offline")),
        )
        val report = (runner(p).runBulk(spec, listOf(1, 2, 3), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(listOf(1, 2), report.succeeded)
        assertEquals(ApiOutcome.AgentOffline("offline"), report.failed[3])
        assertEquals(listOf("sign:1"), p.log)
        assertEquals(1, s.of(1).size)
        assertEquals(1, s.of(3).size)
    }

    @Test fun anExpiredChallengeGetsOneMoreRoundNeverAThird() = runBlocking {
        val p = FakePrompter().apply { repeat(3) { signs += SignResult.Signed(sig) }; codes += TwoFactorAnswer("482913", false, "pw") }
        val s = Script(
            1 to listOf(stepUp(challenge(1)), ApiOutcome.Ok("a")),
            2 to listOf(
                stepUp(challenge(2)),
                stepUp(challenge(12), error = DeviceError.CHALLENGE_EXPIRED),
                stepUp(challenge(22), error = DeviceError.CHALLENGE_EXPIRED),
                ApiOutcome.Ok("b"),
            ),
        )
        val report = (runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(mapOf(1 to "a", 2 to "b"), report.values())
        assertEquals(listOf("sign:2", "sign:1", "2fa:false"), p.log)
        assertEquals(listOf(id(12)), p.signed[1].challenges.map { it.challengeId })
        val last = s.of(2).last()
        assertEquals(JsonPrimitive("482913"), last[ActionRunner.CODE])
        assertFalse(last.containsKey(DeviceAssertion.FIELD))
        assertEquals(JsonPrimitive(bulkId), last[ActionRunner.BULK_ID])
    }

    @Test fun useCodeAsksOneCodeForTheRestOfTheLoop() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.UseCode; codes += TwoFactorAnswer("482913", trustIp = true, password = "correct horse") }
        val s = Script(
            1 to listOf(stepUp(challenge(1)), ApiOutcome.Ok("a")),
            2 to listOf(stepUp(challenge(2)), ApiOutcome.Ok("b")),
        )
        val report = (runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(mapOf(1 to "a", 2 to "b"), report.values())
        assertEquals(listOf("sign:2", "2fa:false"), p.log)
        assertEquals(TwoFactorOptions(trustIpAllowed = false, passwordRequired = true), p.options.single())
        for (t in 1..2) {
            val body = s.of(t).last()
            assertEquals(JsonPrimitive("482913"), body[ActionRunner.CODE])
            assertEquals(JsonPrimitive("correct horse"), body[ActionRunner.PASSWORD])
            assertNull(body[ActionRunner.TRUST_IP])
            assertNull(body[DeviceAssertion.FIELD])
        }
    }

    @Test fun anUnboundSessionAsksTheCodeOnceWithTheIpBox() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", trustIp = true) }
        val s = Script(
            1 to listOf(stepUp(status = null, password = false), ApiOutcome.Ok("a")),
            2 to listOf(stepUp(status = null, password = false), ApiOutcome.Ok("b")),
        )
        val report = (runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(listOf(1, 2), report.succeeded)
        assertEquals(listOf("2fa:false"), p.log)
        assertEquals(JsonPrimitive(true), s.of(2).last()[ActionRunner.TRUST_IP])
    }

    @Test fun aWrongCodeIsAskedAgainAndResumesWhereItStopped() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("000000", false); codes += TwoFactorAnswer("482913", false) }
        val s = Script(
            1 to listOf(stepUp(status = null, password = false), ApiOutcome.StepUpRejected(), ApiOutcome.Ok("a")),
            2 to listOf(stepUp(status = null, password = false), ApiOutcome.Ok("b")),
        )
        val report = (runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(mapOf(1 to "a", 2 to "b"), report.values())
        assertEquals(listOf("2fa:false", "2fa:true"), p.log)
        assertEquals(2, s.of(2).size) // never sent with the wrong code
    }

    @Test fun aChallengeOfAnotherTenantBlocksBeforeAnySignature() = runBlocking {
        val p = FakePrompter()
        val s = Script(1 to listOf(stepUp(challenge(1, tenantId = 6))))
        assertEquals(ActionResult.Blocked(ActionRunner.TENANT_CHANGED), runner(p).runBulk(spec, listOf(1), bulkId = bulkId, call = s.call))
        assertTrue(p.signed.isEmpty())
    }

    @Test fun challengesThatCannotShareASignatureFallBackOnTheCode() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", false, "pw") }
        val s = Script(
            1 to listOf(stepUp(challenge(1, bulk = null)), ApiOutcome.Ok("a")),
            2 to listOf(stepUp(challenge(2, bulk = null)), ApiOutcome.Ok("b")),
        )
        val report = (runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(listOf(1, 2), report.succeeded)
        assertTrue("no bulk id: never one signature for two challenges", p.signed.isEmpty())
        assertEquals(listOf("2fa:false"), p.log)
    }

    @Test fun moreThanFiftyTargetsAreSignedFiftyAtATime() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Signed(sig); signs += SignResult.Signed(sig) }
        val targets = (1..51).toList()
        val s = Script(*targets.map { t -> t to listOf<ApiOutcome<String>>(stepUp(challenge(t)), ApiOutcome.Ok("ok$t")) }.toTypedArray())
        val report = (runner(p).runBulk(spec.copy(targetCount = 51), targets, bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(51, report.succeeded.size)
        assertEquals(listOf("sign:50", "sign:1"), p.log)
    }

    @Test fun cancellingBeforeAnythingWentThroughCancels() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Cancelled }
        val s = Script(1 to listOf(stepUp(challenge(1))), 2 to listOf(stepUp(challenge(2))))
        assertEquals(ActionResult.Cancelled, runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call))
        assertEquals(1, s.of(2).size)
    }

    @Test fun cancellingAfterSomeSuccessesReportsTheSkippedTargets() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Cancelled }
        val s = Script(1 to listOf(ApiOutcome.Ok("a")), 2 to listOf(stepUp(challenge(2))))
        val report = (runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(listOf(1), report.succeeded)
        assertEquals(listOf(2), report.skipped)
    }

    @Test fun anInvalidatedKeyEndsTheSession() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Invalidated }
        val s = Script(1 to listOf(stepUp(challenge(1))))
        assertEquals(ActionResult.SessionExpired, runner(p).runBulk(spec, listOf(1), bulkId = bulkId, call = s.call))
        assertEquals(listOf("sign:1", "invalidated"), p.log)
    }

    @Test fun anExpiredSessionEndsTheRunAtOnce() = runBlocking {
        val p = FakePrompter()
        val s = Script(1 to listOf(ApiOutcome.SessionExpired), 2 to listOf(ApiOutcome.Ok("b")))
        assertEquals(ActionResult.SessionExpired, runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call))
        assertEquals(listOf("expired"), p.log)
        assertTrue(s.of(2).isEmpty())
    }

    @Test fun aChallengeOfAnotherKeyIsNeverSigned() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", false, "pw") }
        val other = challenge(1).copy(keyId = "7c9e6679-7425-40de-944b-e07fc1f90ae7")
        val s = Script(1 to listOf(stepUp(other), ApiOutcome.Ok("a")))
        runner(p).runBulk(spec, listOf(1), bulkId = bulkId, call = s.call)
        assertTrue(p.signed.isEmpty())
        assertEquals(listOf("2fa:false"), p.log)
    }

    @Test fun theLocalTierIsAskedOnceForTheLoop() = runBlocking {
        val p = FakePrompter()
        val s = Script(1 to listOf(ApiOutcome.Ok("a")), 2 to listOf(ApiOutcome.Ok("b")))
        runner(p).runBulk(spec.copy(tier = Tier.T2), listOf(1, 2), bulkId = bulkId, call = s.call)
        assertEquals(listOf("confirm"), p.log)
    }

    /** SSO device keys: an Obligate account in a bound session re-confirms ONCE with Obligate, then one code for the loop. */
    @Test fun obligateReauthOnceThenOneCode() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", false) }
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        val s = Script(1 to listOf(sso, ApiOutcome.Ok("a")), 2 to listOf(sso, ApiOutcome.Ok("b")))
        val report = (runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(listOf(1, 2), report.succeeded)
        assertEquals(listOf("reauth", "2fa:false"), p.log)
        assertTrue(p.options.single().reauthRequired)
    }

    /**
     * The server keeps the re-authentication 5 min and a wrong code does not consume it: a
     * typo asks the code again, never Obligate again (the runner does the same). Only a new
     * step-up asking for it (window ended) re-authenticates again.
     */
    @Test fun aWrongCodeAfterTheObligateReauthDoesNotReauthAgain() = runBlocking {
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        val p = FakePrompter().apply {
            codes += TwoFactorAnswer("111111", false)
            codes += TwoFactorAnswer("482913", false)
        }
        val s = Script(1 to listOf(sso, ApiOutcome.StepUpRejected(), ApiOutcome.Ok("a")), 2 to listOf(sso, ApiOutcome.Ok("b")))
        val report = (runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call) as ActionResult.Done).value
        assertEquals(listOf(1, 2), report.succeeded)
        assertEquals(listOf("reauth", "2fa:false", "2fa:true"), p.log)
        // Still the « Identité reconfirmée » variant of the 2FA sheet for the second code.
        assertTrue(p.options.all { it.reauthRequired })

        // The window ended meanwhile: the server asks again (a new step-up), Obligate again.
        val q = FakePrompter().apply {
            codes += TwoFactorAnswer("111111", false)
            codes += TwoFactorAnswer("482913", false)
        }
        val t = Script(1 to listOf(sso, sso, ApiOutcome.Ok("a")), 2 to listOf(sso, ApiOutcome.Ok("b")))
        assertEquals(listOf(1, 2), (runner(q).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = t.call) as ActionResult.Done).value.succeeded)
        assertEquals(listOf("reauth", "2fa:false", "reauth", "2fa:false"), q.log)
    }

    @Test fun anEndedSessionDuringTheObligateReauthEndsTheRun() = runBlocking {
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        val p = FakePrompter().apply { reauth = SsoReauthResult.Failed("signed_out") }
        val s = Script(1 to listOf(ApiOutcome.Ok("a")), 2 to listOf(sso))
        assertEquals(ActionResult.SessionExpired, runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call))
        assertEquals(listOf("reauth", "expired"), p.log)
    }

    @Test fun aRefusedObligateReauthIsReported() = runBlocking {
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        // Nothing went through: Blocked, never a silent cancel.
        val p = FakePrompter().apply { reauth = SsoReauthResult.Failed("identity") }
        val s = Script(1 to listOf(sso), 2 to listOf(sso))
        assertEquals(ActionResult.Blocked(ActionRunner.SSO_REAUTH_FAILED), runner(p).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = s.call))
        assertEquals(listOf("reauth"), p.log)
        // Some went through: the others fail with that reason in the report.
        val q = FakePrompter().apply { reauth = SsoReauthResult.Failed("no_otp") }
        val t = Script(1 to listOf(ApiOutcome.Ok("a")), 2 to listOf(sso))
        val report = (runner(q).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = t.call) as ActionResult.Done).value
        assertEquals(listOf(1), report.succeeded)
        assertEquals(ApiOutcome.Failure(null, FailureKind.CLIENT, ActionRunner.SSO_REAUTH_FAILED), report.failed[2])
        // Closed by the user: cancelled.
        val r = FakePrompter().apply { reauth = SsoReauthResult.Cancelled }
        assertEquals(ActionResult.Cancelled, runner(r).runBulk(spec, listOf(1, 2), bulkId = bulkId, call = Script(1 to listOf(sso), 2 to listOf(sso)).call))
    }
}
