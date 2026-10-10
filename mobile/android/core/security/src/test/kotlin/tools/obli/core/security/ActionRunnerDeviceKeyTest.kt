package tools.obli.core.security

import java.util.Base64
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
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

/** ActionRunner with device-bound validation. */
class ActionRunnerDeviceKeyTest {
    private val origin = "https://obliance.example.com"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val record = DeviceKeyRecord(origin, 42, "john.smith", keyId, DeviceKeyAlias.of(origin, 42, "install"), "install", DeviceKeyLevel.STRONGBOX, 1)

    private fun challenge(id: String = "1b4e28ba-2fa1-41d2-883f-0016d3cca427", tenantId: Long? = 3, userId: Long = 42, key: String = keyId) = DeviceChallenge(
        1, key, id, DevicePurpose.STEPUP, userId, tenantId, "ACME",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "command.reboot",
        "42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4", 1790000120, null,
    )

    /** J1 as ObliHttp returns it (origin set: the answer came from the client's origin). */
    private fun j1(c: DeviceChallenge? = challenge(), error: DeviceError? = null, status: DeviceKeyStatus = DeviceKeyStatus.ACTIVE, from: String? = origin) =
        ApiOutcome.StepUpRequired(
            "command.reboot", "203.0.113.21", trustIpAllowed = false, codeRequiresPassword = true,
            device = DeviceStepUp(status, c, error), origin = from,
        )

    private class FakePrompter : ActionPrompter {
        val log = mutableListOf<String>()
        val signs = ArrayDeque<SignResult>()
        val codes = ArrayDeque<TwoFactorAnswer?>()
        val options = mutableListOf<TwoFactorOptions>()
        val signed = mutableListOf<DeviceSignRequest>()
        var reauth: SsoReauthResult = SsoReauthResult.Success
        val reauthSpecs = mutableListOf<ActionSpec?>()

        override suspend fun confirmTenantSwitch(spec: ActionSpec, tenantName: String) = true
        override suspend fun confirm(spec: ActionSpec) = true.also { log += "confirm" }
        override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean): TwoFactorAnswer? = error("the runner uses the 4-argument variant")
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
            return signs.removeFirstOrNull() ?: SignResult.Cancelled
        }
        override suspend fun deviceKeyInvalidated(origin: String, keyId: String) { log += "invalidated:$keyId" }
        override suspend fun reauthenticateSso(origin: String, spec: ActionSpec?): SsoReauthResult =
            reauth.also {
                log += "reauth:$origin"
                reauthSpecs += spec
            }
    }

    private val reboot = ActionSpec("device.reboot", Tier.T0, "Redémarrer", "SRV-DEMO01", "Obliance Prod › ACME", tenantId = 3, serverName = "Obliance Prod")
    private val sig = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)

    private fun <T> scripted(vararg answers: ApiOutcome<T>): Pair<MutableList<JsonObject>, suspend (JsonObject) -> ApiOutcome<T>> {
        val bodies = mutableListOf<JsonObject>()
        val queue = ArrayDeque(answers.toList())
        return bodies to { extra -> bodies += extra; queue.removeFirst() }
    }

    private fun runner(p: ActionPrompter, keys: DeviceKeyResolver? = DeviceKeyResolver { if (it == origin) record else null }) = ActionRunner(p, keys)

    @Test fun challengeSignatureResend() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Signed(sig) }
        val (bodies, call) = scripted(j1(), ApiOutcome.Ok("done"))
        assertEquals(ActionResult.Done("done"), runner(p).run(reboot, call = call))
        assertEquals(listOf("sign:1"), p.log)
        val assertion = bodies[1][DeviceAssertion.FIELD]!!.jsonObject
        assertEquals(JsonPrimitive(1), assertion["v"])
        assertEquals(JsonPrimitive(keyId), assertion["keyId"])
        assertEquals("[\"1b4e28ba-2fa1-41d2-883f-0016d3cca427\"]", assertion["challengeIds"].toString())
        assertEquals(JsonPrimitive(Base64.getEncoder().encodeToString(sig)), assertion["signature"])
        assertEquals(setOf(DeviceAssertion.FIELD), bodies[1].keys)
        // What was signed is DeviceProofPayload's, with the app's origin.
        assertTrue(String(p.signed.single().payload, Charsets.UTF_8).startsWith("obli-devkey-v1\npurpose:stepup\norigin:$origin\nuser:42\n"))
    }

    @Test fun useCodeAsksForThePasswordVariant() = runBlocking {
        val p = FakePrompter().apply {
            signs += SignResult.UseCode
            codes += TwoFactorAnswer("482913", trustIp = true, password = "correct horse")
        }
        val (bodies, call) = scripted(j1(), ApiOutcome.Ok(Unit))
        assertEquals(ActionResult.Done(Unit), runner(p).run(reboot, call = call))
        assertEquals(listOf("sign:1", "2fa:false"), p.log)
        assertEquals(TwoFactorOptions(trustIpAllowed = false, passwordRequired = true, reauthRequired = false), p.options.single())
        assertEquals(JsonPrimitive("482913"), bodies[1]["twoFactorCode"])
        assertEquals(JsonPrimitive("correct horse"), bodies[1]["stepUpPassword"])
        assertNull(bodies[1]["trustIp"]) // never granted on a bound session
        assertNull(bodies[1][DeviceAssertion.FIELD])
    }

    @Test fun aRefusedAssertionIsFollowedByACodeWithoutTheAssertion() = runBlocking {
        val p = FakePrompter().apply {
            signs += SignResult.Signed(sig)
            codes += TwoFactorAnswer("482913", false, "pw")
        }
        val bulkId = JsonPrimitive("0f8fad5b-d9cb-469f-a165-70867728950e")
        val (bodies, call) = scripted(j1(), j1(c = null, error = DeviceError.INVALID_ASSERTION), ApiOutcome.Ok(Unit))
        val r = runner(p).run(reboot) { extra ->
            // The screen merges extra into the SAME body; deviceBulkId came from the screen and is kept.
            call(buildJsonObject { put("deviceBulkId", bulkId); extra.forEach { (k, v) -> put(k, v) } })
        }
        assertEquals(ActionResult.Done(Unit), r)
        assertTrue(bodies[1].containsKey(DeviceAssertion.FIELD))
        assertFalse(bodies[2].containsKey(DeviceAssertion.FIELD))
        assertEquals(JsonPrimitive("482913"), bodies[2]["twoFactorCode"])
        assertEquals(bulkId, bodies[2]["deviceBulkId"])
        assertEquals(listOf("sign:1", "2fa:false"), p.log)
    }

    @Test fun anExpiredChallengeGetsOneMoreSignatureNeverAThird() = runBlocking {
        val p = FakePrompter().apply {
            repeat(3) { signs += SignResult.Signed(sig) }
            codes += TwoFactorAnswer("482913", false, "pw")
        }
        val c2 = challenge(id = "7c9e6679-7425-40de-944b-e07fc1f90ae7")
        val c3 = challenge(id = "0f8fad5b-d9cb-469f-a165-70867728950e")
        val (bodies, call) = scripted(j1(), j1(c = c2, error = DeviceError.CHALLENGE_EXPIRED), j1(c = c3, error = DeviceError.CHALLENGE_EXPIRED), ApiOutcome.Ok(Unit))
        assertEquals(ActionResult.Done(Unit), runner(p).run(reboot, call = call))
        assertEquals(listOf("sign:1", "sign:1", "2fa:false"), p.log)
        assertEquals(listOf("1b4e28ba-2fa1-41d2-883f-0016d3cca427", c2.challengeId), p.signed.map { it.challenges.single().challengeId })
        assertTrue(bodies[3].containsKey("twoFactorCode"))
        assertFalse(bodies[3].containsKey(DeviceAssertion.FIELD))
    }

    @Test fun anInvalidatedKeyIsReportedThenTheSessionEnds() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Invalidated }
        val (bodies, call) = scripted<Unit>(j1())
        assertEquals(ActionResult.SessionExpired, runner(p).run(reboot, call = call))
        assertEquals(listOf("sign:1", "invalidated:$keyId"), p.log)
        assertEquals(1, bodies.size)
    }

    @Test fun anotherTenantIsBlockedWithoutAnyPrompt() = runBlocking {
        val p = FakePrompter()
        val (bodies, call) = scripted<Unit>(j1(c = challenge(tenantId = 1)))
        assertEquals(ActionResult.Blocked(ActionRunner.TENANT_CHANGED), runner(p).run(reboot, call = call))
        assertTrue(p.log.isEmpty())
        assertEquals(1, bodies.size)
        // Unknown on either side: not checked.
        val p2 = FakePrompter().apply { signs += SignResult.Signed(sig) }
        val (_, call2) = scripted(j1(c = challenge(tenantId = null)), ApiOutcome.Ok(Unit))
        assertEquals(ActionResult.Done(Unit), runner(p2).run(reboot, call = call2))
        val p3 = FakePrompter().apply { signs += SignResult.Signed(sig) }
        val (_, call3) = scripted(j1(c = challenge(tenantId = 1)), ApiOutcome.Ok(Unit))
        assertEquals(ActionResult.Done(Unit), runner(p3).run(reboot.copy(tenantId = null), call = call3))
    }

    @Test fun anotherUserKeyOrOriginIsNeverSigned() = runBlocking {
        val cases = listOf(
            j1(c = challenge(userId = 43)),
            j1(c = challenge(key = "0f8fad5b-d9cb-469f-a165-70867728950e")),
            j1(from = null),                                   // the answer did not come from the client's origin
        )
        for (out in cases) {
            val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", false, "pw") }
            val (bodies, call) = scripted(out, ApiOutcome.Ok(Unit))
            assertEquals(ActionResult.Done(Unit), runner(p).run(reboot, call = call))
            assertEquals(listOf("2fa:false"), p.log)
            assertTrue(bodies[1].containsKey("twoFactorCode"))
        }
        // No key for this origin (another account signed in since), or no resolver at all.
        for (keys in listOf<DeviceKeyResolver?>(DeviceKeyResolver { null }, null)) {
            val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", false, "pw") }
            val (_, call) = scripted(j1(), ApiOutcome.Ok(Unit))
            assertEquals(ActionResult.Done(Unit), runner(p, keys).run(reboot, call = call))
            assertEquals(listOf("2fa:false"), p.log)
        }
    }

    @Test fun trustIpIsNeverSentWhenNotAllowed() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", trustIp = true) }
        val noShortcut = ApiOutcome.StepUpRequired("profile.ssh_authorize_ip", "203.0.113.21", trustIpAllowed = false, origin = origin)
        val (bodies, call) = scripted(noShortcut, ApiOutcome.Ok(Unit))
        runner(p).run(reboot, call = call)
        assertFalse(p.options.single().trustIpAllowed)
        assertNull(bodies[1]["trustIp"])
        assertNull(bodies[1]["stepUpPassword"])
    }

    @Test fun disabledPolicyIsTheOrdinaryCodeSheet() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", trustIp = true, password = "not asked") }
        val j5 = ApiOutcome.StepUpRequired("command.reboot", "…", trustIpAllowed = true, device = DeviceStepUp(DeviceKeyStatus.DISABLED), origin = origin)
        val (bodies, call) = scripted(j5, ApiOutcome.Ok(Unit))
        assertEquals(ActionResult.Done(Unit), runner(p).run(reboot, call = call))
        assertEquals(TwoFactorOptions(), p.options.single())
        assertEquals(JsonPrimitive(true), bodies[1]["trustIp"])
        assertNull(bodies[1]["stepUpPassword"]) // a password is only sent when the server asks for it
    }

    @Test fun throttledSessionUsesTheCode() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", false, "pw") }
        val (_, call) = scripted(j1(status = DeviceKeyStatus.THROTTLED, c = challenge()), ApiOutcome.Ok(Unit))
        assertEquals(ActionResult.Done(Unit), runner(p).run(reboot, call = call))
        assertEquals(listOf("2fa:false"), p.log)
    }

    @Test fun reauthComesBeforeTheCode() = runBlocking {
        val p = FakePrompter().apply { codes += TwoFactorAnswer("482913", false) }
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, device = DeviceStepUp(DeviceKeyStatus.ACTIVE), origin = origin)
        val (bodies, call) = scripted(sso, ApiOutcome.StepUpRejected(), ApiOutcome.Ok(Unit))
        p.codes += TwoFactorAnswer("482914", false)
        assertEquals(ActionResult.Done(Unit), runner(p).run(reboot, call = call))
        // Re-authentication once, then the code; a wrong code does not re-authenticate again.
        assertEquals(listOf("reauth:$origin", "2fa:false", "2fa:true"), p.log)
        assertTrue(p.options.all { it.reauthRequired })
        assertEquals(JsonPrimitive("482914"), bodies[2]["twoFactorCode"])
        // The host is told which action it is for (the 2FA sheet names it before the Obligate sheet).
        assertEquals(listOf<ActionSpec?>(reboot), p.reauthSpecs)

        // Closed by the user: cancelled, silently, nothing sent again.
        val cancelled = FakePrompter().apply { reauth = SsoReauthResult.Cancelled }
        val (bodies2, call2) = scripted<Unit>(sso)
        assertEquals(ActionResult.Cancelled, runner(cancelled).run(reboot, call = call2))
        assertEquals(listOf("reauth:$origin"), cancelled.log)
        assertEquals(1, bodies2.size)
    }

    @Test fun aRefusedReauthIsReportedNeverACancel() = runBlocking {
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        val p = FakePrompter().apply { reauth = SsoReauthResult.Failed("no_otp") }
        val (bodies, call) = scripted<Unit>(sso)
        assertEquals(ActionResult.Blocked(ActionRunner.SSO_REAUTH_FAILED), runner(p).run(reboot, call = call))
        // No code asked, nothing sent again.
        assertEquals(listOf("reauth:$origin"), p.log)
        assertEquals(1, bodies.size)
    }

    /** The session ended while at Obligate (`signed_out`, or sent to /login): sign in again, like any expired session. */
    @Test fun anEndedSessionDuringTheReauthIsAnExpiredSession() = runBlocking {
        for (reason in listOf("signed_out", "login")) {
            val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
            val p = FakePrompter().apply { reauth = SsoReauthResult.Failed(reason) }
            val (bodies, call) = scripted<Unit>(sso)
            assertEquals(reason, ActionResult.SessionExpired, runner(p).run(reboot, call = call))
            assertEquals(reason, listOf("reauth:$origin", "expired"), p.log)
            assertEquals(1, bodies.size)
        }
        assertTrue(SsoReauthResult.Failed("signed_out").endsSession)
        assertFalse(SsoReauthResult.Failed("identity").endsSession)
        // One list of final reasons for the sheet and the profile security screen.
        for (r in listOf("no_otp", "not_sso", "unsupported", "misconfigured", "origin", "signed_out", "login", "blocked", "tls")) {
            assertFalse(r, SsoReauthResult.Failed.canRetry(r))
        }
        for (r in listOf("identity", "stale_auth", "verifier_unavailable", "unreachable", "expired", "state", "exchange", "error", "page_error", "config", "unexpected")) {
            assertTrue(r, SsoReauthResult.Failed.canRetry(r))
        }
    }

    @Test fun theDefaultPrompterFailsClosed() = runBlocking {
        val none = object : ActionPrompter {
            override suspend fun confirmTenantSwitch(spec: ActionSpec, tenantName: String) = true
            override suspend fun confirm(spec: ActionSpec) = true
            override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean): TwoFactorAnswer? = error("never asked")
            override suspend fun approvalRequested(spec: ActionSpec, approvalId: Long) {}
            override suspend fun unlockPrivacy(spec: ActionSpec, feature: String?, passwordSet: Boolean) = false
            override suspend fun sessionExpired() {}
        }
        assertEquals(SsoReauthResult.Cancelled, none.reauthenticateSso(origin, reboot))
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        val (_, call) = scripted<Unit>(sso)
        assertEquals(ActionResult.Cancelled, runner(none).run(reboot, call = call))
    }

    @Test fun cancellingTheFingerprintCancelsTheAction() = runBlocking {
        val p = FakePrompter().apply { signs += SignResult.Cancelled }
        val (bodies, call) = scripted<Unit>(j1())
        assertEquals(ActionResult.Cancelled, runner(p).run(reboot, call = call))
        assertEquals(1, bodies.size)
    }

    @Test fun lockedOutOrUnavailableFallBackOnTheCode() = runBlocking {
        for (r in listOf(SignResult.LockedOut, SignResult.Unavailable("hw"))) {
            val p = FakePrompter().apply { signs += r; codes += TwoFactorAnswer("482913", false, "pw") }
            val (_, call) = scripted(j1(), ApiOutcome.Ok(Unit))
            assertEquals(ActionResult.Done(Unit), runner(p).run(reboot, call = call))
            assertEquals(listOf("sign:1", "2fa:false"), p.log)
        }
    }

    @Test fun aPrompterWithoutPasswordSupportCancelsAPasswordStepUp() = runBlocking {
        // A prompter written before device keys (only the 3-argument askTwoFactor).
        val old = object : ActionPrompter {
            var asked = 0
            override suspend fun confirmTenantSwitch(spec: ActionSpec, tenantName: String) = true
            override suspend fun confirm(spec: ActionSpec) = true
            override suspend fun askTwoFactor(spec: ActionSpec, currentIp: String?, previousWasWrong: Boolean): TwoFactorAnswer? {
                asked++
                return TwoFactorAnswer("482913", trustIp = true)
            }
            override suspend fun approvalRequested(spec: ActionSpec, approvalId: Long) {}
            override suspend fun unlockPrivacy(spec: ActionSpec, feature: String?, passwordSet: Boolean) = false
            override suspend fun sessionExpired() {}
        }
        val (bodies, call) = scripted<Unit>(j1())
        assertEquals(ActionResult.Cancelled, runner(old).run(reboot, call = call))
        assertEquals(0, old.asked)
        assertEquals(1, bodies.size)
        // Without a password requirement it works as before, minus a forbidden IP trust.
        val (bodies2, call2) = scripted(ApiOutcome.StepUpRequired("x", null, trustIpAllowed = false), ApiOutcome.Ok(Unit))
        assertEquals(ActionResult.Done(Unit), runner(old).run(reboot, call = call2))
        assertNull(bodies2[1]["trustIp"])
    }
}
