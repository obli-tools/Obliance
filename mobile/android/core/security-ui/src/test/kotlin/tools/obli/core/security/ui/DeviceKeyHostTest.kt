package tools.obli.core.security.ui

import androidx.biometric.BiometricPrompt
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceKeyStatus
import tools.obli.core.network.DevicePurpose
import tools.obli.core.network.DeviceStepUp
import tools.obli.core.security.ActionResult
import tools.obli.core.security.ActionRunner
import tools.obli.core.security.ActionSpec
import tools.obli.core.security.DeviceAssertion
import tools.obli.core.security.DeviceKeyAlias
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.DeviceKeyRecord
import tools.obli.core.security.DeviceKeyResolver
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.KeyHealth
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignPromptTexts
import tools.obli.core.security.SignResult
import tools.obli.core.security.SsoReauthResult
import tools.obli.core.security.Tier

/** The host with device-bound validation: the fingerprint prompt, the "password + code" 2FA sheet, invalidation. */
@OptIn(ExperimentalCoroutinesApi::class)
class DeviceKeyHostTest {
    private val origin = "https://obliance.example.com"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val record = DeviceKeyRecord(origin, 42, "john.smith", keyId, DeviceKeyAlias.of(origin, 42, "install"), "install", DeviceKeyLevel.STRONGBOX, 1)
    private val keys = DeviceKeyResolver { if (it == origin) record else null }
    private val texts = SignPromptTexts(
        description = "Double authentification, pour cette action uniquement",
        secondStep = "Deuxième validation : double authentification",
        useCode = "Utiliser un code",
        bulk = { action, count -> "$action sur $count appareils" },
        login = { server -> "Connexion à $server" },
    )

    private class FakeSigner(vararg results: SignResult) : DeviceSigner {
        val prompts = mutableListOf<SignPrompt>()
        private val queue = ArrayDeque(results.toList())
        override suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt): SignResult {
            prompts += prompt
            return queue.removeFirst()
        }
    }

    private val challenge = DeviceChallenge(
        1, keyId, "1b4e28ba-2fa1-41d2-883f-0016d3cca427", DevicePurpose.STEPUP, 42, 3, "ACME",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "command.reboot",
        "42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4", 1790000120, null,
    )

    /** J1 as ObliHttp returns it for this origin. */
    private val j1 = ApiOutcome.StepUpRequired(
        "command.reboot", "203.0.113.21", trustIpAllowed = false, codeRequiresPassword = true,
        device = DeviceStepUp(DeviceKeyStatus.ACTIVE, challenge), origin = origin,
    )

    private val reboot = ActionSpec("device.reboot", Tier.T0, "Redémarrer", "SRV-DEMO01", "ACME", tenantId = 3, serverName = "Obliance Prod")

    private fun <T> scripted(vararg answers: ApiOutcome<T>): Pair<MutableList<JsonObject>, suspend (JsonObject) -> ApiOutcome<T>> {
        val bodies = mutableListOf<JsonObject>()
        val queue = ArrayDeque(answers.toList())
        return bodies to { extra -> bodies += extra; queue.removeFirst() }
    }

    private fun TestScope.launchRun(runner: ActionRunner, spec: ActionSpec, call: suspend (JsonObject) -> ApiOutcome<Unit>) =
        backgroundScope.async { runner.run(spec, call = call) }.also { runCurrent() }

    @Test fun theFingerprintSignsAndTheSameBodyIsResent() = runTest {
        val signer = FakeSigner(SignResult.Signed(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)))
        val host = ActionHostState(deviceSigner = signer, signTexts = texts)
        val (bodies, call) = scripted(j1, ApiOutcome.Ok(Unit))
        val run = launchRun(ActionRunner(host, keys), reboot, call)
        assertEquals(ActionResult.Done(Unit), run.await())
        assertEquals(
            SignPrompt("Redémarrer SRV-DEMO01", "Obliance Prod › ACME", "Double authentification, pour cette action uniquement", "Utiliser un code"),
            signer.prompts.single(),
        )
        assertEquals(setOf(DeviceAssertion.FIELD), bodies[1].keys)
        assertNull(host.prompt.value) // no sheet: the system prompt only
    }

    @Test fun useCodeOpensThePasswordVariantWithoutTheIpBox() = runTest {
        val host = ActionHostState(deviceSigner = FakeSigner(SignResult.UseCode), signTexts = texts)
        val (bodies, call) = scripted(j1, ApiOutcome.Ok(Unit))
        val run = launchRun(ActionRunner(host, keys), reboot, call)
        val p = host.prompt.value as ActionPrompt.TwoFactor
        assertTrue(p.passwordRequired)
        assertFalse(p.showTrustIp)
        p.code = "482913"
        p.trustIp = true                    // even if set somehow, never sent
        host.submitCode(p)                  // no password yet: refused
        runCurrent()
        assertEquals(p, host.prompt.value)
        p.password = "correct horse"
        host.submitCode(p)
        runCurrent()
        assertEquals(ActionResult.Done(Unit), run.await())
        assertEquals(JsonPrimitive("482913"), bodies[1]["twoFactorCode"])
        assertEquals(JsonPrimitive("correct horse"), bodies[1]["stepUpPassword"])
        assertNull(bodies[1]["trustIp"])
        assertNull(bodies[1][DeviceAssertion.FIELD])
        assertEquals("", p.password)        // the sheet does not keep it
    }

    /**
     * SSO device keys: an Obligate account in a bound session. The 2FA sheet explains first
     * (« …reconfirmez d'abord votre identité auprès d'Obligate »), then the
     * app's Obligate sheet, then the code boxes with « Identité reconfirmée,
     * saisissez un nouveau code ».
     */
    @Test fun anObligateAccountReconfirmsThenTypesANewCode() = runTest {
        val sheets = mutableListOf<String>()
        val host = ActionHostState(onReauthenticateSso = { o -> sheets += o; SsoReauthResult.Success })
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        val (bodies, call) = scripted(sso, ApiOutcome.Ok(Unit))
        val run = launchRun(ActionRunner(host, keys), reboot, call)
        val intro = host.prompt.value as ActionPrompt.SsoReauth
        assertEquals(reboot, intro.spec)
        assertTrue(sheets.isEmpty())
        host.startSsoReauth(intro)
        runCurrent()
        assertEquals(listOf(origin), sheets)
        val p = host.prompt.value as ActionPrompt.TwoFactor
        assertTrue(p.options.reauthRequired)
        assertFalse(p.passwordRequired)
        assertFalse(p.showTrustIp)
        p.code = "482913"
        host.submitCode(p)
        runCurrent()
        assertEquals(ActionResult.Done(Unit), run.await())
        assertEquals(JsonPrimitive("482913"), bodies[1]["twoFactorCode"])
        assertNull(bodies[1]["stepUpPassword"])
    }

    @Test fun cancellingTheObligateExplanationOpensNoSheet() = runTest {
        val sheets = mutableListOf<String>()
        val host = ActionHostState(onReauthenticateSso = { o -> sheets += o; SsoReauthResult.Success })
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        val (bodies, call) = scripted<Unit>(sso)
        val run = launchRun(ActionRunner(host, keys), reboot, call)
        assertTrue(host.prompt.value is ActionPrompt.SsoReauth)
        host.cancel()
        runCurrent()
        assertEquals(ActionResult.Cancelled, run.await())
        assertTrue(sheets.isEmpty())
        assertEquals(1, bodies.size)
        assertNull(host.prompt.value)
    }

    @Test fun aRefusedSheetIsReportedAndWithoutASheetNothingIsShown() = runTest {
        val refused = ActionHostState(onReauthenticateSso = { SsoReauthResult.Failed("no_otp") })
        val sso = ApiOutcome.StepUpRequired("command.reboot", null, trustIpAllowed = false, codeRequiresReauth = true, origin = origin)
        val (_, call) = scripted<Unit>(sso)
        val run = launchRun(ActionRunner(refused, keys), reboot, call)
        refused.startSsoReauth(refused.prompt.value as ActionPrompt.SsoReauth)
        runCurrent()
        assertEquals(ActionResult.Blocked(ActionRunner.SSO_REAUTH_FAILED), run.await())
        // No sheet in the app (previews, tests): no prompt at all, cancelled (fail closed).
        val none = ActionHostState()
        assertEquals(SsoReauthResult.Cancelled, none.reauthenticateSso(origin, reboot))
        assertNull(none.prompt.value)
    }

    @Test fun cancellingThePasswordVariantClearsIt() = runTest {
        val host = ActionHostState(deviceSigner = FakeSigner(SignResult.LockedOut), signTexts = texts)
        val (_, call) = scripted<Unit>(j1)
        val run = launchRun(ActionRunner(host, keys), reboot, call)
        val p = host.prompt.value as ActionPrompt.TwoFactor
        p.password = "correct horse"
        host.cancel()
        runCurrent()
        assertEquals(ActionResult.Cancelled, run.await())
        assertEquals("", p.password)
    }

    @Test fun anInvalidatedKeyIsHandedToTheAppAndTheActionEnds() = runTest {
        val reported = mutableListOf<Pair<String, String>>()
        val host = ActionHostState(deviceSigner = FakeSigner(SignResult.Invalidated), signTexts = texts, onDeviceKeyInvalidated = { o, k -> reported += o to k })
        val (bodies, call) = scripted<Unit>(j1)
        val run = launchRun(ActionRunner(host, keys), reboot, call)
        assertEquals(ActionResult.SessionExpired, run.await())
        assertEquals(listOf(origin to keyId), reported)
        assertEquals(1, bodies.size)
    }

    @Test fun withoutASignerTheCodeIsUsed() = runTest {
        val host = ActionHostState()
        val (bodies, call) = scripted(j1, ApiOutcome.Ok(Unit))
        val run = launchRun(ActionRunner(host, keys), reboot, call)
        val p = host.prompt.value as ActionPrompt.TwoFactor
        p.password = "pw"
        p.code = "482913"
        host.submitCode(p)
        runCurrent()
        assertEquals(ActionResult.Done(Unit), run.await())
        assertTrue(bodies[1].containsKey("twoFactorCode"))
    }

    @Test fun biometricErrorsAndKeyStates() {
        assertEquals(SignResult.LockedOut, BiometricSignResults.ofError(BiometricPrompt.ERROR_LOCKOUT))
        assertEquals(SignResult.LockedOut, BiometricSignResults.ofError(BiometricPrompt.ERROR_LOCKOUT_PERMANENT))
        assertEquals(SignResult.UseCode, BiometricSignResults.ofError(BiometricPrompt.ERROR_NEGATIVE_BUTTON))
        for (c in listOf(BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_CANCELED, BiometricPrompt.ERROR_TIMEOUT)) {
            assertEquals(SignResult.Cancelled, BiometricSignResults.ofError(c))
        }
        for (c in listOf(BiometricPrompt.ERROR_HW_UNAVAILABLE, BiometricPrompt.ERROR_NO_BIOMETRICS, BiometricPrompt.ERROR_HW_NOT_PRESENT, 15, -1)) {
            assertTrue(BiometricSignResults.ofError(c) is SignResult.Unavailable)
        }
        assertEquals(SignResult.Invalidated, BiometricSignResults.ofHealth(KeyHealth.Invalidated))
        assertEquals(SignResult.Invalidated, BiometricSignResults.ofHealth(KeyHealth.Missing))
        assertEquals(SignResult.Unavailable("KeyStoreException"), BiometricSignResults.ofHealth(KeyHealth.Unavailable("KeyStoreException")))
    }
}
