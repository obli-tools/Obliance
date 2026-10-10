package tools.obli.core.security.ui

import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import java.security.KeyPairGenerator
import java.security.Signature
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import tools.obli.core.security.DeviceKeyHardware
import tools.obli.core.security.GeneratedKey
import tools.obli.core.security.KeyHealth
import tools.obli.core.security.OpenedSignature
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignResult

/**
 * The fingerprint signer never asks androidx.biometric for a prompt it would
 * silently drop (activity not resumed, fragment state saved): the caller gets
 * `Unavailable` (the code is used) instead of waiting forever with the action
 * host's one-prompt lock held.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BiometricDeviceSignerTest {
    /** A healthy key: `openSignature` succeeds, as with a real per-use Keystore key before the prompt. */
    private class ReadyHardware : DeviceKeyHardware {
        private val pair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        override fun openSignature(alias: String) = OpenedSignature.Ready(Signature.getInstance("SHA256withECDSA").apply { initSign(pair.private) })
        override fun health(alias: String): KeyHealth = KeyHealth.Healthy
        override fun aliases(): Set<String> = emptySet()
        override suspend fun generate(alias: String, attestationChallenge: ByteArray): GeneratedKey = error("not used")
        override fun delete(alias: String) {}
    }

    private val prompt = SignPrompt("Redémarrer SRV-DEMO01", "Obliance Prod › ACME", null, "Utiliser un code")

    @Test fun noPromptFromAnActivityInTheBackground() = runBlocking {
        val controller = Robolectric.buildActivity(FragmentActivity::class.java).setup()
        controller.pause().stop()
        val signer = BiometricDeviceSigner(controller.get(), ReadyHardware())
        val result = withTimeout(10_000) { signer.signWith("obli.devkey.v1.test", byteArrayOf(1, 2, 3), prompt) }
        assertEquals(SignResult.Unavailable(BiometricSignResults.NOT_FOREGROUND), result)
    }

    @Test fun noPromptFromADestroyedActivity() = runBlocking {
        val controller = Robolectric.buildActivity(FragmentActivity::class.java).setup()
        val activity = controller.get()
        controller.pause().stop().destroy()
        val result = withTimeout(10_000) { BiometricDeviceSigner(activity, ReadyHardware()).signWith("obli.devkey.v1.test", byteArrayOf(1), prompt) }
        assertEquals(SignResult.Unavailable(BiometricSignResults.NOT_FOREGROUND), result)
    }

    @Test fun onlyAResumedActivityWithoutSavedStateShowsThePrompt() {
        assertTrue(PromptHost.canShow(Lifecycle.State.RESUMED, finishing = false, stateSaved = false))
        assertFalse(PromptHost.canShow(Lifecycle.State.STARTED, finishing = false, stateSaved = false))
        assertFalse(PromptHost.canShow(Lifecycle.State.CREATED, finishing = false, stateSaved = true))
        assertFalse(PromptHost.canShow(Lifecycle.State.RESUMED, finishing = true, stateSaved = false))
        assertFalse(PromptHost.canShow(Lifecycle.State.RESUMED, finishing = false, stateSaved = true))
        assertFalse(PromptHost.canShow(Lifecycle.State.DESTROYED, finishing = true, stateSaved = true))
    }

    @Test fun theWatchdogIsBoundedByTheChallengeAndTheTicket() {
        // Longer than a step-up / sign-in challenge (120 s), shorter than an enrolment ticket (180 s).
        assertTrue(BiometricDeviceSigner.PROMPT_TIMEOUT_MS in 120_001L until 180_000L)
        assertEquals(SignResult.Unavailable(BiometricSignResults.NOT_FOREGROUND), BiometricSignResults.ofError(BiometricSignResults.NOT_SHOWN_CODE))
    }
}
