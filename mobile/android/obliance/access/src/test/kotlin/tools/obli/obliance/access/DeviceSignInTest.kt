package tools.obli.obliance.access

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import tools.obli.core.model.ObliUser
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DevicePurpose
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignPromptTexts
import tools.obli.core.security.SignResult
import tools.obli.obliance.api.LoginResult
import tools.obli.obliance.api.TwoFactorMethods
import tools.obli.obliance.data.DeviceSignInResult
import tools.obli.obliance.data.sample.SampleData

/** The fingerprint sign-in of the first sign-in, sign-in-again and add-a-server screens. */
@OptIn(ExperimentalCoroutinesApi::class)
class DeviceSignInTest {
    private val dev = "https://obliance-dev.example.org"

    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val challenge = DeviceChallenge(
        1, "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", "1b4e28ba-2fa1-41d2-883f-0016d3cca427", DevicePurpose.LOGIN, 42, null, null,
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "-", "-", 1790000120, null,
    )

    private val texts = SignPromptTexts(
        description = "Double authentification, pour cette action uniquement",
        secondStep = "Deuxième validation : double authentification",
        useCode = "Utiliser un code",
        bulk = { a, n -> "$a sur $n appareils" },
        login = { server -> "Connexion à $server" },
    )

    private object NoSigner : DeviceSigner {
        override suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt): SignResult = error("the repository signs, not the screen")
    }

    private fun signedInWithDevice(services: TestServices, mode: SignInMode = SignInMode.FIRST, now: () -> Long = { 0L }, origin: String? = null): SignInViewModel {
        services.auth.loginResult = LoginResult.TwoFactorRequired(TwoFactorMethods(totp = true, email = true, device = true), challenge)
        val vm = SignInViewModel(services, mode, origin, { false }, now)
        if (origin == null) {
            vm.setAddress("obliance-dev.example.org")
            vm.check()
        }
        vm.setUsername("  john.smith ")
        vm.setPassword("secret")
        vm.signInLocal()
        return vm
    }

    @Test fun `the fingerprint is offered at once, and the e-mail code was not sent`() {
        val services = TestServices(1)
        val vm = signedInWithDevice(services, now = { 5_000L })
        val tf = vm.state.twoFactor!!
        assertNotNull(tf.device)
        val device = tf.device!!
        assertTrue("the prompt shows by itself", device.pending)
        assertEquals(challenge, device.challenge)
        assertEquals("« Renvoyer » is free: no e-mail was sent at login", 0L, tf.resendAvailableAt)
    }

    @Test fun `a signed fingerprint completes the sign-in`() {
        val services = TestServices(1)
        val vm = signedInWithDevice(services)
        services.auth.deviceResult = DeviceSignInResult.Finished(LoginResult.SignedIn(ObliUser(id = 42, username = "john.smith")))
        vm.signInWithDevice(NoSigner, texts)
        assertEquals(Triple(dev, "john.smith", false), services.auth.deviceCalls.single())
        val prompt = services.auth.devicePrompts.single()
        assertEquals("Connexion à Obliance Dev", prompt.title)
        assertEquals("john.smith", prompt.subtitle)
        assertEquals("Utiliser un code", prompt.negative)
        assertEquals(dev, services.auth.completed.single().first)
        assertTrue(vm.state.finished)
        assertTrue("no code was sent", services.auth.verified.isEmpty())
    }

    @Test fun `use a code keeps the offer, and the button asks again`() {
        val services = TestServices(1)
        val vm = signedInWithDevice(services)
        services.auth.deviceResult = DeviceSignInResult.UseCode
        vm.signInWithDevice(NoSigner, texts)
        assertEquals(SignInStep.TWO_FACTOR, vm.state.step)
        assertFalse(vm.state.twoFactor!!.device!!.pending)
        vm.signInWithDevice(NoSigner, texts)
        assertEquals("nothing pending: no second prompt", 1, services.auth.deviceCalls.size)
        vm.useDevice()
        assertTrue(vm.state.twoFactor!!.device!!.pending)
        services.auth.deviceResult = DeviceSignInResult.Cancelled
        vm.signInWithDevice(NoSigner, texts)
        assertEquals(2, services.auth.deviceCalls.size)
        assertNull(vm.state.problem)
        // The code still works.
        vm.setCode("482913")
        assertEquals(1, services.auth.verified.size)
    }

    @Test fun `a refused fingerprint or a lost key falls back on the code with a reason`() {
        val services = TestServices(1)
        val vm = signedInWithDevice(services)
        services.auth.deviceResult = DeviceSignInResult.Refused
        vm.signInWithDevice(NoSigner, texts)
        assertEquals(ProblemKind.DEVICE_REFUSED, vm.state.problem?.kind)
        assertNull("no fingerprint any more for this login", vm.state.twoFactor!!.device)
        vm.useDevice()
        assertNull(vm.state.twoFactor!!.device)

        val services2 = TestServices(1)
        val vm2 = signedInWithDevice(services2)
        services2.auth.deviceResult = DeviceSignInResult.KeyLost
        vm2.signInWithDevice(NoSigner, texts)
        assertEquals(ProblemKind.DEVICE_KEY_LOST, vm2.state.problem?.kind)
        assertNull(vm2.state.twoFactor!!.device)
    }

    @Test fun `without a signer the fingerprint is dropped for this login`() {
        val services = TestServices(1)
        val vm = signedInWithDevice(services)
        vm.signInWithDevice(null, texts)
        assertNull(vm.state.twoFactor!!.device)
        assertTrue(services.auth.deviceCalls.isEmpty())
    }

    @Test fun `a challenge older than its life is renewed before the prompt`() {
        var now = 0L
        val services = TestServices(1)
        val vm = signedInWithDevice(services, now = { now })
        services.auth.deviceResult = DeviceSignInResult.UseCode
        vm.signInWithDevice(NoSigner, texts)
        now += DEVICE_CHALLENGE_STALE_MS
        vm.useDevice()
        vm.signInWithDevice(NoSigner, texts)
        assertEquals(listOf(false, true), services.auth.deviceCalls.map { it.third })
    }

    @Test fun `the session lost during the prompt goes back to the password`() {
        val services = TestServices(1)
        val vm = signedInWithDevice(services)
        services.auth.deviceResult = DeviceSignInResult.Finished(LoginResult.TwoFactorSessionLost)
        vm.signInWithDevice(NoSigner, texts)
        assertEquals(SignInStep.METHOD, vm.state.step)
        assertEquals(ProblemKind.CODE_EXPIRED, vm.state.problem?.kind)
    }

    @Test fun `sign in again names the configured server`() {
        val services = TestServices(3)
        val qual = services.registry.state.value.byId(SampleData.QUAL)!!
        services.sessions.session(SampleData.QUAL)!!.markExpired()
        val vm = signedInWithDevice(services, SignInMode.REAUTH, origin = qual.origin)
        services.auth.deviceResult = DeviceSignInResult.UseCode
        vm.signInWithDevice(NoSigner, texts)
        assertEquals("Connexion à ${qual.displayName}", services.auth.devicePrompts.single().title)
    }

    @Test fun `a login without the device method shows the code only`() {
        val services = TestServices(1)
        services.auth.loginResult = LoginResult.TwoFactorRequired(TwoFactorMethods(totp = true), null)
        val vm = SignInViewModel(services, SignInMode.FIRST, null, { false }, { 0L })
        vm.setAddress("obliance-dev.example.org")
        vm.check()
        vm.setUsername("john.smith")
        vm.setPassword("secret")
        vm.signInLocal()
        assertNull(vm.state.twoFactor!!.device)
        vm.signInWithDevice(NoSigner, texts)
        assertTrue(services.auth.deviceCalls.isEmpty())
    }
}
