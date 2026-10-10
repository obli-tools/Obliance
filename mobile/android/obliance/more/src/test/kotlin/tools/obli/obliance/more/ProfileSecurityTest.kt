package tools.obli.obliance.more

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.captureRoboImage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import tools.obli.core.designsystem.ObliTheme
import tools.obli.core.model.ServerId
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.FailureKind
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.EnrolProof
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignResult
import tools.obli.obliance.data.DeviceKeyEnrolOutcome
import tools.obli.obliance.data.DeviceKeyProposal
import tools.obli.obliance.data.DeviceKeyServerState
import tools.obli.obliance.data.DeviceKeyView
import tools.obli.obliance.data.EnrolProblem
import tools.obli.obliance.data.LocalObliServices
import tools.obli.obliance.data.sample.SampleData
import tools.obli.obliance.data.sample.SampleDeviceKeys
import tools.obli.obliance.data.sample.SampleObliServices

private val signerOk = object : DeviceSigner {
    override suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt) = SignResult.Signed(byteArrayOf(1))
}

private fun prompt(server: String) = SignPrompt("Activer la validation par empreinte", server, null, "Annuler")

/** Profile and security logic: rows per server, the enrolment steps, the secrets cleared, the proposal request taken once. */
@OptIn(ExperimentalCoroutinesApi::class)
class ProfileSecurityViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before fun setUp() = Dispatchers.setMain(dispatcher)

    @After fun tearDown() = Dispatchers.resetMain()

    private fun qualNotEnrolled() = SampleDeviceKeys(
        SampleDeviceKeys.defaultViews() + (SampleData.QUAL to DeviceKeyView(SampleData.QUAL, DeviceKeyServerState.NotEnrolled, SampleDeviceKeys.list(currentKey = null))),
    )

    @Test fun `one row per server in registry order`() = runTest(dispatcher) {
        val services = SampleObliServices()
        val vm = ProfileSecurityViewModel(services, ::prompt)
        backgroundScope.launch { vm.ui.collect { } }
        runCurrent()
        val ui = vm.ui.value
        assertEquals(listOf(SampleData.PROD, SampleData.DEV, SampleData.QUAL), ui.rows.map { it.profile.id })
        assertEquals(DeviceKeyServerState.SsoUnsupported, ui.row(SampleData.PROD)!!.state)
        assertTrue(ui.row(SampleData.QUAL)!!.state is DeviceKeyServerState.Active)
        assertEquals(2, ui.row(SampleData.QUAL)!!.keys!!.size)
        assertEquals("og_john.smith", ui.user?.username)
        assertTrue(ui.obligate)
    }

    @Test fun `explain, credentials, fingerprint, enrolled - the secrets never outlive the call`() = runTest(dispatcher) {
        val keys = qualNotEnrolled()
        val services = SampleObliServices(deviceKeys = keys)
        val vm = ProfileSecurityViewModel(services, ::prompt)
        vm.startEnrol(SampleData.QUAL)
        assertEquals(EnrolStep.Explain(SampleData.QUAL, "Obliance Qual"), vm.enrol.value)
        vm.continueEnrol()
        assertEquals(EnrolStep.Credentials(SampleData.QUAL, "Obliance Qual"), vm.enrol.value)
        // Wrong password: the sheet says so and the fields are empty again.
        vm.password = "wrong"
        vm.code = "482913"
        assertTrue(vm.canSubmit)
        vm.submit(signerOk)
        assertEquals("", vm.password)
        assertEquals("", vm.code)
        runCurrent()
        assertEquals(EnrolStep.Credentials(SampleData.QUAL, "Obliance Qual", wrong = true), vm.enrol.value)
        vm.password = "secret"
        vm.code = "482914"
        vm.submit(signerOk)
        runCurrent()
        assertNull(vm.enrol.value)
        assertEquals(DeviceKeyLevel.STRONGBOX, vm.enrolled.value!!.level)
        assertTrue(keys.views.value.getValue(SampleData.QUAL).state is DeviceKeyServerState.Active)
        vm.enrolledShown()
        assertNull(vm.enrolled.value)
    }

    @Test fun `no fingerprint signer - explained, nothing sent`() = runTest(dispatcher) {
        val services = SampleObliServices(deviceKeys = qualNotEnrolled())
        val vm = ProfileSecurityViewModel(services, ::prompt)
        vm.startEnrol(SampleData.QUAL)
        vm.continueEnrol()
        vm.password = "secret"
        vm.code = "123456"
        vm.submit(null)
        runCurrent()
        assertEquals(EnrolProblem.BIOMETRIC_UNAVAILABLE, (vm.enrol.value as EnrolStep.Credentials).problem)
        assertFalse(services.deviceKeys.views.value.getValue(SampleData.QUAL).state is DeviceKeyServerState.Active)
    }

    @Test fun `incomplete code cannot be sent, cancel clears`() = runTest(dispatcher) {
        val vm = ProfileSecurityViewModel(SampleObliServices(deviceKeys = qualNotEnrolled()), ::prompt)
        vm.startEnrol(SampleData.QUAL)
        vm.continueEnrol()
        vm.password = "secret"
        vm.code = "12345"
        assertFalse(vm.canSubmit)
        vm.submit(signerOk)
        runCurrent()
        assertEquals(EnrolStep.Credentials(SampleData.QUAL, "Obliance Qual"), vm.enrol.value)
        vm.cancelEnrol()
        assertNull(vm.enrol.value)
        assertEquals("", vm.password)
    }

    /** After a rotation the ViewModel survives: the signer is the one the screen gives at the tap (current activity). */
    @Test fun `the enrolment uses the signer given at the tap`() = runTest(dispatcher) {
        val keys = qualNotEnrolled()
        val used = mutableListOf<DeviceSigner>()
        val recording = object : tools.obli.obliance.data.DeviceKeysRepository by keys {
            override suspend fun enrol(serverId: ServerId, proof: EnrolProof, signer: DeviceSigner, prompt: SignPrompt) =
                keys.enrol(serverId, proof, signer, prompt).also { used += signer }
        }
        val vm = ProfileSecurityViewModel(SampleObliServices(deviceKeys = recording), ::prompt)
        val afterRotation = object : DeviceSigner {
            override suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt) = SignResult.Signed(byteArrayOf(2))
        }
        vm.startEnrol(SampleData.QUAL)
        vm.continueEnrol()
        vm.password = "secret"
        vm.code = "482913"
        vm.submit(afterRotation)
        runCurrent()
        assertTrue(used.single() === afterRotation)
        assertNull(vm.enrol.value)
    }

    /** SSO device keys: an Obligate account enrols through Obligate — no password, no code, never sent. */
    @Test fun `sso - explain, reconfirm with Obligate, fingerprint, enrolled`() = runTest(dispatcher) {
        val keys = SampleDeviceKeys(SampleDeviceKeys.ssoViews())
        val proofs = mutableListOf<EnrolProof>()
        val recording = object : tools.obli.obliance.data.DeviceKeysRepository by keys {
            override suspend fun enrol(serverId: ServerId, proof: EnrolProof, signer: DeviceSigner, prompt: SignPrompt) =
                keys.enrol(serverId, proof, signer, prompt).also { proofs += proof }
        }
        val vm = ProfileSecurityViewModel(SampleObliServices(deviceKeys = recording), ::prompt)
        backgroundScope.launch { vm.ui.collect { } }
        runCurrent()
        assertTrue(vm.ui.value.row(SampleData.PROD)!!.sso)
        assertFalse(vm.ui.value.row(SampleData.QUAL)!!.sso)
        vm.startEnrol(SampleData.PROD)
        val explain = vm.enrol.value as EnrolStep.Explain
        assertEquals(EnrolStep.Explain(SampleData.PROD, "Obliance Prod", sso = true), explain)
        assertTrue(vm.canSubmit(explain))
        // « Continuer » does not lead to password + code fields for an Obligate account.
        vm.continueEnrol()
        assertEquals(explain, vm.enrol.value)
        vm.password = "never sent"
        vm.submit(signerOk)
        assertEquals("", vm.password)
        assertEquals(EnrolStep.Credentials(SampleData.PROD, "Obliance Prod", busy = true, sso = true), vm.enrol.value)
        runCurrent()
        assertNull(vm.enrol.value)
        assertEquals(listOf<EnrolProof>(EnrolProof.SsoReauth), proofs)
        assertTrue(keys.views.value.getValue(SampleData.PROD).state is DeviceKeyServerState.Active)
    }

    @Test fun `sso - an expired reauthentication offers Reconfirmer again, a closed sheet too`() = runTest(dispatcher) {
        val keys = SampleDeviceKeys(SampleDeviceKeys.ssoViews())
        val answers = ArrayDeque<DeviceKeyEnrolOutcome>(
            listOf(
                DeviceKeyEnrolOutcome.Failed(EnrolProblem.REAUTH_REQUIRED),
                DeviceKeyEnrolOutcome.Cancelled,
                DeviceKeyEnrolOutcome.Failed(EnrolProblem.REAUTH_FAILED, "no_otp"),
            ),
        )
        val scripted = object : tools.obli.obliance.data.DeviceKeysRepository by keys {
            override suspend fun enrol(serverId: ServerId, proof: EnrolProof, signer: DeviceSigner, prompt: SignPrompt) = answers.removeFirst()
        }
        val vm = ProfileSecurityViewModel(SampleObliServices(deviceKeys = scripted), ::prompt)
        vm.startEnrol(SampleData.PROD)
        vm.submit(signerOk)
        runCurrent()
        val expired = EnrolStep.Credentials(SampleData.PROD, "Obliance Prod", problem = EnrolProblem.REAUTH_REQUIRED, sso = true)
        assertEquals(expired, vm.enrol.value)
        assertTrue(vm.canSubmit(expired))
        vm.submit(signerOk)
        runCurrent()
        assertEquals(EnrolStep.Credentials(SampleData.PROD, "Obliance Prod", sso = true), vm.enrol.value)
        vm.submit(signerOk)
        runCurrent()
        val noOtp = EnrolStep.Credentials(SampleData.PROD, "Obliance Prod", problem = EnrolProblem.REAUTH_FAILED, detail = "no_otp", sso = true)
        assertEquals(noOtp, vm.enrol.value)
        // no_otp cannot be fixed by a new attempt: no « Reconfirmer » (the sheet offered « Fermer » only too).
        assertTrue(noOtp.reauthFinal)
        assertFalse(noOtp.copy(detail = "identity").reauthFinal)
        assertFalse(noOtp.copy(detail = null).reauthFinal)
        assertFalse(expired.reauthFinal)
        // No signer (no FragmentActivity): explained, nothing sent.
        vm.submit(null)
        assertEquals(EnrolProblem.BIOMETRIC_UNAVAILABLE, (vm.enrol.value as EnrolStep.Credentials).problem)
        assertTrue(answers.isEmpty())
    }

    @Test fun `the proposal request is taken once`() = runTest(dispatcher) {
        val vm = ProfileSecurityViewModel(SampleObliServices(deviceKeys = qualNotEnrolled()), ::prompt)
        vm.takeEnrolRequest(SampleData.QUAL)
        vm.continueEnrol()
        vm.takeEnrolRequest(SampleData.QUAL) // recomposition after a rotation
        assertTrue(vm.enrol.value is EnrolStep.Credentials)
    }
}

/** Every state and problem has its sentence, French. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "fr-rFR")
class ProfileSecurityTextsTest {
    private val res get() = ApplicationProvider.getApplicationContext<android.content.Context>().resources

    @Test fun statesAndProblems() {
        val rec = SampleDeviceKeys.record()
        val states = listOf(
            DeviceKeyServerState.Loading, DeviceKeyServerState.SignedOut, DeviceKeyServerState.NotAvailable,
            DeviceKeyServerState.DisabledByAdmin(), DeviceKeyServerState.OriginUnset, DeviceKeyServerState.OriginMismatch("http://10.0.0.5:3001"),
            DeviceKeyServerState.SsoUnsupported, DeviceKeyServerState.TotpRequired, DeviceKeyServerState.NotEligible("too_many_keys"),
            DeviceKeyServerState.NoStrongBiometric, DeviceKeyServerState.NotEnrolled, DeviceKeyServerState.Invalidated,
            DeviceKeyServerState.Active(rec, DeviceKeyLevel.TEE, true), DeviceKeyServerState.Failed(ApiOutcome.Failure(null, FailureKind.NETWORK)),
        )
        states.forEach { assertTrue("$it", stateReason(res, it).isNotBlank()) }
        assertEquals("Pas encore disponible pour les comptes Obligate.", stateReason(res, DeviceKeyServerState.SsoUnsupported))
        assertEquals("Vous avez déjà 5 téléphones enregistrés. Révoquez-en un depuis votre profil.", stateReason(res, DeviceKeyServerState.NotEligible("too_many_keys")))
        assertEquals("Trop d’essais. L’activation est bloquée pendant 24 heures.", stateReason(res, DeviceKeyServerState.NotEligible("enrol_locked")))
        assertTrue(stateReason(res, DeviceKeyServerState.OriginMismatch("http://10.0.0.5:3001")).contains("10.0.0.5:3001"))
        EnrolProblem.entries.forEach { assertTrue("$it", enrolProblemText(res, it, "app_signer").isNotBlank()) }
        assertEquals("Ce téléphone n’a pas pu prouver que la clé est protégée par le matériel (app_signer).", enrolProblemText(res, EnrolProblem.ATTESTATION, "app_signer"))
        assertEquals("Puce de sécurité (StrongBox)", levelText(res, DeviceKeyLevel.STRONGBOX))
        // SSO device keys (enrolAskSso, formal French).
        assertEquals("Pour activer, reconfirmez votre identité auprès d'Obligate.", res.getString(R.string.more_devkey_enrol_ask_sso))
        assertEquals(
            "La reconfirmation Obligate a expiré ou votre compte Obligate a changé. Reconfirmez.",
            enrolProblemText(res, EnrolProblem.REAUTH_REQUIRED, null),
        )
        // A refused reconfirmation: « Réessayez » only when a new attempt can help (as the sheet).
        assertEquals("La reconfirmation auprès d'Obligate n'a pas abouti. Réessayez.", enrolProblemText(res, EnrolProblem.REAUTH_FAILED, "identity"))
        assertEquals("La reconfirmation auprès d'Obligate n'a pas abouti. Réessayez.", enrolProblemText(res, EnrolProblem.REAUTH_FAILED, null))
        assertEquals(
            "Activez d'abord la double authentification dans votre compte Obligate : la reconfirmation demande votre mot de passe et un code.",
            enrolProblemText(res, EnrolProblem.REAUTH_FAILED, "no_otp"),
        )
        for (reason in listOf("not_sso", "unsupported", "misconfigured", "origin", "blocked", "tls")) {
            val text = enrolProblemText(res, EnrolProblem.REAUTH_FAILED, reason)
            assertTrue(reason, text.startsWith("La reconfirmation auprès d'Obligate n'est pas possible pour le moment"))
            assertFalse(reason, text.contains("Réessayez"))
        }
        assertEquals("La vérification Obligate est momentanément indisponible. Réessayez dans un instant.", enrolProblemText(res, EnrolProblem.VERIFIER_UNAVAILABLE, null))
    }

    @Test fun datesAreShortAndToleratesGarbage() {
        assertTrue(formatDate("2026-09-12T08:14:00.000Z")!!.contains("2026"))
        assertNull(formatDate("hier"))
        assertNull(formatDate(null))
    }
}

/** Profile and security screenshots over the sample data, French, phone (build/outputs/roborazzi). */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "fr-rFR-w390dp-h1400dp-xxhdpi")
class ProfileSecurityScreenshotTest {
    @get:Rule val compose = createComposeRule()

    private fun shot(name: String) = (System.getProperty("roborazzi.output.dir") ?: "build/outputs/roborazzi") + "/" + name

    private fun capture(name: String, content: @Composable () -> Unit) {
        compose.setContent { ObliTheme { CompositionLocalProvider(LocalObliServices provides SampleObliServices()) { content() } } }
        compose.waitForIdle()
        compose.onRoot().captureRoboImage(shot(name))
    }

    private fun ui(prod: DeviceKeyServerState, dev: DeviceKeyServerState, qual: DeviceKeyServerState, qualKeys: Boolean = true, server: ServerId = SampleData.PROD): ProfileSecurityUi {
        val profiles = SampleData.profiles
        return ProfileSecurityUi(
            server = profiles.first { it.id == server },
            user = SampleData.probe(server).user,
            multiServer = true,
            rows = listOf(
                DeviceKeyRow(profiles[0], prod),
                DeviceKeyRow(profiles[1], dev, keys = if (dev is DeviceKeyServerState.NotEnrolled) emptyList() else null),
                DeviceKeyRow(profiles[2], qual, keys = if (qualKeys) SampleDeviceKeys.list().validKeys else null),
            ),
        )
    }

    private val active = DeviceKeyServerState.Active(SampleDeviceKeys.record(), DeviceKeyLevel.STRONGBOX, bound = true)

    /** The sample persona: Obligate on Prod and Dev (before SSO device keys), local account enrolled on Qual. */
    @Test fun s85() = capture("more_s85_profile_security.png") {
        ProfileSecurityContent(ui(DeviceKeyServerState.SsoUnsupported, DeviceKeyServerState.SsoUnsupported, active), ProfileSecurityActions())
    }

    @Test fun s85ActivateAndReactivate() = capture("more_s85_activate.png") {
        ProfileSecurityContent(
            ui(DeviceKeyServerState.Invalidated, DeviceKeyServerState.NotEnrolled, DeviceKeyServerState.NoStrongBiometric, qualKeys = false, server = SampleData.QUAL),
            ProfileSecurityActions(),
        )
    }

    @Test fun s85ServerSide() = capture("more_s85_server_states.png") {
        ProfileSecurityContent(
            ui(DeviceKeyServerState.NotAvailable, DeviceKeyServerState.DisabledByAdmin(), DeviceKeyServerState.OriginUnset, qualKeys = false),
            ProfileSecurityActions(),
        )
    }

    @Test fun s85Other() = capture("more_s85_other_states.png") {
        ProfileSecurityContent(
            ui(
                DeviceKeyServerState.OriginMismatch("http://10.0.0.5:3001"),
                DeviceKeyServerState.SignedOut,
                DeviceKeyServerState.Active(SampleDeviceKeys.record(), DeviceKeyLevel.UNVERIFIED, bound = false),
                server = SampleData.QUAL,
            ),
            ProfileSecurityActions(),
        )
    }

    @Test fun phones() = capture("more_s85_phones.png") {
        PhonesContent(DeviceKeyRow(SampleData.profiles[2], active, SampleDeviceKeys.list().validKeys), multiServer = true, onBack = {}, onRevoke = {}, onRevokeAll = {})
    }

    @Test fun phonesEmpty() = capture("more_s85_phones_empty.png") {
        PhonesContent(DeviceKeyRow(SampleData.profiles[2], DeviceKeyServerState.NotEnrolled, emptyList()), multiServer = true, onBack = {}, onRevoke = {}, onRevokeAll = {})
    }

    @Composable
    private fun Over(content: @Composable () -> Unit) {
        Box(Modifier.fillMaxSize()) {
            ProfileSecurityContent(ui(DeviceKeyServerState.SsoUnsupported, DeviceKeyServerState.SsoUnsupported, DeviceKeyServerState.NotEnrolled, qualKeys = false), ProfileSecurityActions())
            Box(Modifier.fillMaxSize().background(ObliTheme.colors.bg.copy(alpha = 0.6f)))
            Box(Modifier.align(Alignment.BottomCenter)) { content() }
        }
    }

    @Test fun enrolExplain() = capture("more_s85_enrol_explain.png") {
        Over { EnrolContent(EnrolStep.Explain(SampleData.QUAL, "Obliance Qual"), "", "", {}, {}, {}, {}, {}) }
    }

    @Test fun enrolCredentials() = capture("more_s85_enrol_credentials.png") {
        Over { EnrolContent(EnrolStep.Credentials(SampleData.QUAL, "Obliance Qual", wrong = true), "motdepasse", "4829", {}, {}, {}, {}, {}) }
    }

    @Test fun enrolRefused() = capture("more_s85_enrol_attestation.png") {
        Over { EnrolContent(EnrolStep.Credentials(SampleData.QUAL, "Obliance Qual", problem = EnrolProblem.ATTESTATION, detail = "bootloader_unlocked"), "", "", {}, {}, {}, {}, {}) }
    }

    @Test fun enrolBusy() = capture("more_s85_enrol_busy.png") {
        Over { EnrolContent(EnrolStep.Credentials(SampleData.QUAL, "Obliance Qual", busy = true), "", "", {}, {}, {}, {}, {}) }
    }

    /** SSO device keys on: Obligate account of Prod not enrolled (« Activer » through Obligate), Dev's enrolled, Qual local. */
    @Test fun s85Sso() = capture("more_s85_sso.png") {
        val views = SampleDeviceKeys.ssoViews()
        val profiles = SampleData.profiles
        ProfileSecurityContent(
            ProfileSecurityUi(
                server = profiles[0],
                user = SampleData.probe(SampleData.PROD).user,
                multiServer = true,
                rows = profiles.map { p -> views.getValue(p.id).let { v -> DeviceKeyRow(p, v.state, v.list?.validKeys, sso = v.sso) } },
            ),
            ProfileSecurityActions(),
        )
    }

    @Test fun enrolExplainSso() = capture("more_s85_enrol_explain_sso.png") {
        Over { EnrolContent(EnrolStep.Explain(SampleData.PROD, "Obliance Prod", sso = true), "", "", {}, {}, {}, {}, {}) }
    }

    @Test fun enrolSsoReauthExpired() = capture("more_s85_enrol_sso_reauth_expired.png") {
        Over { EnrolContent(EnrolStep.Credentials(SampleData.PROD, "Obliance Prod", problem = EnrolProblem.REAUTH_REQUIRED, sso = true), "", "", {}, {}, {}, {}, {}) }
    }

    @Test fun enrolSsoReauthFinal() = capture("more_s85_enrol_sso_reauth_no_otp.png") {
        Over { EnrolContent(EnrolStep.Credentials(SampleData.PROD, "Obliance Prod", problem = EnrolProblem.REAUTH_FAILED, detail = "no_otp", sso = true), "", "", {}, {}, {}, {}, {}) }
    }

    @Test fun enrolSsoBusy() = capture("more_s85_enrol_sso_busy.png") {
        Over { EnrolContent(EnrolStep.Credentials(SampleData.PROD, "Obliance Prod", busy = true, sso = true), "", "", {}, {}, {}, {}, {}) }
    }

    @Test fun proposal() = capture("more_s85_proposal.png") {
        Box(Modifier.fillMaxSize().background(ObliTheme.colors.bg)) {
            Box(Modifier.align(Alignment.BottomCenter)) { ProposalContent("Obliance Qual", {}, {}) }
        }
    }

    /** Plus screen with the profile and security row enabled. */
    @Config(qualifiers = "fr-rFR-w390dp-h844dp-xxhdpi")
    @Test fun moreWithProfile() = capture("more_phone_profile_row.png") {
        MoreRoute(MoreActions(onOpenProfile = {}), appVersion = FALLBACK_APP_VERSION)
    }
}

/** The public proposal host shows nothing without a proposal and the sheet with one. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "fr-rFR-w390dp-h844dp-xxhdpi")
class DeviceKeyProposalHostTest {
    @get:Rule val compose = createComposeRule()

    @Test fun answersGoToTheRepository() {
        val keys = SampleDeviceKeys(proposal = DeviceKeyProposal(SampleData.QUAL, "Obliance Qual"))
        var enabled: ServerId? = null
        compose.setContent {
            ObliTheme { CompositionLocalProvider(LocalObliServices provides SampleObliServices(deviceKeys = keys)) { DeviceKeyProposalHost(onEnable = { enabled = it }) } }
        }
        compose.waitForIdle()
        compose.onNodeWithText("Activer").performClick()
        compose.waitForIdle()
        assertEquals(SampleData.QUAL, enabled)
        assertNull(keys.proposal.value)
    }
}
