package tools.obli.obliance.more

import android.content.res.Resources
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetProperties
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import kotlinx.coroutines.launch
import tools.obli.core.designsystem.ObliDetailTopBar
import tools.obli.core.designsystem.ObliIcons
import tools.obli.core.designsystem.ObliServerTile
import tools.obli.core.designsystem.ObliTheme
import tools.obli.core.designsystem.ObliTokens
import tools.obli.core.designsystem.ObliTypography
import tools.obli.core.designsystem.toColor
import tools.obli.core.model.ServerId
import tools.obli.core.security.ActionResult
import tools.obli.core.security.ActionSpec
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SsoReauthResult
import tools.obli.core.security.Tier
import tools.obli.core.security.ui.rememberDeviceSigner
import tools.obli.core.security.ui.LocalActionFeedback
import tools.obli.core.security.ui.LocalActionRunner
import tools.obli.obliance.api.DeviceKeyInfo
import tools.obli.obliance.data.DeviceKeyServerState
import tools.obli.obliance.data.EnrolProblem
import tools.obli.obliance.data.LocalObliNavigator
import tools.obli.obliance.data.LocalObliServices

/**
 * « Profil et sécurité »: the account of the active server, « Validation par
 * empreinte » with one row per server (device-key states), the enrolment
 * (explanation, password + NEW code, fingerprint) and « Téléphones de ce
 * compte » with Révoquer (T1) / Tout révoquer (T2).
 *
 * [enrolServerId]: open the enrolment of that server at once (the « Utiliser
 * l'empreinte la prochaine fois ? » proposal); [onEnrolRequestHandled] is
 * called once it is taken.
 */
@Composable
fun ProfileSecurityScreen(onBack: () -> Unit, enrolServerId: ServerId? = null, onEnrolRequestHandled: () -> Unit = {}) {
    val services = LocalObliServices.current
    val resources = LocalResources.current
    // The fingerprint signer of the CURRENT activity (a new one after a rotation), handed to the
    // ViewModel at each « Activer »: never one captured by the ViewModel when it was created.
    val signer = rememberDeviceSigner(services.deviceKeys.hardware)
    val vm = viewModel { ProfileSecurityViewModel(services, enrolPrompt = { server -> enrolPrompt(resources, server) }) }
    val ui by vm.ui.collectAsStateWithLifecycle()
    val enrol by vm.enrol.collectAsStateWithLifecycle()
    val enrolled by vm.enrolled.collectAsStateWithLifecycle()
    val runner = LocalActionRunner.current
    val feedback = LocalActionFeedback.current
    val navigator = LocalObliNavigator.current
    val scope = rememberCoroutineScope()
    var phonesFor by rememberSaveable { mutableStateOf<String?>(null) }

    LifecycleResumeEffect(vm) {
        vm.refreshAll()
        onPauseOrDispose { }
    }
    LaunchedEffect(enrolServerId) {
        if (enrolServerId != null) {
            vm.takeEnrolRequest(enrolServerId)
            onEnrolRequestHandled()
        }
    }
    LaunchedEffect(enrolled) {
        val done = enrolled ?: return@LaunchedEffect
        feedback.show(ActionResult.Done(Unit), resources.getString(R.string.more_devkey_enrolled, levelText(resources, done.level)))
        vm.enrolledShown()
    }

    fun revoke(row: DeviceKeyRow, key: DeviceKeyInfo?) {
        val serverName = row.profile.displayName
        val here = key == null || services.deviceKeys.localKey(row.profile.id)?.keyId.equals(key.id, ignoreCase = true)
        val keyId = key?.id ?: services.deviceKeys.localKey(row.profile.id)?.keyId ?: return
        val spec = ActionSpec(
            key = if (key == null) "profile.device_key.disable_here" else "profile.device_key.revoke",
            tier = Tier.T1,
            title = resources.getString(if (key == null) R.string.more_devkey_disable_here else R.string.more_devkey_list_revoke),
            target = key?.label?.takeIf { it.isNotBlank() } ?: resources.getString(if (key == null) R.string.more_devkey_title else R.string.more_devkey_list_unnamed),
            scope = serverName,
            consequence = resources.getString(if (here) R.string.more_devkey_revoke_here_consequence else R.string.more_devkey_revoke_consequence),
            serverName = serverName,
        )
        scope.launch {
            val result = runner.run(spec) { services.deviceKeys.revoke(row.profile.id, keyId) }
            feedback.show(result, resources.getString(if (key == null) R.string.more_devkey_disabled_here else R.string.more_devkey_revoked))
        }
    }

    fun revokeAll(row: DeviceKeyRow) {
        val serverName = row.profile.displayName
        val spec = ActionSpec(
            key = "profile.device_key.revoke_all",
            tier = Tier.T2,
            title = resources.getString(R.string.more_devkey_list_revoke_all),
            target = resources.getString(R.string.more_devkey_revoke_all_target),
            scope = serverName,
            consequence = resources.getString(R.string.more_devkey_revoke_all_consequence),
            targetCount = row.keys?.size?.coerceAtLeast(1) ?: 1,
            serverName = serverName,
        )
        scope.launch {
            val result = runner.run(spec) { services.deviceKeys.revokeAll(row.profile.id) }
            feedback.show(result, resources.getString(R.string.more_devkey_revoked_all))
        }
    }

    val phonesRow = phonesFor?.let { id -> ui.row(ServerId(id)) }
    if (phonesRow != null) {
        BackHandler { phonesFor = null }
        PhonesContent(
            row = phonesRow,
            multiServer = ui.multiServer,
            onBack = { phonesFor = null },
            onRevoke = { key -> revoke(phonesRow, key) },
            onRevokeAll = { revokeAll(phonesRow) },
        )
    } else {
        ProfileSecurityContent(
            ui,
            ProfileSecurityActions(
                onBack = onBack,
                onEnrol = vm::startEnrol,
                onDisableHere = { row -> revoke(row, null) },
                onOpenPhones = { id -> phonesFor = id.value },
                onRetry = vm::refresh,
                onOpenWebProfile = { navigator.openWeb(WEB_PROFILE_PATH, resources.getString(R.string.more_profile_web_title)) },
            ),
        )
    }

    enrol?.let { step -> EnrolSheet(step, vm, onSubmit = { vm.submit(signer) }) }
}

/** The web profile (password, 2FA, SSH keys): client/src/App.tsx `/profile`. */
internal const val WEB_PROFILE_PATH = "/profile"

internal data class ProfileSecurityActions(
    val onBack: () -> Unit = {},
    val onEnrol: (ServerId) -> Unit = {},
    val onDisableHere: (DeviceKeyRow) -> Unit = {},
    val onOpenPhones: (ServerId) -> Unit = {},
    val onRetry: (ServerId) -> Unit = {},
    val onOpenWebProfile: () -> Unit = {},
)

/** Texts of the enrolment's biometric prompt: no device credential, « Annuler » as negative button. */
internal fun enrolPrompt(resources: Resources, serverName: String): SignPrompt = SignPrompt(
    title = resources.getString(R.string.more_devkey_prompt_title),
    subtitle = serverName,
    description = resources.getString(R.string.more_devkey_warn_others),
    negative = resources.getString(R.string.more_cancel),
)

internal fun levelText(resources: Resources, level: DeviceKeyLevel): String = resources.getString(
    when (level) {
        DeviceKeyLevel.STRONGBOX -> R.string.more_devkey_level_strongbox
        DeviceKeyLevel.TEE -> R.string.more_devkey_level_tee
        DeviceKeyLevel.UNVERIFIED -> R.string.more_devkey_level_unverified
    },
)

@Composable
private fun levelLabel(level: DeviceKeyLevel): String = levelText(LocalResources.current, level)

// --- Content ---------------------------------------------------------------------------

@Composable
internal fun ProfileSecurityContent(ui: ProfileSecurityUi, actions: ProfileSecurityActions) {
    val c = ObliTheme.colors
    Column(Modifier.fillMaxSize().background(c.bg)) {
        ObliDetailTopBar(
            title = stringResource(R.string.more_profile_title),
            onBack = actions.onBack,
            backLabel = stringResource(R.string.more_back),
            subtitle = ui.server?.displayName,
        )
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
            Column(
                Modifier.widthIn(max = 640.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 24.dp),
            ) {
                AccountSummary(ui)
                SectionTitle(stringResource(R.string.more_devkey_title))
                Text(stringResource(R.string.more_devkey_intro), style = ObliTypography.body, color = c.text2, modifier = Modifier.padding(start = 4.dp, end = 4.dp, bottom = 12.dp))
                if (!ui.supported) {
                    ListGroup { ReasonBlock(stringResource(R.string.more_devkey_unsupported_app)) }
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        ui.rows.forEach { row -> DeviceKeyServerCard(row, ui.multiServer, actions) }
                    }
                }
                SectionTitle(stringResource(R.string.more_section_account))
                ListGroup {
                    NavRow(MoreIcons.Settings, stringResource(R.string.more_profile_web), stringResource(R.string.more_profile_web_value), actions.onOpenWebProfile)
                }
            }
        }
    }
}

@Composable
private fun AccountSummary(ui: ProfileSecurityUi) {
    val c = ObliTheme.colors
    val user = ui.user ?: return
    ListGroup {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(user.label, style = ObliTypography.rowTitle, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(user.username, style = ObliTypography.monoCaption, color = c.text2, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                stringResource(if (ui.obligate) R.string.more_account_obligate else R.string.more_account_local),
                style = ObliTypography.labelSmall.copy(fontWeight = FontWeight.Normal),
                color = c.textMuted,
            )
            if (!ui.obligate) {
                val on = stringResource(R.string.more_profile_on)
                val off = stringResource(R.string.more_profile_off)
                Text(
                    stringResource(R.string.more_profile_2fa, if (user.totpEnabled) on else off, if (user.emailOtpEnabled) on else off),
                    style = ObliTypography.body,
                    color = c.textMuted,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

/** One server: its device-key state, the action it allows, and its phones list. */
@Composable
private fun DeviceKeyServerCard(row: DeviceKeyRow, multiServer: Boolean, actions: ProfileSecurityActions) {
    val c = ObliTheme.colors
    val state = row.state
    val id = row.profile.id
    ListGroup {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 64.dp)
                .then(if (state is DeviceKeyServerState.Failed) Modifier.clickable { actions.onRetry(id) } else Modifier)
                .padding(start = 16.dp, end = 12.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Box(Modifier.size(36.dp), contentAlignment = Alignment.Center) {
                if (multiServer) ObliServerTile(row.profile.color, row.profile.monogram, row.profile.displayName, size = 28.dp) else IconTile(MoreIcons.Fingerprint)
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(row.profile.displayName, style = rowLabel, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                StateLine(state)
            }
        }
        val action: Pair<String, () -> Unit>? = when (state) {
            DeviceKeyServerState.NotEnrolled -> stringResource(R.string.more_devkey_activate) to { actions.onEnrol(id) }
            DeviceKeyServerState.Invalidated -> stringResource(R.string.more_devkey_reactivate) to { actions.onEnrol(id) }
            else -> null
        }
        val disableHere = state is DeviceKeyServerState.Active || (state is DeviceKeyServerState.DisabledByAdmin && state.record != null)
        if (action != null || disableHere) {
            Row(Modifier.fillMaxWidth().padding(start = 66.dp, end = 12.dp, bottom = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (action != null) KitButton(action.first, action.second, icon = MoreIcons.Fingerprint)
                if (disableHere) KitButton(stringResource(R.string.more_devkey_disable_here), { actions.onDisableHere(row) }, primary = false)
            }
        }
        val keys = row.keys
        if (keys != null && state.showsPhones) {
            NavRow(
                MoreIcons.Smartphone,
                stringResource(R.string.more_devkey_phones),
                pluralStringResource(R.plurals.more_devkey_phones_value, keys.size, keys.size),
                onClick = { actions.onOpenPhones(id) },
            )
        }
    }
}

/** The phones list only means something once the server answered for this account. */
private val DeviceKeyServerState.showsPhones: Boolean
    get() = this !is DeviceKeyServerState.SignedOut && this !is DeviceKeyServerState.NotAvailable && this !is DeviceKeyServerState.Failed && this !is DeviceKeyServerState.Loading

@Composable
private fun StateLine(state: DeviceKeyServerState) {
    val c = ObliTheme.colors
    val res = LocalResources.current
    when (state) {
        is DeviceKeyServerState.Active -> {
            Text(stringResource(R.string.more_devkey_state_active, levelLabel(state.level)), style = ObliTypography.body, color = c.text2)
            if (state.level == DeviceKeyLevel.UNVERIFIED) Warning(stringResource(R.string.more_devkey_level_unverified))
            if (!state.bound) ReasonLine(stringResource(R.string.more_devkey_state_unbound))
        }
        DeviceKeyServerState.NotEnrolled -> Text(stringResource(R.string.more_devkey_state_off), style = ObliTypography.body, color = c.textMuted)
        DeviceKeyServerState.Invalidated -> Warning(stringResource(R.string.more_devkey_invalidated))
        DeviceKeyServerState.Loading -> Text(stringResource(R.string.more_devkey_state_loading), style = ObliTypography.body, color = c.textMuted)
        else -> ReasonLine(stateReason(res, state))
    }
}

/** The reference sentence of a state that offers no « Activer ». */
internal fun stateReason(res: Resources, state: DeviceKeyServerState): String = when (state) {
    DeviceKeyServerState.SignedOut -> res.getString(R.string.more_devkey_state_signed_out)
    DeviceKeyServerState.NotAvailable -> res.getString(R.string.more_devkey_not_available)
    is DeviceKeyServerState.DisabledByAdmin -> res.getString(R.string.more_devkey_disabled_by_admin)
    DeviceKeyServerState.OriginUnset -> res.getString(R.string.more_devkey_origin_unset)
    is DeviceKeyServerState.OriginMismatch -> res.getString(R.string.more_devkey_origin_mismatch, MoreMapper.hostOf(state.origin))
    DeviceKeyServerState.SsoUnsupported -> res.getString(R.string.more_devkey_sso_unsupported)
    DeviceKeyServerState.TotpRequired -> res.getString(R.string.more_devkey_totp_required)
    is DeviceKeyServerState.NotEligible ->
        when {
            state.reason?.contains("too_many", ignoreCase = true) == true -> res.getString(R.string.more_devkey_too_many)
            state.reason?.contains("locked", ignoreCase = true) == true -> res.getString(R.string.more_devkey_enrol_locked)
            else -> res.getString(R.string.more_devkey_not_eligible)
        }
    DeviceKeyServerState.NoStrongBiometric -> res.getString(R.string.more_devkey_no_strong_biometric)
    is DeviceKeyServerState.Failed -> res.getString(R.string.more_devkey_state_failed)
    DeviceKeyServerState.Invalidated -> res.getString(R.string.more_devkey_invalidated)
    DeviceKeyServerState.Loading -> res.getString(R.string.more_devkey_state_loading)
    DeviceKeyServerState.NotEnrolled -> res.getString(R.string.more_devkey_state_off)
    is DeviceKeyServerState.Active -> res.getString(R.string.more_devkey_state_active, levelText(res, state.level))
}

/** Amber icon + text (never colour alone). */
@Composable
private fun Warning(text: String) {
    Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Icon(ObliIcons.TriangleAlert, contentDescription = null, tint = ObliTokens.Status.WARNING.argb.toColor(), modifier = Modifier.padding(top = 3.dp).size(14.dp))
        Text(text, style = ObliTypography.body, color = ObliTheme.colors.text2)
    }
}

@Composable
private fun ColumnScope.ReasonBlock(text: String) {
    ReasonLine(text, Modifier.padding(horizontal = 16.dp, vertical = 14.dp))
}

// --- Phones of the account ----------------------------------------------------------------

@Composable
internal fun PhonesContent(
    row: DeviceKeyRow,
    multiServer: Boolean,
    onBack: () -> Unit,
    onRevoke: (DeviceKeyInfo) -> Unit,
    onRevokeAll: () -> Unit,
) {
    val c = ObliTheme.colors
    val keys = row.keys.orEmpty()
    Column(Modifier.fillMaxSize().background(c.bg)) {
        ObliDetailTopBar(
            title = stringResource(R.string.more_devkey_list_title),
            onBack = onBack,
            backLabel = stringResource(R.string.more_back),
            // The server is always named (a revocation acts on THIS server's account).
            subtitle = row.profile.displayName,
        )
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
            Column(
                Modifier.widthIn(max = 640.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(stringResource(R.string.more_devkey_list_add_hint), style = ObliTypography.body, color = c.text2, modifier = Modifier.padding(horizontal = 4.dp))
                if (keys.isEmpty()) {
                    ListGroup { ReasonBlock(stringResource(R.string.more_devkey_list_empty)) }
                } else {
                    ListGroup { keys.forEach { key -> PhoneRow(key, onRevoke) } }
                    Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.End) {
                        KitButton(stringResource(R.string.more_devkey_list_revoke_all), onRevokeAll, primary = false, icon = ObliIcons.Trash)
                    }
                }
            }
        }
    }
}

@Composable
private fun PhoneRow(key: DeviceKeyInfo, onRevoke: (DeviceKeyInfo) -> Unit) {
    val c = ObliTheme.colors
    Row(
        Modifier.fillMaxWidth().heightIn(min = 72.dp).padding(start = 16.dp, end = 12.dp, top = 12.dp, bottom = 12.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        IconTile(MoreIcons.Smartphone)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                key.label?.takeIf { it.isNotBlank() } ?: stringResource(R.string.more_devkey_list_unnamed),
                style = rowLabel,
                color = c.text,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            if (key.current) Tag(stringResource(R.string.more_devkey_list_this_session))
            if (key.level == DeviceKeyLevel.UNVERIFIED) Warning(levelLabel(key.level)) else Text(levelLabel(key.level), style = ObliTypography.body, color = c.text2)
            formatDate(key.createdAt)?.let { Text(stringResource(R.string.more_devkey_list_added, it), style = ObliTypography.body, color = c.textMuted) }
            val used = formatDate(key.lastUsedAt)
            Text(
                if (used == null) stringResource(R.string.more_devkey_list_never_used) else stringResource(R.string.more_devkey_list_used, used, key.lastUsedIp ?: "—"),
                style = ObliTypography.body,
                color = c.textMuted,
            )
            Row(Modifier.fillMaxWidth().padding(top = 6.dp), horizontalArrangement = Arrangement.End) {
                KitButton(stringResource(R.string.more_devkey_list_revoke), { onRevoke(key) }, primary = false)
            }
        }
    }
}

/** ISO date of the server → short local date ("26/09/2026"); null when absent or unreadable. */
internal fun formatDate(iso: String?): String? {
    if (iso.isNullOrBlank()) return null
    return runCatching {
        DateTimeFormatter.ofLocalizedDate(FormatStyle.SHORT).format(Instant.parse(iso).atZone(ZoneId.systemDefault()))
    }.getOrNull()
}

// --- Enrolment -----------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EnrolSheet(step: EnrolStep, vm: ProfileSecurityViewModel, onSubmit: () -> Unit) {
    val c = ObliTheme.colors
    val busy = (step as? EnrolStep.Credentials)?.busy == true
    ModalBottomSheet(
        onDismissRequest = vm::cancelEnrol,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true, confirmValueChange = { !busy }),
        sheetMaxWidth = 480.dp,
        containerColor = c.surface1,
        dragHandle = { BottomSheetDefaults.DragHandle(color = c.textFaint) },
        properties = ModalBottomSheetProperties(shouldDismissOnBackPress = !busy, shouldDismissOnClickOutside = false),
    ) {
        EnrolContent(
            step,
            password = vm.password,
            code = vm.code,
            onPassword = { vm.password = it },
            onCode = { vm.code = it },
            onContinue = vm::continueEnrol,
            onSubmit = onSubmit,
            onCancel = vm::cancelEnrol,
        )
    }
}

@Composable
internal fun EnrolContent(
    step: EnrolStep,
    password: String,
    code: String,
    onPassword: (String) -> Unit,
    onCode: (String) -> Unit,
    onContinue: () -> Unit,
    onSubmit: () -> Unit,
    onCancel: () -> Unit,
) {
    val c = ObliTheme.colors
    val res = LocalResources.current
    Column(
        Modifier.fillMaxWidth().background(c.surface1).verticalScroll(rememberScrollState()).imePadding().padding(start = 20.dp, end = 20.dp, top = 4.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.Top) {
            Box(Modifier.size(40.dp).clip(RoundedCornerShape(8.dp)).background(c.surface2), contentAlignment = Alignment.Center) {
                Icon(MoreIcons.Fingerprint, contentDescription = null, tint = c.text2, modifier = Modifier.size(20.dp))
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.more_devkey_explain_title), style = ObliTypography.dialogTitle, color = c.text, modifier = Modifier.semantics { heading() })
                Text(step.serverName, style = ObliTypography.monoCaption, color = c.text2)
            }
        }
        when (step) {
            is EnrolStep.Explain -> {
                Text(stringResource(R.string.more_devkey_intro), style = ObliTypography.body, color = c.text2)
                Note(stringResource(R.string.more_devkey_warn_others), ObliIcons.TriangleAlert, ObliTokens.Status.WARNING.argb.toColor())
                Note(stringResource(R.string.more_devkey_warn_new_biometric), ObliIcons.Info, c.text2)
                // Obligate account (SSO device keys): nothing to type here, the Obligate sheet comes next.
                if (step.sso) SsoAsk()
                Row(Modifier.fillMaxWidth().padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.End)) {
                    KitButton(stringResource(R.string.more_cancel), onCancel, primary = false)
                    if (step.sso) {
                        KitButton(stringResource(R.string.more_devkey_reauth), onSubmit, icon = MoreIcons.Fingerprint)
                    } else {
                        KitButton(stringResource(R.string.more_devkey_continue), onContinue)
                    }
                }
            }
            is EnrolStep.Credentials -> if (step.sso) {
                // SSO variant: « Reconfirmer avec Obligate » (again after a refusal), never a password nor a code.
                SsoAsk()
                step.problem?.let { Note(enrolProblemText(res, it, step.detail), ObliIcons.CircleAlert, ObliTokens.Status.WARNING.argb.toColor(), live = true) }
                Row(Modifier.fillMaxWidth().padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.End), verticalAlignment = Alignment.CenterVertically) {
                    if (step.busy) {
                        CircularProgressIndicator(Modifier.size(18.dp), color = c.text2, strokeWidth = 2.dp)
                        Text(stringResource(R.string.more_devkey_busy_sso), style = ObliTypography.body, color = c.text2, modifier = Modifier.weight(1f))
                    } else {
                        KitButton(stringResource(R.string.more_cancel), onCancel, primary = false)
                        // A refusal a new attempt cannot fix (no OTP at Obligate, SSO device keys off…): no « Reconfirmer ».
                        if (!step.reauthFinal) KitButton(stringResource(R.string.more_devkey_reauth), onSubmit, icon = MoreIcons.Fingerprint)
                    }
                }
            } else {
                Text(stringResource(R.string.more_devkey_enrol_ask), style = ObliTypography.body, color = c.text2)
                if (step.wrong) Note(stringResource(R.string.more_devkey_wrong), ObliIcons.CircleAlert, ObliTokens.Status.WARNING.argb.toColor(), live = true)
                step.problem?.let { Note(enrolProblemText(res, it, step.detail), ObliIcons.CircleAlert, ObliTokens.Status.WARNING.argb.toColor(), live = true) }
                PasswordField(password, onPassword, enabled = !step.busy)
                CodeField(code, onCode, enabled = !step.busy)
                Text(stringResource(R.string.more_devkey_enrol_new_code), style = ObliTypography.labelSmall.copy(fontWeight = FontWeight.Normal), color = c.textMuted)
                Row(Modifier.fillMaxWidth().padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.End), verticalAlignment = Alignment.CenterVertically) {
                    if (step.busy) {
                        CircularProgressIndicator(Modifier.size(18.dp), color = c.text2, strokeWidth = 2.dp)
                        Text(stringResource(R.string.more_devkey_busy), style = ObliTypography.body, color = c.text2, modifier = Modifier.weight(1f))
                    } else {
                        KitButton(stringResource(R.string.more_cancel), onCancel, primary = false)
                    }
                    val canSubmit = !step.busy && password.isNotEmpty() && code.length == ProfileSecurityViewModel.CODE_LENGTH
                    KitButton(stringResource(R.string.more_devkey_activate), onSubmit, enabled = canSubmit, icon = MoreIcons.Fingerprint)
                }
            }
        }
    }
}

/** `enrolAskSso` and what Obligate will ask (SSO variant). */
@Composable
private fun SsoAsk() {
    val c = ObliTheme.colors
    Text(stringResource(R.string.more_devkey_enrol_ask_sso), style = ObliTypography.body, color = c.text)
    Text(stringResource(R.string.more_devkey_enrol_sso_hint), style = ObliTypography.labelSmall.copy(fontWeight = FontWeight.Normal), color = c.textMuted)
}

/** The Obligate re-authentication was refused for a reason a new attempt cannot fix (SSO device keys). */
internal val EnrolStep.Credentials.reauthFinal: Boolean
    get() = problem == EnrolProblem.REAUTH_FAILED && detail?.let { !SsoReauthResult.Failed.canRetry(it) } == true

/** Why the enrolment stopped, in the reference wording where it has one. */
internal fun enrolProblemText(res: Resources, problem: EnrolProblem, detail: String?): String = when (problem) {
    EnrolProblem.DISABLED -> res.getString(R.string.more_devkey_disabled_by_admin)
    EnrolProblem.ORIGIN_UNSET -> res.getString(R.string.more_devkey_origin_unset)
    EnrolProblem.ORIGIN_MISMATCH -> res.getString(R.string.more_devkey_origin_mismatch, detail ?: "—")
    EnrolProblem.SSO_UNSUPPORTED -> res.getString(R.string.more_devkey_sso_unsupported)
    EnrolProblem.NO_TOTP -> res.getString(R.string.more_devkey_totp_required)
    EnrolProblem.REAUTH_REQUIRED -> res.getString(R.string.more_devkey_problem_reauth_required)
    // The Obligate sheet already said why (its reason code is the detail); « Réessayez » only
    // when a new attempt can help, as the sheet.
    EnrolProblem.REAUTH_FAILED -> when {
        detail == "no_otp" -> res.getString(R.string.more_devkey_problem_reauth_no_otp)
        detail != null && !SsoReauthResult.Failed.canRetry(detail) -> res.getString(R.string.more_devkey_problem_reauth_final)
        else -> res.getString(R.string.more_devkey_problem_reauth_failed)
    }
    EnrolProblem.VERIFIER_UNAVAILABLE -> res.getString(R.string.more_devkey_problem_verifier_unavailable)
    EnrolProblem.LOCKED -> res.getString(R.string.more_devkey_enrol_locked)
    EnrolProblem.CODE_LOCKED -> res.getString(R.string.more_devkey_code_locked)
    EnrolProblem.RATE_LIMITED -> res.getString(R.string.more_devkey_problem_rate)
    EnrolProblem.CODE_USED -> res.getString(R.string.more_devkey_problem_code_used)
    EnrolProblem.TOO_MANY_KEYS -> res.getString(R.string.more_devkey_too_many)
    EnrolProblem.ALREADY_ENROLLED -> res.getString(R.string.more_devkey_problem_already)
    EnrolProblem.ATTESTATION -> res.getString(R.string.more_devkey_attestation_failed, detail ?: "—")
    EnrolProblem.NOT_HARDWARE_BACKED -> res.getString(R.string.more_devkey_problem_hardware)
    EnrolProblem.TICKET -> res.getString(R.string.more_devkey_problem_ticket)
    EnrolProblem.BUSY -> res.getString(R.string.more_devkey_problem_busy)
    EnrolProblem.KEY_FAILED -> res.getString(R.string.more_devkey_problem_key)
    EnrolProblem.BIOMETRIC_LOCKED -> res.getString(R.string.more_devkey_problem_biometric_locked)
    EnrolProblem.BIOMETRIC_UNAVAILABLE -> res.getString(R.string.more_devkey_problem_biometric)
    EnrolProblem.NOT_AVAILABLE -> res.getString(R.string.more_devkey_not_available)
    EnrolProblem.SESSION_EXPIRED -> res.getString(R.string.more_devkey_problem_session)
    EnrolProblem.NETWORK -> res.getString(R.string.more_devkey_problem_network)
    EnrolProblem.FAILED ->
        if (detail.isNullOrBlank()) res.getString(R.string.more_devkey_problem_failed) else res.getString(R.string.more_devkey_problem_failed_detail, detail.take(80))
}

/** Icon + text on `hover` (not colour alone): warnings and errors of the sheet. */
@Composable
private fun Note(text: String, icon: ImageVector, tint: Color, live: Boolean = false) {
    val c = ObliTheme.colors
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(c.hover).padding(12.dp)
            .let { if (live) it.semantics { liveRegion = LiveRegionMode.Polite } else it },
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(16.dp))
        Text(text, style = ObliTypography.body, color = c.text)
    }
}

/** The account password (`stepUpPassword` of enrol/begin): masked, kept by the ViewModel until sent. */
@Composable
private fun PasswordField(password: String, onChange: (String) -> Unit, enabled: Boolean) {
    val c = ObliTheme.colors
    val label = stringResource(R.string.more_devkey_password)
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(label.uppercase(), style = ObliTypography.overline, color = c.textMuted)
        BasicTextField(
            value = password,
            onValueChange = onChange,
            enabled = enabled,
            textStyle = ObliTypography.body.copy(color = c.text),
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            cursorBrush = SolidColor(c.accentText),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).clip(RoundedCornerShape(6.dp)).background(c.surface2)
                .padding(horizontal = 12.dp, vertical = 14.dp).semantics { contentDescription = label },
        )
    }
}

/** Six boxes over one numeric field (one-time-code autofill, TalkBack reads one field). */
@Composable
private fun CodeField(code: String, onChange: (String) -> Unit, enabled: Boolean) {
    val c = ObliTheme.colors
    val label = stringResource(R.string.more_devkey_code)
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(label.uppercase(), style = ObliTypography.overline, color = c.textMuted)
        BasicTextField(
            value = TextFieldValue(code, selection = TextRange(code.length)),
            onValueChange = { v -> onChange(v.text.filter { it.isDigit() }.take(ProfileSecurityViewModel.CODE_LENGTH)) },
            enabled = enabled,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            cursorBrush = SolidColor(Color.Transparent),
            modifier = Modifier.fillMaxWidth().semantics { contentDescription = label },
            decorationBox = { inner ->
                Box {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        repeat(ProfileSecurityViewModel.CODE_LENGTH) { i ->
                            val ch = code.getOrNull(i)
                            val focused = i == code.length
                            Box(
                                Modifier.weight(1f).height(56.dp).clip(RoundedCornerShape(6.dp)).background(c.surface2)
                                    .border(if (focused) 2.dp else 1.dp, if (focused) c.accentLine else c.divider, RoundedCornerShape(6.dp)),
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(ch?.toString() ?: "", style = ObliTypography.otp, color = c.text)
                            }
                        }
                    }
                    Box(Modifier.matchParentSize().alpha(0f)) { inner() }
                }
            },
        )
    }
}

// --- « Utiliser l'empreinte la prochaine fois ? » -----------------------------------------------

/**
 * The first-2FA proposal: after a 6-digit code went through on a
 * server where this phone could enrol, « Utiliser l'empreinte la prochaine
 * fois ? ». « Activer » calls [onEnable] with that server (the app opens « Profil et sécurité »
 * on its enrolment); « Plus tard » is remembered 30 days. Place it once in the shell.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceKeyProposalHost(onEnable: (ServerId) -> Unit) {
    val services = LocalObliServices.current
    val proposal by services.deviceKeys.proposal.collectAsStateWithLifecycle()
    val registry by services.registry.state.collectAsStateWithLifecycle()
    val p = proposal ?: return
    val c = ObliTheme.colors
    ModalBottomSheet(
        onDismissRequest = { services.deviceKeys.answerProposal(accepted = false) },
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        sheetMaxWidth = 480.dp,
        containerColor = c.surface1,
        dragHandle = { BottomSheetDefaults.DragHandle(color = c.textFaint) },
    ) {
        ProposalContent(
            serverName = p.serverName.takeIf { registry.isMultiServer },
            onEnable = {
                services.deviceKeys.answerProposal(accepted = true)
                onEnable(p.serverId)
            },
            onLater = { services.deviceKeys.answerProposal(accepted = false) },
        )
    }
}

@Composable
internal fun ProposalContent(serverName: String?, onEnable: () -> Unit, onLater: () -> Unit) {
    val c = ObliTheme.colors
    Column(
        Modifier.fillMaxWidth().background(c.surface1).padding(start = 20.dp, end = 20.dp, top = 4.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(40.dp).clip(RoundedCornerShape(8.dp)).background(c.surface2), contentAlignment = Alignment.Center) {
                Icon(MoreIcons.Fingerprint, contentDescription = null, tint = c.text2, modifier = Modifier.size(20.dp))
            }
            Text(stringResource(R.string.more_devkey_propose_title), style = ObliTypography.dialogTitle, color = c.text, modifier = Modifier.weight(1f).semantics { heading() })
        }
        Text(
            if (serverName != null) stringResource(R.string.more_devkey_propose_body_server, serverName) else stringResource(R.string.more_devkey_propose_body),
            style = ObliTypography.body,
            color = c.text2,
        )
        Row(Modifier.fillMaxWidth().padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.End)) {
            KitButton(stringResource(R.string.more_devkey_propose_later), onLater, primary = false)
            KitButton(stringResource(R.string.more_devkey_propose_enable), onEnable, icon = MoreIcons.Fingerprint)
        }
    }
}
