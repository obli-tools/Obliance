package tools.obli.obliance.app

import androidx.annotation.StringRes
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable
import tools.obli.core.designsystem.ObliIcons

/** Navigation 3 keys of the shell (saved with the back stacks, hence @Serializable). */
@Serializable
sealed interface AppKey : NavKey

@Serializable
data object TriageKey : AppKey

@Serializable
data object DevicesKey : AppKey

@Serializable
data object ActivityKey : AppKey

@Serializable
data object FleetKey : AppKey

@Serializable
data object MoreKey : AppKey

/**
 * Device detail, pushed on the stack it was opened from (À traiter or Appareils).
 * [tab]: the first tab ("processes"…) when a notification names one; it only
 * applies to a new entry (another tab = another key).
 */
@Serializable
data class DeviceKey(val serverId: String, val deviceId: Long, val tab: String? = null) : AppKey

/** Web view: a same-origin page of [serverId], pushed on the current destination. */
@Serializable
data class WebKey(val serverId: String, val path: String, val title: String) : AppKey

/*
 * 0.2.0 "Agir": pushed on the CURRENT destination's stack (device flows on the
 * stack of the device detail, usually Appareils; Activité flows on Activité).
 * Full screen on phones; detail pane on wide windows, except ObliReach.
 */

/** Terminal: [wtsSessionId] null = SYSTEM; [resumeId] = a live session to resume (pill, notification, Activité). */
@Serializable
data class TerminalKey(
    val serverId: String,
    val deviceId: Long,
    val protocol: String,
    val wtsSessionId: Int? = null,
    val resumeId: String? = null,
) : AppKey

/** ObliReach viewer, always full screen. */
@Serializable
data class ReachKey(val serverId: String, val deviceId: Long) : AppKey

/** Script picker; [deviceIds] may be empty (from Activité: targets chosen in the run preparation). */
@Serializable
data class ScriptPickerKey(val serverId: String, val deviceIds: List<Long>) : AppKey

/** Run preparation; [rerunOf] = the batch whose failures are re-run. */
@Serializable
data class RunScriptKey(val serverId: String, val scriptId: Long, val deviceIds: List<Long>, val rerunOf: String? = null) : AppKey

/** Batch in flight and outputs. */
@Serializable
data class BatchKey(val serverId: String, val batchId: String) : AppKey

/** Schedules and scenarios of the active server. */
@Serializable
data object SchedulesKey : AppKey

@Serializable
data object ScenariosKey : AppKey

/** Server list and "add a server", pushed on the Plus stack. */
@Serializable
data object ServersKey : AppKey

@Serializable
data object AddServerKey : AppKey

/** 0.3.0, pushed on the Plus stack like [ServersKey]: app settings, notifications, about. */
@Serializable
data object AppSettingsKey : AppKey

@Serializable
data object NotificationSettingsKey : AppKey

@Serializable
data object AboutKey : AppKey

/**
 * 0.4.0, on the Plus stack: « Profil et sécurité » (fingerprint
 * validation). [enrolServerId]: open that server's enrolment at once (the
 * « Utiliser l'empreinte la prochaine fois ? » proposal).
 */
@Serializable
data class ProfileSecurityKey(val enrolServerId: String? = null) : AppKey

/** The 5 destinations of the shell, in this order; each has its own back stack. */
enum class Destination(val root: AppKey, @param:StringRes val label: Int, val icon: ImageVector) {
    TRIAGE(TriageKey, R.string.app_nav_triage, ObliIcons.Siren),
    DEVICES(DevicesKey, R.string.app_nav_devices, ObliIcons.Monitor),
    ACTIVITY(ActivityKey, R.string.app_nav_activity, ObliIcons.Activity),
    FLEET(FleetKey, R.string.app_nav_fleet, ObliIcons.LayoutDashboard),
    MORE(MoreKey, R.string.app_nav_more, ObliIcons.Menu),
}
