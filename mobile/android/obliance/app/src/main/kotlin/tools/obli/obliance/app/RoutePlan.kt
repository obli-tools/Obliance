package tools.obli.obliance.app

import tools.obli.core.auth.ServerRegistryState
import tools.obli.core.model.ServerId
import tools.obli.core.model.SessionProbe
import tools.obli.obliance.api.DeviceLocation
import tools.obli.obliance.api.MASTER_TENANT_ID
import tools.obli.obliance.data.TenantScope
import tools.obli.obliance.notifications.NotificationRoute
import tools.obli.obliance.triage.TriageRequest

/**
 * What the shell does with the route of a tapped notification
 * (implicit server switch, device tenant rule). NAVIGATION ONLY: a route never runs an
 * action; the user acts on the screen it opens.
 */
internal sealed interface RoutePlan {
    /**
     * Device detail on the À traiter stack. [switchServer]: the implicit switch to
     * [serverId] (« Passé sur … · Revenir »). [tenant]: what to do about the
     * device's tenant once the server is active.
     */
    data class OpenDevice(
        val serverId: ServerId,
        val deviceId: Long,
        val tab: String?,
        val label: String?,
        val switchServer: Boolean,
        val tenant: TenantRule,
    ) : RoutePlan

    /** A same-origin page of [serverId]: its native screen or the web view, after the implicit switch. */
    data class OpenPath(val serverId: ServerId, val path: String, val switchServer: Boolean) : RoutePlan

    /**
     * À traiter, popped to its root, with [request] (null: the screen as it is).
     * An inbox item is addressed on its own server: no server switch.
     */
    data class Triage(val request: TriageRequest?) : RoutePlan

    /** Sign-in-again of the ACTIVE server (the app's own session-expired sheet). */
    data object ReauthActive : RoutePlan

    /** Sign-in-again of a server that is NOT active: the active server stays. */
    data class ReauthOther(val serverId: ServerId) : RoutePlan
}

/** Device tenant rule: the tenant of a device opened from a notification. */
internal sealed interface TenantRule {
    /**
     * Open it in the session tenant: platform admin on the master tenant
     * (global view sees every tenant), the device is known to be in the session
     * tenant, or there is no signed-in session to ask.
     */
    data object Stay : TenantRule

    /** Ask `GET /api/tenants/locate-device/:id`; switch when it names another tenant than [currentTenantId]. */
    data class Locate(val currentTenantId: Long?) : TenantRule
}

/**
 * Pure planner of a [route].
 *
 * @param registry the server registry now (active server, known servers).
 * @param tenantScope the tenants of the ACTIVE server (its session tenant is the freshest).
 * @param probe `/api/auth/me` of the ROUTE's server, null when it is not signed in.
 */
internal fun planRoute(
    route: NotificationRoute,
    registry: ServerRegistryState,
    tenantScope: TenantScope,
    probe: SessionProbe?,
): RoutePlan {
    // Removed (or unknown) server: just À traiter.
    if (registry.byId(route.serverId) == null) return RoutePlan.Triage(null)
    val active = registry.activeId == route.serverId
    return when (route) {
        is NotificationRoute.Device -> RoutePlan.OpenDevice(
            serverId = route.serverId,
            deviceId = route.deviceId,
            tab = route.tab,
            label = route.label,
            switchServer = !active,
            tenant = tenantRule(route, active, tenantScope, probe),
        )
        is NotificationRoute.Path -> RoutePlan.OpenPath(route.serverId, route.path, switchServer = !active)
        is NotificationRoute.Approval -> RoutePlan.Triage(TriageRequest.Approval(route.serverId, route.approvalId))
        is NotificationRoute.Enrolment -> RoutePlan.Triage(TriageRequest.Enrolment(route.serverId, route.deviceId))
        // « N en attente » of a burst: the segment, on that server's chip (2+ servers).
        is NotificationRoute.Enrolments -> RoutePlan.Triage(TriageRequest.Enrolments(route.serverId.takeIf { registry.isMultiServer }))
        is NotificationRoute.Approvals -> RoutePlan.Triage(TriageRequest.Approvals(route.serverId.takeIf { registry.isMultiServer }))
        // The server chip only exists with two servers or more.
        is NotificationRoute.Inbox -> RoutePlan.Triage(TriageRequest.Alerts(route.serverId.takeIf { registry.isMultiServer }))
        is NotificationRoute.SignIn -> when {
            // Signed in again since the notification: nothing to re-authenticate.
            probe != null -> RoutePlan.Triage(TriageRequest.Alerts(route.serverId.takeIf { registry.isMultiServer }))
            active -> RoutePlan.ReauthActive
            else -> RoutePlan.ReauthOther(route.serverId)
        }
    }
}

/** Device tenant rule for a device route (see [TenantRule]). */
internal fun tenantRule(route: NotificationRoute.Device, active: Boolean, tenantScope: TenantScope, probe: SessionProbe?): TenantRule {
    val p = probe ?: return TenantRule.Stay
    // The active server's scope follows switches made since the probe.
    val current = if (active && tenantScope.serverId == route.serverId) tenantScope.currentTenantId ?: p.currentTenantId else p.currentTenantId
    if (p.user.isPlatformAdmin && current == MASTER_TENANT_ID) return TenantRule.Stay
    if (route.tenantId != null && route.tenantId == current) return TenantRule.Stay
    return TenantRule.Locate(current)
}

/** The tenant to switch to once `locate-device` answered ([location] null: not found or failed → stay). */
internal fun tenantToSwitch(rule: TenantRule, location: DeviceLocation?): Long? {
    if (rule !is TenantRule.Locate) return null
    val target = location?.tenantId ?: return null
    return target.takeIf { it != rule.currentTenantId }
}

/**
 * What the ONE snackbar names after an implicit switch:
 * "Obliance Qual › Default" (server and tenant), "Obliance Qual" (server) or
 * "ACME" (tenant only), with whether the server changed; null when nothing changed.
 */
internal fun switchTarget(serverName: String?, tenantName: String?): Pair<String, Boolean>? = when {
    serverName != null && tenantName != null -> "$serverName › $tenantName" to true
    serverName != null -> serverName to true
    tenantName != null -> tenantName to false
    else -> null
}
