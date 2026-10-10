package tools.obli.obliance.data

import androidx.compose.runtime.staticCompositionLocalOf
import tools.obli.core.auth.ServerRegistry
import tools.obli.core.auth.ServerSessions
import tools.obli.core.model.ServerId
import tools.obli.core.security.ActionSessionInfo

/**
 * Everything a screen of the native Obliance app may use.
 * Provided once by :obliance:app through
 * [LocalObliServices]; screen modules read `LocalObliServices.current` and
 * never build their own clients.
 *
 * Multi-server rule: an item always travels with the
 * [ServerId] of the server it came from, and every call about it goes through
 * THAT server's session (`sessions.session(serverId)`), never the active one.
 */
interface ObliServices {
    /** The configured servers (1..8), their order, colours and the active one. */
    val registry: ServerRegistry

    /** One session per server (HTTP bound to its origin, auth state, realtime); ONE socket, the active server's. */
    val sessions: ServerSessions

    val auth: AuthRepository
    val tenants: TenantsRepository
    val alerts: AlertsRepository
    val devices: DevicesRepository

    /**
     * « Validation par empreinte » of every server:
     * profile and security states, enrolment, the account's phones, key health. The
     * default (test fakes, previews) is [DeviceKeysRepository.None].
     */
    val deviceKeys: DeviceKeysRepository get() = DeviceKeysRepository.None

    /**
     * For the action host's runner:
     * the session tenant the app last read for each origin (a challenge
     * of another tenant is never signed: « Le tenant a changé ») and the
     * server's name (always in the fingerprint prompt). Null (test fakes,
     * previews): only what each ActionSpec sets.
     */
    val actionSessions: ActionSessionInfo? get() = null

    /**
     * SSO device keys: the native Obligate re-authentication,
     * shown by the app's `SsoReauthHost` (obliance:access). Null (test
     * fakes, previews): none — every re-authentication fails closed.
     */
    val ssoReauth: SsoReauthBroker? get() = null

    /**
     * Implicit server switch ("Bascule implicite"): makes
     * [serverId] the active server when it is not already, so its screens
     * (device detail…) can open. Returns the PREVIOUSLY active server id when a
     * switch happened (for the 5 s "Revenir" action), or null when [serverId]
     * already was the active server or is unknown.
     */
    suspend fun openOn(serverId: ServerId): ServerId?
}

/** Provided by :obliance:app at the root; screenshot tests provide [tools.obli.obliance.data.sample.SampleObliServices]. */
val LocalObliServices = staticCompositionLocalOf<ObliServices> {
    error("LocalObliServices is not provided: wrap the screen in CompositionLocalProvider(LocalObliServices provides ...)")
}
