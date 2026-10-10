package tools.obli.core.auth

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import tools.obli.core.model.ServerId
import tools.obli.core.model.ServerProfile
import tools.obli.core.model.SessionProbe
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.ObliHttp
import tools.obli.core.realtime.RealtimeClient

sealed interface AuthState {
    /** Not probed yet (cold start). */
    data object Unknown : AuthState
    data class SignedIn(val probe: SessionProbe) : AuthState

    /** 401 on a probe or a call: the sign-in-again screen for the active server, a mention elsewhere. */
    data object Expired : AuthState

    /** The server did not answer; the last known state is kept by the UI. */
    data class Unreachable(val since: Long) : AuthState
    data object SignedOut : AuthState
}

/**
 * Everything that belongs to ONE server: its HTTP client
 * bound to its origin, its authentication state and its real-time client.
 * Created lazily per profile by [ServerSessions]; app repositories hang off it.
 */
class ServerSession(
    val id: ServerId,
    /** Current profile from the registry (name, colour… may change; the origin never does). */
    private val profileNow: () -> ServerProfile,
    val http: ObliHttp,
    private val realtimeFactory: (ServerSession) -> RealtimeClient,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    val profile: ServerProfile get() = profileNow()

    private val _auth = MutableStateFlow<AuthState>(AuthState.Unknown)
    val auth: StateFlow<AuthState> = _auth.asStateFlow()

    val realtime: RealtimeClient by lazy { realtimeFactory(this) }

    /**
     * Server user id of the account signed in on this server, null unless
     * [auth] is [AuthState.SignedIn]. The device key of an origin is the one of
     * THIS user: no header and no
     * signature while nobody is signed in.
     */
    val userId: Long? get() = (_auth.value as? AuthState.SignedIn)?.probe?.user?.id

    @Volatile private var lastUser: Long? = null

    /**
     * The user last seen signed in here, kept after an expiry or a sign-out
     * (and replaced by the next sign-in): whose key a sign-out forgets
     * when the session is already gone.
     */
    val lastUserId: Long? get() = userId ?: lastUser

    /** `GET /api/auth/me`: who is signed in, the session tenant, forced 2FA setup. */
    suspend fun probe(): AuthState {
        val state = when (val out = http.get("/api/auth/me")) {
            is ApiOutcome.Ok -> decodeProbe(out.value)?.let { AuthState.SignedIn(it) } ?: AuthState.Unreachable(clock())
            ApiOutcome.SessionExpired -> AuthState.Expired
            else -> AuthState.Unreachable(clock())
        }
        // Unreachable keeps what we knew (a signed-in user stays signed in offline).
        if (state is AuthState.Unreachable && _auth.value is AuthState.SignedIn) return _auth.value
        setAuth(state)
        return state
    }

    private fun setAuth(state: AuthState) {
        if (state is AuthState.SignedIn) lastUser = state.probe.user.id
        _auth.value = state
    }

    /**
     * Any call of this server that answered 401 Authentication required. A
     * signed-out session stays signed out: a stray 401 (or a refused socket
     * handshake) after "Se déconnecter" must not turn it into an expired one.
     */
    fun markExpired() {
        _auth.update { if (it == AuthState.SignedOut) it else AuthState.Expired }
    }

    fun markSignedOut() {
        setAuth(AuthState.SignedOut)
    }

    /** A `/api/auth/me` answer obtained elsewhere (sign-in flow, previews and tests). */
    fun markSignedIn(probe: SessionProbe) {
        setAuth(AuthState.SignedIn(probe))
    }

    companion object {
        private val json = Json { ignoreUnknownKeys = true; explicitNulls = false; coerceInputValues = true }

        fun decodeProbe(data: JsonElement?): SessionProbe? = try {
            data?.let { json.decodeFromJsonElement(SessionProbe.serializer(), it) }
        } catch (_: Exception) {
            null
        }
    }
}
