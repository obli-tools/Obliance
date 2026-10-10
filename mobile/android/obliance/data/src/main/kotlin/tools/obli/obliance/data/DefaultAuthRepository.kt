package tools.obli.obliance.data

import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import tools.obli.core.auth.AddServerResult
import tools.obli.core.auth.AuthState
import tools.obli.core.auth.ServerRegistry
import tools.obli.core.auth.ServerSessions
import tools.obli.core.model.ServerId
import tools.obli.core.network.ApiOutcome
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DeviceError
import tools.obli.core.network.DevicePurpose
import tools.obli.core.network.ObliHttp
import tools.obli.core.security.DeviceSignRequest
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignResult
import tools.obli.obliance.api.AuthApi
import tools.obli.obliance.api.DeviceLoginAnswer
import tools.obli.obliance.api.LoginResult
import tools.obli.obliance.api.SsoConfig
import tools.obli.obliance.api.TwoFactorMethod
import tools.obli.shell.net.ServerUrl

internal class DefaultAuthRepository(
    private val registry: ServerRegistry,
    private val sessions: ServerSessions,
    /** HTTP client of an origin that may not be configured yet (same OkHttp client and cookie jar). */
    private val httpFor: (origin: String) -> ObliHttp,
    /** Expires the cookies of an origin (WebCookieJar.clearOrigin). */
    private val clearCookies: (origin: String) -> Unit,
    private val appScope: CoroutineScope,
    /** This phone's device keys; null: none. */
    private val deviceKeys: DeviceKeyLink? = null,
    private val clock: () -> Long = System::currentTimeMillis,
) : AuthRepository {
    /**
     * The key whose header the pending login of an origin carried (ObliHttp
     * origin to key id): the code and the fingerprint of that login use it,
     * and nothing else. Dropped when the login is over.
     */
    private val loginKeys = ConcurrentHashMap<String, String>()

    override suspend fun checkServer(address: String): ServerCheck {
        val origin = when (val r = ServerUrl.normalize(address)) {
            is ServerUrl.Result.Ok -> r.url
            is ServerUrl.Result.Invalid -> return ServerCheck.Invalid(r.problem)
        }
        val existing = registry.state.value.byUrl(origin)
        if (existing == null && registry.state.value.profiles.size >= ServerRegistry.MAX_SERVERS) {
            return ServerCheck.LimitReached(origin)
        }
        val api = AuthApi(httpFor(origin))
        val health = when (val out = api.health()) {
            is ApiOutcome.Ok -> out.value
            is ApiOutcome.Failure -> return ServerCheck.Unreachable(origin, out)
            else -> return ServerCheck.NotObliance(origin)
        }
        if (!health.isOk) return ServerCheck.NotObliance(origin)
        // sso-config always answers 200 on an Obliance server; a failure only hides the SSO button.
        val sso = (api.ssoConfig() as? ApiOutcome.Ok)?.value ?: SsoConfig()
        return ServerCheck.Ok(origin, health, sso, existing)
    }

    /**
     * With the explicit `X-Obli-Device-Key` of the key remembered for
     * [username] on this origin: the server binds the new
     * session to it, and offers the fingerprint when the key is eligible
     * ([LoginResult.TwoFactorRequired.deviceChallenge]).
     */
    override suspend fun login(origin: String, username: String, password: String): LoginResult {
        val http = httpFor(origin)
        val key = deviceKeys?.let { runCatching { it.loginKey(http.origin, username) }.getOrNull() }
        if (key != null) loginKeys[http.origin] = key.keyId else loginKeys.remove(http.origin)
        return AuthApi(http).login(username, password, key?.keyId)
    }

    /** The code of a pending login, with the header its login carried (the server binds the new session to that key). */
    override suspend fun verifyTwoFactor(origin: String, method: TwoFactorMethod, code: String): LoginResult {
        val http = httpFor(origin)
        return AuthApi(http).verifyTwoFactor(method, code, liveLoginKey(http.origin))
    }

    /** The pending login's key id, only while this phone still holds that key. */
    private fun liveLoginKey(origin: String): String? {
        val keyId = loginKeys[origin] ?: return null
        return keyId.takeIf { deviceKeys?.record(origin, it) != null }
    }

    /**
     * The challenge must name the key the login carried, of the user
     * that key was enrolled for (and remembered under [username]); the payload
     * is DeviceProofPayload's (DeviceSignRequest.login). A signature made
     * after the challenge's 120 s (the prompt stayed open) is not sent: a new
     * challenge is asked (device-challenge) and signed instead. Two contacts
     * at most; anything else falls back on the code.
     */
    override suspend fun signInWithDevice(
        origin: String,
        username: String,
        challenge: DeviceChallenge,
        signer: DeviceSigner,
        prompt: SignPrompt,
        challengeStale: Boolean,
    ): DeviceSignInResult {
        val link = deviceKeys ?: return DeviceSignInResult.UseCode
        val http = httpFor(origin)
        val keyId = loginKeys[http.origin] ?: return DeviceSignInResult.UseCode
        val record = link.record(http.origin, keyId) ?: return DeviceSignInResult.UseCode
        if (!record.username.equals(username.trim(), ignoreCase = true)) return DeviceSignInResult.UseCode
        val api = AuthApi(http)
        var current = challenge
        if (challengeStale) {
            current = when (val fresh = api.deviceChallenge(record.keyId)) {
                is ApiOutcome.Ok -> fresh.value
                is ApiOutcome.Validation -> return DeviceSignInResult.Finished(LoginResult.TwoFactorSessionLost)
                is ApiOutcome.RateLimited -> return DeviceSignInResult.Finished(LoginResult.RateLimited(fresh.retryAfterSec))
                else -> return DeviceSignInResult.UseCode
            }
        }
        var receivedAt = clock()
        for (attempt in 0 until MAX_LOGIN_SIGNATURES) {
            if (current.purpose != DevicePurpose.LOGIN || current.keyId != record.keyId || current.userId != record.userId) return DeviceSignInResult.UseCode
            val request = try {
                DeviceSignRequest.login(http.origin, record, current)
            } catch (_: IllegalArgumentException) {
                return DeviceSignInResult.UseCode
            }
            val der = when (val signed = signer.sign(record, request.payload, prompt)) {
                is SignResult.Signed -> signed.der
                SignResult.UseCode, SignResult.LockedOut, is SignResult.Unavailable -> return DeviceSignInResult.UseCode
                SignResult.Cancelled -> return DeviceSignInResult.Cancelled
                SignResult.Invalidated -> {
                    link.loginKeyGone(http.origin, record.keyId)
                    loginKeys.remove(http.origin)
                    return DeviceSignInResult.KeyLost
                }
            }
            val last = attempt == MAX_LOGIN_SIGNATURES - 1
            if (clock() - receivedAt >= LOGIN_PROMPT_MAX_MS) {
                // The prompt stayed open past the challenge's life.
                if (last) return DeviceSignInResult.Refused
                current = when (val fresh = api.deviceChallenge(record.keyId)) {
                    is ApiOutcome.Ok -> fresh.value
                    is ApiOutcome.Validation -> return DeviceSignInResult.Finished(LoginResult.TwoFactorSessionLost)
                    is ApiOutcome.RateLimited -> return DeviceSignInResult.Finished(LoginResult.RateLimited(fresh.retryAfterSec))
                    else -> return DeviceSignInResult.UseCode
                }
                receivedAt = clock()
                continue
            }
            when (val answer = api.verifyDevice(request.assertion(der))) {
                is DeviceLoginAnswer.Done -> {
                    if (answer.result is LoginResult.SignedIn) loginKeys.remove(http.origin)
                    return DeviceSignInResult.Finished(answer.result)
                }
                is DeviceLoginAnswer.Refused -> {
                    if (answer.keyRevoked) {
                        link.loginKeyGone(http.origin, record.keyId)
                        loginKeys.remove(http.origin)
                        return DeviceSignInResult.KeyLost
                    }
                    val renewed = answer.renewed
                    if (answer.error != DeviceError.CHALLENGE_EXPIRED || renewed == null || last) return DeviceSignInResult.Refused
                    current = renewed
                    receivedAt = clock()
                }
            }
        }
        return DeviceSignInResult.Refused
    }

    override suspend fun resendEmailCode(origin: String): ApiOutcome<Unit> = AuthApi(httpFor(origin)).resendEmailCode()

    override suspend fun completeSignIn(origin: String, displayName: String?, activate: Boolean): SignInResult =
        // Not cancelled with the calling screen: the registry changes (a first
        // server swaps the sign-in screen for the shell) before this returns.
        appScope.async { doCompleteSignIn(origin, displayName, activate) }.await()

    private suspend fun doCompleteSignIn(origin: String, displayName: String?, activate: Boolean): SignInResult {
        loginKeys.remove(httpFor(origin).origin)
        val profile = registry.state.value.byUrl(origin) ?: when (val added = registry.add(origin, displayName)) {
            is AddServerResult.Added -> added.profile
            is AddServerResult.AlreadyConfigured -> added.existing
            else -> return SignInResult.Refused(added)
        }
        val session = sessions.session(profile.id) ?: return SignInResult.NotSignedIn(AuthState.Unknown)
        // Before the session reads as signed in (no header sent yet): a key revoked meanwhile is
        // forgotten, or its header would end the new session at its first request.
        deviceKeys?.let { runCatching { it.beforeSignedIn(session) } }
        val state = session.probe()
        if (state !is AuthState.SignedIn) return SignInResult.NotSignedIn(state)
        val wasActive = registry.state.value.activeId == profile.id
        when {
            // Closes the previous server's socket and opens this one.
            activate && !wasActive -> sessions.activate(profile.id)
            // New cookie (first server, or signed in again): handshake again with it.
            wasActive -> session.realtime.reconnect()
        }
        return SignInResult.Done(registry.state.value.byId(profile.id) ?: profile, state.probe)
    }

    /**
     * `POST /api/auth/logout` WITH this phone's key of the session's
     * user (the server revokes it: `logout`), then the key is forgotten here —
     * offline too (the server row then waits for a manual revocation or the
     * 180-day expiry; nobody can sign with it any more).
     *
     * The user is only known once `/api/auth/me` answered in this process: after
     * a cold start offline (or with the server down) it is not, yet « Se
     * déconnecter » is offered. Then EVERY key of this origin is forgotten (one
     * profile per origin: signing out of the server means this phone is no
     * longer a second factor there), and the header is sent only when it can
     * only be that one key (the server ignores a key of another user anyway).
     */
    override suspend fun signOut(serverId: ServerId): ApiOutcome<Unit> {
        val session = sessions.session(serverId) ?: return noServer
        val origin = session.http.origin
        val userId = session.lastUserId
        val link = deviceKeys
        val (keyId, users) = when {
            link == null -> null to emptyList<Long>()
            userId != null -> link.keyIdOf(origin, userId) to listOf(userId)
            else -> link.recordsOf(origin).let { records -> records.singleOrNull()?.keyId to records.map { it.userId }.distinct() }
        }
        val out = AuthApi(session.http).logout(keyId)
        clearCookies(session.profile.origin)
        session.realtime.disconnect()
        session.markSignedOut()
        users.forEach { link?.forget(origin, it) }
        return out
    }

    companion object {
        /** One signature, and one more for a renewed challenge: 2 contacts at most. */
        const val MAX_LOGIN_SIGNATURES = 2

        /** A `login` challenge lives 120 s; a signature made later is not sent (5 s of margin). */
        const val LOGIN_PROMPT_MAX_MS = 115_000L
    }
}
