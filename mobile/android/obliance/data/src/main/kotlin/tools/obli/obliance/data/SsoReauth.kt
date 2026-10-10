package tools.obli.obliance.data

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import tools.obli.core.security.SsoReauthResult

/**
 * SSO device keys: the native Obligate
 * re-authentication of ONE server session, asked by the action host (a code
 * in a bound session of an Obligate account, `codeRequiresReauth`), by the profile and security screen
 * (enrolment of an Obligate account) and by the web view (its
 * « Reconfirmer avec Obligate »). It is SHOWN by the one host the app mounts
 * (obliance:access `SsoReauthHost`): an in-app web view sharing the process
 * cookie store, `/auth/sso-redirect?reauth=1&return=<path>` → Obligate →
 * `/auth/callback` → `<path>?reauth=ok` (never a Custom Tab: the OAuth state
 * and `pendingReauth` live in the server session).
 *
 * One sheet at a time (the requests queue on a mutex). Fails closed: without
 * a host on screen the answer is [SsoReauthResult.Cancelled] at once.
 */
class SsoReauthBroker {
    /** A re-authentication waiting for the sheet: [origin]'s session, success on [returnPath]`?reauth=ok`. */
    class Request internal constructor(val origin: String, val returnPath: String) {
        internal val reply = CompletableDeferred<SsoReauthResult>()

        /** The sheet's answer; only the first one counts. */
        fun complete(result: SsoReauthResult) {
            reply.complete(result)
        }
    }

    private val mutex = Mutex()
    private val hosts = AtomicInteger(0)
    private val _request = MutableStateFlow<Request?>(null)

    /** The request the host must show, null when none. */
    val request: StateFlow<Request?> = _request.asStateFlow()

    /** True while a host can show the sheet. */
    val hasHost: Boolean get() = hosts.get() > 0

    /**
     * Called by the host when it enters the composition; call the returned
     * function when it leaves. A pending request stays pending across a
     * recreated host (rotation): the new host shows it again; its caller's
     * scope bounds its life.
     */
    fun attachHost(): () -> Unit {
        hosts.incrementAndGet()
        val detached = AtomicBoolean(false)
        return { if (detached.compareAndSet(false, true)) hosts.decrementAndGet() }
    }

    /**
     * Re-authenticates the session of [origin] (the server's ObliHttp origin,
     * never one read from an answer). [returnPath]: the same-origin path the
     * server comes back to (web view: the page's; else `/`).
     */
    suspend fun reauthenticate(origin: String, returnPath: String = "/"): SsoReauthResult {
        if (!hasHost) return SsoReauthResult.Cancelled
        return mutex.withLock {
            if (!hasHost) return@withLock SsoReauthResult.Cancelled
            val r = Request(origin, returnPath)
            _request.value = r
            try {
                r.reply.await()
            } finally {
                r.reply.complete(SsoReauthResult.Cancelled)
                _request.compareAndSet(r, null)
            }
        }
    }
}
