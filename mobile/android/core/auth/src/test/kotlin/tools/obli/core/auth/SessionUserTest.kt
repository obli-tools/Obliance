package tools.obli.core.auth

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.CookieJar
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.model.ObliUser
import tools.obli.core.model.SessionProbe
import tools.obli.core.network.ObliHttp
import tools.obli.core.realtime.ConnectionState
import tools.obli.core.realtime.RealtimeClient
import tools.obli.core.realtime.RealtimeEvent
import tools.obli.shell.nav.Origins

/**
 * The session's user for device keys:
 * [ServerSession.userId] only while signed in, [ServerSession.lastUserId]
 * kept for the sign-out, [ServerSessions.byOrigin] by the HTTP origin, and
 * `/api/auth/me` → `deviceKey`.
 */
class SessionUserTest {
    private class Silent : RealtimeClient {
        override val state: StateFlow<ConnectionState> = MutableStateFlow(ConnectionState.DISCONNECTED)
        override val events: SharedFlow<RealtimeEvent> = MutableSharedFlow()
        override fun connect() = Unit
        override fun reconnect() = Unit
        override fun disconnect() = Unit
        override fun emit(name: String, payload: JsonElement?) = false
        override suspend fun emitWithAck(name: String, payload: JsonElement?, timeoutMs: Long): JsonElement? = null
    }

    private class MemoryStore : ServerRegistryStore {
        var saved: ServerRegistryState? = null
        override suspend fun load() = saved
        override suspend fun save(state: ServerRegistryState) { saved = state }
    }

    private val scope = CoroutineScope(Dispatchers.Unconfined)
    private val server = MockWebServer().apply { start() }
    private val client = ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA")
    private val mockOrigin = Origins.of(server.url("/").toString())!!

    @After fun tearDown() {
        scope.cancel()
        server.close()
    }

    private fun answer(code: Int, body: String) {
        server.enqueue(MockResponse.Builder().code(code).addHeader("Content-Type", "application/json").body(body).build())
    }

    @Test fun userIdOnlyWhileSignedInLastUserKept() = runBlocking {
        val s = ServerSession(tools.obli.core.model.ServerId("s"), { error("unused") }, ObliHttp(mockOrigin, client), { Silent() })
        assertNull(s.userId)
        assertNull(s.lastUserId)
        answer(200, """{"success":true,"data":{"user":{"id":42,"username":"john.smith"},"currentTenantId":1,"deviceKey":{"bound":true,"keyId":"6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"}}}""")
        val probe = (s.probe() as AuthState.SignedIn).probe
        assertEquals(42L, s.userId)
        assertTrue(probe.deviceKey!!.bound)
        assertEquals("6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", probe.deviceKey!!.keyId)
        // Expired: no header any more, but the sign-out still knows whose key it was.
        s.markExpired()
        assertNull(s.userId)
        assertEquals(42L, s.lastUserId)
        s.markSignedOut()
        assertNull(s.userId)
        assertEquals(42L, s.lastUserId)
        // Another account signs in: its id replaces the last one.
        s.markSignedIn(SessionProbe(ObliUser(7, "other")))
        assertEquals(7L, s.userId)
        assertEquals(7L, s.lastUserId)
    }

    @Test fun anOlderServerHasNoDeviceKeyPart() = runBlocking {
        val s = ServerSession(tools.obli.core.model.ServerId("s"), { error("unused") }, ObliHttp(mockOrigin, client), { Silent() })
        answer(200, """{"success":true,"data":{"user":{"id":42,"username":"john.smith"}}}""")
        assertNull((s.probe() as AuthState.SignedIn).probe.deviceKey)
        answer(200, """{"success":true,"data":{"user":{"id":42,"username":"john.smith"},"deviceKey":{"bound":false}}}""")
        assertFalse((s.probe() as AuthState.SignedIn).probe.deviceKey!!.bound)
    }

    @Test fun byOriginFindsTheSessionOfItsHttpOrigin() = runBlocking {
        var n = 0
        val registry = ServerRegistry(MemoryStore()) { "id-${++n}" }
        val sessions = ServerSessions(registry, { p, now -> ServerSession(p.id, now, ObliHttp(p.origin, client), { Silent() }) }, scope)
        val prod = (registry.add("obliance-prod.example.org", "Obliance Prod") as AddServerResult.Added).profile
        val qual = (registry.add("obliance-qual.example.org", "Obliance Qual") as AddServerResult.Added).profile
        assertSame(sessions.session(prod.id), sessions.byOrigin("https://obliance-prod.example.org"))
        assertSame(sessions.session(qual.id), sessions.byOrigin("https://obliance-qual.example.org"))
        assertNull(sessions.byOrigin("https://obliance-dev.example.org"))
        // Exact origin only: no prefix, no path.
        assertNull(sessions.byOrigin("https://obliance-prod.example.org/"))
        assertNull(sessions.byOrigin("https://obliance-prod.example.org.evil.example"))
    }
}
