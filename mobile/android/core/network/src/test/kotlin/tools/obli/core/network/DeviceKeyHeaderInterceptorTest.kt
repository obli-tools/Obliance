package tools.obli.core.network

import kotlinx.coroutines.runBlocking
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.CookieJar
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import tools.obli.shell.nav.Origins

/** `X-Obli-Device-Key`: origin, user, account change, explicit header first, never redirected. */
class DeviceKeyHeaderInterceptorTest {
    private val a = MockWebServer()
    private val b = MockWebServer()
    private lateinit var originA: String
    private lateinit var originB: String

    /** What the app wires: the user signed in on each origin, and the keys held per (origin, user). */
    private val signedIn = mutableMapOf<String, Long>()
    private val keys = mutableMapOf<Pair<String, Long>, String>()
    private val source: (String) -> String? = { origin -> signedIn[origin]?.let { keys[origin to it] } }

    private lateinit var client: OkHttpClient

    @Before fun setUp() {
        a.start()
        b.start()
        originA = Origins.of(a.url("/").toString())!!
        originB = Origins.of(b.url("/").toString())!!
        client = ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA", source)
    }

    @After fun tearDown() {
        a.close()
        b.close()
    }

    private fun ok(server: MockWebServer) = server.enqueue(
        MockResponse.Builder().code(200).addHeader("Content-Type", "application/json").body("""{"data":{}}""").build(),
    )

    private val keyA = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val keyA2 = "0f8fad5b-d9cb-469f-a165-70867728950e"

    @Test fun onlyTheKeyOfThisOriginAndThisUser() = runBlocking {
        signedIn[originA] = 42
        signedIn[originB] = 42
        keys[originA to 42L] = keyA
        ok(a); ok(b)
        ObliHttp(originA, client).get("/api/auth/me")
        ObliHttp(originB, client).get("/api/auth/me")
        assertEquals(keyA, a.takeRequest().headers[DeviceKeyHeader.NAME])
        // Same user id on another server: never A's key.
        assertNull(b.takeRequest().headers[DeviceKeyHeader.NAME])
    }

    @Test fun notSentAfterAnAccountChange() = runBlocking {
        signedIn[originA] = 42
        keys[originA to 42L] = keyA
        ok(a); ok(a); ok(a)
        val http = ObliHttp(originA, client)
        http.get("/api/devices")
        signedIn[originA] = 43                // another account signed in on A
        http.get("/api/devices")
        signedIn.remove(originA)              // signed out
        http.get("/api/devices")
        assertEquals(keyA, a.takeRequest().headers[DeviceKeyHeader.NAME])
        assertNull(a.takeRequest().headers[DeviceKeyHeader.NAME])
        assertNull(a.takeRequest().headers[DeviceKeyHeader.NAME])
    }

    @Test fun anExplicitHeaderIsNeverReplaced() = runBlocking {
        signedIn[originA] = 42
        keys[originA to 42L] = keyA
        ok(a)
        ObliHttp(originA, client).call(ObliHttp.Method.POST, "/api/auth/login", headers = mapOf(DeviceKeyHeader.NAME to keyA2)) { it }
        val req = a.takeRequest()
        assertEquals(listOf(keyA2), req.headers.values(DeviceKeyHeader.NAME))
    }

    @Test fun invalidOrFailingSourcesSendNothing() = runBlocking {
        val odd = ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA") { "not-a-uuid\r\nX-Evil: 1" }
        val failing = ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA") { error("store not loaded") }
        ok(a); ok(a)
        assertTrue(ObliHttp(originA, odd).get("/api/x") is ApiOutcome.Ok)
        assertTrue(ObliHttp(originA, failing).get("/api/x") is ApiOutcome.Ok)
        val first = a.takeRequest()
        assertNull(first.headers[DeviceKeyHeader.NAME])
        assertNull(first.headers["X-Evil"])
        assertNull(a.takeRequest().headers[DeviceKeyHeader.NAME])
        assertEquals(2, a.requestCount)
    }

    @Test fun aRedirectToAnotherOriginIsNotFollowed() = runBlocking {
        signedIn[originA] = 42
        keys[originA to 42L] = keyA
        a.enqueue(MockResponse.Builder().code(302).addHeader("Location", b.url("/steal").toString()).build())
        val out = ObliHttp(originA, client).get("/api/x")
        assertEquals(ApiOutcome.Failure(302, FailureKind.CLIENT), out)
        assertEquals(0, b.requestCount)
        assertEquals(1, a.requestCount)
    }

    @Test fun withoutASourceTheClientIsUnchanged() = runBlocking {
        ok(a)
        ObliHttp(originA, ObliHttp.defaultClient(CookieJar.NO_COOKIES, "UA")).get("/api/x")
        assertNull(a.takeRequest().headers[DeviceKeyHeader.NAME])
    }

    @Test fun theStepUpOriginIsSetOnlyForAnAnswerOfThisOrigin() = runBlocking {
        val body = """{"error":"twoFactorCode required","twoFactorRequired":true,"action":"command.reboot","deviceKeyStatus":"active"}"""
        a.enqueue(MockResponse.Builder().code(401).addHeader("Content-Type", "application/json").body(body).build())
        val same = ObliHttp(originA, client).post("/api/commands") as ApiOutcome.StepUpRequired
        assertEquals(originA, same.origin)

        // A client that sends the request elsewhere (a hostile interceptor, a proxy bug): the answer
        // is B's, so it can never lead to a signature for A.
        b.enqueue(MockResponse.Builder().code(401).addHeader("Content-Type", "application/json").body(body).build())
        val bUrl = b.url("/")
        val rerouting = client.newBuilder().addInterceptor(Interceptor { chain ->
            val r = chain.request()
            chain.proceed(r.newBuilder().url(r.url.newBuilder().host(bUrl.host).port(bUrl.port).build()).build())
        }).build()
        val other = ObliHttp(originA, rerouting).post("/api/commands") as ApiOutcome.StepUpRequired
        assertNull(other.origin)
    }

    @Test fun aRevokedKeyIsReportedWithTheKeyTheRequestCarried() = runBlocking {
        signedIn[originA] = 42
        keys[originA to 42L] = keyA
        val reports = mutableListOf<Pair<String, String?>>()
        val http = ObliHttp(originA, client) { origin, keyId -> reports += origin to keyId }
        a.enqueue(MockResponse.Builder().code(401).addHeader("Content-Type", "application/json")
            .body("""{"success":false,"error":"Authentication required","deviceKeyStatus":"revoked"}""").build())
        a.enqueue(MockResponse.Builder().code(401).addHeader("Content-Type", "application/json")
            .body("""{"success":false,"error":"Authentication required"}""").build())
        assertEquals(ApiOutcome.SessionExpired, http.get("/api/devices"))
        assertEquals(ApiOutcome.SessionExpired, http.get("/api/devices"))
        assertEquals(listOf(originA to keyA), reports)
    }
}
