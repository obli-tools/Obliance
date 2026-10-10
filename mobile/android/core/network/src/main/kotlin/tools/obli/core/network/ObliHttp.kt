package tools.obli.core.network

import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import tools.obli.shell.nav.Origins

/**
 * The HTTP client of ONE server. Every call is resolved
 * against [origin] and refused otherwise: a path from an alert or a link can
 * never send the session cookie to another host. Never retries a POST.
 *
 * Device-bound validation: a step-up
 * 401 carries [ApiOutcome.StepUpRequired.origin] only when it came from
 * [origin]; a `401 deviceKeyStatus:'revoked'` is reported to
 * [onDeviceKeyRevoked] with the key id the request carried.
 */
class ObliHttp(
    val origin: String,
    private val client: OkHttpClient,
    /** Called (on the caller's coroutine) after a 401 `revoked`; `keyId` is the `X-Obli-Device-Key` the request carried. */
    private val onDeviceKeyRevoked: ((origin: String, keyId: String?) -> Unit)? = null,
) {
    init {
        require(Origins.of(origin) == origin) { "not a normalised origin: $origin" }
    }

    enum class Method { GET, POST, PUT, PATCH, DELETE }

    /**
     * @param headers explicit request headers. Used for the explicit
     *   `X-Obli-Device-Key` of the sign-in, which the automatic
     *   [DeviceKeyHeaderInterceptor] never replaces.
     * @param errorBody sees the JSON object of a non-2xx answer (before it is
     *   classified): the fingerprint sign-in reads `deviceError` and a renewed
     *   `deviceChallenge` of its `401 Invalid code` there. Never
     *   called for a 2xx answer nor for a body that is not a JSON object.
     */
    suspend fun <T> call(
        method: Method,
        path: String,
        body: JsonObject? = null,
        headers: Map<String, String> = emptyMap(),
        errorBody: ((status: Int, body: JsonObject) -> Unit)? = null,
        decode: (JsonElement?) -> T?,
    ): ApiOutcome<T> {
        val url = urlFor(path) ?: return ApiOutcome.Failure(null, FailureKind.CLIENT, "refused path")
        val requestBody = when {
            body != null -> body.toString().toRequestBody(JSON)
            method == Method.GET || method == Method.DELETE -> null
            else -> "{}".toRequestBody(JSON)
        }
        val request = try {
            Request.Builder()
                .url(url)
                .method(method.name, requestBody)
                .header("Accept", "application/json")
                .apply { headers.forEach { (name, value) -> header(name, value) } }
                .build()
        } catch (_: IllegalArgumentException) {
            return ApiOutcome.Failure(null, FailureKind.CLIENT, "refused header")
        }
        return try {
            client.newCall(request).await().use { r ->
                val contentType = r.header("Content-Type")
                val text = r.body.string()
                val out = ApiResponses.classify(r.code, contentType, text, r.header("Retry-After"), decode)
                if (errorBody != null && r.code !in 200..299) {
                    ApiResponses.errorObject(contentType, text)?.let { obj -> runCatching { errorBody(r.code, obj) } }
                }
                val revoked = onDeviceKeyRevoked
                if (revoked != null && ApiResponses.isDeviceKeyRevoked(r.code, contentType, text)) {
                    runCatching { revoked(origin, r.request.header(DeviceKeyHeader.NAME)) }
                }
                if (out is ApiOutcome.StepUpRequired) {
                    // Only an answer of THIS origin may lead to a signature.
                    out.copy(origin = origin.takeIf { Origins.of(r.request.url.toString()) == it })
                } else {
                    out
                }
            }
        } catch (e: IOException) {
            ApiResponses.network(e.javaClass.simpleName)
        }
    }

    suspend fun get(path: String): ApiOutcome<JsonElement?> = call(Method.GET, path) { ApiResponses.unwrap(it) ?: kotlinx.serialization.json.JsonNull }

    suspend fun post(path: String, body: JsonObject? = null): ApiOutcome<JsonElement?> =
        call(Method.POST, path, body) { ApiResponses.unwrap(it) ?: kotlinx.serialization.json.JsonNull }

    /** Absolute URL of a same-origin relative path, or null (protocol-relative, other host, control chars…). */
    fun urlFor(path: String): HttpUrl? = Origins.resolveRelativePath(origin, path)?.toHttpUrlOrNull()

    companion object {
        private val JSON = "application/json; charset=utf-8".toMediaType()

        /**
         * The single OkHttp client of the app: 10 s connect / 20 s read, the
         * app's User-Agent, the shared cookie jar (WebView CookieManager on
         * Android), never a redirect. With [deviceKeyHeader], every request to
         * an origin for which it returns a key id carries `X-Obli-Device-Key`
         * ([DeviceKeyHeaderInterceptor]).
         */
        fun defaultClient(
            cookieJar: CookieJar,
            userAgent: String,
            deviceKeyHeader: ((origin: String) -> String?)? = null,
        ): OkHttpClient =
            OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(20, TimeUnit.SECONDS)
                .callTimeout(60, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false)
                .followRedirects(false)
                .followSslRedirects(false)
                .cookieJar(cookieJar)
                .apply { if (deviceKeyHeader != null) addInterceptor(DeviceKeyHeaderInterceptor(deviceKeyHeader)) }
                .addNetworkInterceptor { chain ->
                    chain.proceed(chain.request().newBuilder().header("User-Agent", userAgent).build())
                }
                .build()
    }
}

private suspend fun Call.await(): Response = suspendCancellableCoroutine { cont ->
    cont.invokeOnCancellation { runCatching { cancel() } }
    enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            if (!cont.isCancelled) cont.resumeWith(Result.failure(e))
        }

        override fun onResponse(call: Call, response: Response) {
            cont.resume(response)
        }
    })
}
