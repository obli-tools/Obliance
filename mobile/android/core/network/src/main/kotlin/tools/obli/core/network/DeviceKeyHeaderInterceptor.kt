package tools.obli.core.network

import okhttp3.Interceptor
import okhttp3.Response
import tools.obli.shell.nav.Origins

/**
 * Adds `X-Obli-Device-Key: <keyId>` to every request whose origin O has a key
 * for the user of the session signed in on O.
 * [source] gets the request's origin and answers that key id, or
 * null (no key, no signed-in user, another account on O since…): it is the
 * source that ties the key to (origin, user), never a server answer.
 *
 * An explicit header (the sign-in) is never replaced. A value that is
 * not a UUID is never sent. Web views do not go through OkHttp and never send it.
 */
class DeviceKeyHeaderInterceptor(private val source: (origin: String) -> String?) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.header(DeviceKeyHeader.NAME) != null) return chain.proceed(request)
        val origin = Origins.of(request.url.toString()) ?: return chain.proceed(request)
        val keyId = try {
            source(origin)
        } catch (_: RuntimeException) {
            null // store not loaded yet, or anything odd: no header (the server then asks for the code)
        }
        if (!DeviceKeyHeader.isValidKeyId(keyId)) return chain.proceed(request)
        return chain.proceed(request.newBuilder().header(DeviceKeyHeader.NAME, keyId!!).build())
    }
}
