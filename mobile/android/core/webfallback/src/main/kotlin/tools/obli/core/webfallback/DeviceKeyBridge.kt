package tools.obli.core.webfallback

import android.net.Uri
import android.util.Log
import android.webkit.WebView
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.ScriptHandler
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.findViewTreeLifecycleOwner
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import tools.obli.shell.core.obj
import tools.obli.shell.core.str
import tools.obli.shell.nav.Origins

/*
 * Web view bridge, bridgeVersion 2: the web pages of the app sign a step-up
 * challenge with this phone's key instead of asking for the 2FA code.
 *
 * Only `window.ObliNative.signDeviceChallenge(challengeJson)` is offered here
 * (capability `deviceKey`): the other bridge methods belong to the WebView
 * shell. Transport as in the shell: WebViewCompat.addWebMessageListener
 * (object `__obliBridge`, allowed origin = the page's server only) and a
 * document-start script (same origin rule) that defines the frozen
 * `window.__obli_native` and `window.ObliNative`. Without both WebView
 * features, nothing is injected and the page asks for the code.
 * The bridge never adds X-Obli-Device-Key: the web view shares the app's
 * cookie, hence its bound session.
 */

/** What the page reads in `window.__obli_native` (the app's identity; platform `android`). */
data class WebBridgeInfo(val app: String, val appVersion: String, val versionCode: Int)

/**
 * Signs a challenge the page of [pageOrigin] relayed, and returns the
 * bridge's answer object: `{deviceAssertion}`, `{cancelled:true}`,
 * `{useCode:true}` or `{error}`. Implemented by the app over core:security
 * `WebChallengeSigning` (the origin/key/tenant checks and the native prompt).
 */
fun interface WebDeviceChallengeSigner {
    suspend fun sign(pageOrigin: String, challengeJson: String): JsonObject
}

/** Everything the web view needs to offer `signDeviceChallenge`. */
class WebDeviceBridge(val info: WebBridgeInfo, val signer: WebDeviceChallengeSigner)

/** Provided by the app when device-bound validation exists; null (default): no bridge at all. */
val LocalWebDeviceBridge = staticCompositionLocalOf<WebDeviceBridge?> { null }

/** The JavaScript side (pure string building, tested on Node). */
object DeviceBridgeScript {
    const val CHANNEL = "__obliBridge"
    const val BRIDGE_VERSION = 2
    const val CAPABILITY = "deviceKey"
    const val METHOD = "signDeviceChallenge"

    fun build(info: WebBridgeInfo): String {
        val infoJson = buildJsonObject {
            put("platform", "android")
            put("app", info.app)
            put("appVersion", info.appVersion)
            put("versionCode", info.versionCode)
            put("bridgeVersion", BRIDGE_VERSION)
            put("capabilities", JsonArray(listOf(JsonPrimitive(CAPABILITY))))
        }.toString()
        return TEMPLATE.replace("__INFO__", infoJson).replace("__CHANNEL__", JsonPrimitive(CHANNEL).toString())
    }

    private val TEMPLATE = """
(function () {
  'use strict';
  if (window.__obli_native && window.ObliNative) { return; }
  var INFO = __INFO__;
  var CHANNEL = __CHANNEL__;
  var freeze = Object.freeze || function (o) { return o; };
  INFO.capabilities = freeze(INFO.capabilities.slice());
  var seq = 0;
  var pending = {};
  var channel = null;

  function onReply(ev) {
    var msg;
    try { msg = JSON.parse(ev && ev.data); } catch (e) { return; }
    if (!msg || typeof msg.id !== 'number') { return; }
    var p = pending[msg.id];
    if (!p) { return; }
    delete pending[msg.id];
    if (msg.ok === true) { p.resolve(msg.result); }
    else { p.reject(new Error(typeof msg.error === 'string' ? msg.error : 'native bridge error')); }
  }

  function getChannel() {
    if (channel) { return channel; }
    var c = window[CHANNEL];
    if (!c || typeof c.postMessage !== 'function') { return null; }
    if (typeof c.addEventListener === 'function') { c.addEventListener('message', onReply); }
    else { c.onmessage = onReply; }
    channel = c;
    return c;
  }

  function call(method, params) {
    return new Promise(function (resolve, reject) {
      var c = getChannel();
      if (!c) { reject(new Error('native bridge unavailable')); return; }
      var id = ++seq;
      pending[id] = { resolve: resolve, reject: reject };
      try {
        c.postMessage(JSON.stringify({ id: id, method: method, params: params || {} }));
      } catch (e) {
        delete pending[id];
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  var api = {
    signDeviceChallenge: function (challengeJson) {
      if (typeof challengeJson !== 'string') { return Promise.reject(new Error('challengeJson must be a string')); }
      return call('signDeviceChallenge', { challengeJson: challengeJson });
    }
  };

  function define(name, value) {
    try {
      Object.defineProperty(window, name, { value: value, writable: false, configurable: false, enumerable: false });
    } catch (e) {
      window[name] = value;
    }
  }
  define('__obli_native', freeze(INFO));
  define('ObliNative', freeze(api));
})();
"""
}

/** Messages of the transport: `{id, method, params}` in, `{id, ok, result}` / `{id, ok:false, error}` out. */
object DeviceBridgeProtocol {
    /** A request larger than this is refused unread (a challenge is ~600 characters). */
    const val MAX_MESSAGE_LENGTH = 16_384

    sealed interface Parsed {
        data class Request(val id: Long, val method: String, val challengeJson: String?) : Parsed
        data class Invalid(val id: Long?, val message: String) : Parsed
    }

    private val json = Json { isLenient = false }

    fun parse(data: String?): Parsed {
        if (data == null || data.length > MAX_MESSAGE_LENGTH) return Parsed.Invalid(null, "invalid message")
        val obj = try {
            json.parseToJsonElement(data) as? JsonObject
        } catch (_: Exception) {
            null
        } ?: return Parsed.Invalid(null, "invalid message")
        val id = (obj["id"] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()
            ?: return Parsed.Invalid(null, "invalid id")
        val method = obj.str("method") ?: return Parsed.Invalid(id, "invalid method")
        val challengeJson = obj.obj("params")?.str("challengeJson")
        return Parsed.Request(id, method, challengeJson)
    }

    fun success(id: Long, result: JsonElement): String = buildJsonObject {
        put("id", id)
        put("ok", true)
        put("result", result)
    }.toString()

    fun failure(id: Long, message: String): String = buildJsonObject {
        put("id", id)
        put("ok", false)
        put("error", message)
    }.toString()

    /** The answer object of a refusal (`{error}`), resolved, not rejected. */
    fun refusal(code: String): JsonObject = buildJsonObject { put("error", code) }
}

/**
 * Limits of the bridge for ONE web view (a same-origin script must not be able
 * to show the fingerprint prompt again and again until a reflex touch signs
 * the request it chose): a challenge is prompted at most once, an expired one
 * never ([SKEW_MS] of clock allowance); after an answer that is not a
 * signature (cancelled, « Utiliser un code », an error) the bridge refuses
 * for [COOLDOWN_MS]; at most [MAX_PER_MINUTE] calls a minute. A refusal
 * answers `{error}`: the page asks for the code. Pure JVM (tested without a
 * WebView); thread-safe.
 */
internal class DeviceBridgeGate(private val clock: () -> Long = System::currentTimeMillis) {
    private val seen = LinkedHashSet<String>()
    private val recent = ArrayDeque<Long>()
    private var cooldownUntil = 0L

    /**
     * Null when [challengeJson] may go to the signer now (it is then counted
     * and its challenge id remembered), else the error code to answer.
     */
    @Synchronized
    fun admit(challengeJson: String): String? {
        val now = clock()
        if (now < cooldownUntil) return RATE_LIMITED
        val obj = try {
            json.parseToJsonElement(challengeJson) as? JsonObject
        } catch (_: Exception) {
            null
        } ?: return BAD_CHALLENGE
        val challengeId = obj.str("challengeId")?.takeIf { it.isNotBlank() } ?: return BAD_CHALLENGE
        val expiresAt = (obj["expiresAt"] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: return BAD_CHALLENGE
        if (expiresAt * 1000 + SKEW_MS < now) return EXPIRED
        if (challengeId in seen) return RATE_LIMITED
        while (recent.isNotEmpty() && now - recent.first() >= MINUTE_MS) recent.removeFirst()
        if (recent.size >= MAX_PER_MINUTE) return RATE_LIMITED
        recent.addLast(now)
        seen += challengeId
        if (seen.size > MAX_SEEN) seen.remove(seen.first())
        return null
    }

    /** The signer's answer: anything but `{deviceAssertion}` cools the bridge down. */
    @Synchronized
    fun answered(result: JsonObject) {
        if (ASSERTION !in result) cooldownUntil = clock() + COOLDOWN_MS
    }

    companion object {
        const val RATE_LIMITED = "rate_limited"
        const val EXPIRED = "expired"
        const val BAD_CHALLENGE = "bad_challenge"
        const val ASSERTION = "deviceAssertion"

        /** Refusals after a prompt that did not sign (cancel, code, error). */
        const val COOLDOWN_MS = 30_000L

        /** Calls admitted per minute and web view (an action takes 1, or 2 after `challenge_expired`). */
        const val MAX_PER_MINUTE = 5

        /** Phone clock ahead of the server's by up to this much still accepts a challenge. */
        const val SKEW_MS = 30_000L

        private const val MINUTE_MS = 60_000L
        private const val MAX_SEEN = 64
        private val json = Json { isLenient = false }
    }
}

/**
 * Native side of `signDeviceChallenge` for ONE web view of [origin]:
 * main frame only, the message's origin AND the page shown now must be
 * [origin], the view must be on screen (attached, its window focused — no
 * other window such as the app lock or a sheet on top — and the activity
 * resumed), the [gate]'s limits, and one prompt at a time (a second request
 * meanwhile answers `{error:'busy'}`). The signature runs in [scope] (the
 * view's composition): leaving the page cancels the prompt.
 */
internal class DeviceBridgeListener(
    private val origin: String,
    private val bridge: WebDeviceBridge,
    private val scope: CoroutineScope,
    private val gate: DeviceBridgeGate = DeviceBridgeGate(),
) : WebViewCompat.WebMessageListener {
    private val busy = AtomicBoolean(false)

    override fun onPostMessage(view: WebView, message: WebMessageCompat, sourceOrigin: Uri, isMainFrame: Boolean, replyProxy: JavaScriptReplyProxy) {
        // allowedOriginRules already restrict this; checked again on purpose.
        if (Origins.of(sourceOrigin.toString()) != origin) return
        val request = when (val parsed = DeviceBridgeProtocol.parse(message.data)) {
            is DeviceBridgeProtocol.Parsed.Invalid -> {
                parsed.id?.let { reply(replyProxy, DeviceBridgeProtocol.failure(it, parsed.message)) }
                return
            }
            is DeviceBridgeProtocol.Parsed.Request -> parsed
        }
        if (!isMainFrame) {
            reply(replyProxy, DeviceBridgeProtocol.failure(request.id, "bridge is only available to the main frame"))
            return
        }
        if (request.method != DeviceBridgeScript.METHOD) {
            reply(replyProxy, DeviceBridgeProtocol.failure(request.id, "unknown method"))
            return
        }
        val challengeJson = request.challengeJson
        if (challengeJson == null) {
            reply(replyProxy, DeviceBridgeProtocol.failure(request.id, "invalid params"))
            return
        }
        // The page on screen now (not only the sender's origin) must be the server's.
        if (Origins.of(view.url) != origin) {
            reply(replyProxy, DeviceBridgeProtocol.success(request.id, DeviceBridgeProtocol.refusal("not_active_server")))
            return
        }
        // Only while the page is what the user sees: never from the background, never under
        // another window (the app lock screen, an action sheet), never on a paused activity.
        if (!onScreen(view)) {
            reply(replyProxy, DeviceBridgeProtocol.success(request.id, DeviceBridgeProtocol.refusal(NOT_VISIBLE)))
            return
        }
        if (!busy.compareAndSet(false, true)) {
            reply(replyProxy, DeviceBridgeProtocol.success(request.id, DeviceBridgeProtocol.refusal("busy")))
            return
        }
        gate.admit(challengeJson)?.let { refused ->
            busy.set(false)
            reply(replyProxy, DeviceBridgeProtocol.success(request.id, DeviceBridgeProtocol.refusal(refused)))
            return
        }
        scope.launch {
            try {
                val result = bridge.signer.sign(origin, challengeJson)
                gate.answered(result)
                reply(replyProxy, DeviceBridgeProtocol.success(request.id, result))
            } catch (e: CancellationException) {
                val cancelled = buildJsonObject { put("cancelled", true) }
                gate.answered(cancelled)
                reply(replyProxy, DeviceBridgeProtocol.success(request.id, cancelled))
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "signDeviceChallenge failed: ${e.javaClass.simpleName}")
                val refusal = DeviceBridgeProtocol.refusal("unavailable")
                gate.answered(refusal)
                reply(replyProxy, DeviceBridgeProtocol.success(request.id, refusal))
            } finally {
                busy.set(false)
            }
        }
    }

    private fun onScreen(view: WebView): Boolean {
        if (!view.isAttachedToWindow || !view.isShown || !view.hasWindowFocus()) return false
        // Window focus already implies a resumed activity; the lifecycle says so when it is known.
        val state = view.findViewTreeLifecycleOwner()?.lifecycle?.currentState ?: return true
        return state.isAtLeast(Lifecycle.State.RESUMED)
    }

    private fun reply(proxy: JavaScriptReplyProxy, json: String) {
        // Always true here: the listener only exists when the feature does.
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) return
        try {
            proxy.postMessage(json)
        } catch (_: RuntimeException) {
            // The page navigated away or the view is gone: nobody is listening any more.
        }
    }

    private companion object {
        const val TAG = "ObliWebBridge"
        const val NOT_VISIBLE = "not_visible"
    }
}

/**
 * Registers the bridge on [webView] for exactly [origin], BEFORE the first
 * load. Returns the document-start script handler, or null when the WebView
 * lacks a feature (then nothing is registered: the page uses the code).
 */
internal fun installDeviceBridge(webView: WebView, origin: String, bridge: WebDeviceBridge, scope: CoroutineScope): ScriptHandler? {
    // Both features or nothing: a listener without the script (or the reverse) is useless.
    if (!WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) return null
    if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) return null
    val rules = setOf(origin)
    return try {
        WebViewCompat.addWebMessageListener(webView, DeviceBridgeScript.CHANNEL, rules, DeviceBridgeListener(origin, bridge, scope))
        if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            WebViewCompat.addDocumentStartJavaScript(webView, DeviceBridgeScript.build(bridge.info), rules)
        } else {
            null
        }
    } catch (e: RuntimeException) {
        Log.w("ObliWebBridge", "bridge registration failed: ${e.javaClass.simpleName}")
        runCatching { WebViewCompat.removeWebMessageListener(webView, DeviceBridgeScript.CHANNEL) }
        null
    }
}
