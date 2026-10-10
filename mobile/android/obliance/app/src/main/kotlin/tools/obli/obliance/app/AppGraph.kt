package tools.obli.obliance.app

import android.content.Context
import androidx.core.content.edit
import android.os.Build
import androidx.biometric.BiometricManager
import java.security.MessageDigest
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import tools.obli.core.auth.ServerRegistry
import tools.obli.core.auth.ServerSession
import tools.obli.core.auth.ServerSessions
import tools.obli.core.data.AndroidWebCookies
import tools.obli.core.data.DataStoreServerRegistryStore
import tools.obli.core.network.ObliHttp
import tools.obli.core.network.WebCookieJar
import tools.obli.core.realtime.SocketIoRealtimeClient
import tools.obli.obliance.api.ObliEvents
import tools.obli.core.devicekey.DataStoreDeviceKeyStore
import tools.obli.core.devicekey.KeystoreDeviceKeys
import tools.obli.obliance.data.DefaultObliServices
import tools.obli.obliance.data.DeviceKeyDeps
import tools.obli.obliance.data.DeviceKeyProposalMemory
import tools.obli.obliance.data.ObliServices
import tools.obli.obliance.data.SsoReauthBroker
import tools.obli.obliance.remote.RemoteAccess

/**
 * The manual dependency graph of the application: ONE
 * OkHttp client (shared cookie jar = the WebView CookieManager), the persisted
 * server registry, one session per server with its Socket.IO client, the
 * repositories, and the transport of the remote-access tunnels. Built once in [ObliNextApplication].
 *
 * The process also starts in the background (notification worker every 15
 * minutes, a notification action, the Quick Settings tile): [foreground]
 * follows the process lifecycle so the socket only opens while an activity is
 * visible (DefaultObliServices.start).
 */
class AppGraph(context: Context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val cookieJar = WebCookieJar(AndroidWebCookies())

    /**
     * Device-bound validation:
     * the Keystore keys and their records. Records are loaded by
     * DefaultObliServices.start before the first key check.
     */
    private val deviceKeyStore = DataStoreDeviceKeyStore(context)
    private val deviceKeyHardware = KeystoreDeviceKeys(context)

    /**
     * ONE client; every request to an origin whose signed-in user has a key on
     * this phone carries `X-Obli-Device-Key` (the lambda runs per request, once
     * the services exist; before that, no header).
     */
    val client: OkHttpClient = ObliHttp.defaultClient(cookieJar, USER_AGENT, deviceKeyHeader = { origin -> defaultServices.deviceKeyHeader(origin) })
    val registry = ServerRegistry(DataStoreServerRegistryStore(context)).apply {
        // A removed server leaves no session cookie behind.
        addRemovalListener { profile -> cookieJar.clearOrigin(profile.origin) }
    }

    val sessions = ServerSessions(
        registry,
        { profile, profileNow ->
            ServerSession(
                id = profile.id,
                profileNow = profileNow,
                // A `401 revoked` purges the key the request carried.
                http = ObliHttp(profile.origin, client) { origin, keyId -> defaultServices.deviceKeyRevoked(origin, keyId) },
                realtimeFactory = { session ->
                    val origin = session.profile.origin
                    SocketIoRealtimeClient(origin, client, { cookieJar.headerFor(origin) }, USER_AGENT, ObliEvents.LISTENED)
                },
            )
        },
        scope,
    )

    init {
        // Terminal and ObliReach tunnels: the same client, user agent and cookie session.
        RemoteAccess.configure(client, USER_AGENT, cookieJar::headerFor)
    }

    /**
     * SSO device keys: the native Obligate
     * re-authentication, asked by the action host, the profile and security screen and the web view, shown by
     * ObliNextApp's SsoReauthHost (the process cookie store: same session).
     */
    private val ssoReauth = SsoReauthBroker()

    private val defaultServices: DefaultObliServices = DefaultObliServices(
        registry = registry,
        sessions = sessions,
        httpFor = { origin -> ObliHttp(origin, client) },
        clearCookies = cookieJar::clearOrigin,
        scope = scope,
        ssoReauth = ssoReauth,
        deviceKeyDeps = DeviceKeyDeps(
            store = deviceKeyStore,
            hardware = deviceKeyHardware,
            strongBiometric = {
                BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
            },
            deviceLabel = { deviceLabel() },
            appVersion = BuildConfig.VERSION_NAME,
            proposals = PrefsProposalMemory(context),
            load = { deviceKeyStore.load() },
            // Enrolment of an Obligate account (profile and security screen): the sheet, then begin at once.
            reauth = { origin -> ssoReauth.reauthenticate(origin) },
        ),
    )
    val services: ObliServices get() = defaultServices

    private val _ready = MutableStateFlow(false)

    /** True once the registry is loaded (before that, the UI shows the bare background). */
    val ready: StateFlow<Boolean> = _ready.asStateFlow()

    private val _foreground = MutableStateFlow(false)

    /** True between ProcessLifecycleOwner ON_START and ON_STOP (an activity of the app is visible). */
    val foreground: StateFlow<Boolean> = _foreground.asStateFlow()

    /** Call once, from Application.onCreate (main thread). */
    fun start() {
        if (Looper.myLooper() == Looper.getMainLooper()) observeForeground() else Handler(Looper.getMainLooper()).post(::observeForeground)
        scope.launch {
            registry.load()
            defaultServices.start(foreground)
            _ready.value = true
        }
    }

    /** Runs [block] in the application scope once the registry is loaded. */
    fun whenReady(block: suspend () -> Unit) {
        scope.launch {
            ready.first { it }
            block()
        }
    }

    /** ProcessLifecycleOwner observers must be added on the main thread. */
    private fun observeForeground() {
        val lifecycle = ProcessLifecycleOwner.get().lifecycle
        _foreground.value = lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) {
                    _foreground.value = true
                }

                override fun onStop(owner: LifecycleOwner) {
                    _foreground.value = false
                }
            },
        )
    }

    companion object {
        /** The server sees the app like the WebView shell, with the native marker. */
        val USER_AGENT = "Mozilla/5.0 (Linux; Android ${android.os.Build.VERSION.RELEASE}) ObliApp/${BuildConfig.VERSION_NAME} (obliance; Android)"
    }
}

/** Label of this phone's key in the account's phone list ("samsung SM-S911B"): shown to the account only. */
private fun deviceLabel(): String =
    listOf(Build.MANUFACTURER, Build.MODEL).map { it.orEmpty().trim() }.filter { it.isNotEmpty() }.distinct().joinToString(" ").ifEmpty { "Android" }

/**
 * « Plus tard » of the first-2FA proposal, per (origin, server user), in the
 * app's private preferences (allowBackup=false). The key is hashed: no origin
 * nor user id in the file.
 */
private class PrefsProposalMemory(context: Context) : DeviceKeyProposalMemory {
    private val prefs = context.getSharedPreferences("obli_device_key_proposals", Context.MODE_PRIVATE)

    override fun declinedAt(key: String): Long? = prefs.getLong(hash(key), -1L).takeIf { it >= 0 }

    override fun decline(key: String, at: Long) {
        prefs.edit { putLong(hash(key), at) }
    }

    private fun hash(key: String): String =
        MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }.take(32)
}
