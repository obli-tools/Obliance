package tools.obli.core.security.ui

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import java.security.Signature
import kotlin.coroutines.resume
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import tools.obli.core.security.DeviceKeyHardware
import tools.obli.core.security.DeviceSigner
import tools.obli.core.security.KeyHealth
import tools.obli.core.security.OpenedSignature
import tools.obli.core.security.SignPrompt
import tools.obli.core.security.SignResult

/**
 * [DeviceSigner] on androidx.biometric:
 * the key's health is checked first (`initSign` without authentication), then
 * a `BiometricPrompt` bound to the key by a `CryptoObject(Signature)` with
 * BIOMETRIC_STRONG ONLY — never DEVICE_CREDENTIAL, so the PIN can never sign
 * (the Keystore enforces it too, and the attestation proves it to the
 * server) — and `setConfirmationRequired(true)`. The signature is made with
 * the Signature the authentication unlocked, for this payload only.
 *
 * API 26–27: androidx.biometric uses FingerprintManager with the same
 * CryptoObject (the activity must be AppCompat-themed, as the app's are).
 *
 * The prompt is only shown by a RESUMED activity whose fragment state is not
 * saved: androidx.biometric otherwise drops the request without any callback
 * (« Called after onSaveInstanceState() »), which would leave the caller —
 * and the action host's one-prompt-at-a-time lock — waiting forever. Then
 * [SignResult.Unavailable] (the code is used). A watchdog ([promptTimeoutMs])
 * ends a prompt that never answers the same way.
 */
class BiometricDeviceSigner(
    private val activity: FragmentActivity,
    private val hardware: DeviceKeyHardware,
    /** Longest wait for the prompt's answer (a challenge lives 120 s, an enrolment ticket 180 s). */
    private val promptTimeoutMs: Long = PROMPT_TIMEOUT_MS,
) : DeviceSigner {
    override suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt): SignResult {
        // The health check before each signature.
        val signature = when (val opened = withContext(Dispatchers.IO) { hardware.openSignature(alias) }) {
            is OpenedSignature.Ready -> opened.signature
            is OpenedSignature.Failed -> return BiometricSignResults.ofHealth(opened.health)
        }
        if (!withContext(Dispatchers.Main.immediate) { PromptHost.canShow(activity) }) return SignResult.Unavailable(BiometricSignResults.NOT_FOREGROUND)
        val canAuthenticate = BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)
        if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS) return SignResult.Unavailable("biometric_$canAuthenticate")
        val auth = withTimeoutOrNull(promptTimeoutMs) { authenticate(signature, prompt) }
            ?: return SignResult.Unavailable(BiometricSignResults.PROMPT_TIMEOUT)
        val unlocked = when (auth) {
            is Auth.Succeeded -> auth.signature
            is Auth.Error -> return BiometricSignResults.ofError(auth.code)
        }
        return withContext(Dispatchers.Default) {
            try {
                unlocked.update(payload)
                SignResult.Signed(unlocked.sign())
            } catch (e: Exception) {
                SignResult.Unavailable(e.javaClass.simpleName)
            }
        }
    }

    private sealed interface Auth {
        class Succeeded(val signature: Signature) : Auth
        class Error(val code: Int) : Auth
    }

    private suspend fun authenticate(signature: Signature, prompt: SignPrompt): Auth = withContext(Dispatchers.Main.immediate) {
        suspendCancellableCoroutine { cont ->
            val biometricPrompt = BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val unlocked = result.cryptoObject?.signature
                        if (cont.isActive) cont.resume(if (unlocked != null) Auth.Succeeded(unlocked) else Auth.Error(NO_CRYPTO_OBJECT))
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (cont.isActive) cont.resume(Auth.Error(errorCode))
                    }
                    // onAuthenticationFailed (a finger not recognised) is not final: the prompt stays.
                },
            )
            val info = try {
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle(prompt.title)
                    .apply { prompt.subtitle?.let(::setSubtitle) }
                    .apply { prompt.description?.let(::setDescription) }
                    .setNegativeButtonText(prompt.negative)
                    .setAllowedAuthenticators(BIOMETRIC_STRONG)
                    .setConfirmationRequired(true)
                    .build()
            } catch (_: IllegalArgumentException) {
                null
            }
            if (info == null) {
                cont.resume(Auth.Error(NO_CRYPTO_OBJECT))
                return@suspendCancellableCoroutine
            }
            // Checked again on the main thread, right before showing (nothing can run in between).
            if (!PromptHost.canShow(activity)) {
                cont.resume(Auth.Error(NOT_SHOWN))
                return@suspendCancellableCoroutine
            }
            cont.invokeOnCancellation { runCatching { biometricPrompt.cancelAuthentication() } }
            try {
                biometricPrompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
            } catch (_: RuntimeException) {
                if (cont.isActive) cont.resume(Auth.Error(NO_CRYPTO_OBJECT))
            }
        }
    }

    companion object {
        /** Not a BiometricPrompt code: the prompt could not be built or gave no CryptoObject back. */
        private const val NO_CRYPTO_OBJECT = -1

        /** Not a BiometricPrompt code: the activity could not show the prompt (not resumed, state saved). */
        private const val NOT_SHOWN = BiometricSignResults.NOT_SHOWN_CODE

        /** A little over the challenge's 120 s, under the enrolment ticket's 180 s. */
        const val PROMPT_TIMEOUT_MS = 150_000L
    }
}

/**
 * Whether [FragmentActivity] can show a BiometricPrompt now: resumed, not
 * finishing or destroyed, fragment state not saved. Main thread only.
 */
internal object PromptHost {
    fun canShow(activity: FragmentActivity): Boolean = canShow(
        state = activity.lifecycle.currentState,
        finishing = activity.isFinishing || activity.isDestroyed,
        stateSaved = activity.supportFragmentManager.isStateSaved,
    )

    fun canShow(state: Lifecycle.State, finishing: Boolean, stateSaved: Boolean): Boolean =
        state.isAtLeast(Lifecycle.State.RESUMED) && !finishing && !stateSaved
}

/** How the biometric step ends, as pure functions. */
internal object BiometricSignResults {
    /**
     * ERROR_LOCKOUT(_PERMANENT) → [SignResult.LockedOut] (then password + code);
     * ERROR_NEGATIVE_BUTTON → [SignResult.UseCode]; ERROR_USER_CANCELED,
     * ERROR_CANCELED and ERROR_TIMEOUT → [SignResult.Cancelled]; anything else
     * (no hardware, no biometric enrolled, security update required…) →
     * [SignResult.Unavailable]: the code is used.
     */
    fun ofError(code: Int): SignResult = when (code) {
        BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> SignResult.LockedOut
        BiometricPrompt.ERROR_NEGATIVE_BUTTON -> SignResult.UseCode
        BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_CANCELED, BiometricPrompt.ERROR_TIMEOUT -> SignResult.Cancelled
        NOT_SHOWN_CODE -> SignResult.Unavailable(NOT_FOREGROUND)
        else -> SignResult.Unavailable("biometric_error_$code")
    }

    /** Not a BiometricPrompt code: the activity could not show the prompt (not resumed, state saved). */
    const val NOT_SHOWN_CODE = -2

    /** [SignResult.Unavailable] reason: the app was not in the foreground (the prompt could not be shown). */
    const val NOT_FOREGROUND = "not_foreground"

    /** [SignResult.Unavailable] reason: the prompt never answered within the watchdog. */
    const val PROMPT_TIMEOUT = "prompt_timeout"

    /** The key's health before the prompt: invalidated or missing → [SignResult.Invalidated]. */
    fun ofHealth(health: KeyHealth): SignResult = when (health) {
        KeyHealth.Invalidated, KeyHealth.Missing -> SignResult.Invalidated
        is KeyHealth.Unavailable -> SignResult.Unavailable(health.reason)
        KeyHealth.Healthy -> SignResult.Unavailable("healthy key without signature")
    }
}
