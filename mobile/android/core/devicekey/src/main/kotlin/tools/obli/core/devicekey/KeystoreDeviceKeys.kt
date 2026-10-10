package tools.obli.core.devicekey

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import tools.obli.core.security.DeviceKeyAlias
import tools.obli.core.security.DeviceKeyHardware
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.GeneratedKey
import tools.obli.core.security.HardwareNotSecureException
import tools.obli.core.security.KeyHealth
import tools.obli.core.security.OpenedSignature

/**
 * The device keys in the Android Keystore.
 * One EC P-256 key per (origin, server user, install), never
 * exportable, a BIOMETRIC_STRONG authentication at every use, dead when a
 * biometric is enrolled or the screen lock removed. Only `obli.devkey.v1.*`
 * aliases are ever touched.
 */
class KeystoreDeviceKeys(
    context: Context,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) : DeviceKeyHardware {
    private val packageManager = context.applicationContext.packageManager

    /**
     * Generates the key of [alias] (replacing any) with the plan of this API
     * level and [attestationChallenge] = the enrolment ticket's nonce. StrongBox
     * when the phone has one; on StrongBoxUnavailableException or any
     * ProviderException, once more without (TEE). Then the local check
     * (KeyInfo): not in secure hardware → alias deleted, [HardwareNotSecureException].
     * The server decides on the attestation chain returned here (leaf first).
     */
    override suspend fun generate(alias: String, attestationChallenge: ByteArray): GeneratedKey = withContext(io) {
        require(DeviceKeyAlias.isOurs(alias)) { "not a device-key alias" }
        require(attestationChallenge.size in 1..MAX_CHALLENGE_BYTES) { "attestation challenge of ${attestationChallenge.size} bytes" }
        val plan = KeySpecPlan.forSdk(Build.VERSION.SDK_INT, hasStrongBox())
        deleteQuietly(alias)
        val used = try {
            generateWith(alias, attestationChallenge, plan)
            plan
        } catch (e: ProviderException) {
            // StrongBoxUnavailableException is a ProviderException; some StrongBox
            // implementations fail with a plain one: retry in the TEE.
            deleteQuietly(alias)
            if (!plan.strongBox) throw e
            generateWith(alias, attestationChallenge, plan.withoutStrongBox())
            plan.withoutStrongBox()
        }
        try {
            val keyStore = keyStore()
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: throw IllegalStateException("key not found after generation")
            val level = localLevel(privateKey, used) ?: throw HardwareNotSecureException("key not in secure hardware")
            val spki = keyStore.getCertificate(alias)?.publicKey?.encoded ?: throw IllegalStateException("no public key")
            val chain = keyStore.getCertificateChain(alias)?.map { it.encoded }.orEmpty()
            GeneratedKey(spki, chain, level)
        } catch (e: Exception) {
            deleteQuietly(alias)
            throw e
        }
    }

    override fun delete(alias: String) {
        if (!DeviceKeyAlias.isOurs(alias)) return
        keyStore().deleteEntry(alias)
    }

    override fun health(alias: String): KeyHealth = when (val opened = openSignature(alias)) {
        is OpenedSignature.Ready -> KeyHealth.Healthy
        is OpenedSignature.Failed -> opened.health
    }

    /**
     * `initSign` WITHOUT authentication (keyHealth): it succeeds on a
     * healthy per-use key; the returned Signature goes into the prompt's
     * CryptoObject and is authorised by the biometric for ONE operation.
     */
    override fun openSignature(alias: String): OpenedSignature {
        if (!DeviceKeyAlias.isOurs(alias)) return OpenedSignature.Failed(KeyHealth.Missing)
        return try {
            val keyStore = keyStore()
            if (!keyStore.containsAlias(alias)) return OpenedSignature.Failed(KeyHealth.Missing)
            val key = keyStore.getKey(alias, null) as? PrivateKey ?: return OpenedSignature.Failed(KeyHealth.Missing)
            val signature = Signature.getInstance(KeySpecPlan.SIGNATURE_ALGORITHM)
            signature.initSign(key)
            OpenedSignature.Ready(signature)
        } catch (e: Exception) {
            OpenedSignature.Failed(healthOf(e))
        }
    }

    override fun aliases(): Set<String> = try {
        keyStore().aliases().toList().filter(DeviceKeyAlias::isOurs).toSet()
    } catch (_: Exception) {
        emptySet()
    }

    private fun hasStrongBox(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun generateWith(alias: String, challenge: ByteArray, plan: KeySpecPlan) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(plan.curve))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setAttestationChallenge(challenge)
        when (plan.perUseAuth) {
            PerUseAuth.BIOMETRIC_STRONG_EVERY_USE -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                legacyPerUse(builder)
            }
            PerUseAuth.VALIDITY_MINUS_ONE -> legacyPerUse(builder)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (plan.strongBox) builder.setIsStrongBoxBacked(true)
            if (plan.unlockedDeviceRequired) builder.setUnlockedDeviceRequired(true)
        }
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(builder.build())
            generateKeyPair()
        }
    }

    @Suppress("DEPRECATION")
    private fun legacyPerUse(builder: KeyGenParameterSpec.Builder) {
        builder.setUserAuthenticationValidityDurationSeconds(-1)
    }

    /** Local check: API 31+ KeyInfo.securityLevel, below `isInsideSecureHardware`. Null = not hardware. */
    @SuppressLint("NewApi")
    private fun localLevel(key: PrivateKey, plan: KeySpecPlan): DeviceKeyLevel? {
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            LocalKeyLevel.of(Build.VERSION.SDK_INT, info.securityLevel, insideSecureHardware = false, strongBoxRequested = plan.strongBox)
        } else {
            @Suppress("DEPRECATION")
            LocalKeyLevel.of(Build.VERSION.SDK_INT, null, info.isInsideSecureHardware, plan.strongBox)
        }
    }

    private fun deleteQuietly(alias: String) {
        runCatching { delete(alias) }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /** KeyMint accepts an attestation challenge of at most 128 bytes (ours: 32). */
        const val MAX_CHALLENGE_BYTES = 128

        /**
         * A Keystore failure → the key's state. Only a KeyPermanentlyInvalidatedException
         * (anywhere in the causes) declares the key dead; anything else is
         * [KeyHealth.Unavailable]: the code is used, the key is kept.
         */
        internal fun healthOf(e: Throwable): KeyHealth {
            var cause: Throwable? = e
            var depth = 0
            while (cause != null && depth < 8) {
                if (cause is KeyPermanentlyInvalidatedException) return KeyHealth.Invalidated
                cause = cause.cause
                depth++
            }
            return KeyHealth.Unavailable(e.javaClass.simpleName)
        }
    }
}

/** The local reading of where a key lives, as a pure function. */
internal object LocalKeyLevel {
    /** `KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT`. */
    const val TRUSTED_ENVIRONMENT = 1

    /** `KeyProperties.SECURITY_LEVEL_STRONGBOX`. */
    const val STRONGBOX = 2

    /**
     * API 31+: the KeyInfo security level must be STRONGBOX or
     * TRUSTED_ENVIRONMENT (SOFTWARE, UNKNOWN and UNKNOWN_SECURE are refused);
     * below 31: `isInsideSecureHardware`, StrongBox when it was requested and
     * the generation succeeded with it. Null = "non protégée par le matériel".
     */
    fun of(sdk: Int, securityLevel: Int?, insideSecureHardware: Boolean, strongBoxRequested: Boolean): DeviceKeyLevel? =
        if (sdk >= 31) {
            when (securityLevel) {
                STRONGBOX -> DeviceKeyLevel.STRONGBOX
                TRUSTED_ENVIRONMENT -> DeviceKeyLevel.TEE
                else -> null
            }
        } else if (insideSecureHardware) {
            if (strongBoxRequested) DeviceKeyLevel.STRONGBOX else DeviceKeyLevel.TEE
        } else {
            null
        }
}
