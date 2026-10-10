package tools.obli.core.devicekey

/** How "a biometric at EVERY use" is expressed to the Keystore. */
enum class PerUseAuth {
    /**
     * API 26–29: `setUserAuthenticationValidityDurationSeconds(-1)`, i.e. an
     * authentication per operation, through a `CryptoObject` — fingerprint only
     * (attested `userAuthType` = fingerprint, no password bit).
     */
    VALIDITY_MINUS_ONE,

    /** API 30+: `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` (timeout 0 = every use, never the device credential). */
    BIOMETRIC_STRONG_EVERY_USE,
}

/**
 * The Keystore parameters of a device key for one API level, as data:
 * `KeystoreDeviceKeys` applies it, and it is tested on the JVM (Robolectric
 * has no AndroidKeyStore). The server checks the attested result:
 * EC P-256, SIGN, generated, user authentication on every use with the
 * biometric bit only, hardware level, `attestationChallenge` = the enrolment
 * nonce. Never included: device properties (IMEI, serial) in the attestation,
 * Android Protected Confirmation, an attest-key alias.
 */
data class KeySpecPlan(
    val sdk: Int,
    val perUseAuth: PerUseAuth,
    /** `setIsStrongBoxBacked(true)`; on StrongBoxUnavailableException or ANY ProviderException, retried without (TEE). */
    val strongBox: Boolean,
    /** `setUnlockedDeviceRequired(true)` (API 28+): nothing signs before the phone is unlocked. */
    val unlockedDeviceRequired: Boolean,
) {
    /** `secp256r1` (P-256). */
    val curve: String get() = CURVE

    /** `KeyProperties.DIGEST_SHA256`. */
    val digest: String get() = DIGEST

    /** `KeyProperties.PURPOSE_SIGN` only. */
    val signOnly: Boolean get() = true
    val userAuthenticationRequired: Boolean get() = true

    /** The key dies when a biometric is enrolled (or all are removed). */
    val invalidatedByBiometricEnrollment: Boolean get() = true

    /** `setAttestationChallenge(ticket nonce)`: always. */
    val attestationChallenge: Boolean get() = true

    /** `setDevicePropertiesAttestationIncluded(true)` would expose the IMEI and the serial: never. */
    val devicePropertiesAttestation: Boolean get() = false

    /** Android Protected Confirmation: never. */
    val protectedConfirmation: Boolean get() = false

    /** `setAttestKeyAlias`: never. */
    val attestKeyAlias: Boolean get() = false

    /** The TEE retry after a StrongBox failure. */
    fun withoutStrongBox(): KeySpecPlan = copy(strongBox = false)

    companion object {
        const val MIN_SDK = 26
        const val CURVE = "secp256r1"
        const val DIGEST = "SHA-256"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /** @param hasStrongBox `PackageManager.FEATURE_STRONGBOX_KEYSTORE` (API 28+). */
        fun forSdk(sdk: Int, hasStrongBox: Boolean): KeySpecPlan {
            require(sdk >= MIN_SDK) { "API $sdk is below the minimum ($MIN_SDK)" }
            return KeySpecPlan(
                sdk = sdk,
                perUseAuth = if (sdk >= 30) PerUseAuth.BIOMETRIC_STRONG_EVERY_USE else PerUseAuth.VALIDITY_MINUS_ONE,
                // API 26–27: no StrongBox at all.
                strongBox = sdk >= 28 && hasStrongBox,
                unlockedDeviceRequired = sdk >= 28,
            )
        }
    }
}
