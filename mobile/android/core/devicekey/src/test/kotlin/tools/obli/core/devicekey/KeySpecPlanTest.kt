package tools.obli.core.devicekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.security.DeviceKeyLevel

/** The Keystore parameters per API level: 26, 28, 30, 35, with and without StrongBox. */
class KeySpecPlanTest {
    private fun assertCommon(p: KeySpecPlan) {
        assertEquals("secp256r1", p.curve)
        assertEquals("SHA-256", p.digest)
        assertTrue(p.signOnly)
        assertTrue(p.userAuthenticationRequired)
        assertTrue(p.invalidatedByBiometricEnrollment)
        assertTrue(p.attestationChallenge)
        // Always excluded.
        assertFalse(p.devicePropertiesAttestation)
        assertFalse(p.protectedConfirmation)
        assertFalse(p.attestKeyAlias)
    }

    @Test fun api26And27FingerprintPerUseNoStrongBoxNoUnlockFlag() {
        for (sdk in listOf(26, 27)) {
            for (strongBox in listOf(false, true)) {
                val p = KeySpecPlan.forSdk(sdk, strongBox)
                assertCommon(p)
                assertEquals(PerUseAuth.VALIDITY_MINUS_ONE, p.perUseAuth)
                assertFalse("no StrongBox before API 28", p.strongBox)
                assertFalse(p.unlockedDeviceRequired)
            }
        }
    }

    @Test fun api28And29() {
        for (sdk in listOf(28, 29)) {
            val tee = KeySpecPlan.forSdk(sdk, hasStrongBox = false)
            assertCommon(tee)
            assertEquals(PerUseAuth.VALIDITY_MINUS_ONE, tee.perUseAuth)
            assertFalse(tee.strongBox)
            assertTrue(tee.unlockedDeviceRequired)
            val sb = KeySpecPlan.forSdk(sdk, hasStrongBox = true)
            assertTrue(sb.strongBox)
            assertTrue(sb.unlockedDeviceRequired)
            assertEquals(tee, sb.withoutStrongBox())
        }
    }

    @Test fun api30AndLaterBiometricStrongEveryUse() {
        for (sdk in listOf(30, 31, 33, 35, 36, 37)) {
            for (strongBox in listOf(false, true)) {
                val p = KeySpecPlan.forSdk(sdk, strongBox)
                assertCommon(p)
                assertEquals(PerUseAuth.BIOMETRIC_STRONG_EVERY_USE, p.perUseAuth)
                assertEquals(strongBox, p.strongBox)
                assertTrue(p.unlockedDeviceRequired)
                // The TEE retry changes nothing else.
                assertEquals(p.copy(strongBox = false), p.withoutStrongBox())
            }
        }
    }

    @Test fun belowTheMinimumIsRefused() {
        assertThrows(IllegalArgumentException::class.java) { KeySpecPlan.forSdk(25, false) }
    }

    @Test fun localLevel() {
        // API 31+: KeyInfo.securityLevel.
        assertEquals(DeviceKeyLevel.STRONGBOX, LocalKeyLevel.of(35, LocalKeyLevel.STRONGBOX, insideSecureHardware = false, strongBoxRequested = true))
        assertEquals(DeviceKeyLevel.TEE, LocalKeyLevel.of(35, LocalKeyLevel.TRUSTED_ENVIRONMENT, false, strongBoxRequested = true))
        for (level in listOf(0, -1, -2, 3, null)) assertNull(LocalKeyLevel.of(31, level, insideSecureHardware = true, strongBoxRequested = false))
        // Below 31: isInsideSecureHardware (StrongBox when it was requested and granted).
        assertEquals(DeviceKeyLevel.STRONGBOX, LocalKeyLevel.of(30, null, insideSecureHardware = true, strongBoxRequested = true))
        assertEquals(DeviceKeyLevel.TEE, LocalKeyLevel.of(28, null, insideSecureHardware = true, strongBoxRequested = false))
        assertEquals(DeviceKeyLevel.TEE, LocalKeyLevel.of(26, null, insideSecureHardware = true, strongBoxRequested = false))
        assertNull(LocalKeyLevel.of(29, null, insideSecureHardware = false, strongBoxRequested = true))
    }
}
