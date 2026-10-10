package tools.obli.core.security

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A Keystore stand-in: aliases with a state, software EC keys. */
internal class FakeHardware : DeviceKeyHardware {
    val keys = mutableMapOf<String, KeyHealth>()
    val deleted = mutableListOf<String>()
    private val pairs = mutableMapOf<String, java.security.KeyPair>()

    override suspend fun generate(alias: String, attestationChallenge: ByteArray): GeneratedKey {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        pairs[alias] = kp
        keys[alias] = KeyHealth.Healthy
        return GeneratedKey(kp.public.encoded, listOf(byteArrayOf(1)), DeviceKeyLevel.TEE)
    }

    override fun delete(alias: String) {
        deleted += alias
        keys.remove(alias)
        pairs.remove(alias)
    }

    override fun health(alias: String): KeyHealth = keys[alias] ?: KeyHealth.Missing

    override fun openSignature(alias: String): OpenedSignature = when (val h = health(alias)) {
        KeyHealth.Healthy -> OpenedSignature.Ready(Signature.getInstance("SHA256withECDSA").apply { initSign(pairs.getValue(alias).private) })
        else -> OpenedSignature.Failed(h)
    }

    override fun aliases(): Set<String> = keys.keys.toSet()
}

/** Health, reconciliation, invalidation, revocation and sign-out purges. */
class DeviceKeyMaintenanceTest {
    private val prod = "https://obliance.example.com"
    private val qual = "https://qual.example.com"
    private val install = "0123456789abcdef0123456789abcdef"

    private fun record(origin: String, userId: Long, keyId: String) =
        DeviceKeyRecord(origin, userId, "john.smith", keyId, DeviceKeyAlias.of(origin, userId, install), install, DeviceKeyLevel.STRONGBOX, 1)

    private val a = record(prod, 42, "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f")
    private val b = record(qual, 42, "0f8fad5b-d9cb-469f-a165-70867728950e")

    private class Setup(val store: InMemoryDeviceKeyStore, val hw: FakeHardware, val m: DeviceKeyMaintenance, val log: MutableList<String>)

    private fun setup(vararg records: DeviceKeyRecord, reportFails: Boolean = false): Setup {
        val store = InMemoryDeviceKeyStore(records.toList())
        val hw = FakeHardware()
        records.forEach { hw.keys[it.alias] = KeyHealth.Healthy }
        val log = mutableListOf<String>()
        val m = DeviceKeyMaintenance(
            store,
            hw,
            reportInvalidated = { origin, keyId ->
                log += "report:$origin:$keyId"
                if (reportFails) throw java.io.IOException("offline")
            },
            endSession = { origin -> log += "end:$origin" },
        )
        return Setup(store, hw, m, log)
    }

    @Test fun reconcileDeletesOrphansAndSendsDeadKeysThroughTheInvalidationFlow() = runBlocking {
        val s = setup(a, b)
        val orphan = DeviceKeyAlias.of(prod, 57, install)
        s.hw.keys[orphan] = KeyHealth.Healthy               // alias without a record
        s.hw.keys["someone.elses.alias"] = KeyHealth.Healthy // not ours: never touched
        s.hw.keys.remove(b.alias)                           // screen lock removed: the key is gone
        val report = s.m.reconcile()
        assertEquals(1, report.orphanAliasesDeleted)
        assertEquals(listOf(b), report.deadRecords)
        assertTrue(orphan in s.hw.deleted)
        assertFalse("someone.elses.alias" in s.hw.deleted)
        assertEquals(listOf(a), s.store.records.value)
        // Same effect as an invalidation: reported, then the session ends (cookie + sign-in-again screen).
        assertEquals(listOf("report:$qual:${b.keyId}", "end:$qual"), s.log)
    }

    @Test fun anAliasBeingEnrolledIsNeverAnOrphan() = runBlocking {
        val s = setup()
        val enrolling = DeviceKeyAlias.of(prod, 42, install)
        s.hw.keys[enrolling] = KeyHealth.Healthy
        assertTrue(DeviceKeyLocks.reserve(enrolling))
        try {
            assertEquals(0, s.m.reconcile().orphanAliasesDeleted)
            assertFalse(DeviceKeyLocks.reserve(enrolling))  // a second enrolment of the same key waits
        } finally {
            DeviceKeyLocks.release(enrolling)
        }
        assertEquals(1, s.m.reconcile().orphanAliasesDeleted)
    }

    @Test fun anInvalidatedKeyIsReportedPurgedAndTheSessionEndsEvenOffline() = runBlocking {
        val s = setup(a, reportFails = true)
        s.hw.keys[a.alias] = KeyHealth.Invalidated
        assertEquals(KeyHealth.Invalidated, s.m.check(a))
        assertNull(s.store.find(prod, 42))
        assertTrue(a.alias in s.hw.deleted)
        assertEquals(listOf("report:$prod:${a.keyId}", "end:$prod"), s.log)
        // Handled once: a second signal (the signer found it dead too) does nothing.
        s.m.check(a)
        assertFalse(s.m.invalidated(prod, a.keyId))
        assertEquals(2, s.log.size)
    }

    @Test fun anUnavailableKeyIsKept() = runBlocking {
        val s = setup(a)
        s.hw.keys[a.alias] = KeyHealth.Unavailable("KeyStoreException")
        assertEquals(KeyHealth.Unavailable("KeyStoreException"), s.m.check(a))
        assertEquals(listOf(a), s.store.records.value)
        assertEquals(0, s.m.reconcile().deadRecords.size)
        assertTrue(s.log.isEmpty())
        assertEquals(KeyHealth.Healthy, setup(a).m.check(a))
    }

    @Test fun checkOriginUsesTheSessionUsersKey() = runBlocking {
        val s = setup(a)
        s.hw.keys[a.alias] = KeyHealth.Invalidated
        val otherUser = DeviceKeyResolver { origin -> s.store.find(origin, 43) }
        assertNull(s.m.checkOrigin(otherUser, prod))
        assertTrue(s.log.isEmpty())
        val sameUser = DeviceKeyResolver { origin -> s.store.find(origin, 42) }
        assertEquals(KeyHealth.Invalidated, s.m.checkOrigin(sameUser, prod))
        assertEquals("end:$prod", s.log.last())
    }

    @Test fun aRevocationPurgesOnlyTheKeyTheRequestCarried() = runBlocking {
        val s = setup(a, b)
        assertFalse(s.m.revoked(prod, null))
        assertFalse(s.m.revoked(prod, b.keyId))             // B's key id, on A: not A's key
        assertFalse(s.m.revoked(prod, "7c9e6679-7425-40de-944b-e07fc1f90ae7"))
        assertEquals(2, s.store.records.value.size)
        assertTrue(s.m.revoked(prod, a.keyId))
        assertEquals(listOf(b), s.store.records.value)
        assertEquals(listOf(a.alias), s.hw.deleted)
        assertTrue(s.log.isEmpty())                          // the server already revoked it: no report
    }

    @Test fun signOutForgetsTheKeyOfThatUserOnly() = runBlocking {
        val s = setup(a, b)
        assertEquals(a, s.m.forget(prod, 42))
        assertNull(s.m.forget(prod, 42))
        assertNull(s.m.forget(qual, 43))
        assertEquals(listOf(b), s.store.records.value)
        assertEquals(listOf(a.alias), s.hw.deleted)
    }

    @Test fun aNewerEnrolmentOfTheSameUserIsNotPurgedByAnOldSignal() = runBlocking {
        val s = setup(a)
        val newer = a.copy(keyId = "7c9e6679-7425-40de-944b-e07fc1f90ae7", createdAt = 2)
        s.store.put(newer)
        assertFalse(s.m.revoked(prod, a.keyId))              // the old key id is no longer recorded
        assertEquals(listOf(newer), s.store.records.value)
        assertTrue(s.hw.deleted.isEmpty())
    }
}
