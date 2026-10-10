package tools.obli.core.security

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** Keys indexed by (origin, server user id): never another account's key, never another origin's. */
class SessionDeviceKeysTest {
    private val prod = "https://obliance.example.com"
    private val qual = "https://qual.example.com"

    private fun record(origin: String, userId: Long, username: String, keyId: String, createdAt: Long = 1) =
        DeviceKeyRecord(origin, userId, username, keyId, DeviceKeyAlias.of(origin, userId, "i"), "i", DeviceKeyLevel.TEE, createdAt)

    @Test fun theKeyFollowsTheUserSignedInOnThatOrigin() = runBlocking {
        val store = InMemoryDeviceKeyStore()
        store.put(record(prod, 42, "john.smith", "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"))
        store.put(record(qual, 42, "john.smith", "0f8fad5b-d9cb-469f-a165-70867728950e"))
        val sessions = mutableMapOf<String, Long>(prod to 42)
        val keys = SessionDeviceKeys(store) { sessions[it] }
        assertEquals("6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", keys.headerFor(prod))
        assertNull(keys.headerFor(qual))                 // not signed in there
        sessions[qual] = 42
        assertEquals("0f8fad5b-d9cb-469f-a165-70867728950e", keys.headerFor(qual))
        sessions[prod] = 43                              // another account on prod
        assertNull(keys.keyFor(prod))
        assertNull(keys.headerFor("https://other.example.com"))
    }

    @Test fun storeSemantics() = runBlocking {
        val store = InMemoryDeviceKeyStore()
        val a = record(prod, 42, "john.smith", "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", createdAt = 1)
        store.put(a)
        val a2 = a.copy(keyId = "7c9e6679-7425-40de-944b-e07fc1f90ae7")
        store.put(a2)                                    // replaces (origin, user)
        assertEquals(listOf(a2), store.records.value)
        // Username lookup ignores case; with a re-created user of the same name, the newest.
        val b = record(prod, 57, "John.Smith", "0f8fad5b-d9cb-469f-a165-70867728950e", createdAt = 9)
        store.put(b)
        assertEquals(b, store.findByUsername(prod, " JOHN.SMITH "))
        assertNull(store.findByUsername(qual, "john.smith"))
        assertNull(store.findByUsername(prod, " "))
        assertEquals(a2, store.remove(prod, 42))
        assertNull(store.remove(prod, 42))
        assertEquals(listOf(b), store.records.value)
        // One install id per origin, stable.
        val id = store.installId(prod)
        assertEquals(id, store.installId(prod))
        assertNotEquals(id, store.installId(qual))
    }

    @Test fun recordsAreValidated() {
        assertThrows(IllegalArgumentException::class.java) { record(prod, 42, "u", "not-a-uuid") }
        assertThrows(IllegalArgumentException::class.java) { record(prod, 0, "u", "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f") }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceKeyRecord(prod, 42, "u", "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", "someone.else", "i", DeviceKeyLevel.TEE, 1)
        }
    }
}
