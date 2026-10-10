package tools.obli.core.devicekey

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.security.DeviceKeyAlias
import tools.obli.core.security.DeviceKeyLevel
import tools.obli.core.security.DeviceKeyRecord

/**
 * The persisted records per (origin, user) and install ids per origin. The
 * DataStore is an in-memory one that outlives the store objects (a "restart"
 * is a new store over the same data): the JVM file storage of DataStore
 * cannot replace its file on a Windows build host, and the file I/O is
 * DataStore's own business anyway.
 */
class DataStoreDeviceKeyStoreTest {
    private class MemoryDataStore(initial: Preferences = emptyPreferences()) : DataStore<Preferences> {
        private val state = MutableStateFlow(initial)
        private val mutex = Mutex()
        override val data: Flow<Preferences> = state
        override suspend fun updateData(transform: suspend (Preferences) -> Preferences): Preferences =
            mutex.withLock { transform(state.value).also { state.value = it } }
    }

    private val prod = "https://obliance.example.com"
    private val qual = "https://qual.example.com"
    private var ids = 0
    private val disk = MemoryDataStore()

    /** A new store over the same data (an app restart). */
    private fun open(): Pair<DataStoreDeviceKeyStore, DataStore<Preferences>> =
        DataStoreDeviceKeyStore(disk) { "%032x".format(++ids) } to disk

    private fun record(origin: String, userId: Long, keyId: String, install: String) =
        DeviceKeyRecord(origin, userId, "john.smith", keyId, DeviceKeyAlias.of(origin, userId, install), install, DeviceKeyLevel.STRONGBOX, 1_790_000_000_000)

    @Test fun recordsAndInstallIdsSurviveARestart() = runBlocking {
        val (store, _) = open()
        assertFalse(store.loaded.value)
        assertTrue(store.records.value.isEmpty())             // nothing before load: no header, the code is used
        val install = store.installId(prod)
        assertEquals(install, store.installId(prod))
        assertNotEquals(install, store.installId(qual))
        val a = record(prod, 42, "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", install)
        store.put(a)
        assertEquals(listOf(a), store.records.value)
        assertTrue(store.loaded.value)

        val (again, _) = open()
        assertTrue(again.records.value.isEmpty())
        again.load()
        assertEquals(listOf(a), again.records.value)
        assertEquals(a, again.find(prod, 42))
        assertEquals(a, again.findByUsername(prod, "JOHN.SMITH"))
        assertEquals(install, again.installId(prod))          // kept across restarts
    }

    @Test fun putReplacesTheKeyOfTheSameUserAndRemoveReturnsIt() = runBlocking {
        val (store, _) = open()
        store.load()
        val install = store.installId(prod)
        val a = record(prod, 42, "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", install)
        val b = record(prod, 57, "0f8fad5b-d9cb-469f-a165-70867728950e", install)
        store.put(a)
        store.put(b)
        val a2 = a.copy(keyId = "7c9e6679-7425-40de-944b-e07fc1f90ae7")
        store.put(a2)
        assertEquals(setOf(a2, b), store.records.value.toSet())
        assertEquals(a2, store.remove(prod, 42))
        assertNull(store.remove(prod, 42))
        val (again, _) = open()
        again.load()
        assertEquals(listOf(b), again.records.value)
    }

    @Test fun aWriteBeforeLoadKeepsWhatWasStored() = runBlocking {
        val (store, _) = open()
        val install = store.installId(prod)
        val a = record(prod, 42, "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", install)
        store.put(a)
        val (again, _) = open()
        // No explicit load: the put loads first, and does not overwrite A.
        val b = record(qual, 42, "0f8fad5b-d9cb-469f-a165-70867728950e", again.installId(qual))
        again.put(b)
        assertEquals(setOf(a, b), again.records.value.toSet())
    }

    @Test fun anUnreadableDocumentIsNothingStored() = runBlocking {
        val (_, ds) = open()
        ds.edit { it[stringPreferencesKey("device_keys_v1")] = "{corrupted" }
        val (store, _) = open()
        store.load()
        assertTrue(store.records.value.isEmpty())
        assertTrue(store.loaded.value)
    }

    @Test fun anUnreadableFileIsNothingStored() = runBlocking {
        val failing = object : DataStore<Preferences> {
            override val data: Flow<Preferences> = flow { throw IOException("corrupted file") }
            override suspend fun updateData(transform: suspend (Preferences) -> Preferences): Preferences = transform(emptyPreferences())
        }
        val store = DataStoreDeviceKeyStore(failing) { "%032x".format(++ids) }
        store.load()
        assertTrue(store.records.value.isEmpty())
        assertTrue(store.loaded.value)
    }
}
