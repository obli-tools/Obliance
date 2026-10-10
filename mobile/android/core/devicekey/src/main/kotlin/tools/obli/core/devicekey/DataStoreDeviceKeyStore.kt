package tools.obli.core.devicekey

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import tools.obli.core.security.DeviceKeyRecord
import tools.obli.core.security.DeviceKeyRecordsCodec
import tools.obli.core.security.DeviceKeyStore
import tools.obli.core.security.DeviceKeyStoreState
import tools.obli.core.security.randomInstallId

private val Context.obliDeviceKeys: DataStore<Preferences> by preferencesDataStore(name = "obli_device_keys")

/**
 * The phone's device-key records, one per (server origin, server
 * user id), persisted as ONE JSON document in DataStore (the app has
 * allowBackup=false: it never leaves the phone; a record without its Keystore
 * alias is found by the reconciliation anyway). Only ids and public facts are
 * stored, never a secret.
 *
 * [records] is an in-memory snapshot read synchronously by the OkHttp
 * interceptor: empty until [load] ran, i.e. no header and no signature — the
 * server then asks for the code, never a weaker path. Writes load first.
 */
class DataStoreDeviceKeyStore internal constructor(
    private val store: DataStore<Preferences>,
    private val newInstallId: () -> String,
) : DeviceKeyStore {
    constructor(context: Context) : this(context.applicationContext.obliDeviceKeys, ::randomInstallId)

    private val mutex = Mutex()
    private val state = MutableStateFlow(DeviceKeyStoreState())
    private val recordsFlow = MutableStateFlow<List<DeviceKeyRecord>>(emptyList())
    private val _loaded = MutableStateFlow(false)

    override val records: StateFlow<List<DeviceKeyRecord>> = recordsFlow.asStateFlow()

    /** True once the stored document was read (start-up: load, then reconcile). */
    val loaded: StateFlow<Boolean> = _loaded.asStateFlow()

    /** Reads the stored records once; later calls do nothing. */
    suspend fun load() {
        mutex.withLock { ensureLoaded() }
    }

    override suspend fun put(record: DeviceKeyRecord) {
        mutex.withLock {
            ensureLoaded()
            val next = state.value.copy(
                records = state.value.records.filterNot { it.origin == record.origin && it.userId == record.userId } + record,
            )
            // Stored first, then published: the header never names a key the disk does not know.
            persist(next)
            publish(next)
        }
    }

    override suspend fun remove(origin: String, userId: Long): DeviceKeyRecord? = mutex.withLock {
        ensureLoaded()
        val removed = state.value.records.firstOrNull { it.origin == origin && it.userId == userId } ?: return@withLock null
        val next = state.value.copy(records = state.value.records - removed)
        // Published first: the key stops being used at once, even if the write fails.
        publish(next)
        persist(next)
        removed
    }

    override suspend fun installId(origin: String): String = mutex.withLock {
        ensureLoaded()
        state.value.installIds[origin]?.let { return@withLock it }
        val id = newInstallId()
        val next = state.value.copy(installIds = state.value.installIds + (origin to id))
        persist(next)
        publish(next)
        id
    }

    private suspend fun ensureLoaded() {
        if (_loaded.value) return
        val text = try {
            store.data.first()[KEY]
        } catch (_: java.io.IOException) {
            null // unreadable: nothing stored (the reconciliation deletes the orphan aliases)
        }
        publish(DeviceKeyRecordsCodec.decode(text))
        _loaded.value = true
    }

    private suspend fun persist(next: DeviceKeyStoreState) {
        val text = DeviceKeyRecordsCodec.encode(next)
        store.edit { it[KEY] = text }
    }

    private fun publish(next: DeviceKeyStoreState) {
        state.value = next
        recordsFlow.value = next.records
    }

    private companion object {
        val KEY = stringPreferencesKey("device_keys_v1")
    }
}
