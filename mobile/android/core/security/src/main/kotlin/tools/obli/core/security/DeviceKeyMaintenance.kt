package tools.obli.core.security

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Aliases being enrolled (generated, not yet recorded): a reconciliation or a
 * purge never deletes them, so a key being enrolled is never taken for an
 * orphan. Process-wide, like the Keystore itself.
 */
object DeviceKeyLocks {
    private val pending = mutableSetOf<String>()

    /** False when an enrolment of the same alias is already running. */
    fun reserve(alias: String): Boolean = synchronized(pending) { pending.add(alias) }

    fun release(alias: String) {
        synchronized(pending) { pending.remove(alias) }
    }

    fun isPending(alias: String): Boolean = synchronized(pending) { alias in pending }
}

/** What [DeviceKeyMaintenance.reconcile] did. */
data class ReconcileReport(
    /** `obli.devkey.v1.*` aliases without a record, deleted. */
    val orphanAliasesDeleted: Int,
    /** Records whose key was invalidated or lost, handed to the invalidation flow. */
    val deadRecords: List<DeviceKeyRecord>,
)

/**
 * Life of the keys on the phone (key
 * health, invalidation, sign-out, reconciliation). Pure
 * orchestration: the Keystore is [hardware], the server call and the session
 * end are the app's (paths and cookies are not core's business).
 *
 * A key that is invalidated (new biometric) or missing (screen lock removed:
 * the Keystore destroyed it) takes the SAME path: report to
 * the server (`POST …/device-keys/:id/invalidated`, best effort), delete the
 * record and the alias, then [endSession] — clear the origin's cookie and show
 * the sign-in-again screen — even when the report failed for lack of network.
 */
class DeviceKeyMaintenance(
    private val store: DeviceKeyStore,
    private val hardware: DeviceKeyHardware,
    /** `POST /api/profile/device-keys/:keyId/invalidated` on [origin] with the session (may throw: ignored). */
    private val reportInvalidated: suspend (origin: String, keyId: String) -> Unit,
    /** Clears the cookie of [origin] and shows the sign-in-again screen for that server (sign in again with password + code). */
    private val endSession: suspend (origin: String) -> Unit,
) {
    private val lock = Mutex()
    private val handling = Mutex()
    private val inFlight = mutableSetOf<String>()

    /**
     * At start-up (after the store is loaded): deletes the `obli.devkey.v1.*`
     * aliases that have no record, and sends the records whose key is dead
     * through [invalidated]. A key whose state is merely unavailable is kept.
     */
    suspend fun reconcile(): ReconcileReport {
        val (orphans, dead) = lock.withLock {
            val records = store.records.value
            val known = records.map { it.alias }.toSet()
            val orphans = hardware.aliases().filter { DeviceKeyAlias.isOurs(it) && it !in known && !DeviceKeyLocks.isPending(it) }
            orphans.forEach { runCatching { hardware.delete(it) } }
            orphans.size to records.filter { hardware.health(it.alias).isDead }
        }
        dead.forEach { invalidated(it) }
        return ReconcileReport(orphans, dead)
    }

    /**
     * On return to the foreground (active server) and before a signature:
     * the record's key health; a dead key goes through [invalidated].
     */
    suspend fun check(record: DeviceKeyRecord): KeyHealth {
        val health = hardware.health(record.alias)
        if (health.isDead) invalidated(record)
        return health
    }

    /** [check] for the key of [origin] as [keys] resolves it (the session user's), if any. */
    suspend fun checkOrigin(keys: DeviceKeyResolver, origin: String): KeyHealth? {
        val record = keys.keyFor(origin) ?: return null
        return check(record)
    }

    /**
     * Invalidation for [record]: report (best effort), purge the record
     * and the alias, then [endSession]. Runs once per key even when the health
     * check and a signature find it dead at the same time.
     */
    suspend fun invalidated(record: DeviceKeyRecord) {
        if (!claim(record.keyId)) return
        try {
            // Already handled (the record is gone): no second report, no second sign-in-again screen.
            if (store.records.value.none { it.origin == record.origin && it.keyId == record.keyId }) return
            try {
                reportInvalidated(record.origin, record.keyId)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // No network: the server key stays listed until revoked by hand or stale;
                // nobody can sign with it any more.
            }
            purge(record)
            endSession(record.origin)
        } finally {
            release(record.keyId)
        }
    }

    /**
     * [ActionPrompter.deviceKeyInvalidated] (a signature found the key dead):
     * [invalidated] for the record of [keyId] on [origin]. False when there is
     * none (already handled).
     */
    suspend fun invalidated(origin: String, keyId: String): Boolean {
        val record = store.records.value.firstOrNull { it.origin == origin && it.keyId == keyId } ?: return false
        invalidated(record)
        return true
    }

    /**
     * `401 {deviceKeyStatus:'revoked'}` (ObliHttp's `onDeviceKeyRevoked`): the
     * server revoked [keyId] and destroyed the session. Purges the local key
     * ONLY when it is the one [keyId] names on [origin] — the key the request
     * carried, i.e. the key of the session's user. True when purged.
     */
    suspend fun revoked(origin: String, keyId: String?): Boolean {
        if (keyId == null) return false
        val record = store.records.value.firstOrNull { it.origin == origin && it.keyId == keyId } ?: return false
        purge(record)
        return true
    }

    /**
     * After `POST /api/auth/logout` (sent WITH the header, which
     * revokes the key server side) or offline anyway — forget the key of
     * (origin, user). Returns the purged record.
     */
    suspend fun forget(origin: String, userId: Long): DeviceKeyRecord? {
        val record = store.find(origin, userId) ?: return null
        purge(record)
        return record
    }

    private suspend fun purge(record: DeviceKeyRecord) {
        lock.withLock {
            // Only this key's record: a newer enrolment of the same (origin, user) is kept.
            if (store.find(record.origin, record.userId)?.keyId == record.keyId) store.remove(record.origin, record.userId)
            if (store.records.value.none { it.alias == record.alias } && !DeviceKeyLocks.isPending(record.alias)) {
                runCatching { hardware.delete(record.alias) }
            }
        }
    }

    private suspend fun claim(keyId: String): Boolean = handling.withLock { inFlight.add(keyId) }

    private suspend fun release(keyId: String) = handling.withLock { inFlight.remove(keyId) }
}
