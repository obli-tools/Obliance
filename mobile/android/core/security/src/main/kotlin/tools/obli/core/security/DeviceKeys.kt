package tools.obli.core.security

import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The phone's device-key records, one per (origin, server user id).
 * Reads are synchronous (an in-memory snapshot: the OkHttp interceptor calls
 * them on its threads); writes are suspending and persisted.
 */
interface DeviceKeyStore {
    val records: StateFlow<List<DeviceKeyRecord>>

    fun find(origin: String, userId: Long): DeviceKeyRecord? =
        records.value.firstOrNull { it.origin == origin && it.userId == userId }

    /**
     * The key whose remembered username matches [username] ignoring case (the
     * explicit header of the sign-in, before any session exists). With several
     * (a user deleted and re-created), the newest.
     */
    fun findByUsername(origin: String, username: String): DeviceKeyRecord? {
        val wanted = username.trim()
        if (wanted.isEmpty()) return null
        return records.value.filter { it.origin == origin && it.username.equals(wanted, ignoreCase = true) }.maxByOrNull { it.createdAt }
    }

    /** Adds [record], replacing the one of the same (origin, userId). */
    suspend fun put(record: DeviceKeyRecord)

    /** Removes the record of (origin, userId); returns it. */
    suspend fun remove(origin: String, userId: Long): DeviceKeyRecord?

    /** A random id of this installation for [origin] (created once, kept across keys): `installId` of enrol/begin. */
    suspend fun installId(origin: String): String
}

/** The key of (origin, user of the session signed in on that origin), or null. */
fun interface DeviceKeyResolver {
    fun keyFor(origin: String): DeviceKeyRecord?
}

/**
 * The link between the sessions and the store: the key of an origin
 * is the one of the user signed in THERE, never another account's. Serves the
 * [tools.obli.core.network.DeviceKeyHeaderInterceptor] ([headerFor]) and the
 * [ActionRunner] ([keyFor]).
 */
class SessionDeviceKeys(
    private val store: DeviceKeyStore,
    /** Server user id of the session signed in on the origin, null when none. */
    private val sessionUser: (origin: String) -> Long?,
) : DeviceKeyResolver {
    override fun keyFor(origin: String): DeviceKeyRecord? {
        val userId = sessionUser(origin) ?: return null
        return store.find(origin, userId)
    }

    /** For `ObliHttp.defaultClient(…, deviceKeyHeader = keys::headerFor)`. */
    fun headerFor(origin: String): String? = keyFor(origin)?.keyId
}

/** Signs a payload with a Keystore key after a BIOMETRIC_STRONG authentication. */
interface DeviceSigner {
    /** Checks the key's health, shows the biometric prompt bound to the key, signs [payload]. */
    suspend fun sign(record: DeviceKeyRecord, payload: ByteArray, prompt: SignPrompt): SignResult = signWith(record.alias, payload, prompt)

    /** Same by Keystore alias: the enrolment signs before any record exists. */
    suspend fun signWith(alias: String, payload: ByteArray, prompt: SignPrompt): SignResult
}

/** A freshly generated key: SPKI DER, attestation chain (leaf first, DER), local security level. */
class GeneratedKey(
    val spki: ByteArray,
    val chain: List<ByteArray>,
    /** Local reading only (KeyInfo): the server decides on the attestation. */
    val securityLevel: DeviceKeyLevel,
)

/** The key is not in secure hardware (KeyInfo): the alias is already deleted. */
class HardwareNotSecureException(message: String) : Exception(message)

/** Generates and deletes Keystore keys (implemented by core:devicekey `KeystoreDeviceKeys`). */
interface DeviceKeyGenerator {
    /** Generates a new key under [alias] (replacing any), with [attestationChallenge] = the enrolment nonce. */
    suspend fun generate(alias: String, attestationChallenge: ByteArray): GeneratedKey

    fun delete(alias: String)
}

/**
 * State of a Keystore key (`keyHealth`): `Signature.initSign` without
 * any authentication, which succeeds on a healthy per-use key.
 */
sealed interface KeyHealth {
    data object Healthy : KeyHealth

    /** `KeyPermanentlyInvalidatedException`: a biometric was added, or all were removed. */
    data object Invalidated : KeyHealth

    /** No such alias: the screen lock was removed (the Keystore destroyed the key), or a restored record. */
    data object Missing : KeyHealth

    /**
     * Anything else (Keystore busy, device locked, provider error): the key is
     * NOT declared dead for this — no signature now, the code is used.
     */
    data class Unavailable(val reason: String) : KeyHealth

    /** Invalidated or missing: the invalidation flow (report, purge, sign in again). */
    val isDead: Boolean get() = this == Invalidated || this == Missing
}

/** A signature ready for the biometric `CryptoObject` (`initSign` done), or why there is none. */
sealed interface OpenedSignature {
    class Ready(val signature: java.security.Signature) : OpenedSignature
    data class Failed(val health: KeyHealth) : OpenedSignature
}

/** The whole Keystore side of device keys (core:devicekey `KeystoreDeviceKeys`; fakes in tests). */
interface DeviceKeyHardware : DeviceKeyGenerator {
    fun health(alias: String): KeyHealth

    /** `Signature("SHA256withECDSA").initSign(key)` for the prompt's CryptoObject (the health check before each signature). */
    fun openSignature(alias: String): OpenedSignature

    /** Every Keystore alias of this app's device keys (`obli.devkey.v1.*`). */
    fun aliases(): Set<String>
}

/** An in-memory [DeviceKeyStore] (tests, previews). */
class InMemoryDeviceKeyStore(
    initial: List<DeviceKeyRecord> = emptyList(),
    private val newInstallId: () -> String = ::randomInstallId,
) : DeviceKeyStore {
    private val state = MutableStateFlow(initial)
    private val installIds = mutableMapOf<String, String>()
    private val mutex = Mutex()

    override val records: StateFlow<List<DeviceKeyRecord>> = state.asStateFlow()

    override suspend fun put(record: DeviceKeyRecord) {
        state.update { list -> list.filterNot { it.origin == record.origin && it.userId == record.userId } + record }
    }

    override suspend fun remove(origin: String, userId: Long): DeviceKeyRecord? {
        var removed: DeviceKeyRecord? = null
        state.update { list ->
            removed = list.firstOrNull { it.origin == origin && it.userId == userId }
            list.filterNot { it.origin == origin && it.userId == userId }
        }
        return removed
    }

    override suspend fun installId(origin: String): String = mutex.withLock { installIds.getOrPut(origin, newInstallId) }
}

/** 32 hex characters from [SecureRandom] (the server column holds 64). */
fun randomInstallId(): String {
    val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
    return bytes.joinToString("") { "%02x".format(it) }
}
