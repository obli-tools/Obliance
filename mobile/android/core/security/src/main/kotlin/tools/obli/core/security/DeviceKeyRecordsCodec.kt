package tools.obli.core.security

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import tools.obli.shell.core.Jsons
import tools.obli.shell.core.arr
import tools.obli.shell.core.obj
import tools.obli.shell.core.str
import tools.obli.shell.core.strictLong

/** What a [DeviceKeyStore] persists: the records and one install id per origin. */
data class DeviceKeyStoreState(
    val records: List<DeviceKeyRecord> = emptyList(),
    val installIds: Map<String, String> = emptyMap(),
)

/**
 * One JSON document for the device-key store (core:devicekey
 * `DataStoreDeviceKeyStore`): `{v:1, records:[…], installIds:{origin:id}}`.
 * Tolerant on read: an unreadable document is "nothing stored", an invalid
 * entry is dropped (its alias, if any, is then an orphan the reconciliation
 * deletes). Only ids and public facts are stored — never a secret.
 */
object DeviceKeyRecordsCodec {
    const val VERSION = 1L

    private val INSTALL_ID = Regex("^[0-9a-f]{32}$")

    fun encode(state: DeviceKeyStoreState): String = buildJsonObject {
        put("v", JsonPrimitive(VERSION))
        put(
            "records",
            JsonArray(
                state.records.map { r ->
                    buildJsonObject {
                        put("origin", JsonPrimitive(r.origin))
                        put("userId", JsonPrimitive(r.userId))
                        put("username", JsonPrimitive(r.username))
                        put("keyId", JsonPrimitive(r.keyId))
                        put("alias", JsonPrimitive(r.alias))
                        put("installId", JsonPrimitive(r.installId))
                        put("securityLevel", JsonPrimitive(r.securityLevel.wire))
                        put("createdAt", JsonPrimitive(r.createdAt))
                    }
                },
            ),
        )
        put("installIds", JsonObject(state.installIds.mapValues { JsonPrimitive(it.value) }))
    }.toString()

    fun decode(text: String?): DeviceKeyStoreState {
        val root = Jsons.parseObject(text) ?: return DeviceKeyStoreState()
        if (root.strictLong("v") != VERSION) return DeviceKeyStoreState()
        val records = root.arr("records").orEmpty().mapNotNull { (it as? JsonObject)?.let(::record) }
            // One record per (origin, user): the newest wins.
            .groupBy { it.origin to it.userId }.values.map { same -> same.maxBy { it.createdAt } }
        val installIds = root.obj("installIds")?.mapNotNull { (origin, id) ->
            val value = (id as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (DeviceProofPayload.isAsciiOrigin(origin) && value != null && INSTALL_ID.matches(value)) origin to value else null
        }?.toMap().orEmpty()
        return DeviceKeyStoreState(records, installIds)
    }

    private fun record(o: JsonObject): DeviceKeyRecord? = try {
        val origin = o.str("origin")?.takeIf(DeviceProofPayload::isAsciiOrigin) ?: return null
        val record = DeviceKeyRecord(
            origin = origin,
            userId = o.strictLong("userId") ?: return null,
            username = o.str("username") ?: return null,
            keyId = o.str("keyId") ?: return null,
            alias = o.str("alias") ?: return null,
            installId = o.str("installId")?.takeIf { INSTALL_ID.matches(it) } ?: return null,
            securityLevel = DeviceKeyLevel.of(o.str("securityLevel")) ?: return null,
            createdAt = o.strictLong("createdAt") ?: return null,
        )
        // The alias is a function of (origin, user, install): anything else is not ours.
        record.takeIf { it.alias == DeviceKeyAlias.of(it.origin, it.userId, it.installId) }
    } catch (_: IllegalArgumentException) {
        null // DeviceKeyRecord's own checks (user id, UUID, alias)
    }
}
