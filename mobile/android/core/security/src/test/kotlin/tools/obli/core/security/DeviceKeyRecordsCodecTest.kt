package tools.obli.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The stored document of the device-key store: round trip, tolerance, nothing secret. */
class DeviceKeyRecordsCodecTest {
    private val prod = "https://obliance.example.com"
    private val install = "0123456789abcdef0123456789abcdef"
    private val a = DeviceKeyRecord(prod, 42, "john.smith", "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f", DeviceKeyAlias.of(prod, 42, install), install, DeviceKeyLevel.STRONGBOX, 1_790_000_000_000)
    private val b = DeviceKeyRecord("https://qual.example.com:8443", 7, "admin", "0f8fad5b-d9cb-469f-a165-70867728950e", DeviceKeyAlias.of("https://qual.example.com:8443", 7, install), install, DeviceKeyLevel.TEE, 5)

    @Test fun roundTrip() {
        val state = DeviceKeyStoreState(listOf(a, b), mapOf(prod to install))
        val text = DeviceKeyRecordsCodec.encode(state)
        assertEquals(state, DeviceKeyRecordsCodec.decode(text))
        assertTrue(text.startsWith("{\"v\":1,"))
        assertEquals(DeviceKeyStoreState(), DeviceKeyRecordsCodec.decode(DeviceKeyRecordsCodec.encode(DeviceKeyStoreState())))
    }

    @Test fun unreadableDocumentsAreEmpty() {
        for (text in listOf(null, "", "not json", "[]", "{\"v\":2,\"records\":[]}", "{\"records\":[]}")) {
            assertEquals(DeviceKeyStoreState(), DeviceKeyRecordsCodec.decode(text))
        }
    }

    @Test fun invalidEntriesAreDropped() {
        val good = DeviceKeyRecordsCodec.encode(DeviceKeyStoreState(listOf(a)))
        fun with(from: String, to: String): List<DeviceKeyRecord> {
            val text = good.replace(from, to)
            check(text != good) { "not applied: $from" }
            return DeviceKeyRecordsCodec.decode(text).records
        }
        assertEquals(listOf(a), DeviceKeyRecordsCodec.decode(good).records)
        assertTrue(with("\"keyId\":\"6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f\"", "\"keyId\":\"x\"").isEmpty())
        assertTrue(with("\"userId\":42", "\"userId\":\"42\"").isEmpty())
        assertTrue(with("\"securityLevel\":\"strongbox\"", "\"securityLevel\":\"software\"").isEmpty())
        assertTrue(with("\"origin\":\"$prod\"", "\"origin\":\"https://Obliance.example.com\"").isEmpty())
        assertTrue(with("\"installId\":\"$install\"", "\"installId\":\"i\"").isEmpty())
        // An alias that is not the one of (origin, user, install): not ours.
        assertTrue(with("\"alias\":\"${a.alias}\"", "\"alias\":\"${DeviceKeyAlias.of(prod, 43, install)}\"").isEmpty())
    }

    @Test fun oneRecordPerOriginAndUserTheNewestWins() {
        val older = a.copy(keyId = "7c9e6679-7425-40de-944b-e07fc1f90ae7", createdAt = 1)
        val state = DeviceKeyRecordsCodec.decode(DeviceKeyRecordsCodec.encode(DeviceKeyStoreState(listOf(older, a))))
        assertEquals(listOf(a), state.records)
    }

    @Test fun installIdsAreValidated() {
        val text = """{"v":1,"records":[],"installIds":{"$prod":"$install","https://x.example.com":"short","bad origin":"$install"}}"""
        assertEquals(mapOf(prod to install), DeviceKeyRecordsCodec.decode(text).installIds)
    }

    @Test fun noSecretField() {
        val text = DeviceKeyRecordsCodec.encode(DeviceKeyStoreState(listOf(a)))
        for (word in listOf("password", "code", "signature", "nonce", "private")) assertFalse(word, text.contains(word, ignoreCase = true))
    }
}
