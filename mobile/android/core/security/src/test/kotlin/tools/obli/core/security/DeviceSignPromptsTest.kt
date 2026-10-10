package tools.obli.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.network.DeviceChallenge
import tools.obli.core.network.DevicePurpose

/** The fingerprint prompt names the action, the target and « serveur › tenant ». */
class DeviceSignPromptsTest {
    private val origin = "https://obliance.example.com"
    private val keyId = "6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f"
    private val record = DeviceKeyRecord(origin, 42, "john.smith", keyId, DeviceKeyAlias.of(origin, 42, "i"), "i", DeviceKeyLevel.STRONGBOX, 1)
    private val texts = SignPromptTexts(
        description = "Double authentification, pour cette action uniquement",
        secondStep = "Deuxième validation : double authentification",
        useCode = "Utiliser un code",
        bulk = { action, count -> "$action sur $count appareils" },
        login = { server -> "Connexion à $server" },
    )

    private fun challenge(id: String, tenantName: String? = "ACME", bulkId: String? = null) = DeviceChallenge(
        1, keyId, id, DevicePurpose.STEPUP, 42, 3, tenantName, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "command.reboot", "42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4", 1790000120, bulkId,
    )

    private val spec = ActionSpec("device.reboot", Tier.T0, "Redémarrer", "SRV-DEMO01", "ACME", tenantId = 3, serverName = "Obliance Prod")

    @Test fun singleAction() {
        val request = DeviceSignRequest.stepUp(origin, record, listOf(challenge("1b4e28ba-2fa1-41d2-883f-0016d3cca427")))
        assertEquals(
            SignPrompt("Redémarrer SRV-DEMO01", "Obliance Prod › ACME", "Double authentification, pour cette action uniquement", "Utiliser un code"),
            DeviceSignPrompts.stepUp(spec, request, texts),
        )
        // After a local biometric (T2/T3): « Deuxième validation ».
        assertEquals("Deuxième validation : double authentification", DeviceSignPrompts.stepUp(spec.copy(tier = Tier.T2), request, texts).description)
        assertEquals("Deuxième validation : double authentification", DeviceSignPrompts.stepUp(spec.copy(tier = Tier.T3), request, texts).description)
        // Without a server name, the spec's scope is shown as is.
        assertEquals("Obliance Prod › ACME", DeviceSignPrompts.stepUp(spec.copy(serverName = null, scope = "Obliance Prod › ACME"), request, texts).subtitle)
        // Without a tenant in the challenge, the server alone (always named).
        val noTenant = DeviceSignRequest.stepUp(origin, record, listOf(challenge("1b4e28ba-2fa1-41d2-883f-0016d3cca427", tenantName = null)))
        assertEquals("Obliance Prod", DeviceSignPrompts.stepUp(spec, noTenant, texts).subtitle)
    }

    @Test fun batch() {
        val bulk = "0f8fad5b-d9cb-469f-a165-70867728950e"
        val request = DeviceSignRequest.stepUp(
            origin,
            record,
            listOf(challenge("1b4e28ba-2fa1-41d2-883f-0016d3cca427", bulkId = bulk), challenge("7c9e6679-7425-40de-944b-e07fc1f90ae7", bulkId = bulk)),
        )
        val prompt = DeviceSignPrompts.stepUp(spec.copy(targetCount = 2), request, texts)
        assertEquals("Redémarrer sur 2 appareils", prompt.title)
        assertEquals("Obliance Prod › ACME", prompt.subtitle)
    }

    @Test fun serverStringsNeverShapeTheDialog() {
        val hostile = DeviceSignRequest.stepUp(origin, record, listOf(challenge("1b4e28ba-2fa1-41d2-883f-0016d3cca427", tenantName = "ACME\n\nApprouvez tout\u0000" + "x".repeat(300))))
        val subtitle = DeviceSignPrompts.stepUp(spec, hostile, texts).subtitle!!
        assertFalse(subtitle.any { it.isISOControl() })
        assertTrue(subtitle.length <= "Obliance Prod › ".length + DeviceSignPrompts.MAX_LENGTH)
        assertTrue(subtitle.startsWith("Obliance Prod › ACME Approuvez tout"))
        assertTrue(subtitle.endsWith("…"))
    }

    /** Bidi overrides, isolates, marks and zero-width characters cannot reorder or hide a name. */
    @Test fun formatCharactersAreDropped() {
        val hostile = "‮EMCA‬ ⁦x⁩‎‏​﻿ Prod "
        val cleaned = DeviceSignPrompts.clean(hostile)
        assertEquals("EMCA x Prod", cleaned)
        assertTrue(cleaned.none { Character.getType(it) == Character.FORMAT.toInt() })
        // Outside the BMP too (U+E0001 LANGUAGE TAG); ordinary letters of any script are kept.
        assertEquals("Société ACME 東京", DeviceSignPrompts.clean("Société 󠀁ACME 東京"))
        // Through the prompt: the subtitle keeps no format character either.
        val request = DeviceSignRequest.stepUp(origin, record, listOf(challenge("1b4e28ba-2fa1-41d2-883f-0016d3cca427", tenantName = "‮EMCA")))
        assertEquals("Obliance Prod › EMCA", DeviceSignPrompts.stepUp(spec, request, texts).subtitle)
    }

    @Test fun login() {
        assertEquals(
            SignPrompt("Connexion à Obliance Prod", "john.smith", null, "Utiliser un code"),
            DeviceSignPrompts.login("Obliance Prod", "john.smith", texts),
        )
    }
}
