package tools.obli.core.designsystem

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.model.ServerColor

/** Every declared text/background pair ≥ 4.5:1. */
class ContrastTest {
    private fun assertAtLeast(min: Double, fg: Long, bg: Long, what: String) {
        val r = Contrast.ratio(fg, bg)
        assertTrue("$what: ${"%.2f".format(r)}:1 < $min:1", r >= min)
    }

    @Test fun referenceValues() {
        assertEquals(21.0, Contrast.ratio(0xFFFFFFFF, 0xFF000000), 0.01)
        assertEquals(1.0, Contrast.ratio(0xFF131728, 0xFF131728), 0.001)
    }

    @Test fun textOnSurfaces() {
        for ((name, t) in THEMES) {
            for ((sName, bg) in listOf("bg" to t.bg, "chrome" to t.chrome, "surface1" to t.surface1, "surface2" to t.surface2, "active" to t.active)) {
                assertAtLeast(4.5, t.text, bg, "$name text on $sName")
                assertAtLeast(4.5, t.text2, bg, "$name text2 on $sName")
                assertAtLeast(4.5, t.textMuted, bg, "$name textMuted on $sName")
            }
        }
    }

    @Test fun filledButtonsPassAAWithWhite() {
        assertAtLeast(4.5, ObliTokens.ON_FILL, ObliTokens.oblianceOperator.fill, "white on #C83232")
        assertAtLeast(4.5, ObliTokens.ON_FILL, ObliTokens.oblianceNight.fill, "white on night fill")
        val (_, dimAccent) = themeTokens(ObliThemeVariant.DIM, ObliTokens.oblianceOperator, ObliTokens.oblianceNight)
        assertAtLeast(4.5, ObliTokens.ON_FILL, dimAccent.fill, "dim white on fill")
        // The brand red is NOT a filled-button colour: it fails AA with white.
        assertTrue(Contrast.ratio(ObliTokens.ON_FILL, ObliTokens.oblianceOperator.brand) < 4.5)
    }

    @Test fun serverThemeAccents() {
        for ((name, accent, surfaces) in listOf(
            Triple("neon", ObliTokens.neonAccent, ObliTokens.neon), Triple("modern", ObliTokens.modernAccent, ObliTokens.modern),
        )) {
            assertAtLeast(4.5, ObliTokens.ON_FILL, accent.fill, "$name white on fill")
            assertAtLeast(4.5, accent.accent2, surfaces.chrome, "$name accent2 on chrome")
            assertAtLeast(4.5, accent.accent2, surfaces.surface1, "$name accent2 on surface1")
        }
    }

    @Test fun serverThemeMapping() {
        assertEquals(ObliThemeVariant.NEON, ObliThemeVariant.fromServerTheme("neon"))
        assertEquals(ObliThemeVariant.MODERN, ObliThemeVariant.fromServerTheme(" Modern "))
        assertEquals(ObliThemeVariant.DIM, ObliThemeVariant.fromServerTheme("obli-dim"))
        assertEquals(ObliThemeVariant.DIM, ObliThemeVariant.fromServerTheme(" Obli-Dim "))
        assertEquals(ObliThemeVariant.OPERATOR, ObliThemeVariant.fromServerTheme("obli-operator"))
        assertEquals(ObliThemeVariant.OPERATOR, ObliThemeVariant.fromServerTheme("obli-daylight"))
        assertEquals(ObliThemeVariant.OPERATOR, ObliThemeVariant.fromServerTheme(null))
        // A theme newer than this app (or garbage) never breaks it: Operator.
        assertEquals(ObliThemeVariant.OPERATOR, ObliThemeVariant.fromServerTheme("obli-some-future-theme"))
        assertEquals(ObliThemeVariant.OPERATOR, ObliThemeVariant.fromServerTheme(""))
    }

    @Test fun dimChangesNeutralsOnly() {
        // Absolute rule: Dim wears the accent the app injects for Operator, whatever the app.
        val otherApp = AccentTokens(brand = 0xFF2BC4BD, fill = 0xFF1F8F8A, fillPressed = 0xFF18706C, accent2 = 0xFF5FD9D3)
        for (accent in listOf(ObliTokens.oblianceOperator, otherApp)) {
            val (surfaces, worn) = themeTokens(ObliThemeVariant.DIM, accent, ObliTokens.oblianceNight)
            assertSame(accent, worn)
            assertSame(ObliTokens.dim, surfaces)
            assertSame(accent, themeTokens(ObliThemeVariant.OPERATOR, accent, ObliTokens.oblianceNight).second)
        }
        // The Polar Night neutrals of the web palette.
        with(ObliTokens.dim) {
            assertEquals(0xFF2E3440, bg)
            assertEquals(0xFF282D37, chrome)
            assertEquals(0xFF3B4252, surface1)
            assertEquals(0xFF4C566A, divider)
            assertEquals(0xFFECEFF4, text)
            assertEquals(0xFFD8DEE9, text2)
        }
    }

    @Test fun everyVariantIsDark() {
        // MainActivity keeps light system-bar icons (transparent bars over `chrome`) and
        // ObliTheme a dark Material scheme for every variant: each one, Dim included, is dark.
        for (v in ObliThemeVariant.entries) {
            val (s, _) = themeTokens(v, ObliTokens.oblianceOperator, ObliTokens.oblianceNight)
            for ((sName, surface) in listOf("bg" to s.bg, "chrome" to s.chrome, "surface1" to s.surface1)) {
                assertTrue("$v $sName is not dark", Contrast.luminance(surface) < 0.18)
                assertTrue("$v text darker than $sName", Contrast.luminance(s.text) > Contrast.luminance(surface))
            }
            assertAtLeast(4.5, 0xFFFFFFFF, s.chrome, "$v light system-bar icons on chrome")
        }
    }

    /**
     * Obli Dim, variant « B », same thresholds as the web (client
     * index.css `--c-accent-as-text`): accent-coloured TEXT takes Obliance's
     * lighter tint #FF6868 (its accent-hover), ≥ 3.5:1 on the cards and ≥
     * 4.4:1 on the page; fills, borders, rings and indicators keep the brand
     * red, and filled buttons keep #C83232 with white.
     */
    @Test fun dimAccentAsText() {
        val obliance = ObliTokens.oblianceOperator
        val surface2Dim = ObliTokens.dim.surface2
        val roles = accentRoles(ObliThemeVariant.DIM, obliance)
        assertEquals(0xFFFF6868, obliance.hover)
        assertEquals(obliance.hover, roles.text)
        assertEquals(obliance.brand, roles.line)
        with(ObliTokens.dim) {
            assertAtLeast(3.5, roles.text, surface1, "dim accent text on cards")
            assertAtLeast(4.4, roles.text, bg, "dim accent text on page")
            assertAtLeast(4.5, roles.text, chrome, "dim accent text on chrome (top bar, navigation)")
            assertAtLeast(3.0, roles.text, surface2, "dim accent text on inputs / pill containers")
            // Why: the brand red as text would be far below on the same cards (2.3:1).
            assertTrue(Contrast.ratio(obliance.brand, surface1) < 3.0)
        }
        // What the components read in Dim.
        val colors = ObliColors.of(ObliThemeVariant.DIM, obliance, ObliTokens.oblianceNight)
        assertEquals(obliance.hover.toColor(), colors.accentText)
        assertEquals(obliance.brand.toColor(), colors.accentLine)
        assertEquals(obliance.fill.toColor(), colors.accentFill)
        assertEquals(obliance.brand.toColor(), colors.brand)
        assertAtLeast(4.5, ObliTokens.ON_FILL, obliance.fill, "dim filled button label")
        // Known exception, the design rule shared with the web (« Fills, borders and rings keep the
        // brand red »): brand-red borders and focus rings are below 3:1 on the Dim inputs.
        assertTrue(Contrast.ratio(obliance.brand, surface2Dim) < 3.0)
    }

    /**
     * Accent text is also drawn on backgrounds that are not a plain surface:
     * the accent tints of tonal buttons, selected chips and the navigation
     * indicator (12–18 %), and the `active` snackbar. On Obli Dim the tints
     * are opaque (composited on the page colour) and the snackbar action is
     * the plain text colour, so every real pair holds the floor.
     */
    @Test fun dimAccentTextOnItsRealBackgrounds() {
        val obliance = ObliTokens.oblianceOperator
        val dim = ObliColors.of(ObliThemeVariant.DIM, obliance, ObliTokens.oblianceNight)
        for (alpha in listOf(0.12f, 0.14f, 0.18f)) {
            val tint = dim.accentTint(alpha)
            assertEquals("opaque $alpha tint", 1f, tint.alpha)
            // Opaque: the same pair on the page, the cards, the sheets and the chrome.
            assertAtLeast(3.5, argb(dim.accentText), argb(tint), "dim accent text on its $alpha tint")
            assertAtLeast(3.5, argb(dim.accentText), Contrast.blend(Contrast.withAlpha(obliance.brand, alpha.toDouble()), ObliTokens.dim.bg), "dim accent text on its $alpha tint (tokens)")
        }
        assertAtLeast(4.5, argb(dim.accentTextRaised), argb(dim.active), "dim snackbar action on active")
        assertEquals(dim.text, dim.accentTextRaised)
        // A glyph on a brand-red fill (checkbox tick): non-text, ≥ 3:1.
        assertAtLeast(3.0, argb(dim.onAccentLine), argb(dim.accentLine), "dim tick on the brand-red fill")
        // Why: a translucent brand tint over the cards, and #FF6868 on active, fall below.
        assertTrue(Contrast.ratio(obliance.hover, Contrast.blend(Contrast.withAlpha(obliance.brand, 0.12), ObliTokens.dim.surface1)) < 3.5)
        assertTrue(Contrast.ratio(obliance.hover, ObliTokens.dim.active) < 3.5)
    }

    @Test fun tintsRaisedTextAndTicksUnchangedOutsideDim() {
        for (v in ObliThemeVariant.entries.filter { it != ObliThemeVariant.DIM }) {
            val c = ObliColors.of(v, ObliTokens.oblianceOperator, ObliTokens.oblianceNight)
            assertFalse("$v", c.opaqueTints)
            for (alpha in listOf(0.12f, 0.14f, 0.18f)) assertEquals("$v tint $alpha", c.accentLine.copy(alpha = alpha), c.accentTint(alpha))
            assertEquals("$v raised", c.accentText, c.accentTextRaised)
            assertEquals("$v tick", c.bg, c.onAccentLine)
        }
    }

    private fun argb(c: Color): Long = c.toArgb().toLong() and 0xFFFFFFFFL

    @Test fun accentRolesUnchangedOutsideDim() {
        for (v in ObliThemeVariant.entries.filter { it != ObliThemeVariant.DIM }) {
            val (_, accent) = themeTokens(v, ObliTokens.oblianceOperator, ObliTokens.oblianceNight)
            assertEquals("$v text", accent.accent2, accentRoles(v, accent).text)
            assertEquals("$v line", accent.accent2, accentRoles(v, accent).line)
            val colors = ObliColors.of(v, ObliTokens.oblianceOperator, ObliTokens.oblianceNight)
            assertEquals(colors.accent2, colors.accentText)
            assertEquals(colors.accent2, colors.accentLine)
        }
        // Another app wearing Dim: ITS lighter tint as text, ITS brand as line; hover defaults to accent2.
        val otherApp = AccentTokens(brand = 0xFF2BC4BD, fill = 0xFF1F8F8A, fillPressed = 0xFF18706C, accent2 = 0xFF5FD9D3)
        assertEquals(otherApp.accent2, otherApp.hover)
        assertEquals(AccentRoles(text = 0xFF5FD9D3, line = 0xFF2BC4BD), accentRoles(ObliThemeVariant.DIM, otherApp))
    }

    @Test fun accent2OnChrome() {
        assertAtLeast(4.5, ObliTokens.oblianceOperator.accent2, ObliTokens.operator.chrome, "accent2 on chrome")
        assertAtLeast(4.5, ObliTokens.oblianceNight.accent2, ObliTokens.night.chrome, "night accent2 on chrome")
        assertAtLeast(4.5, ObliTokens.oblianceOperator.accent2, ObliTokens.dim.chrome, "dim accent2 on chrome")
    }

    @Test fun statusLabelsOnTheirPill() {
        // Status colours are constant across themes: check them on every theme's cards.
        for ((name, t) in NEAR_BLACK_THEMES) for (s in ObliTokens.Status.entries) {
            val pill = Contrast.blend(Contrast.withAlpha(s.argb, 0.12), t.surface1)
            assertAtLeast(4.5, s.argb, pill, "$name status ${s.name} on its pill")
        }
    }

    /**
     * Obli Dim keeps the constant status colours on its mid-dark slate
     * cards (#3B4252). There, saturated hues cannot all reach 4.5:1 without
     * turning pastel (critical and maintenance would both become pale pink):
     * the floor on Dim is 3:1 (WCAG large text and non-text), the level of the
     * web Dim palette on the same cards (#FF6B6B 3.6:1, #8A93A6 3.3:1).
     */
    @Test fun statusLabelsOnDimPills() {
        val t = ObliTokens.dim
        for (s in ObliTokens.Status.entries) {
            val pill = Contrast.blend(Contrast.withAlpha(s.argb, 0.12), t.surface1)
            assertAtLeast(3.0, s.argb, pill, "dim status ${s.name} on its pill")
            assertAtLeast(3.0, s.argb, t.surface1, "dim status ${s.name} on surface1")
        }
        // Online and warning, the most frequent labels, stay AA on Dim.
        for (s in listOf(ObliTokens.Status.ONLINE, ObliTokens.Status.WARNING)) {
            assertAtLeast(4.5, s.argb, Contrast.blend(Contrast.withAlpha(s.argb, 0.12), t.surface1), "dim status ${s.name} on its pill")
        }
    }

    private companion object {
        /** Near-black themes: every coloured foreground holds 4.5:1 there. */
        val NEAR_BLACK_THEMES = listOf(
            "operator" to ObliTokens.operator, "night" to ObliTokens.night,
            "neon" to ObliTokens.neon, "modern" to ObliTokens.modern,
        )
        val THEMES = NEAR_BLACK_THEMES + ("dim" to ObliTokens.dim)
    }

    @Test fun serverMonogramsOnTheirTile() {
        // The tile has an opaque chrome base under the 18 % tint, whatever it sits on.
        for ((name, t) in NEAR_BLACK_THEMES) {
            for (c in ServerColor.entries) {
                val tile = Contrast.blend(Contrast.withAlpha(c.argb, 0.18), t.chrome)
                assertAtLeast(4.5, c.argb, tile, "$name server ${c.name} monogram on its tile")
                assertAtLeast(6.0, c.argb, t.bg, "$name server ${c.name} on bg")
            }
        }
    }

    /** Same limit as [statusLabelsOnDimPills] for the constant identity palette on Dim's lighter chrome. */
    @Test fun serverMonogramsOnDimTile() {
        for (c in ServerColor.entries) {
            val tile = Contrast.blend(Contrast.withAlpha(c.argb, 0.18), ObliTokens.dim.chrome)
            assertAtLeast(3.0, c.argb, tile, "dim server ${c.name} monogram on its tile")
        }
    }
}
