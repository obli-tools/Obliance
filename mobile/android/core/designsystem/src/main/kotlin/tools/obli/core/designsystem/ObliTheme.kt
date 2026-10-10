package tools.obli.core.designsystem

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver

fun Long.toColor(): Color = Color(this.toInt())

/**
 * OPERATOR / NEON / MODERN / DIM mirror the web themes a user picks on each
 * server (`preferences.preferredTheme`); NIGHT is the app's own low-light variant.
 * Every variant is DARK (dark Material scheme, light system-bar icons, dark
 * terminal), Obli Dim included: it is the mid-dark companion of Obli Daylight.
 */
enum class ObliThemeVariant {
    OPERATOR, NIGHT, NEON, MODERN, DIM;

    companion object {
        /**
         * Web theme id -> variant. `obli-daylight` (light) falls back to Operator
         * until the light theme ships; so does any id this app does not know yet
         * (a newer server theme): never an error.
         */
        fun fromServerTheme(id: String?): ObliThemeVariant = when (id?.trim()?.lowercase()) {
            "neon" -> NEON
            "modern" -> MODERN
            "obli-dim" -> DIM
            else -> OPERATOR
        }
    }
}

/**
 * Surfaces and accent a variant wears. Obli Dim changes the NEUTRALS only: it
 * wears the app's own Operator accent (Obliance red, injected per app), never
 * a Dim-specific one.
 */
internal fun themeTokens(
    variant: ObliThemeVariant,
    accentOperator: AccentTokens,
    accentNight: AccentTokens,
): Pair<SurfaceTokens, AccentTokens> = when (variant) {
    ObliThemeVariant.OPERATOR -> ObliTokens.operator to accentOperator
    ObliThemeVariant.NIGHT -> ObliTokens.night to accentNight
    ObliThemeVariant.NEON -> ObliTokens.neon to ObliTokens.neonAccent
    ObliThemeVariant.MODERN -> ObliTokens.modern to ObliTokens.modernAccent
    ObliThemeVariant.DIM -> ObliTokens.dim to accentOperator
}

/**
 * How a variant draws its accent outside filled buttons (`accentFill`) and
 * brand fills (`brand`), as ARGB so the contrast rules are JVM-tested:
 * - [text]: accent used as FOREGROUND (text, links, icons, text buttons,
 *   selected tab labels, cursor);
 * - [line]: accent used as a LINE or a TINT (borders, focus rings,
 *   indicators, progress lines, dots, 12 % tonal backgrounds).
 */
data class AccentRoles(val text: Long, val line: Long)

/**
 * Obli Dim, variant « B », same rule as the web (client
 * index.css `--c-accent-as-text`): the brand red is only 2.3:1 on the Dim
 * cards, so accent-coloured TEXT takes the app's lighter tint
 * ([AccentTokens.hover], Obliance #FF6868: 3.6:1 on cards, 4.4:1 on the
 * page), while fills, borders, rings and indicators keep the brand red
 * ([AccentTokens.brand]; filled buttons keep [AccentTokens.fill]). Every
 * other variant is unchanged: both roles are its [AccentTokens.accent2].
 */
fun accentRoles(variant: ObliThemeVariant, accent: AccentTokens): AccentRoles = when (variant) {
    ObliThemeVariant.DIM -> AccentRoles(text = accent.hover, line = accent.brand)
    else -> AccentRoles(text = accent.accent2, line = accent.accent2)
}

/** Semantic colours of the Obli design system, per variant. */
@Immutable
data class ObliColors(
    val bg: Color,
    val chrome: Color,
    val surface1: Color,
    val surface2: Color,
    val hover: Color,
    val active: Color,
    val divider: Color,
    val text: Color,
    val text2: Color,
    val textMuted: Color,
    val textFaint: Color,
    val brand: Color,
    val accentFill: Color,
    val accentFillPressed: Color,
    /** The raw accent2 token. Components draw the accent with [accentText] / [accentLine]. */
    val accent2: Color,
    val onAccentFill: Color,
    /** Accent as FOREGROUND: text, links, icons, text buttons, selected tab labels, cursor ([AccentRoles.text]). */
    val accentText: Color = accent2,
    /** Accent as a LINE or TINT: borders, focus rings, indicators, progress lines, 12 % tonal backgrounds ([AccentRoles.line]). */
    val accentLine: Color = accent2,
    /**
     * Accent as FOREGROUND on the raised [active] surface (snackbar actions).
     * [accentText] everywhere but Obli Dim, where #FF6868 is only 2.7:1 on
     * `active`: the plain [text] there.
     */
    val accentTextRaised: Color = accentText,
    /**
     * A glyph drawn ON an [accentLine] fill (checkbox tick). [bg] everywhere
     * but Obli Dim, whose fill is the brand red: white there, as on filled buttons.
     */
    val onAccentLine: Color = bg,
    /**
     * Obli Dim: the accent tints ([accentTint]) are opaque, composited on
     * [bg], so accent text on them keeps its floor on every surface (a
     * translucent brand tint over the Dim cards leaves #FF6868 at 3.4:1).
     */
    val opaqueTints: Boolean = false,
) {
    /**
     * The accent TINT behind accent-coloured text and icons (tonal buttons,
     * selected chips, navigation indicator): [accentLine] at [alpha];
     * translucent everywhere but Obli Dim, where it is composited on [bg]
     * ([opaqueTints]).
     */
    fun accentTint(alpha: Float = 0.12f): Color {
        val tint = accentLine.copy(alpha = alpha)
        return if (opaqueTints) tint.compositeOver(bg) else tint
    }

    companion object {
        fun of(surfaces: SurfaceTokens, accent: AccentTokens, roles: AccentRoles = AccentRoles(accent.accent2, accent.accent2)) = ObliColors(
            bg = surfaces.bg.toColor(), chrome = surfaces.chrome.toColor(), surface1 = surfaces.surface1.toColor(),
            surface2 = surfaces.surface2.toColor(), hover = surfaces.hover.toColor(), active = surfaces.active.toColor(),
            divider = surfaces.divider.toColor(), text = surfaces.text.toColor(), text2 = surfaces.text2.toColor(),
            textMuted = surfaces.textMuted.toColor(), textFaint = surfaces.textFaint.toColor(),
            brand = accent.brand.toColor(), accentFill = accent.fill.toColor(), accentFillPressed = accent.fillPressed.toColor(),
            accent2 = accent.accent2.toColor(), onAccentFill = ObliTokens.ON_FILL.toColor(),
            accentText = roles.text.toColor(), accentLine = roles.line.toColor(),
        )

        /** The colours [variant] wears with the app's accents (what [ObliTheme] animates to). */
        fun of(variant: ObliThemeVariant, accentOperator: AccentTokens, accentNight: AccentTokens): ObliColors {
            val (surfaces, accent) = themeTokens(variant, accentOperator, accentNight)
            val colors = of(surfaces, accent, accentRoles(variant, accent))
            // Obli Dim (choice « B »): where #FF6868 cannot hold its floor (ContrastTest.dimAccentTextOnItsRealBackgrounds).
            return if (variant != ObliThemeVariant.DIM) colors else colors.copy(
                accentTextRaised = colors.text,
                onAccentLine = ObliTokens.ON_FILL.toColor(),
                opaqueTints = true,
            )
        }
    }
}

val LocalObliColors = staticCompositionLocalOf { ObliColors.of(ObliTokens.operator, ObliTokens.oblianceOperator) }

/**
 * Root theme. Material 3 is tuned so no red tint reaches elevated surfaces
 * (`surfaceTint = Transparent`).
 */
@Composable
fun ObliTheme(
    variant: ObliThemeVariant = ObliThemeVariant.OPERATOR,
    accentOperator: AccentTokens = ObliTokens.oblianceOperator,
    accentNight: AccentTokens = ObliTokens.oblianceNight,
    content: @Composable () -> Unit,
) {
    val target = ObliColors.of(variant, accentOperator, accentNight)
    // Switching server switches theme: fade the colours (200 ms) instead of a jump.
    val colors = animateColors(target)
    CompositionLocalProvider(LocalObliColors provides colors) {
        MaterialTheme(colorScheme = colors.toMaterial(), typography = ObliTypography.material, content = content)
    }
}

@Composable
private fun animateColors(t: ObliColors): ObliColors {
    val spec = tween<Color>(durationMillis = 200)
    @Composable fun a(c: Color) = animateColorAsState(c, spec, label = "obliTheme").value
    return ObliColors(
        bg = a(t.bg), chrome = a(t.chrome), surface1 = a(t.surface1), surface2 = a(t.surface2),
        hover = a(t.hover), active = a(t.active), divider = a(t.divider), text = a(t.text),
        text2 = a(t.text2), textMuted = a(t.textMuted), textFaint = a(t.textFaint), brand = a(t.brand),
        accentFill = a(t.accentFill), accentFillPressed = a(t.accentFillPressed), accent2 = a(t.accent2),
        onAccentFill = t.onAccentFill, accentText = a(t.accentText), accentLine = a(t.accentLine),
        accentTextRaised = a(t.accentTextRaised), onAccentLine = a(t.onAccentLine), opaqueTints = t.opaqueTints,
    )
}

object ObliTheme {
    val colors: ObliColors
        @Composable get() = LocalObliColors.current
}

internal fun ObliColors.toMaterial(): ColorScheme = darkColorScheme(
    primary = accentFill,
    onPrimary = onAccentFill,
    secondary = accentText,
    background = bg,
    onBackground = text,
    surface = surface1,
    onSurface = text,
    surfaceVariant = surface2,
    onSurfaceVariant = text2,
    surfaceTint = Color.Transparent,
    outline = divider,
    outlineVariant = divider,
    error = ObliTokens.DANGER.toColor(),
    onError = Color.White,
    surfaceContainerLowest = bg,
    surfaceContainerLow = chrome,
    surfaceContainer = surface1,
    surfaceContainerHigh = surface2,
    surfaceContainerHighest = hover,
)
