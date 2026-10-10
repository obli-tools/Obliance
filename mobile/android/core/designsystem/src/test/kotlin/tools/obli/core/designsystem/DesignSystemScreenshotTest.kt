package tools.obli.core.designsystem

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.unit.dp
import com.github.takahirom.roborazzi.captureRoboImage
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import tools.obli.core.model.ServerColor

/** Visual check of the tokens and components, both themes. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w390dp-h400dp-xxhdpi")
class DesignSystemScreenshotTest {
    @get:Rule val compose = createComposeRule()

    private fun shot(name: String) = (System.getProperty("roborazzi.output.dir") ?: "build/outputs/roborazzi") + "/" + name

    @Composable
    private fun Sample(variant: ObliThemeVariant) = ObliTheme(variant) {
        val c = ObliTheme.colors
        Column(
            Modifier.fillMaxWidth().background(c.bg).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("À traiter", style = ObliTypography.screenTitle, color = c.text)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                ObliServerTile(ServerColor.VIOLET, "OP", "Obliance Prod")
                Text("Default · Vue globale", style = ObliTypography.label, color = c.text)
            }
            Column(Modifier.fillMaxWidth().background(c.surface1).padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    ObliServerTile(ServerColor.FUCHSIA, "OQ", "Obliance Qual")
                    Text("CRITIQUE · DEFAULT · 02:58", style = ObliTypography.overline, color = c.textMuted)
                }
                Text("SRV-DEMO03 — Hors ligne", style = ObliTypography.rowTitle, color = c.text)
                Text("Aucun push reçu depuis 5 min.", style = ObliTypography.body, color = c.text2)
                ObliStatusPill(ObliTokens.Status.OFFLINE, "Hors ligne")
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ServerColor.entries.forEach { ObliServerTile(it, it.name.take(2), it.name, size = 28.dp) }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ObliStatusPill(ObliTokens.Status.ONLINE, "En ligne")
                ObliStatusPill(ObliTokens.Status.WARNING, "Attention")
                ObliStatusPill(ObliTokens.Status.CRITICAL, "Critique")
            }
            // Accent roles (Obli Dim choice « B »): text link and tonal label in accentText,
            // tint and border in accentLine, filled button in accentFill.
            Row(
                Modifier.fillMaxWidth().background(c.surface1).padding(12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Voir tout", style = ObliTypography.label, color = c.accentText)
                Box(
                    Modifier.clip(RoundedCornerShape(8.dp)).background(c.accentTint())
                        .border(1.dp, c.accentLine, RoundedCornerShape(8.dp)).padding(horizontal = 12.dp, vertical = 6.dp),
                ) { Text("Agir", style = ObliTypography.label, color = c.accentText) }
                Box(Modifier.clip(RoundedCornerShape(8.dp)).background(c.accentFill).padding(horizontal = 12.dp, vertical = 6.dp)) {
                    Text("Activer", style = ObliTypography.label, color = c.onAccentFill)
                }
            }
        }
    }

    @Test fun operator() {
        compose.setContent { Sample(ObliThemeVariant.OPERATOR) }
        compose.onRoot().captureRoboImage(shot("designsystem_operator.png"))
    }

    @Test fun neon() {
        compose.setContent { Sample(ObliThemeVariant.NEON) }
        compose.onRoot().captureRoboImage(shot("designsystem_neon.png"))
    }

    @Test fun modern() {
        compose.setContent { Sample(ObliThemeVariant.MODERN) }
        compose.onRoot().captureRoboImage(shot("designsystem_modern.png"))
    }

    @Test fun night() {
        compose.setContent { Sample(ObliThemeVariant.NIGHT) }
        compose.onRoot().captureRoboImage(shot("designsystem_night.png"))
    }

    @Test fun dim() {
        compose.setContent { Sample(ObliThemeVariant.DIM) }
        compose.onRoot().captureRoboImage(shot("designsystem_dim.png"))
    }
}
