package tools.obli.obliance.devices

import android.content.res.Resources
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import tools.obli.core.security.ActionResult

/** « Tout analyser » says how many scans were sent when a step-up stopped it early (French). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "fr-rFR")
class ScanAllTextsTest {
    private val res: Resources get() = ApplicationProvider.getApplicationContext<android.content.Context>().resources

    private fun done(n: Int) = ActionResult.Done((1..n).map { CommandDto(id = "c$it", deviceId = 187, type = "scan_inventory", status = "pending") })

    @Test fun allThreeOrAPartOfThem() {
        assertEquals("Analyses demandées", ActController.scanAllDone(res, done(3)))
        assertEquals("1 analyse sur 3 demandée", ActController.scanAllDone(res, done(1)))
        assertEquals("2 analyses sur 3 demandées", ActController.scanAllDone(res, done(2)))
        // Not a success: the snackbar explains the result itself (this text is not shown).
        assertEquals("Analyses demandées", ActController.scanAllDone(res, ActionResult.Cancelled))
    }
}
