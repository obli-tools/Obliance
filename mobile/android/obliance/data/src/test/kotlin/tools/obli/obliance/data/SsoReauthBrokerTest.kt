package tools.obli.obliance.data

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import tools.obli.core.security.SsoReauthResult

/** SSO device keys: the Obligate re-authentication broker (one sheet at a time, fail closed without a host). */
@OptIn(ExperimentalCoroutinesApi::class)
class SsoReauthBrokerTest {
    @Test fun withoutAHostItFailsClosedAtOnce() = runTest {
        val b = SsoReauthBroker()
        assertFalse(b.hasHost)
        assertEquals(SsoReauthResult.Cancelled, b.reauthenticate("https://obliance-prod.example.org"))
        assertNull(b.request.value)
    }

    @Test fun theHostAnswersOneRequestAtATime() = runTest {
        val b = SsoReauthBroker()
        val detach = b.attachHost()
        assertTrue(b.hasHost)
        val first = async { b.reauthenticate("https://obliance-prod.example.org", "/devices/12") }
        val second = async { b.reauthenticate("https://obliance-dev.example.org") }
        runCurrent()
        val r1 = b.request.value!!
        assertEquals("https://obliance-prod.example.org", r1.origin)
        assertEquals("/devices/12", r1.returnPath)
        r1.complete(SsoReauthResult.Success)
        r1.complete(SsoReauthResult.Failed("identity")) // only the first answer counts
        runCurrent()
        assertEquals(SsoReauthResult.Success, first.await())
        val r2 = b.request.value!!
        assertEquals("https://obliance-dev.example.org", r2.origin)
        assertEquals("/", r2.returnPath)
        r2.complete(SsoReauthResult.Failed("no_otp"))
        assertEquals(SsoReauthResult.Failed("no_otp"), second.await())
        runCurrent()
        assertNull(b.request.value)
        detach()
        detach() // idempotent
        assertFalse(b.hasHost)
    }

    @Test fun aCancelledCallerTakesItsRequestAway() = runTest {
        val b = SsoReauthBroker()
        b.attachHost()
        val job = launch { b.reauthenticate("https://obliance-prod.example.org") }
        runCurrent()
        assertNotNull(b.request.value)
        job.cancel()
        runCurrent()
        assertNull(b.request.value)
    }
}
