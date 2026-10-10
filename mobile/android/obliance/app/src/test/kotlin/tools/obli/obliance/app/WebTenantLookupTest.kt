package tools.obli.obliance.app

import org.junit.Assert.assertEquals
import org.junit.Test
import tools.obli.core.model.ServerId
import tools.obli.core.security.WebChallengeSigning.TenantLookup
import tools.obli.obliance.api.Tenant
import tools.obli.obliance.data.TenantScope

/**
 * The web bridge's prompt names the challenge's tenant from the app's own list
 * of the active server, never from the
 * page's `tenantName`.
 */
class WebTenantLookupTest {
    private val prod = ServerId("prod")
    private val qual = ServerId("qual")
    private val loaded = TenantScope(serverId = prod, tenants = listOf(Tenant(1, "Default"), Tenant(3, "ACME")), currentTenantId = 1)

    @Test fun aTenantOfTheUserIsNamedByTheApp() {
        assertEquals(TenantLookup.Known("ACME"), webTenantLookup(loaded, prod, 3))
        assertEquals(TenantLookup.Known("Default"), webTenantLookup(loaded, prod, 1))
    }

    @Test fun anIdOutsideTheLoadedListIsRefused() {
        assertEquals(TenantLookup.NotMine, webTenantLookup(loaded, prod, 42))
    }

    @Test fun withoutTheActiveServersListTheIdIsShown() {
        assertEquals(TenantLookup.Unknown, webTenantLookup(TenantScope(serverId = prod), prod, 3))
        assertEquals(TenantLookup.Unknown, webTenantLookup(loaded, qual, 3))
        assertEquals(TenantLookup.Unknown, webTenantLookup(loaded, null, 3))
    }
}
