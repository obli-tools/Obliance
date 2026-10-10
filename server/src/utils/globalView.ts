import { AsyncLocalStorage } from 'node:async_hooks';
import type { Request, Response, NextFunction } from 'express';
import { isMasterTenant } from '@obliance/shared';

/**
 * Master-tenant "god view" (cross-tenant reads, aggregates and actions):
 * for the PLATFORM ADMIN (`users.role = 'admin'`) on the master tenant ONLY.
 *
 * Any other account of the master tenant — a master-tenant admin
 * (`user_tenants.role = 'admin'`, every tenant capability), a custom role
 * granting `devices.manage`, a plain member — is limited to tenant 1 like
 * any tenant is limited to itself (tenant isolation rule). Same rule as
 * resolveRequestDevice
 * (services/deviceScope.service.ts).
 *
 * Two entry points:
 *  - hasGlobalView(req)  — routes / controllers that hold the request;
 *  - isGodView(tenantId) — services that only receive a tenant id. It is the
 *    replacement for `isMasterTenant(tenantId)` wherever that test WIDENS a
 *    lookup to every tenant. Inside an HTTP request it reads the session of
 *    the request (AsyncLocalStorage, set by requestScope below, mounted right
 *    after the session middleware): a user session that is not a platform
 *    admin never gets the god view, whatever tenant id the code passes.
 *    Outside any user session (background jobs, agent / push routes) the
 *    caller is internal code and the historical rule — master tenant id =
 *    every tenant — is kept. Socket.io handlers run in the scope of their
 *    handshake request (socket.ts, runInRequestScope).
 *
 * Do NOT use isGodView for tests that are not about widening a scope (the
 * master tenant cannot be deleted, audit filed in tenant 1…): keep
 * isMasterTenant there.
 */

interface RequestScope { req: Request }
const scopeStore = new AsyncLocalStorage<RequestScope>();

/** Express middleware: every handler down the chain (and every promise it
 *  starts) can ask isGodView() about the session of this request. */
export function requestScope(req: Request, _res: Response, next: NextFunction): void {
  scopeStore.run({ req }, next);
}

/** Same scope outside Express: the Socket.io layer runs each incoming
 *  packet of a socket inside the scope of its handshake request (socket.ts),
 *  so the services its handlers call apply the same rule. */
export function runInRequestScope<T>(req: Request, fn: () => T): T {
  return scopeStore.run({ req }, fn);
}

/** Request level: platform admin on the master tenant. */
export function hasGlobalView(req: Pick<Request, 'session'> & { tenantId?: number }): boolean {
  const session = req.session as { role?: string; currentTenantId?: number } | undefined;
  const tenantId = req.tenantId ?? session?.currentTenantId;
  return session?.role === 'admin' && isMasterTenant(tenantId);
}

/** Does the current request belong to a user session that is NOT a platform
 *  admin? (null: not inside a user request — internal code.) */
export function currentSessionIsPlatformAdmin(): boolean | null {
  const s = scopeStore.getStore();
  const session = s?.req?.session as { userId?: number; role?: string } | undefined;
  if (!session?.userId) return null;
  return session.role === 'admin';
}

/**
 * Service level replacement for `isMasterTenant(tenantId)` when the test
 * widens a lookup to every tenant: true only for the master tenant id AND
 * (no user session in scope — internal code — OR a platform admin's session).
 */
export function isGodView(tenantId: number | null | undefined): boolean {
  if (!isMasterTenant(tenantId)) return false;
  const platformAdmin = currentSessionIsPlatformAdmin();
  return platformAdmin === null ? true : platformAdmin;
}
