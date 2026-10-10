import type { RemoteSession } from '@obliance/shared';

/**
 * The body of the POST /api/remote/sessions answer.
 *
 * It is the created session plus `deviceTenantId` — the tenant the target
 * DEVICE belongs to. The session's own `tenantId` is the tenant of the caller's
 * SESSION (1 = master on a god-view start), which does not tell where the
 * device lives; the Oblireach Desktop password vault needs the device's tenant
 * to scope a saved secret (a master-tenant entry is only typed into
 * master-tenant devices, never widened across the god view).
 *
 * Also carries `conptyDegradedHint` — true when the device's known Windows
 * build predates ConPTY (Windows 10 1809 / Server 2019, build 17763): the
 * agent still opens a shell (a degraded plain-pipe fallback,
 * tunnel_shell_pipe_windows.go), this is only a hint so a viewer can show the
 * degraded badge immediately instead of waiting for the tunnel's first "mode"
 * control frame. false (including an unknown build) never blocks anything —
 * the tunnel's own "mode" frame is always the source of truth.
 *
 * Pure and additive: it copies the session as-is and appends fields. It is
 * kept here so the exact shape is unit-tested (verify-reach-vault.ts) without
 * standing up the route.
 */
export function sessionCreatedAnswer(
  session: RemoteSession,
  dev: { tenant_id: number; uuid?: string | null },
  conptyDegradedHint = false,
): RemoteSession & { deviceTenantId: number; conptyDegradedHint: boolean; deviceUuid?: string } {
  // deviceUuid: the device's stable identity (Oblireach Desktop vault entries
  // restricted to machines match on it; a numeric id changes on re-enrolment).
  const out: RemoteSession & { deviceTenantId: number; conptyDegradedHint: boolean; deviceUuid?: string } =
    { ...session, deviceTenantId: dev.tenant_id, conptyDegradedHint };
  if (typeof dev.uuid === 'string' && dev.uuid) out.deviceUuid = dev.uuid;
  return out;
}
