import { clientIp as resolveClientIp } from '../utils/clientIp';
import { db } from '../db';
import type { Request } from 'express';
import { isMasterTenant } from '@obliance/shared';

export interface AuditLogEntry {
  tenantId: number;
  userId?: number;
  deviceId?: number;
  action: string;
  resourceType?: string;
  resourcePath?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
}

export interface AuditLogRow {
  id: number;
  tenantId: number;
  /** Tenant display name. Always populated (the join is unconditional);
   *  the UI consumes it on master view to render a per-row tenant chip
   *  + tenant filter dropdown. */
  tenantName: string | null;
  userId: number | null;
  username: string | null;
  deviceId: number | null;
  deviceName: string | null;
  action: string;
  resourceType: string | null;
  resourcePath: string | null;
  /** Display name resolved from the owning table when possible
   *  (e.g. `scripts.name` for `resource_type='script'`). `null` when
   *  the entity has been deleted, or when the resource_type doesn't
   *  map to a nameable table (commands, files, sessions, etc.). The
   *  raw `resourceType:resourcePath` pair stays available so the UI
   *  can always fall back to it for debugging. */
  resourceName: string | null;
  details: Record<string, unknown> | null;
  ipAddress: string | null;
  createdAt: string;
}

function rowToAudit(r: any): AuditLogRow {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    tenantName: r.tenant_name ?? null,
    userId: r.user_id,
    username: r.username ?? null,
    deviceId: r.device_id,
    deviceName: r.device_name ?? null,
    action: r.action,
    resourceType: r.resource_type,
    resourcePath: r.resource_path,
    resourceName: r.resource_name ?? null,
    details: typeof r.details === 'string' ? JSON.parse(r.details) : r.details,
    ipAddress: r.ip_address,
    createdAt: r.created_at,
  };
}

/** Resolves the human-readable name for an audit row's resource via
 *  correlated subqueries.
 *
 *  A first cut used N LEFT JOINs gated by `resource_type`. That broke:
 *  PostgreSQL doesn't reliably short-circuit `AND` inside an `ON`
 *  clause, so `al.resource_path::int` ended up evaluating for every
 *  row regardless of `resource_type`, and any non-numeric
 *  `resource_path` (file paths under `resource_type='file'`, etc.)
 *  threw "invalid input syntax for type integer" — the whole SELECT
 *  failed and the page went red. Subqueries dodge the issue: each
 *  branch is only executed when the WHERE predicate is true, and we
 *  compare `id::text = resource_path` (cast the PK, not the path).
 *  With LIMIT 100 + indexed PK lookups this stays cheap.
 *
 *  Names resolve in the entry's own tenant only (resources the tenant owns,
 *  or that the master tenant shares with it): an entry citing the id of
 *  another tenant's group / team / script… must not print its name to the
 *  readers of this tenant's log — the master tenant's own entries included,
 *  since a master-tenant reader who is not a platform admin only sees the
 *  master tenant (E13/N1). The platform admin's god view (globalView)
 *  resolves every tenant; accounts and tenants are platform-wide. */
function resourceNameSelect(globalView: boolean) {
  const ALL = globalView ? 'TRUE' : 'FALSE';
  return db.raw(`
  COALESCE(
    (SELECT name     FROM scripts                   WHERE al.resource_type = 'script'          AND scripts.id::text                   = al.resource_path
       AND (${ALL} OR scripts.tenant_id IS NULL OR scripts.tenant_id = al.tenant_id OR al.tenant_id = ANY(scripts.target_tenant_ids))),
    (SELECT name     FROM scenarios                 WHERE al.resource_type = 'scenario'        AND scenarios.id::text                 = al.resource_path
       AND (${ALL} OR scenarios.tenant_id = al.tenant_id OR al.tenant_id = ANY(scenarios.target_tenant_ids))),
    (SELECT name     FROM user_teams                WHERE al.resource_type = 'team'            AND user_teams.id::text                = al.resource_path
       AND (${ALL} OR user_teams.tenant_id = al.tenant_id)),
    (SELECT username FROM users                     WHERE al.resource_type = 'user'            AND users.id::text                     = al.resource_path),
    (SELECT name     FROM device_groups             WHERE al.resource_type = 'group'           AND device_groups.id::text             = al.resource_path
       AND (${ALL} OR device_groups.tenant_id = al.tenant_id)),
    (SELECT name     FROM agent_api_keys            WHERE al.resource_type = 'api_key'         AND agent_api_keys.id::text            = al.resource_path
       AND (${ALL} OR agent_api_keys.tenant_id = al.tenant_id)),
    (SELECT name     FROM tenants                   WHERE al.resource_type = 'tenant'          AND tenants.id::text                   = al.resource_path),
    (SELECT name     FROM script_schedules          WHERE al.resource_type = 'schedule'        AND script_schedules.id::text          = al.resource_path
       AND (${ALL} OR script_schedules.tenant_id = al.tenant_id OR al.tenant_id = ANY(script_schedules.target_tenant_ids))),
    (SELECT name     FROM software_compliance_lists WHERE al.resource_type = 'software_policy' AND software_compliance_lists.id::text = al.resource_path
       AND (${ALL} OR software_compliance_lists.tenant_id = al.tenant_id))
  ) as resource_name
`);
}

/** Name of the entry's device, in the same rule as resourceNameSelect: a
 *  device of the entry's tenant (any tenant in the platform admin's god
 *  view). A device since transferred to another tenant is no longer named. */
function deviceNameSelect(globalView: boolean) {
  return db.raw(
    `CASE WHEN ${globalView ? 'TRUE' : 'FALSE'} OR d.tenant_id = al.tenant_id THEN COALESCE(d.display_name, d.hostname) END as device_name`,
  );
}

function clientIpFromReq(req: Request | undefined): string | undefined {
  if (!req) return undefined;
  // Through OUR proxies only (utils/clientIp.ts), never the left-most XFF value.
  return resolveClientIp(req) || undefined;
}

export const auditService = {
  /** Write a raw audit entry. Never throws — logging must not break the
   *  request that's trying to be audited. */
  async log(entry: AuditLogEntry): Promise<void> {
    try {
      await db('audit_logs').insert({
        tenant_id: entry.tenantId,
        user_id: entry.userId ?? null,
        device_id: entry.deviceId ?? null,
        action: entry.action,
        resource_type: entry.resourceType ?? null,
        resource_path: entry.resourcePath ?? null,
        details: entry.details ? JSON.stringify(entry.details) : null,
        ip_address: entry.ipAddress ?? null,
      });
    } catch {
      // Audit logging must never break the calling request. Any failure here
      // (table missing during migration, JSON too large, etc.) is swallowed.
    }
  },

  /** Convenience helper for route handlers — pulls tenantId/userId/ip from req. */
  async logReq(
    req: Request,
    action: string,
    extras: Partial<Omit<AuditLogEntry, 'action' | 'tenantId' | 'userId' | 'ipAddress'>> = {},
  ): Promise<void> {
    const tenantId = (req as any).tenantId as number | undefined;
    const userId = (req.session as any)?.userId as number | undefined;
    if (!tenantId) return; // can't audit without a tenant scope
    await this.log({
      tenantId,
      userId,
      action,
      ipAddress: clientIpFromReq(req),
      ...extras,
    });
  },

  /** As logReq, but filed in `tenantId` (a master-tenant action that touched
   *  another tenant's devices leaves a trace in that tenant's own log). */
  async logReqAs(
    req: Request,
    tenantId: number,
    action: string,
    extras: Partial<Omit<AuditLogEntry, 'action' | 'tenantId' | 'userId' | 'ipAddress'>> = {},
  ): Promise<void> {
    const userId = (req.session as any)?.userId as number | undefined;
    await this.log({
      tenantId,
      userId,
      action,
      ipAddress: clientIpFromReq(req),
      ...extras,
    });
  },

  async getByDevice(deviceId: number, tenantId: number, limit = 50): Promise<AuditLogRow[]> {
    const rows = await db('audit_logs as al')
      .leftJoin('users as u', 'u.id', 'al.user_id')
      .leftJoin('devices as d', 'd.id', 'al.device_id')
      .where({ 'al.device_id': deviceId, 'al.tenant_id': tenantId })
      .select(
        'al.*',
        'u.username',
        deviceNameSelect(false),
        resourceNameSelect(false),
      )
      .orderBy('al.created_at', 'desc')
      .limit(limit);
    return rows.map(rowToAudit);
  },

  /** Tenant-wide list with filters + pagination. */
  async list(params: {
    tenantId: number;
    action?: string;          // exact or prefix match (e.g. "user." matches all user actions)
    userId?: number;
    deviceId?: number;
    resourceType?: string;
    search?: string;          // match against resource_path or details text
    since?: Date;
    until?: Date;
    limit?: number;
    offset?: number;
    /** Master-only narrow filter — pick one tenant within the god
     *  view. Silently dropped for non-master callers (they're already
     *  scoped to their own tenant; allowing this would let them peek
     *  at other tenants' logs by ID). */
    filterTenantId?: number;
    /** true only for the platform admin on the master tenant (the route
     *  decides, `req.session.role === 'admin'`): the cross-tenant feed and
     *  names resolved in every tenant. Any other reader of the master
     *  tenant (a master-tenant admin, a `supervision:read` holder) gets the
     *  master tenant's own entries, like any tenant (N1). Fail-closed:
     *  absent = false. */
    globalView?: boolean;
  }): Promise<{ items: AuditLogRow[]; total: number }> {
    const page = Math.max(0, params.offset ?? 0);
    const limit = Math.min(500, Math.max(1, params.limit ?? 100));

    // Master tenant gets the cross-tenant audit feed (essential for a
    // platform admin investigating an incident across customers) — for
    // the platform admin only (globalView).
    const isMaster = isMasterTenant(params.tenantId) && params.globalView === true;
    const base = db('audit_logs as al')
      .leftJoin('users as u', 'u.id', 'al.user_id')
      .leftJoin('devices as d', 'd.id', 'al.device_id')
      // Always join `tenants` so master rows carry a tenant name column;
      // child tenants get the join too but ignore it.
      .leftJoin('tenants as ten', 'ten.id', 'al.tenant_id');
    if (!isMaster) base.where({ 'al.tenant_id': params.tenantId });
    // Narrow filter — master only (non-master is already scoped above).
    if (isMaster && Number.isFinite(params.filterTenantId)) {
      base.where('al.tenant_id', params.filterTenantId);
    }

    if (params.action) {
      if (params.action.endsWith('.')) {
        base.where('al.action', 'like', `${params.action}%`);
      } else {
        base.where('al.action', params.action);
      }
    }
    if (params.userId) base.where('al.user_id', params.userId);
    if (params.deviceId) base.where('al.device_id', params.deviceId);
    if (params.resourceType) base.where('al.resource_type', params.resourceType);
    if (params.since) base.where('al.created_at', '>=', params.since);
    if (params.until) base.where('al.created_at', '<=', params.until);
    if (params.search) {
      const q = `%${params.search}%`;
      base.where((b) => {
        b.where('al.resource_path', 'like', q)
         .orWhereRaw('details::text ILIKE ?', [q])
         .orWhere('u.username', 'like', q);
      });
    }

    const countRes = await base.clone().count<{ c: string }[]>({ c: 'al.id' });
    const total = parseInt((countRes[0] as any)?.c || '0', 10);

    const rows = await base
      .select(
        'al.*',
        'u.username',
        deviceNameSelect(isMaster),
        'ten.name as tenant_name',
        resourceNameSelect(isMaster),
      )
      .orderBy('al.created_at', 'desc')
      .limit(limit)
      .offset(page);

    return { items: rows.map(rowToAudit), total };
  },
};
