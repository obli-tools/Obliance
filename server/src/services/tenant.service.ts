import type { Request } from 'express';
import { db } from '../db';
import { MASTER_TENANT_ID } from '@obliance/shared';
import type { Tenant, TenantWithRole } from '@obliance/shared';
import { AppError } from '../middleware/errorHandler';
import { clientIp } from '../utils/clientIp';

/** E3: an account without any tenant gets no session (never the master
 *  tenant it is not a member of). Code read by the login page. */
export function noTenantAccessError(): AppError {
  return new AppError(403, 'This account has no access to any tenant. Ask an administrator to grant it access.', 'noTenantAccess');
}

/** A sign-in refused for that reason (password, second factor or SSO),
 *  audited in the master tenant — the platform's own log, as the account has
 *  no tenant. Returns the error to answer with. */
export async function refuseSignInWithoutTenant(
  req: Request,
  user: { id: number; username: string },
  via: string,
): Promise<AppError> {
  try {
    const { auditService } = await import('./audit.service');
    await auditService.log({
      tenantId: MASTER_TENANT_ID,
      userId: user.id,
      action: 'auth.login_refused',
      resourceType: 'user',
      resourcePath: String(user.id),
      details: { username: user.username, reason: 'no_tenant', via },
      ipAddress: clientIp(req) || undefined,
    });
  } catch { /* the audit never breaks the answer */ }
  return noTenantAccessError();
}

interface TenantRow {
  id: number;
  name: string;
  slug: string;
  two_step_approval?: boolean;
  created_at: Date;
  updated_at: Date;
}

interface UserRow {
  id: number;
  username: string;
  display_name: string | null;
  role: string;
  is_active: boolean;
  email: string | null;
}

function rowToTenant(row: TenantRow): Tenant {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    twoStepApproval: !!row.two_step_approval,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

export const tenantService = {
  async getAll(): Promise<Tenant[]> {
    const rows = await db('tenants').select<TenantRow[]>('*').orderBy('id');
    return rows.map(rowToTenant);
  },

  async getById(id: number): Promise<Tenant | null> {
    const row = await db('tenants').where({ id }).first<TenantRow>();
    return row ? rowToTenant(row) : null;
  },

  async getBySlug(slug: string): Promise<Tenant | null> {
    const row = await db('tenants').where({ slug }).first<TenantRow>();
    return row ? rowToTenant(row) : null;
  },

  async create(data: { name: string; slug: string }): Promise<Tenant> {
    const [row] = await db('tenants')
      .insert({ name: data.name, slug: data.slug })
      .returning('*');
    return rowToTenant(row as TenantRow);
  },

  async update(id: number, data: { name?: string; slug?: string; twoStepApproval?: boolean }): Promise<Tenant | null> {
    const patch: any = { updated_at: db.fn.now() };
    if (data.name !== undefined) patch.name = data.name;
    if (data.slug !== undefined) patch.slug = data.slug;
    if (data.twoStepApproval !== undefined) patch.two_step_approval = data.twoStepApproval;
    const [row] = await db('tenants').where({ id }).update(patch).returning('*');
    return row ? rowToTenant(row as TenantRow) : null;
  },

  async delete(id: number): Promise<void> {
    // Strip the tenant id from any master-owned fan-out array before
    // dropping the row. Without this, scripts/scenarios/schedules/
    // compliance policies that targeted this tenant would carry a
    // dangling id forever — and the cross-tenant read scope would
    // perform a wasted `id = ANY(...)` test against the dead value.
    // CASCADE on tenant_id covers the owner side; the array side is
    // application-level and has to be cleaned explicitly.
    await db.transaction(async (trx) => {
      const FANOUT_TABLES = ['scripts', 'scenarios', 'script_schedules', 'compliance_policies'] as const;
      for (const table of FANOUT_TABLES) {
        const has = await trx.schema.hasColumn(table, 'target_tenant_ids');
        if (!has) continue;
        await trx.raw(
          `UPDATE ${table}
              SET target_tenant_ids = NULLIF(array_remove(target_tenant_ids, ?), '{}')::int[]
            WHERE ? = ANY(target_tenant_ids)`,
          [id, id],
        );
      }
      await trx('tenants').where({ id }).delete();
    });
  },

  /** Returns the first tenant accessible by userId (lowest id). */
  async getFirstTenantForUser(userId: number): Promise<Tenant | null> {
    const row = await db('tenants')
      .join('user_tenants', 'tenants.id', 'user_tenants.tenant_id')
      .where('user_tenants.user_id', userId)
      .orderBy('tenants.id')
      .first<TenantRow & { role: string }>('tenants.*');
    return row ? rowToTenant(row) : null;
  },

  /**
   * The tenant a session of this user starts on (sign-in, or a session to
   * repair): the first tenant it belongs to. A platform admin without any
   * membership row (implicit access to every tenant, as the SSO sign-in
   * leaves it) starts on the master tenant. Anyone else without a tenant gets
   * null, NEVER the master tenant (E3: god views are keyed on the master
   * tenant id in places, and a user removed from every tenant must not land
   * there with its team grants): the caller refuses the session.
   */
  async sessionTenantFor(userId: number, platformRole: string | null | undefined): Promise<number | null> {
    const tenant = await this.getFirstTenantForUser(userId);
    if (tenant) return tenant.id;
    return platformRole === 'admin' ? MASTER_TENANT_ID : null;
  },

  /** Returns all tenants accessible by userId, with tenant-level role. */
  async getTenantsForUser(userId: number): Promise<TenantWithRole[]> {
    const rows = await db('tenants')
      .join('user_tenants', 'tenants.id', 'user_tenants.tenant_id')
      .where('user_tenants.user_id', userId)
      .orderBy('tenants.id')
      .select<(TenantRow & { role: string })[]>('tenants.*', 'user_tenants.role');
    return rows.map((r) => ({ ...rowToTenant(r), role: r.role as 'admin' | 'member' }));
  },

  /** Check if user has access to a specific tenant. */
  async userHasAccess(userId: number, tenantId: number): Promise<boolean> {
    const row = await db('user_tenants')
      .where({ user_id: userId, tenant_id: tenantId })
      .first('user_id');
    return !!row;
  },

  async getMembers(tenantId: number): Promise<(UserRow & { tenantRole: string })[]> {
    return db('users')
      .join('user_tenants', 'users.id', 'user_tenants.user_id')
      .where('user_tenants.tenant_id', tenantId)
      .select<(UserRow & { tenantRole: string })[]>(
        'users.id',
        'users.username',
        'users.display_name',
        'users.role',
        'users.is_active',
        'users.email',
        db.raw('user_tenants.role as "tenantRole"'),
      )
      .orderBy('users.username');
  },

  /** `role`: a permission set slug (tenant.routes.ts tenantRoleFrom). */
  async addUser(tenantId: number, userId: number, role: string): Promise<void> {
    await db('user_tenants')
      .insert({ tenant_id: tenantId, user_id: userId, role })
      .onConflict(['user_id', 'tenant_id'])
      .merge({ role });
  },

  async removeUser(tenantId: number, userId: number): Promise<void> {
    // The user's teams of that tenant go too (teams are mono-tenant): a team
    // membership left behind kept its device grants and capabilities
    // (remote shells, file explorer) on the tenant's devices. Same rule as the
    // Obligate callback's tenant reconciliation.
    await db.transaction(async (trx) => {
      const teamIds = await trx('team_memberships')
        .join('user_teams', 'user_teams.id', 'team_memberships.team_id')
        .where({ 'team_memberships.user_id': userId, 'user_teams.tenant_id': tenantId })
        .pluck('team_memberships.team_id') as number[];
      if (teamIds.length > 0) {
        await trx('team_memberships').where({ user_id: userId }).whereIn('team_id', teamIds).delete();
      }
      await trx('user_tenants').where({ tenant_id: tenantId, user_id: userId }).delete();
    });
  },

  async updateUserRole(tenantId: number, userId: number, role: string): Promise<void> {
    await db('user_tenants')
      .where({ tenant_id: tenantId, user_id: userId })
      .update({ role });
  },
};
