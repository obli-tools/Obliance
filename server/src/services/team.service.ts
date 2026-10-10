import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import type { UserTeam, TeamPermission } from '@obliance/shared';

interface TeamRow {
  id: number;
  uuid: string;
  name: string;
  description: string | null;
  can_create: boolean;
  tenant_id: number;
  tenant_name?: string; // populated by JOIN when fetching all tenants
  created_at: Date;
  updated_at: Date;
}

interface PermissionRow {
  id: number;
  team_id: number;
  tenant_id: number;
  scope: 'group' | 'device' | 'ungrouped';
  scope_id: number;
  level: 'ro' | 'rw';
  recursive?: boolean;
}

function rowToTeam(row: TeamRow): UserTeam {
  return {
    id: row.id,
    uuid: row.uuid,
    name: row.name,
    canCreate: row.can_create,
    tenantId: row.tenant_id,
    // Always exposed when the row was joined with `tenants` (the
    // god-view query does this). The /admin/users page renders it
    // both in the team-list rows and in the create-team selector
    // so admins see "ACME" / "CONTOSO" instead of "Tenant 2".
    tenantName: row.tenant_name ?? undefined,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

// Whitelist of capabilities accepted by the validator. Older installs
// have rows with legacy values (pre-rename, before the enum was
// stabilised); those values would round-trip from GET → toggle → PUT
// and trip the Zod validator on /teams/:id/permissions, surfacing as
// "Validation failed" with no recoverable UX. We silently drop them on
// read so the toggle UI can re-save without 400-ing.
//
// MUST stay in sync with `CAPABILITY_VALUES` in
// validators/team.schema.ts AND `Capability` in shared/types.ts —
// the three are the same list expressed three ways.
const VALID_CAPABILITIES = new Set([
  'monitor', 'execute', 'remote', 'files', 'power', 'shell',
  'supervision:read',
  'agent_config:custom_sections',
  'agent_config:discovery',
  'agent_config:keys',
  'agent_config:approval',
  'hyperv:view',
  'hyperv:power',
  'hyperv:manage',
  'veeam:view',
  'veeam:control',
]);

function rowToPermission(row: any): TeamPermission {
  const rawCaps = row.capabilities
    ? (typeof row.capabilities === 'string' ? JSON.parse(row.capabilities) : row.capabilities)
    : (row.level === 'rw' ? ['monitor', 'execute'] : ['monitor']);
  const caps = (Array.isArray(rawCaps) ? rawCaps : []).filter((c: any) => typeof c === 'string' && VALID_CAPABILITIES.has(c));
  return {
    id: row.id,
    tenantId: row.tenant_id,
    teamId: row.team_id,
    scope: row.scope,
    scopeId: row.scope_id,
    level: row.level,
    capabilities: caps,
    // Group grants only; a row written before migration 143 is recursive.
    ...(row.scope === 'group' ? { recursive: row.recursive !== false } : {}),
  };
}

export const teamService = {
  /**
   * Returns teams scoped to a tenant.
   * If tenantId is null (platform admin cross-tenant view), returns ALL teams across
   * all tenants, joined with tenant name.
   */
  async getAll(tenantId: number | null): Promise<UserTeam[]> {
    const query = db('user_teams')
      .join('tenants', 'user_teams.tenant_id', 'tenants.id')
      .select('user_teams.*', 'tenants.name as tenant_name')
      .orderBy('user_teams.name');
    if (tenantId !== null) {
      query.where('user_teams.tenant_id', tenantId);
    }
    const rows = await query;
    return rows.map(rowToTeam);
  },

  /** UNSAFE without tenant scope — callers MUST pair this with a
   *  `team.tenantId === req.tenantId || isMasterTenant(req.tenantId)`
   *  check before exposing the row to the user (see
   *  `teamsController.setPermissions` for the canonical pattern). The
   *  helper is left tenant-agnostic on purpose because internal jobs
   *  (e.g. agentHub.unbindTeam, group cascade) need cross-tenant access. */
  async getById(id: number): Promise<UserTeam | null> {
    const row = await db<TeamRow>('user_teams').where({ id }).first();
    return row ? rowToTeam(row) : null;
  },

  async create(data: { name: string; description?: string | null; canCreate?: boolean }, tenantId: number): Promise<UserTeam> {
    const [row] = await db<TeamRow>('user_teams')
      .insert({
        name: data.name,
        description: data.description ?? null,
        can_create: data.canCreate ?? false,
        tenant_id: tenantId,
      })
      .returning('*');
    return rowToTeam(row);
  },

  async update(
    id: number,
    data: { name?: string; description?: string | null; canCreate?: boolean },
  ): Promise<UserTeam | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };
    if (data.name !== undefined) updateData.name = data.name;
    if (data.description !== undefined) updateData.description = data.description;
    if (data.canCreate !== undefined) updateData.can_create = data.canCreate;

    const [row] = await db<TeamRow>('user_teams')
      .where({ id })
      .update(updateData)
      .returning('*');
    return row ? rowToTeam(row) : null;
  },

  async delete(id: number): Promise<boolean> {
    const count = await db('user_teams').where({ id }).del();
    return count > 0;
  },

  // ── Members ──

  async getMembers(teamId: number): Promise<number[]> {
    const rows = await db('team_memberships')
      .where({ team_id: teamId })
      .select('user_id');
    return rows.map((r) => r.user_id);
  },

  async setMembers(teamId: number, userIds: number[]): Promise<void> {
    // Teams are mono-tenant: a member must belong to the team's tenant (a
    // platform admin needs no row there — it bypasses team checks anyway).
    const team = await db('user_teams').where({ id: teamId }).first('tenant_id') as { tenant_id: number } | undefined;
    if (!team) throw new AppError(404, 'Team not found');
    const wanted = [...new Set(userIds.map(Number))];
    if (wanted.length > 0) {
      const allowed = new Set((await db('users')
        .leftJoin('user_tenants', function () {
          this.on('user_tenants.user_id', '=', 'users.id').andOnVal('user_tenants.tenant_id', '=', team.tenant_id);
        })
        .whereIn('users.id', wanted)
        .where((q) => q.where('users.role', 'admin').orWhereNotNull('user_tenants.user_id'))
        .pluck('users.id') as number[]).map(Number));
      if (wanted.some((u) => !allowed.has(u))) throw new AppError(400, "Every member must belong to the team's tenant");
    }
    await db.transaction(async (trx) => {
      await trx('team_memberships').where({ team_id: teamId }).del();
      if (userIds.length > 0) {
        await trx('team_memberships').insert(
          userIds.map((uid) => ({ team_id: teamId, user_id: uid })),
        );
      }
    });
  },

  async getUserTeams(userId: number): Promise<UserTeam[]> {
    const rows = await db<TeamRow>('user_teams')
      .join('team_memberships', 'user_teams.id', 'team_memberships.team_id')
      .where('team_memberships.user_id', userId)
      .select('user_teams.*')
      .orderBy('user_teams.name');
    return rows.map(rowToTeam);
  },

  // ── Permissions ──

  async getPermissions(teamId: number): Promise<TeamPermission[]> {
    const rows = await db<PermissionRow>('team_permissions')
      .where({ team_id: teamId })
      .orderBy('scope')
      .orderBy('scope_id');
    return rows.map(rowToPermission);
  },

  async setPermissions(
    teamId: number,
    permissions: Array<{ scope: 'group' | 'device' | 'ungrouped'; scopeId: number; level: 'ro' | 'rw'; capabilities?: string[]; recursive?: boolean }>,
  ): Promise<TeamPermission[]> {
    // Resolve tenant_id from the team
    const team = await db('user_teams').where({ id: teamId }).select('tenant_id').first();
    const tenantId = team?.tenant_id;
    if (!tenantId) throw new AppError(404, 'Team not found');
    // Scopes of a team: groups and devices of its own tenant only (the
    // closure would otherwise give it rights on another tenant's subtree).
    for (const [scope, table] of [['group', 'device_groups'], ['device', 'devices']] as const) {
      const ids = [...new Set(permissions.filter((p) => p.scope === scope).map((p) => Number(p.scopeId)))];
      if (ids.length === 0) continue;
      const found = await db(table).whereIn('id', ids).where({ tenant_id: tenantId }).pluck('id') as number[];
      if (found.length !== ids.length) throw new AppError(400, `Every ${scope} scope must belong to the team's tenant`);
    }

    return db.transaction(async (trx) => {
      await trx('team_permissions').where({ team_id: teamId }).del();
      if (permissions.length > 0) {
        await trx('team_permissions').insert(
          permissions.map((p) => ({
            team_id: teamId,
            tenant_id: tenantId,
            scope: p.scope,
            scope_id: p.scopeId,
            level: p.level,
            capabilities: JSON.stringify(p.capabilities ?? (p.level === 'rw' ? ['monitor', 'execute'] : ['monitor'])),
            // Only a group grant can be non-recursive (default: recursive).
            recursive: p.scope === 'group' ? p.recursive !== false : true,
          })),
        );
      }
      const rows = await trx<PermissionRow>('team_permissions')
        .where({ team_id: teamId })
        .orderBy('scope')
        .orderBy('scope_id');
      return rows.map(rowToPermission);
    });
  },

  /**
   * Adds (or re-levels) one scope of a team. team_permissions has no unique
   * (team_id, scope, scope_id) constraint — an ON CONFLICT on it failed with
   * a 500 — and its tenant_id is NOT NULL: the team's tenant. The group or
   * device must belong to that tenant too. Capabilities are the column
   * default for a new row (never widened here).
   */
  async addPermission(
    teamId: number,
    scope: 'group' | 'device' | 'ungrouped',
    scopeId: number,
    level: 'ro' | 'rw',
  ): Promise<TeamPermission> {
    return db.transaction(async (trx) => {
      const team = await trx('user_teams').where({ id: teamId }).first('tenant_id') as { tenant_id: number } | undefined;
      if (!team) throw new Error(`Team ${teamId} not found`);
      if (scope !== 'ungrouped') {
        const table = scope === 'group' ? 'device_groups' : 'devices';
        if (!(await trx(table).where({ id: scopeId, tenant_id: team.tenant_id }).first('id'))) {
          throw new Error(`${scope} ${scopeId} is not in the tenant of team ${teamId}`);
        }
      }
      const existing = await trx('team_permissions').where({ team_id: teamId, scope, scope_id: scopeId }).first('id') as { id: number } | undefined;
      const [row] = existing
        ? await trx<PermissionRow>('team_permissions').where({ id: existing.id }).update({ level }).returning('*')
        : await trx<PermissionRow>('team_permissions')
          .insert({ team_id: teamId, tenant_id: team.tenant_id, scope, scope_id: scopeId, level })
          .returning('*');
      return rowToPermission(row);
    });
  },

  async removePermission(permissionId: number): Promise<boolean> {
    const count = await db('team_permissions').where({ id: permissionId }).del();
    return count > 0;
  },
};
