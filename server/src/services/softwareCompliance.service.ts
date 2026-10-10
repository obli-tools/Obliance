import { db } from '../db';
import { isMasterTenant, MASTER_TENANT_ID } from '@obliance/shared';
import { isGodView } from '../utils/globalView';
import { commandService } from './command.service';
import type {
  SoftwareComplianceList, SoftwareComplianceEntry, SoftwareComplianceResult, SoftwareComplianceEntryResult,
  KnownSoftwareApp, SoftwareEntrySourceConfig, SoftwareEntryAlternative, SoftwareOsCondition, SoftwareMatchType,
} from '@obliance/shared';
import { manualIdsForWrite, toIdList } from '../utils/groupTargets';
import { resolveGroupTargetGroupIds } from './groupTargets.service';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import {
  deviceOsFacts, matchOsCondition, parseStoredOsCondition, sanitizeOsCondition,
  type DeviceOsFacts, type SoftwareDeviceOsRow,
} from '../utils/softwareOsCondition';
import {
  MAX_ALTERNATIVES, aggregateEntryResult, alternativeEligible, alternativeInstallable, applyInstallAck,
  buildAgentEntries, commandOutcome, complianceScore, decideRemediation, emptyRemediationState,
  entryAlternatives, isPlainEntry, remediationInfo, startManualCycle,
  type AgentEntryResult, type CommandOutcome, type RemediationAlternative, type RemediationDecision,
  type RemediationStateData,
} from '../utils/softwareAlternatives';

const MATCH_TYPES: readonly SoftwareMatchType[] = ['exact', 'contains', 'regex'];
const PLATFORMS = ['windows', 'linux', 'macos', 'freebsd', 'all'];
/** Columns of `devices` the OS conditions read. */
const DEVICE_OS_COLUMNS = ['id', 'tenant_id', 'os_type', 'os_name', 'os_version', 'os_build', 'os_distro'] as const;
type DeviceOsRecord = SoftwareDeviceOsRow & { id: number; tenant_id: number };

interface NormalizedAlternative {
  name: string;
  matchType: SoftwareMatchType;
  publisher: string | null;
  minVersion: string | null;
  maxVersion: string | null;
  osCondition: SoftwareOsCondition | null;
  sources: any[];
  legacy: { installSource: string | null; installId: string | null; installScript: string | null; msiUrl: string | null; msiParams: string | null };
}
interface NormalizedEntry { label: string | null; sortOrder: number; alternatives: NormalizedAlternative[] }

const s = (v: unknown, max = 500): string | null => {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  return t ? t.slice(0, max) : null;
};

class SoftwareComplianceService {
  // ─── Row mappers ──────────────────────────────────────────────────────────
  rowToList(row: any): SoftwareComplianceList {
    const targetPlatform = row.target_platform || 'all';
    return {
      id: row.id, uuid: row.uuid, tenantId: row.tenant_id,
      name: row.name, description: row.description,
      listType: row.list_type,
      targetType: row.target_type,
      targetIds: Array.isArray(row.target_ids) ? row.target_ids : (typeof row.target_ids === 'string' ? JSON.parse(row.target_ids) : []),
      targetManualGroupIds: toIdList(row.target_manual_group_ids),
      targetPlatform,
      osCondition: targetPlatform === 'all' ? null : (parseStoredOsCondition(row.os_condition) ?? null),
      autoRemediate: row.auto_remediate,
      enabled: row.enabled,
      entries: [],
      createdBy: row.created_by, createdAt: row.created_at, updatedAt: row.updated_at,
    };
  }

  private rowToAlternative(row: any, sources: SoftwareEntrySourceConfig[]): SoftwareEntryAlternative {
    return {
      id: row.id, name: row.name, matchType: row.match_type,
      publisher: row.publisher ?? null, minVersion: row.min_version ?? null, maxVersion: row.max_version ?? null,
      sources, osCondition: parseStoredOsCondition(row.os_condition),
    };
  }

  /**
   * An entry from its row (= its first alternative) and the rows of its
   * alternatives 2..N (parent_entry_id = row.id, by alt_order).
   */
  rowToEntry(row: any, sources: SoftwareEntrySourceConfig[] = [], children: Array<{ row: any; sources: SoftwareEntrySourceConfig[] }> = []): SoftwareComplianceEntry {
    const first = this.rowToAlternative(row, sources);
    return {
      id: row.id, listId: row.list_id,
      name: row.name, matchType: row.match_type,
      publisher: row.publisher, minVersion: row.min_version,
      maxVersion: row.max_version, installSource: row.install_source,
      installId: row.install_id, installScript: row.install_script,
      msiUrl: row.msi_url ?? null, msiParams: row.msi_params ?? null,
      sortOrder: row.sort_order,
      sources,
      label: row.label ?? null,
      osCondition: first.osCondition,
      alternatives: [first, ...children.map((c) => this.rowToAlternative(c.row, c.sources))],
    };
  }

  rowToSource(row: any): SoftwareEntrySourceConfig {
    return {
      id: row.id, entryId: row.entry_id,
      packageManager: row.package_manager,
      packageId: row.package_id ?? null,
      msiUrl: row.msi_url ?? null,
      repoPackageId: row.repo_package_id ?? null,
      repoPackageUuid: row.repo_package_uuid ?? null,
      installScript: row.install_script ?? null,
      msiParams: row.msi_params ?? null,
      platformScope: row.platform_scope,
      sortOrder: row.sort_order ?? 0,
    };
  }

  /** Load sources for a set of entry IDs, optionally joining repo package UUID */
  private async loadSources(entryIds: number[], trx?: any): Promise<Record<number, SoftwareEntrySourceConfig[]>> {
    if (!entryIds.length) return {};
    const q = (trx || db)('software_compliance_entry_sources as s')
      .leftJoin('software_repo_packages as rp', 'rp.id', 's.repo_package_id')
      .whereIn('s.entry_id', entryIds)
      .orderBy('s.sort_order')
      .select('s.*', 'rp.uuid as repo_package_uuid');
    const rows = await q;
    const map: Record<number, SoftwareEntrySourceConfig[]> = {};
    for (const r of rows) {
      if (!map[r.entry_id]) map[r.entry_id] = [];
      map[r.entry_id].push(this.rowToSource(r));
    }
    return map;
  }

  /** Entries (with their alternatives and sources) of the given lists, by list id. */
  private async loadEntries(listIds: number[], trx?: any): Promise<Record<number, SoftwareComplianceEntry[]>> {
    if (!listIds.length) return {};
    const rows = await (trx || db)('software_compliance_entries')
      .whereIn('list_id', listIds)
      .orderBy([{ column: 'sort_order' }, { column: 'alt_order' }, { column: 'id' }]);
    const sourcesMap = await this.loadSources(rows.map((r: any) => r.id), trx);
    const children: Record<number, Array<{ row: any; sources: SoftwareEntrySourceConfig[] }>> = {};
    for (const r of rows) {
      if (r.parent_entry_id == null) continue;
      (children[r.parent_entry_id] ??= []).push({ row: r, sources: sourcesMap[r.id] || [] });
    }
    const byList: Record<number, SoftwareComplianceEntry[]> = {};
    for (const r of rows) {
      if (r.parent_entry_id != null) continue;
      const kids = (children[r.id] || []).sort((a, b) => (a.row.alt_order ?? 0) - (b.row.alt_order ?? 0) || a.row.id - b.row.id);
      (byList[r.list_id] ??= []).push(this.rowToEntry(r, sourcesMap[r.id] || [], kids));
    }
    return byList;
  }

  rowToResult(row: any): SoftwareComplianceResult {
    return {
      id: row.id, deviceId: row.device_id,
      deviceName: row.device_name ?? null,
      listId: row.list_id, tenantId: row.tenant_id,
      results: row.results || [], complianceScore: parseFloat(row.compliance_score),
      checkedAt: row.checked_at, createdAt: row.created_at,
    };
  }

  // ─── Entries input ────────────────────────────────────────────────────────
  /**
   * Request entries → validated entries with 1..MAX_ALTERNATIVES alternatives.
   * Accepts the old shape (top-level fields only = one alternative).
   */
  private normalizeEntries(raw: unknown): NormalizedEntry[] {
    if (!Array.isArray(raw)) return [];
    return raw.map((e: any, i: number) => {
      const altsRaw: any[] = Array.isArray(e?.alternatives) && e.alternatives.length > 0 ? e.alternatives : [e];
      if (altsRaw.length > MAX_ALTERNATIVES) {
        throw new AppError(400, `An entry cannot have more than ${MAX_ALTERNATIVES} alternatives`, 'SW_TOO_MANY_ALTERNATIVES');
      }
      const alternatives = altsRaw.map((a: any, ai: number): NormalizedAlternative => {
        const name = s(a?.name);
        if (!name) throw new AppError(400, `Entry ${i + 1}: every alternative needs a software name`, 'SW_ALTERNATIVE_NAME_REQUIRED');
        const sources = (Array.isArray(a?.sources) ? a.sources : []).filter((x: any) => x && typeof x.packageManager === 'string' && x.packageManager);
        // The legacy columns: from the first source, else (old clients, first
        // alternative only) the top-level legacy fields.
        const legacySrc = ai === 0 ? a : {};
        return {
          name,
          matchType: MATCH_TYPES.includes(a?.matchType) ? a.matchType : 'contains',
          publisher: s(a?.publisher),
          minVersion: s(a?.minVersion, 100),
          maxVersion: s(a?.maxVersion, 100),
          osCondition: sanitizeOsCondition(a?.osCondition),
          sources,
          legacy: {
            installSource: sources[0]?.packageManager || s(legacySrc.installSource, 100),
            installId: sources[0]?.packageId || s(legacySrc.installId),
            installScript: sources[0]?.installScript || (typeof legacySrc.installScript === 'string' && legacySrc.installScript ? legacySrc.installScript : null),
            msiUrl: sources[0]?.msiUrl || (typeof legacySrc.msiUrl === 'string' && legacySrc.msiUrl ? legacySrc.msiUrl : null),
            msiParams: sources[0]?.msiParams || (typeof legacySrc.msiParams === 'string' && legacySrc.msiParams ? legacySrc.msiParams : null),
          },
        };
      });
      return {
        label: s(e?.label, 300),
        sortOrder: Number.isInteger(e?.sortOrder) ? e.sortOrder : i,
        alternatives,
      };
    });
  }

  private altRow(listId: number, a: NormalizedAlternative) {
    return {
      list_id: listId, name: a.name, match_type: a.matchType, publisher: a.publisher,
      min_version: a.minVersion, max_version: a.maxVersion,
      install_source: a.legacy.installSource, install_id: a.legacy.installId,
      install_script: a.legacy.installScript, msi_url: a.legacy.msiUrl, msi_params: a.legacy.msiParams,
      os_condition: a.osCondition ? JSON.stringify(a.osCondition) : null,
    };
  }

  /** Insert the entries of a list (entry rows, then alternatives 2..N, then sources). */
  private async writeEntries(trx: any, listId: number, entries: NormalizedEntry[]): Promise<void> {
    if (!entries.length) return;
    const parents = await trx('software_compliance_entries').insert(entries.map((e) => ({
      ...this.altRow(listId, e.alternatives[0]),
      sort_order: e.sortOrder, label: e.label, alt_order: 0, parent_entry_id: null,
    }))).returning('*');

    const rowAlts: Array<{ id: number; alt: NormalizedAlternative }> = [];
    const childRows: any[] = [];
    const childAlts: NormalizedAlternative[] = [];
    entries.forEach((e, i) => {
      rowAlts.push({ id: parents[i].id, alt: e.alternatives[0] });
      e.alternatives.slice(1).forEach((a, ai) => {
        childRows.push({
          ...this.altRow(listId, a),
          sort_order: parents[i].sort_order, label: null, alt_order: ai + 1, parent_entry_id: parents[i].id,
        });
        childAlts.push(a);
      });
    });
    if (childRows.length) {
      const kids = await trx('software_compliance_entries').insert(childRows).returning('*');
      kids.forEach((k: any, i: number) => rowAlts.push({ id: k.id, alt: childAlts[i] }));
    }

    // A repository package: MSI sources only, and only a package of the
    // list's tenant or of the master tenant (the agent download route
    // enforces the same rule).
    const wantedRepo = [...new Set(rowAlts.flatMap(({ alt }) => alt.sources
      .filter((s: any) => s.packageManager === 'msi' && Number.isInteger(Number(s.repoPackageId)) && Number(s.repoPackageId) > 0)
      .map((s: any) => Number(s.repoPackageId))))];
    const allowedRepo = new Set<number>();
    if (wantedRepo.length) {
      const owner = await trx('software_compliance_lists').where({ id: listId }).first('tenant_id');
      const rows = await trx('software_repo_packages').whereIn('id', wantedRepo)
        .whereIn('tenant_id', [owner?.tenant_id ?? -1, MASTER_TENANT_ID]).select('id');
      rows.forEach((r: any) => allowedRepo.add(Number(r.id)));
    }
    const repoOf = (src: any): number | null =>
      src.packageManager === 'msi' && allowedRepo.has(Number(src.repoPackageId)) ? Number(src.repoPackageId) : null;

    const srcRows = rowAlts.flatMap(({ id, alt }) => alt.sources.map((src: any, si: number) => ({
      entry_id: id,
      package_manager: String(src.packageManager).slice(0, 20),
      package_id: src.packageId || null,
      msi_url: repoOf(src) ? null : (src.msiUrl || null),
      repo_package_id: repoOf(src),
      install_script: src.installScript || null,
      msi_params: src.msiParams ? String(src.msiParams).slice(0, 4000) : null,
      platform_scope: src.platformScope || 'any',
      sort_order: src.sortOrder ?? si,
    })));
    if (srcRows.length) await trx('software_compliance_entry_sources').insert(srcRows);
  }

  // ─── Lists CRUD ───────────────────────────────────────────────────────────
  async getLists(tenantId: number): Promise<SoftwareComplianceList[]> {
    const rows = await db('software_compliance_lists').where({ tenant_id: tenantId });
    const entriesByList = await this.loadEntries(rows.map((r: any) => r.id));
    return rows.map((r: any) => ({ ...this.rowToList(r), entries: entriesByList[r.id] || [] }));
  }

  async getListById(id: number, tenantId: number, trx?: any): Promise<SoftwareComplianceList | null> {
    const row = await (trx || db)('software_compliance_lists').where({ id, tenant_id: tenantId }).first();
    if (!row) return null;
    const entriesByList = await this.loadEntries([id], trx);
    return { ...this.rowToList(row), entries: entriesByList[id] || [] };
  }

  async createList(
    tenantId: number,
    data: {
      name: string; description?: string; listType: string; targetType: string;
      targetIds: number[]; targetManualGroupIds?: number[]; targetPlatform: string; autoRemediate: boolean;
      osCondition?: unknown;
      entries: any[]; enabled?: boolean; createdBy?: number;
    },
  ): Promise<SoftwareComplianceList> {
    const entries = this.normalizeEntries(data.entries);
    const targetPlatform = PLATFORMS.includes(data.targetPlatform) ? data.targetPlatform : 'all';
    const id = await db.transaction(async (trx) => {
      const [row] = await trx('software_compliance_lists').insert({
        tenant_id: tenantId, name: data.name, description: data.description,
        list_type: data.listType || 'blacklist',
        target_type: data.targetType || 'all',
        target_ids: JSON.stringify(data.targetIds || []),
        target_manual_group_ids: JSON.stringify(manualIdsForWrite({ ...data, targetType: data.targetType || 'all' }) ?? []),
        target_platform: targetPlatform,
        os_condition: this.listOsConditionJson(data.osCondition, targetPlatform),
        auto_remediate: data.autoRemediate ?? false,
        enabled: data.enabled !== false,
        created_by: data.createdBy,
      }).returning('*');
      await this.writeEntries(trx, row.id, entries);
      return row.id as number;
    });
    return (await this.getListById(id, tenantId))!;
  }

  private listOsConditionJson(raw: unknown, targetPlatform: string): string | null {
    if (targetPlatform === 'all') return null;
    const c = sanitizeOsCondition(raw, targetPlatform);
    // A bare platform carries nothing the target platform does not already say.
    if (!c || (!c.distro && !c.minVersion && !c.maxVersion && !c.edition)) return null;
    return JSON.stringify(c);
  }

  async updateList(
    id: number, tenantId: number,
    data: Partial<{
      name: string; description: string; listType: string; targetType: string;
      targetIds: number[]; targetManualGroupIds: number[]; targetPlatform: string; autoRemediate: boolean;
      osCondition: unknown;
      enabled: boolean; entries: any[];
    }>,
  ): Promise<SoftwareComplianceList | null> {
    const entries = data.entries !== undefined ? this.normalizeEntries(data.entries) : undefined;
    const done = await db.transaction(async (trx) => {
      // Ownership first: the entries below are keyed by list id only.
      const current = await trx('software_compliance_lists').where({ id, tenant_id: tenantId })
        .first('target_type', 'target_ids', 'target_manual_group_ids', 'target_platform', 'os_condition');
      if (!current) return false;

      const updates: any = { updated_at: new Date() };
      if (data.name !== undefined) updates.name = data.name;
      if (data.description !== undefined) updates.description = data.description;
      if (data.listType !== undefined) updates.list_type = data.listType;
      if (data.targetType !== undefined) updates.target_type = data.targetType;
      if (data.targetIds !== undefined) updates.target_ids = JSON.stringify(data.targetIds);
      if (data.targetPlatform !== undefined && PLATFORMS.includes(data.targetPlatform)) updates.target_platform = data.targetPlatform;
      if (updates.target_platform !== undefined || data.osCondition !== undefined) {
        const platform = updates.target_platform ?? current.target_platform ?? 'all';
        // Platform changed without a new condition: the old bounds meant another OS.
        const raw = data.osCondition !== undefined ? data.osCondition
          : (platform === current.target_platform ? current.os_condition : null);
        updates.os_condition = this.listOsConditionJson(typeof raw === 'string' ? JSON.parse(raw) : raw, platform);
      }
      if (data.targetType !== undefined || data.targetIds !== undefined || data.targetManualGroupIds !== undefined) {
        const manual = manualIdsForWrite(data, current);
        if (manual !== undefined) updates.target_manual_group_ids = JSON.stringify(manual);
      }
      if (data.autoRemediate !== undefined) updates.auto_remediate = data.autoRemediate;
      if (data.enabled !== undefined) updates.enabled = data.enabled;

      await trx('software_compliance_lists').where({ id, tenant_id: tenantId }).update(updates);

      if (entries !== undefined) {
        // Cascade delete handles alternatives, sources and remediation state.
        await trx('software_compliance_entries').where({ list_id: id }).delete();
        await this.writeEntries(trx, id, entries);
      }
      return true;
    });
    return done ? this.getListById(id, tenantId) : null;
  }

  async deleteList(id: number, tenantId: number): Promise<void> {
    await db('software_compliance_lists').where({ id, tenant_id: tenantId }).delete();
  }

  // ─── Results ──────────────────────────────────────────────────────────────
  async getLatestResults(deviceId: number, tenantId: number): Promise<SoftwareComplianceResult[]> {
    const rows = await db('software_compliance_results as sr')
      .leftJoin('software_compliance_lists as sl', 'sl.id', 'sr.list_id')
      .leftJoin('devices as d', 'd.id', 'sr.device_id')
      .where({ 'sr.device_id': deviceId, 'sr.tenant_id': tenantId })
      .orderBy('sr.checked_at', 'desc')
      .limit(200)
      .select(
        'sr.*',
        'sl.name as list_name',
        'sl.list_type as list_type',
        db.raw(`COALESCE(NULLIF(d.display_name, ''), d.hostname) AS device_name`),
      );
    return rows.map((row: any) => {
      const result = this.rowToResult(row);
      if (row.list_name) {
        result.list = { id: row.list_id, name: row.list_name, listType: row.list_type };
      }
      return result;
    });
  }

  async getAllResults(tenantId: number, page = 1, limit = 100, deviceId?: number): Promise<SoftwareComplianceResult[]> {
    const offset = (page - 1) * limit;
    let q = db('software_compliance_results as sr')
      .leftJoin('software_compliance_lists as sl', 'sl.id', 'sr.list_id')
      .leftJoin('devices as d', 'd.id', 'sr.device_id')
      .where({ 'sr.tenant_id': tenantId })
      .orderBy('sr.checked_at', 'desc')
      .limit(limit)
      .offset(offset)
      .select(
        'sr.*',
        'sl.name as list_name',
        'sl.list_type as list_type',
        db.raw(`COALESCE(NULLIF(d.display_name, ''), d.hostname) AS device_name`),
      );
    if (deviceId) q = q.where({ 'sr.device_id': deviceId });
    const rows = await q;
    return rows.map((row: any) => {
      const result = this.rowToResult(row);
      if (row.list_name) {
        result.list = { id: row.list_id, name: row.list_name, listType: row.list_type };
      }
      return result;
    });
  }

  async storeResults(
    deviceId: number,
    tenantId: number,
    listId: number,
    results: SoftwareComplianceEntryResult[],
    score: number,
  ): Promise<SoftwareComplianceResult> {
    const [row] = await db('software_compliance_results')
      .insert({
        device_id: deviceId,
        list_id: listId,
        tenant_id: tenantId,
        results: JSON.stringify(results),
        compliance_score: score,
        checked_at: new Date(),
      })
      .returning('*');

    // Hydrate list name for the socket event
    const list = await db('software_compliance_lists').where({ id: listId, tenant_id: tenantId }).first('id', 'name', 'list_type');
    const result = this.rowToResult(row);
    if (list) {
      result.list = { id: list.id, name: list.name, listType: list.list_type };
    }
    return result;
  }

  /**
   * Results posted by the agent (POST /api/agent/software-compliance): the
   * per-alternative results are folded into one result per entry, the
   * server-driven remediation advances, then the result is stored. Returns
   * null (nothing stored) when the list is not the device tenant's or the
   * device is outside the list's platform / OS condition.
   */
  async processAgentResults(
    device: DeviceOsRecord, tenantId: number, listId: number, raw: unknown[], rawScore: unknown,
  ): Promise<SoftwareComplianceResult | null> {
    // The device tenant's list, or a master-tenant list (god-view check of
    // this device): stored under the device tenant, as before.
    const owner = await db('software_compliance_lists').where({ id: listId }).first('tenant_id');
    if (!owner || (owner.tenant_id !== tenantId && !isMasterTenant(owner.tenant_id))) return null;
    const list = await this.getListById(listId, owner.tenant_id);
    if (!list) return null;
    const facts = deviceOsFacts(device);
    if (!this.deviceInScope(list, facts)) return null;

    const agentResults: AgentEntryResult[] = raw
      .filter((r): r is Record<string, any> => !!r && typeof r === 'object')
      .map((r) => ({ ...r, entryId: Number(r.entryId) } as AgentEntryResult));
    const byId = new Map(agentResults.map((r) => [r.entryId, r]));
    const known = new Set<number>();
    for (const e of list.entries) {
      known.add(e.id);
      for (const a of entryAlternatives(e)) if (a.id != null) known.add(a.id);
    }
    // Payload built before the last edit of the list (ids re-created): stored as sent.
    if (agentResults.some((r) => !known.has(r.entryId))) {
      const score = Number(rawScore);
      return this.storeResults(device.id, tenantId, listId, agentResults as unknown as SoftwareComplianceEntryResult[], Number.isFinite(score) ? score : complianceScore(agentResults));
    }

    const results: SoftwareComplianceEntryResult[] = [];
    for (const entry of list.entries) {
      const agg = aggregateEntryResult(entry, list.listType, byId);
      if (!agg) continue;
      if (list.listType === 'whitelist' && !isPlainEntry(entry) && agg.status !== 'error') {
        try {
          await this.remediationStep(device, list, entry, facts, agg);
        } catch (err) {
          logger.error({ err, deviceId: device.id, listId, entryId: entry.id }, 'Software remediation step failed');
        }
      }
      results.push(agg);
    }
    return this.storeResults(device.id, tenantId, listId, results, complianceScore(results));
  }

  private stateFromRow(row: any): RemediationStateData {
    const attempts = Array.isArray(row?.attempts) ? row.attempts : (typeof row?.attempts === 'string' ? JSON.parse(row.attempts) : []);
    const iso = (v: any) => (v ? new Date(v).toISOString() : null);
    return {
      attempts,
      cycleStartedAt: iso(row?.cycle_started_at),
      exhaustedAt: iso(row?.exhausted_at),
      succeededAlternativeId: row?.succeeded_alternative_id ?? null,
      succeededAt: iso(row?.succeeded_at),
      failedCycles: Number(row?.failed_cycles ?? 0) || 0,
    };
  }

  private stateToRow(st: RemediationStateData) {
    return {
      attempts: JSON.stringify(st.attempts.slice(-MAX_ALTERNATIVES * 2)),
      cycle_started_at: st.cycleStartedAt ? new Date(st.cycleStartedAt) : null,
      exhausted_at: st.exhaustedAt ? new Date(st.exhaustedAt) : null,
      succeeded_alternative_id: st.succeededAlternativeId,
      succeeded_at: st.succeededAt ? new Date(st.succeededAt) : null,
      failed_cycles: st.failedCycles ?? 0,
      updated_at: new Date(),
    };
  }

  private remediationAlternatives(entry: SoftwareComplianceEntry, facts: DeviceOsFacts): RemediationAlternative[] {
    return entryAlternatives(entry).map((a) => ({
      id: a.id ?? entry.id, eligible: alternativeEligible(a, facts), installable: alternativeInstallable(a),
    }));
  }

  private async commandOutcomes(trx: any, st: RemediationStateData): Promise<Record<string, CommandOutcome>> {
    const ids = st.attempts.filter((a) => a.outcome === 'pending' && a.commandId).map((a) => a.commandId!) as string[];
    if (!ids.length) return {};
    const rows = await trx('command_queue').whereIn('id', ids).select('id', 'status', 'expires_at', 'created_at');
    const now = new Date();
    const out: Record<string, CommandOutcome> = {};
    for (const id of ids) out[id] = commandOutcome(rows.find((r: any) => r.id === id), now);
    return out;
  }

  /** Queue the install of the decision's alternative; records the command id (or the failure) in the state. */
  private async enqueueAlternativeInstall(
    stateRowId: number, device: DeviceOsRecord, list: SoftwareComplianceList, entry: SoftwareComplianceEntry,
    decision: RemediationDecision, createdBy: number | null,
  ) {
    const alts = entryAlternatives(entry);
    const idx = alts.findIndex((a) => (a.id ?? entry.id) === decision.install);
    const alt = alts[idx];
    const attempt = decision.state.attempts[decision.state.attempts.length - 1];
    try {
      const s0 = alt.sources?.[0];
      const cmd = await commandService.enqueue({
        deviceId: device.id, tenantId: list.tenantId, type: 'install_software',
        payload: {
          listId: list.id, entryId: entry.id, entryName: alt.name,
          alternativeId: decision.install, alternativeIndex: idx + 1, remediationId: stateRowId,
          // Legacy fields for older agents
          installSource: s0?.packageManager ?? null, installId: s0?.packageId ?? null,
          installScript: s0?.installScript ?? null, msiUrl: s0?.msiUrl ?? null, msiParams: s0?.msiParams ?? null,
          sources: alt.sources ?? [],
        },
        priority: 'low', expiresInSeconds: 600,
        sourceType: 'software_remediation', sourceId: String(stateRowId),
        createdBy: createdBy ?? undefined,
      });
      attempt.commandId = cmd.id;
      return cmd;
    } catch (err) {
      attempt.outcome = 'install_failed';
      attempt.finishedAt = new Date().toISOString();
      attempt.detail = 'could not queue the install command';
      logger.error({ err, deviceId: device.id, entryId: entry.id }, 'Software remediation: enqueue failed');
      return null;
    }
  }

  /**
   * One step of the server-driven remediation of a whitelist entry with
   * alternatives (utils/softwareAlternatives.ts decideRemediation), under a
   * row lock on its (device, entry) state. Mutates `agg` (status + info).
   */
  private async remediationStep(
    device: DeviceOsRecord, list: SoftwareComplianceList, entry: SoftwareComplianceEntry,
    facts: DeviceOsFacts, agg: SoftwareComplianceEntryResult,
  ): Promise<void> {
    const detected = agg.status === 'compliant';
    const existing = await db('software_compliance_remediations').where({ device_id: device.id, entry_id: entry.id }).first('id');
    // Nothing to remember: no state yet, and nothing to start.
    if (!existing && (detected || !list.autoRemediate)) return;

    const alternatives = entryAlternatives(entry);
    const named = alternatives.map((a) => ({ id: a.id ?? entry.id, name: a.name }));
    await db.transaction(async (trx) => {
      await trx.raw(
        `INSERT INTO software_compliance_remediations (tenant_id, device_id, list_id, entry_id)
         VALUES (?, ?, ?, ?) ON CONFLICT (device_id, entry_id) DO NOTHING`,
        [list.tenantId, device.id, list.id, entry.id],
      );
      const row = await trx('software_compliance_remediations')
        .where({ device_id: device.id, entry_id: entry.id }).forUpdate().first();
      const state = this.stateFromRow(row);
      const checkedAt = agg.checkedAt ? new Date(agg.checkedAt) : new Date();
      const decision = decideRemediation({
        state, detected, checkedAt: Number.isNaN(checkedAt.getTime()) ? new Date() : checkedAt, now: new Date(),
        autoRemediate: list.autoRemediate,
        alternatives: this.remediationAlternatives(entry, facts),
        commands: await this.commandOutcomes(trx, state),
      });
      if (decision.install != null) {
        await this.enqueueAlternativeInstall(row.id, device, list, entry, decision, list.createdBy ?? null);
      }
      await trx('software_compliance_remediations').where({ id: row.id }).update(this.stateToRow(decision.state));

      agg.status = decision.status;
      agg.remediation = remediationInfo(decision, named);
      if (decision.remediationState === 'installing') {
        agg.remediationTriggered = true;
        const alt = agg.remediation?.alternativeName;
        agg.detail = alt ? `installing alternative: ${alt}` : agg.detail;
      } else if (decision.remediationState === 'exhausted') {
        agg.detail = 'every eligible alternative was tried';
      } else if (decision.remediationState === 'failed') {
        agg.detail = 'install failed: every alternative failed, retries included';
      } else if (decision.remediationState === 'no_eligible' && !detected) {
        agg.detail = 'no alternative can be installed on this device';
      } else if (decision.status === 'remediated') {
        agg.remediationTriggered = true;
        agg.detail = 'software installed successfully';
      }
    });
  }

  /**
   * Ack of an install command queued by the remediation (command.service).
   * Records the attempt's outcome and queues the post-install check right
   * away: detected → done; failed / not detected → next alternative.
   */
  async onRemediationAck(cmdRow: any, success: boolean, errorText: string | null): Promise<void> {
    const stateId = parseInt(String(cmdRow.source_id), 10);
    if (!Number.isInteger(stateId)) return;
    const deviceId = Number(cmdRow.device_id);
    let listId: number | null = null;
    let tenantId: number | null = null;
    let createdBy: number | null = null;
    await db.transaction(async (trx) => {
      const row = await trx('software_compliance_remediations')
        .where({ id: stateId, device_id: deviceId, tenant_id: Number(cmdRow.tenant_id) }).forUpdate().first();
      if (!row) return;
      const next = applyInstallAck(this.stateFromRow(row), String(cmdRow.id), success, errorText, new Date());
      if (!next) return;
      await trx('software_compliance_remediations').where({ id: row.id }).update(this.stateToRow(next));
      listId = row.list_id;
      tenantId = row.tenant_id;
      createdBy = cmdRow.created_by ?? null;
    });
    if (listId == null || tenantId == null) return;
    try {
      await this.triggerCheck(deviceId, listId, tenantId, createdBy ?? undefined, { strict: false, internal: true });
    } catch (err) {
      logger.error({ err, deviceId, listId }, 'Software remediation: post-install check not queued');
    }
  }

  // ─── Triggering ───────────────────────────────────────────────────────────
  /** Platform + OS condition of the list. */
  deviceInScope(list: Pick<SoftwareComplianceList, 'targetPlatform' | 'osCondition'>, facts: DeviceOsFacts): boolean {
    if (list.targetPlatform && list.targetPlatform !== 'all' && facts.platform !== list.targetPlatform) return false;
    return matchOsCondition(list.osCondition ?? null, facts);
  }

  private checkPayload(list: SoftwareComplianceList, facts: DeviceOsFacts, onlyEntryIds?: ReadonlySet<number>) {
    return {
      listId: list.id, listType: list.listType,
      entries: buildAgentEntries(list.entries, list.listType, facts, onlyEntryIds),
      autoRemediate: onlyEntryIds ? true : list.autoRemediate,
    };
  }

  private async loadDevice(deviceId: number, tenantId: number, internal = false): Promise<DeviceOsRecord | null> {
    const q = db('devices').where({ id: deviceId });
    if (!internal && !isGodView(tenantId)) q.where({ tenant_id: tenantId });
    return (await q.first(...DEVICE_OS_COLUMNS)) ?? null;
  }

  /**
   * Check one device against one list. A device outside the list's platform /
   * OS condition is not evaluated: `strict` → 409, else null.
   */
  async triggerCheck(
    deviceId: number, listId: number, tenantId: number, createdBy?: number,
    opts: { strict?: boolean; internal?: boolean } = {},
  ) {
    const strict = opts.strict !== false;
    const list = await this.getListById(listId, tenantId);
    if (!list) throw new AppError(404, 'List not found');
    const device = await this.loadDevice(deviceId, tenantId, opts.internal);
    if (!device) throw new AppError(404, 'Device not found');
    const facts = deviceOsFacts(device);
    if (!this.deviceInScope(list, facts)) {
      if (strict) throw new AppError(409, 'This device is outside the platform / OS versions of the list', 'SW_LIST_OUT_OF_SCOPE');
      return null;
    }

    return commandService.enqueue({
      deviceId, tenantId, type: 'check_software_compliance',
      payload: this.checkPayload(list, facts),
      priority: 'normal', expiresInSeconds: 600, createdBy,
    });
  }

  /** Online approved target devices of a list (groups + platform + OS condition). */
  private async targetDevices(list: SoftwareComplianceList): Promise<Array<{ device: DeviceOsRecord; facts: DeviceOsFacts }>> {
    let deviceQuery = db('devices')
      .where({ tenant_id: list.tenantId, approval_status: 'approved' })
      .whereIn('status', ['online', 'warning', 'critical']);

    if (list.targetPlatform && list.targetPlatform !== 'all') {
      deviceQuery = deviceQuery.where({ os_type: list.targetPlatform });
    }
    if (list.targetType === 'group' && list.targetIds.length > 0) {
      // Devices of these groups (+ descendants, except manual groups)
      const allGroupIds = await resolveGroupTargetGroupIds({ groupIds: list.targetIds, manualGroupIds: list.targetManualGroupIds });
      deviceQuery = deviceQuery.whereIn('group_id', allGroupIds);
    }
    const rows: DeviceOsRecord[] = await deviceQuery.select(...DEVICE_OS_COLUMNS);
    return rows
      .map((device) => ({ device, facts: deviceOsFacts(device) }))
      .filter(({ facts }) => matchOsCondition(list.osCondition ?? null, facts));
  }

  /**
   * Trigger a compliance check across ALL target devices of a list at once.
   * Useful for "scan now" after creating/editing a list — no need to wait
   * for the 6h scheduled sweep. Returns the number of devices enqueued.
   */
  async triggerCheckForList(listId: number, tenantId: number, createdBy: number): Promise<number> {
    const list = await this.getListById(listId, tenantId);
    if (!list) throw new Error('List not found');

    let enqueued = 0;
    for (const { device, facts } of await this.targetDevices(list)) {
      try {
        await commandService.enqueue({
          deviceId: device.id, tenantId, type: 'check_software_compliance',
          payload: this.checkPayload(list, facts),
          priority: 'normal', expiresInSeconds: 600, createdBy,
        });
        enqueued++;
      } catch { /* device offline / queue full — skip silently */ }
    }
    return enqueued;
  }

  /**
   * Manual remediation of entries on one device:
   *  - plain entries: install / uninstall command, as always;
   *  - whitelist entries with alternatives: a fresh remediation cycle from the
   *    first eligible alternative (then the post-install checks carry on);
   *  - blacklist entries with alternatives: one check run that removes every
   *    detected alternative eligible on the device.
   */
  async triggerRemediation(
    deviceId: number, listId: number, entryIds: number[],
    tenantId: number, createdBy: number,
  ) {
    const list = await this.getListById(listId, tenantId);
    if (!list) throw new Error('List not found');

    const wanted = new Set(entryIds.map(Number));
    const entriesToRemediate = list.entries.filter(e => wanted.has(e.id));
    if (entriesToRemediate.length === 0) throw new Error('No matching entries found');

    const cmdType = list.listType === 'whitelist' ? 'install_software' : 'uninstall_software';
    const plain = entriesToRemediate.filter((e) => isPlainEntry(e));
    const withAlternatives = entriesToRemediate.filter((e) => !isPlainEntry(e));

    const cmds: any[] = await Promise.all(plain.map(entry =>
      commandService.enqueue({
        deviceId, tenantId, type: cmdType as any,
        payload: {
          listId, entryId: entry.id, entryName: entry.name,
          // Legacy fields for backward compat with older agents
          installSource: entry.installSource, installId: entry.installId,
          installScript: entry.installScript,
          msiUrl: entry.msiUrl, msiParams: entry.msiParams,
          // New multi-source array
          sources: entry.sources,
        },
        priority: 'low', expiresInSeconds: 300, createdBy,
      })
    ));
    if (!withAlternatives.length) return cmds;

    const device = await this.loadDevice(deviceId, tenantId);
    if (!device) throw new AppError(404, 'Device not found');
    const facts = deviceOsFacts(device);

    if (list.listType === 'blacklist') {
      cmds.push(await commandService.enqueue({
        deviceId, tenantId, type: 'check_software_compliance',
        payload: this.checkPayload(list, facts, new Set(withAlternatives.map((e) => e.id))),
        priority: 'normal', expiresInSeconds: 600, createdBy,
      }));
      return cmds;
    }

    let noEligible = 0;
    for (const entry of withAlternatives) {
      await db.transaction(async (trx) => {
        await trx.raw(
          `INSERT INTO software_compliance_remediations (tenant_id, device_id, list_id, entry_id)
           VALUES (?, ?, ?, ?) ON CONFLICT (device_id, entry_id) DO NOTHING`,
          [list.tenantId, deviceId, list.id, entry.id],
        );
        const row = await trx('software_compliance_remediations')
          .where({ device_id: deviceId, entry_id: entry.id }).forUpdate().first();
        const state = row ? this.stateFromRow(row) : emptyRemediationState();
        const decision = startManualCycle({
          state, now: new Date(),
          alternatives: this.remediationAlternatives(entry, facts),
          commands: await this.commandOutcomes(trx, state),
        });
        if (!decision) return; // an install of this entry is still running
        if (decision.install == null) { noEligible++; return; }
        const cmd = await this.enqueueAlternativeInstall(row.id, device, list, entry, decision, createdBy);
        await trx('software_compliance_remediations').where({ id: row.id }).update(this.stateToRow(decision.state));
        if (cmd) cmds.push(cmd);
      });
    }
    if (cmds.length === 0 && noEligible > 0) {
      throw new AppError(409, 'No alternative of these entries can be installed on this device', 'SW_NO_ELIGIBLE_ALTERNATIVE');
    }
    return cmds;
  }

  // ─── Known apps ──────────────────────────────────────────────────────────
  async getKnownApps(tenantId: number, osType?: string, search?: string): Promise<KnownSoftwareApp[]> {
    // The 500 most installed apps — filtered BEFORE that limit by the search
    // (name or publisher), so an app present on one machine is found too.
    // God view: the devices of every tenant, like the other fleet aggregates.
    let q = db('device_inventory_software as s')
      .join('devices as d', 'd.id', 's.device_id')
      .groupByRaw('LOWER(s.name), s.publisher, s.source')
      .select(
        db.raw('MIN(s.name) as name'),
        's.publisher',
        's.source',
        db.raw('MIN(s.package_id) as package_id'),
        db.raw('MIN(d.os_type) as os_type'),
        db.raw('COUNT(DISTINCT s.device_id) as device_count'),
        db.raw('MAX(s.version) as latest_version'),
      )
      .orderBy('device_count', 'desc')
      .orderBy('name', 'asc')
      .limit(500);

    if (!isGodView(tenantId)) q = q.where({ 'd.tenant_id': tenantId });
    if (osType) {
      q = q.where({ 'd.os_type': osType });
    }
    const term = (search ?? '').trim().slice(0, 100);
    if (term) {
      const like = `%${term.replace(/[\\%_]/g, (c) => '\\' + c)}%`;
      q = q.where(function () { this.whereILike('s.name', like).orWhereILike('s.publisher', like); });
    }

    const rows = await q;
    return rows.map((r: any) => ({
      name: r.name,
      publisher: r.publisher ?? null,
      source: r.source,
      packageId: r.package_id ?? null,
      osType: r.os_type,
      deviceCount: parseInt(r.device_count, 10),
      latestVersion: r.latest_version ?? null,
    }));
  }

  // ─── Scheduled checks ────────────────────────────────────────────────────
  /**
   * Run software compliance checks for all enabled lists across all tenants.
   * Called periodically by index.ts (default every 6h).
   * Skips devices that were already checked within the interval.
   */
  async runScheduledChecks(intervalMs: number) {
    const rows = await db('software_compliance_lists').where({ enabled: true });
    const cutoff = new Date(Date.now() - intervalMs);

    for (const row of rows) {
      // Entries (alternatives + sources) of the list
      const entries = (await this.loadEntries([row.id]))[row.id] || [];
      if (!entries.length) continue;
      const list: SoftwareComplianceList = { ...this.rowToList(row), entries };

      // Target devices — groups, platform and OS condition
      for (const { device, facts } of await this.targetDevices(list)) {
        // Skip if already checked recently
        const lastCheck = await db('software_compliance_results')
          .where({ device_id: device.id, list_id: list.id })
          .orderBy('checked_at', 'desc')
          .first();

        if (lastCheck && new Date(lastCheck.checked_at) > cutoff) continue;

        try {
          await commandService.enqueue({
            deviceId: device.id, tenantId: list.tenantId,
            type: 'check_software_compliance',
            payload: this.checkPayload(list, facts),
            priority: 'low', expiresInSeconds: 600, createdBy: list.createdBy ?? 0,
          });
        } catch {
          // Device may be offline or queue full — skip silently
        }
      }
    }
  }
}

export const softwareComplianceService = new SoftwareComplianceService();
