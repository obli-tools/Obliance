import type { Request } from 'express';
import { db } from '../db';
import { logger } from '../utils/logger';
import { auditService } from './audit.service';
import { obligateService } from './obligate.service';

// Device identity v2 — server side.
//
// An upgraded agent keeps its legacy UUID (X-Device-UUID) until we answer its
// push with X-Obli-Device-Id-Ack. Until then it sends the shared ID it wants
// (X-Obli-Device-Id) and the IDs it claims to have used before
// (X-Obli-Previous-Ids). A claimed row is re-keyed ("adopted") only when the
// presenting key may act for it AND the hostname matches: a machine sharing a
// junk SMBIOS UUID with another must not take over the other's history.

export const IDENTITY_HEADER_TARGET = 'x-obli-device-id';
export const IDENTITY_HEADER_PREVIOUS = 'x-obli-previous-ids';
export const IDENTITY_HEADER_ACK = 'X-Obli-Device-Id-Ack';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_CLAIMS = 8;

export interface IdentityClaim {
  target: string;
  claims: string[];
}

function normUuid(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  return UUID_RE.test(s) ? s : null;
}

function shortHost(h: unknown): string {
  return typeof h === 'string' ? h.trim().toLowerCase().split('.')[0] : '';
}

/** Key binding rule shared with the WS channel: a row bound to another key
 *  of the tenant is not ours to act on. */
function keyMayActFor(row: { api_key_id: number | null }, apiKeyId: number): boolean {
  return row.api_key_id == null || row.api_key_id === apiKeyId;
}

/** uuid null = ignore the v2 headers for this push (no ack): the agent stays
 *  on its legacy ID, exactly as a v1 agent would — never worse than v1. */
export type PushIdentityResult = { uuid: string | null; adoptedFrom: string | null; deviceId: number | null };

export const deviceIdentityService = {
  /** Reads the v2 headers; null when absent or malformed (v1 agent). */
  parseHeaders(req: Request): IdentityClaim | null {
    const target = normUuid(req.headers[IDENTITY_HEADER_TARGET]);
    if (!target) return null;
    const raw = req.headers[IDENTITY_HEADER_PREVIOUS];
    const list = (Array.isArray(raw) ? raw.join(',') : (raw ?? '')).split(',');
    const claims: string[] = [];
    for (const c of list) {
      const u = normUuid(c);
      if (u && u !== target && !claims.includes(u)) claims.push(u);
      if (claims.length >= MAX_CLAIMS) break;
    }
    return { target, claims };
  },

  /**
   * Decides which UUID the push is about, adopting a claimed row when
   * allowed. The caller then looks the device up / registers it under
   * `uuid` and answers with the ack header.
   */
  async resolvePush(opts: {
    tenantId: number;
    apiKeyId: number;
    hostname: string | undefined;
    claim: IdentityClaim;
  }): Promise<PushIdentityResult> {
    const { tenantId, apiKeyId, hostname, claim } = opts;
    const { target, claims } = claim;

    // 1. Already keyed by the shared ID (normal case after the switch, or a
    //    replay after a lost ack). devices.uuid is unique across tenants.
    const existing = await db('devices').where({ uuid: target }).first('id', 'tenant_id', 'api_key_id');
    if (existing) {
      if (existing.tenant_id !== tenantId) {
        logger.warn({ target, tenantId, ownerTenant: existing.tenant_id }, 'identity v2: shared ID already enrolled in another tenant — switch not acknowledged');
        return { uuid: null, adoptedFrom: null, deviceId: null };
      }
      if (!keyMayActFor(existing, apiKeyId)) {
        logger.warn({ deviceId: existing.id, target, apiKeyId }, 'identity v2: shared ID bound to another API key — switch not acknowledged');
        return { uuid: null, adoptedFrom: null, deviceId: null };
      }
      return { uuid: target, adoptedFrom: null, deviceId: existing.id };
    }

    // 2. Adopt the first claimable row.
    const host = shortHost(hostname);
    for (const old of claims) {
      const row = await db('devices').where({ uuid: old, tenant_id: tenantId })
        .first('id', 'api_key_id', 'hostname');
      if (!row) continue;
      if (!keyMayActFor(row, apiKeyId)) {
        logger.warn({ deviceId: row.id, old, target }, 'identity v2: claim refused (API key not bound to the claimed device)');
        await auditService.log({ tenantId, deviceId: row.id, action: 'device.identity_claim_refused', details: { from: old, to: target, reason: 'api_key' } });
        continue;
      }
      if (!host || shortHost(row.hostname) !== host) {
        logger.warn({ deviceId: row.id, old, target, rowHost: row.hostname, pushHost: hostname }, 'identity v2: claim refused (hostname differs: another machine with the same legacy ID)');
        await auditService.log({ tenantId, deviceId: row.id, action: 'device.identity_claim_refused', details: { from: old, to: target, reason: 'hostname', hostname: hostname ?? null } });
        continue;
      }
      const adopted = await db.transaction(async (trx) => {
        // Re-check under lock: two pushes racing for the same row.
        const locked = await trx('devices').where({ id: row.id, uuid: old }).forUpdate().first('id');
        if (!locked) return false;
        await trx('device_uuid_aliases').insert({ device_id: row.id, tenant_id: tenantId, uuid: old, reason: 'migrated' });
        await trx('devices').where({ id: row.id }).update({ uuid: target, updated_at: new Date() });
        return true;
      });
      if (!adopted) continue;
      logger.info({ deviceId: row.id, from: old, to: target }, 'identity v2: device re-keyed to the shared ID');
      await this.followReach(old, target, tenantId);
      await auditService.log({ tenantId, deviceId: row.id, action: 'device.identity_migrated', details: { from: old, to: target } });
      // The old link stays registered: apps that have not migrated yet still
      // match this device through it.
      void obligateService.registerDeviceLink(target, `/devices/${row.id}`);
      return { uuid: target, adoptedFrom: old, deviceId: row.id };
    }

    // 3. Nothing adoptable: the caller registers a new row under the shared ID.
    return { uuid: target, adoptedFrom: null, deviceId: null };
  },

  /**
   * Device lookup for every agent endpoint except the push: by UUID, then by
   * alias (requests in flight while the agent switches). Same tenant, key
   * binding enforced on the alias path, most recent alias wins.
   */
  async findDevice<T = any>(uuid: string, tenantId: number, apiKeyId?: number): Promise<T | undefined> {
    const direct = await db('devices').where({ uuid, tenant_id: tenantId }).first();
    if (direct) return direct as T;
    const u = normUuid(uuid);
    if (!u) return undefined;
    const q = db('device_uuid_aliases as a')
      .join('devices as d', 'd.id', 'a.device_id')
      .where({ 'a.uuid': u, 'a.tenant_id': tenantId, 'd.tenant_id': tenantId })
      .orderBy('a.created_at', 'desc')
      .select('d.*');
    if (apiKeyId != null) {
      q.where(function () { this.whereNull('d.api_key_id').orWhere('d.api_key_id', apiKeyId); });
    }
    return (await q.first()) as T | undefined;
  },

  /**
   * The device row moved old -> new: the ObliReach side follows (its row and
   * live channel are keyed by devices.uuid; the ObliReach agent itself may
   * still report the old ID until it migrates on its own).
   */
  async followReach(oldUuid: string, newUuid: string, tenantId: number): Promise<void> {
    try {
      const clash = await db('oblireach_devices').where({ device_uuid: newUuid, tenant_id: tenantId }).first('id');
      if (clash) {
        // The ObliReach agent already reported under the new ID: drop the stale row.
        await db('oblireach_devices').where({ device_uuid: oldUuid, tenant_id: tenantId }).delete();
      } else {
        await db('oblireach_devices').where({ device_uuid: oldUuid, tenant_id: tenantId })
          .update({ device_uuid: newUuid, legacy_uuid: oldUuid });
      }
      const { oblireachHub } = await import('./oblireachHub.service');
      oblireachHub.rekey(oldUuid, newUuid, tenantId);
    } catch (err) {
      logger.error({ err, oldUuid, newUuid }, 'identity v2: ObliReach re-key failed');
    }
  },

  /**
   * The uuid an ObliReach agent's traffic is filed under: the devices.uuid of
   * its machine whenever we can tell, so everything keyed by devices.uuid
   * (sessions, chat, queue, UI) keeps working whichever agent migrated first.
   * Order: the shared ID, the agent's current ID, its claims, then aliases.
   * Unknown everywhere (standalone ObliReach agent): the shared ID if
   * announced, else the agent's own.
   */
  async canonicalReachUuid(incoming: string, claim: IdentityClaim | null, tenantId: number): Promise<string> {
    const cands = [...new Set([claim?.target, normUuid(incoming) ?? incoming, ...(claim?.claims ?? [])]
      .filter((v): v is string => !!v))];
    for (const c of cands) {
      const row = await db('devices').where({ uuid: c, tenant_id: tenantId }).first('id');
      if (row) return c;
    }
    for (const c of cands) {
      const viaAlias = await db('device_uuid_aliases as a')
        .join('devices as d', 'd.id', 'a.device_id')
        .where({ 'a.uuid': c, 'a.tenant_id': tenantId })
        .orderBy('a.created_at', 'desc')
        .first('d.uuid');
      if (viaAlias) return viaAlias.uuid as string;
    }
    return claim?.target ?? incoming;
  },

  /** Previous UUIDs of a device (newest first). */
  async aliasesOf(deviceId: number): Promise<string[]> {
    const rows = await db('device_uuid_aliases').where({ device_id: deviceId })
      .orderBy('created_at', 'desc').select('uuid');
    return [...new Set(rows.map((r: { uuid: string }) => r.uuid))];
  },

  /** Every UUID the device is or was known by: current first. */
  async allUuidsOf(device: { id: number; uuid: string }): Promise<string[]> {
    return [device.uuid, ...(await this.aliasesOf(device.id)).filter((u) => u !== device.uuid)];
  },
};
