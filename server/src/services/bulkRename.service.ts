// Bulk rename ("name replacer") — export the devices of ONE tenant as CSV,
// re-import a CSV of old name → new name, preview, then apply in a single
// transaction.
//
// What a rename changes: `devices.display_name` ONLY (the Obliance alias the
// pencil on the device page edits, same rules: services/deviceName.ts). The
// hostname reported by the agent is never touched and nothing is sent to the
// agent.
//
// Tenant isolation (the whole point of this file):
//  - every query is bounded by `devices.tenant_id = <target>` — the target is
//    the session tenant, or, for a platform admin on the master tenant only,
//    one tenant chosen explicitly (no "all tenants" export, the master god
//    view does NOT apply here);
//  - a non-admin only ever sees / renames the devices of the session tenant
//    on which his teams give him write access (the single-rename rule:
//    requireDeviceWrite → permissionService.canWriteDevice);
//  - an uuid / a name of a device outside that scope is "not found", the same
//    answer as a device that does not exist (no existence oracle);
//  - the preview is kept server-side behind a random token bound to the user,
//    the session tenant and the target; the apply works on that stored plan
//    only (no second parsing) and re-checks the scope inside the transaction.

import crypto from 'node:crypto';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { isMasterTenant } from '@obliance/shared';
import { permissionService } from './permission.service';
import { validateDeviceDisplayName, effectiveDeviceName, type DeviceNameError } from './deviceName';

export const BULK_RENAME_MAX_ROWS = 10_000;
export const BULK_RENAME_MAX_BYTES = 2 * 1024 * 1024;
export const BULK_RENAME_PREVIEW_TTL_MS = 15 * 60_000;
const MAX_STORED_PREVIEWS = 200;

export interface BulkRenameCaller {
  userId: number;
  /** Platform admin (users.role = 'admin'). */
  isAdmin: boolean;
  /** req.tenantId — the session's current tenant. */
  sessionTenantId: number;
}

export type Delimiter = ',' | ';' | '\t';

export type RowStatus =
  | 'ok' | 'unchanged' | 'not_found' | 'ambiguous' | 'invalid_name' | 'duplicate' | 'missing_key';

export type RowWarning = 'duplicate_new_name' | 'name_in_use';

export interface PreviewRow {
  /** Record number in the file (the header, when present, is record 1). */
  line: number;
  status: RowStatus;
  warnings: RowWarning[];
  /** What the file said (echoed back: the caller's own data). */
  input: { uuid: string | null; oldName: string | null; newName: string };
  matchedBy: 'uuid' | 'name' | 'hostname' | null;
  /** Only for a device inside the caller's scope. */
  deviceId: number | null;
  uuid: string | null;
  hostname: string | null;
  currentName: string | null;
  newName: string | null;
  invalidReason: DeviceNameError | null;
  /** ambiguous: how many devices of the scope carry that name. */
  candidates: number | null;
}

export interface PreviewResult {
  token: string;
  expiresAt: string;
  targetTenantId: number;
  delimiter: Delimiter;
  headerDetected: boolean;
  rows: PreviewRow[];
  counts: Record<RowStatus | 'total' | 'empty' | 'warnings', number>;
}

interface ScopeDevice {
  id: number;
  uuid: string;
  hostname: string;
  display_name: string | null;
}

interface PlanEntry { line: number; deviceId: number; from: string | null; to: string }

interface StoredPreview {
  userId: number;
  sessionTenantId: number;
  targetTenantId: number;
  expiresAt: number;
  plan: Map<number, PlanEntry>; // line → entry (status ok only)
  previewRows: number;
  busy: boolean;
}

const previews = new Map<string, StoredPreview>();

function sweep(now = Date.now()): void {
  for (const [k, v] of previews) if (v.expiresAt <= now) previews.delete(k);
}

/** Test hook. */
export function _resetBulkRenamePreviews(): void { previews.clear(); }
/** Test hook: expire every stored preview. */
export function _expireBulkRenamePreviews(): void { for (const v of previews.values()) v.expiresAt = 0; }

// ─── Target tenant + scope ──────────────────────────────────────────────────

/**
 * The tenant the operation works on. Always explicit. Equal to the session
 * tenant, except for a platform admin on the master tenant who may name any
 * existing tenant. Anything else is refused without saying whether that
 * tenant exists.
 */
export async function resolveTargetTenant(caller: BulkRenameCaller, raw: unknown): Promise<number> {
  const target = typeof raw === 'number' ? raw : (typeof raw === 'string' && /^\d{1,9}$/.test(raw.trim()) ? Number(raw.trim()) : NaN);
  if (!Number.isInteger(target) || target <= 0) {
    throw new AppError(400, 'A target tenant is required', 'bulk_rename_target_required');
  }
  if (target === caller.sessionTenantId) return target;
  if (caller.isAdmin && isMasterTenant(caller.sessionTenantId)) {
    const t = await db('tenants').where({ id: target }).first('id');
    if (!t) throw new AppError(404, 'Tenant not found', 'bulk_rename_tenant_not_found');
    return target;
  }
  throw new AppError(403, 'Insufficient permissions', 'bulk_rename_target_forbidden');
}

/** Ids of the target tenant's devices the caller may rename. */
async function scopeIds(caller: BulkRenameCaller, targetTenantId: number, candidateIds?: number[]): Promise<Set<number> | 'all'> {
  if (caller.isAdmin) return 'all';
  const visible = await permissionService.getVisibleDeviceIds(caller.userId, false);
  if (visible === 'all') return 'all';
  let ids = visible;
  if (candidateIds) { const c = new Set(candidateIds); ids = ids.filter((id) => c.has(id)); }
  if (ids.length === 0) return new Set();
  // Bound to the target tenant BEFORE the per-device write check.
  const inTenant = await db('devices').whereIn('id', ids).andWhere('tenant_id', targetTenantId).pluck('id') as number[];
  const out = new Set<number>();
  for (const id of inTenant) {
    if (await permissionService.canWriteDevice(caller.userId, id, false)) out.add(id);
  }
  return out;
}

async function scopeDevices(caller: BulkRenameCaller, targetTenantId: number): Promise<ScopeDevice[]> {
  const rows = await db('devices')
    .where('tenant_id', targetTenantId)
    .select('id', 'uuid', 'hostname', 'display_name') as ScopeDevice[];
  const scope = await scopeIds(caller, targetTenantId);
  return scope === 'all' ? rows : rows.filter((r) => scope.has(r.id));
}

// ─── CSV helpers ─────────────────────────────────────────────────────────────

export function parseDelimiter(raw: unknown): Delimiter {
  const s = typeof raw === 'string' ? raw : '';
  if (s === ';' || s === 'semicolon') return ';';
  if (s === '\t' || s === 'tab') return '\t';
  return ',';
}

/** CSV cell with formula-injection protection: a cell starting with
 *  = + - @ TAB or CR is prefixed with an apostrophe (OWASP), then quoted when
 *  it holds the delimiter, a quote, a line break or edge spaces. */
export function csvCell(v: unknown, delim: Delimiter): string {
  let s = v === null || v === undefined ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  if (s.includes(delim) || /["\r\n]/.test(s) || s !== s.trim()) s = `"${s.replace(/"/g, '""')}"`;
  return s;
}

/** Undo csvCell's apostrophe (only that exact signature). */
function unescapeCell(s: string): string {
  return /^'[=+\-@\t\r]/.test(s) ? s.slice(1) : s;
}

/** First record's delimiter: the most frequent of ; , TAB outside quotes. */
export function detectDelimiter(text: string): Delimiter | null {
  const counts: Record<Delimiter, number> = { ';': 0, ',': 0, '\t': 0 };
  let inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { inQ = !inQ; continue; }
    if (!inQ && (c === '\n' || c === '\r')) break;
    if (!inQ && (c === ';' || c === ',' || c === '\t')) counts[c]++;
  }
  const best = (Object.keys(counts) as Delimiter[]).sort((a, b) => counts[b] - counts[a])[0];
  return counts[best] > 0 ? best : null;
}

/** RFC 4180 parser (quoted fields, "" escapes, CRLF / LF / CR). Returns the
 *  records with their 1-based record number. */
export function parseCsv(text: string, delim: Delimiter): Array<{ line: number; cells: string[] }> {
  const out: Array<{ line: number; cells: string[] }> = [];
  let row: string[] = [];
  let field = '';
  let inQ = false;
  let record = 1;
  const push = () => { row.push(field); field = ''; };
  const end = () => { push(); out.push({ line: record++, cells: row }); row = []; };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false;
      } else field += c;
      continue;
    }
    // Opening quote (tolerates spaces before it: `a; "b;c"`).
    if (c === '"' && field.trim() === '') { field = ''; inQ = true; continue; }
    if (c === delim) { push(); continue; }
    if (c === '\r') { if (text[i + 1] === '\n') i++; end(); continue; }
    if (c === '\n') { end(); continue; }
    field += c;
  }
  if (field !== '' || row.length > 0) end();
  return out;
}

const COMBINING_MARKS = new RegExp(`[${String.fromCharCode(0x300)}-${String.fromCharCode(0x36f)}]`, 'g');
const norm = (s: string) => s.normalize('NFD').replace(COMBINING_MARKS, '').toLowerCase().replace(/[\s_\-.]+/g, '');
const UUID_HEADERS = new Set(['deviceuuid', 'uuid', 'agentuuid', 'uuidappareil']);
const OLD_HEADERS = new Set(['oldname', 'anciennom', 'currentname', 'nomactuel', 'name', 'nom', 'displayname', 'old', 'ancien']);
const HOST_HEADERS = new Set(['hostname', 'host', 'computername', 'nommachine']);
const NEW_HEADERS = new Set(['newname', 'nouveaunom', 'new', 'nouveau']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface InputRow { line: number; uuid: string | null; oldName: string | null; newName: string }

function readRows(text: string, delimHint?: Delimiter | null): { rows: InputRow[]; delimiter: Delimiter; headerDetected: boolean } {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const delimiter = delimHint ?? detectDelimiter(text);
  if (!delimiter) throw new AppError(400, 'The file needs at least two columns (old name and new name)', 'bulk_rename_two_columns');
  const records = parseCsv(text, delimiter)
    .filter((r) => r.cells.some((c) => c.trim() !== ''));
  if (records.length === 0) throw new AppError(400, 'The file is empty', 'bulk_rename_empty_file');

  const head = records[0].cells.map((c) => norm(c));
  const idx = (set: Set<string>) => head.findIndex((h) => set.has(h));
  const iNew = idx(NEW_HEADERS);
  let iUuid = idx(UUID_HEADERS);
  let iOld = idx(OLD_HEADERS);
  let iHost = idx(HOST_HEADERS);
  let headerDetected = false;
  let body = records;
  let jNew: number;
  if (iNew >= 0) {
    if (iUuid < 0 && iOld < 0 && iHost < 0) {
      throw new AppError(400, 'The header has no device_uuid / old_name / hostname column', 'bulk_rename_no_key_column');
    }
    headerDetected = true;
    body = records.slice(1);
    jNew = iNew;
  } else {
    // No header: column 1 = uuid or old name, column 2 = new name.
    if (records.some((r) => r.cells.length < 2)) {
      throw new AppError(400, 'The file needs at least two columns (old name and new name)', 'bulk_rename_two_columns');
    }
    iUuid = -1; iOld = 0; iHost = -1; jNew = 1;
  }
  if (body.length > BULK_RENAME_MAX_ROWS) {
    throw new AppError(400, `Too many rows (max ${BULK_RENAME_MAX_ROWS})`, 'bulk_rename_too_many_rows');
  }
  const cell = (cells: string[], i: number) => (i >= 0 && i < cells.length ? unescapeCell(cells[i]).trim() : '');
  const rows: InputRow[] = body.map((r) => {
    let uuid = cell(r.cells, iUuid);
    let oldName = cell(r.cells, iOld) || cell(r.cells, iHost);
    if (!headerDetected && UUID_RE.test(oldName)) { uuid = oldName; oldName = ''; }
    return { line: r.line, uuid: uuid || null, oldName: oldName || null, newName: cell(r.cells, jNew) };
  });
  return { rows, delimiter, headerDetected };
}

// ─── Export ──────────────────────────────────────────────────────────────────

export const EXPORT_COLUMNS = [
  'device_uuid', 'current_name', 'hostname', 'serial', 'manufacturer', 'model', 'os', 'os_version', 'group',
  'ip_local', 'ip_public', 'mac_addresses', 'last_user', 'domain', 'last_seen', 'status', 'new_name',
] as const;

// Placeholder serials some OEM boards report (not a serial).
const JUNK_SERIAL = /^(to be filled by o\.?e\.?m\.?|default string|system serial number|system manufacturer|system product name|not specified|not applicable|none|n\/a|0+|x+|\.+|base board serial number)$/i;
const cleanSerial = (v: unknown): string => {
  const s = typeof v === 'string' ? v.trim() : '';
  return s && !JUNK_SERIAL.test(s) ? s : '';
};

/**
 * Logon domain of the last user ("ACME\\jdupont" → ACME, "j@acme.fr" →
 * acme.fr). A local account (domain part = the machine's hostname) or a bare
 * user name gives ''. The agent does not report the machine's AD membership:
 * this is the best signal Obliance holds.
 */
export function logonDomain(lastUser: unknown, hostname: unknown): string {
  const u = typeof lastUser === 'string' ? lastUser.trim() : '';
  let dom = '';
  const bs = u.indexOf('\\');
  if (bs > 0) dom = u.slice(0, bs);
  else { const at = u.lastIndexOf('@'); if (at > 0 && at < u.length - 1) dom = u.slice(at + 1); }
  dom = dom.trim();
  const host = typeof hostname === 'string' ? hostname.trim() : '';
  if (!dom || (host && dom.toLowerCase() === host.toLowerCase()) || dom === '.') return '';
  return dom;
}

const jval = (v: unknown): any => {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string') { try { return JSON.parse(v); } catch { return null; } }
  return v;
};

export async function buildExport(caller: BulkRenameCaller, targetTenantId: number, delim: Delimiter): Promise<{ csv: string; count: number; tenantSlug: string }> {
  const tenant = await db('tenants').where({ id: targetTenantId }).first('slug') as { slug: string } | undefined;
  const devices = await db('devices')
    .where('tenant_id', targetTenantId)
    .select('id', 'uuid', 'hostname', 'display_name', 'status', 'os_type', 'os_name', 'os_version', 'group_id',
      'ip_local', 'ip_public', 'mac_address', 'last_logged_in_user', 'last_seen_at') as any[];
  const scope = await scopeIds(caller, targetTenantId);
  const rows = scope === 'all' ? devices : devices.filter((d) => scope.has(d.id));

  // Group path ("Paris / Compta"), groups of the target tenant only.
  const groups = await db('device_groups').where('tenant_id', targetTenantId).select('id', 'parent_id', 'name') as Array<{ id: number; parent_id: number | null; name: string }>;
  const gById = new Map(groups.map((g) => [g.id, g]));
  const gPath = (id: number | null): string => {
    const parts: string[] = [];
    const seen = new Set<number>();
    let cur = id !== null ? gById.get(id) : undefined;
    while (cur && !seen.has(cur.id)) { seen.add(cur.id); parts.unshift(cur.name); cur = cur.parent_id !== null ? gById.get(cur.parent_id) : undefined; }
    return parts.join(' / ');
  };

  // Latest hardware scan per device (board manufacturer / model, NIC MACs).
  // Serial / maker / model: the MACHINE first (maker's serial = Dell service
  // tag: raw.wmi.bios.serial on Windows, raw.dmi.product_serial on Linux;
  // raw.wmi.system / raw.dmi for maker and model — agents that report them),
  // then the board (motherboard.serial, raw.wmi.mb.serial). Only those keys
  // are read out of `raw`.
  type Hw = { motherboard: any; nics: any; serials: Array<string | null>; sysMaker: string | null; sysModel: string | null };
  const hw = new Map<number, Hw>();
  if (rows.length > 0) {
    const hwRows = await db.raw(
      `SELECT DISTINCT ON (h.device_id) h.device_id, h.motherboard, h.network_interfaces,
              h.raw->'wmi'->'bios'->>'serial'       AS bios_serial,
              h.raw->'dmi'->>'product_serial'       AS dmi_serial,
              h.raw->'wmi'->'mb'->>'serial'         AS mb_raw_serial,
              COALESCE(NULLIF(h.raw->'wmi'->'system'->>'manufacturer', ''), NULLIF(h.raw->'dmi'->>'sys_vendor', ''))  AS sys_maker,
              COALESCE(NULLIF(h.raw->'wmi'->'system'->>'model', ''),        NULLIF(h.raw->'dmi'->>'product_name', '')) AS sys_model
         FROM device_inventory_hardware h
         JOIN devices d ON d.id = h.device_id AND d.tenant_id = ?
        ORDER BY h.device_id, h.scanned_at DESC`, [targetTenantId]);
    for (const r of (hwRows.rows ?? hwRows) as any[]) {
      const mb = jval(r.motherboard) ?? {};
      hw.set(r.device_id, {
        motherboard: mb, nics: jval(r.network_interfaces),
        serials: [r.bios_serial, r.dmi_serial, mb.serial, r.mb_raw_serial],
        sysMaker: cleanSerial(r.sys_maker) ? r.sys_maker.trim() : null,
        sysModel: cleanSerial(r.sys_model) ? r.sys_model.trim() : null,
      });
    }
  }

  rows.sort((a, b) => effectiveDeviceName(a).localeCompare(effectiveDeviceName(b), undefined, { sensitivity: 'base' }));
  const lines: string[] = [EXPORT_COLUMNS.join(delim)];
  for (const d of rows) {
    const h = hw.get(d.id);
    const macs: string[] = [];
    const addMac = (m: unknown) => {
      const s = typeof m === 'string' ? m.trim().toUpperCase() : '';
      if (s && !/^(00[:-]){5}00$/.test(s) && !macs.includes(s)) macs.push(s);
    };
    addMac(d.mac_address);
    if (Array.isArray(h?.nics)) for (const n of h!.nics) addMac(n?.mac);
    const mb = h?.motherboard ?? {};
    const values: Record<(typeof EXPORT_COLUMNS)[number], unknown> = {
      device_uuid: d.uuid,
      current_name: effectiveDeviceName(d),
      hostname: d.hostname,
      serial: (h?.serials ?? []).map(cleanSerial).find((x) => x !== '') ?? '',
      status: d.status,
      os: d.os_name || d.os_type,
      os_version: d.os_version,
      group: gPath(d.group_id ?? null),
      ip_local: d.ip_local,
      ip_public: d.ip_public,
      mac_addresses: macs.join(' '),
      last_user: d.last_logged_in_user,
      domain: logonDomain(d.last_logged_in_user, d.hostname),
      last_seen: d.last_seen_at ? new Date(d.last_seen_at).toISOString() : '',
      manufacturer: h?.sysMaker ?? mb.manufacturer ?? '',
      model: h?.sysModel ?? mb.model ?? mb.product ?? '',
      new_name: '',
    };
    lines.push(EXPORT_COLUMNS.map((c) => csvCell(values[c], delim)).join(delim));
  }
  return { csv: String.fromCharCode(0xfeff) + lines.join('\r\n') + '\r\n', count: rows.length, tenantSlug: tenant?.slug ?? String(targetTenantId) };
}

// ─── Preview ─────────────────────────────────────────────────────────────────

export async function preview(caller: BulkRenameCaller, targetTenantId: number, text: string, delimHint?: Delimiter | null): Promise<PreviewResult> {
  if (Buffer.byteLength(text, 'utf8') > BULK_RENAME_MAX_BYTES) {
    throw new AppError(413, 'File too large (max 2 MB)', 'bulk_rename_too_large');
  }
  const { rows: input, delimiter, headerDetected } = readRows(text, delimHint);
  const devices = await scopeDevices(caller, targetTenantId);

  const byUuid = new Map<string, ScopeDevice>();
  const byName = new Map<string, ScopeDevice[]>();
  const byHost = new Map<string, ScopeDevice[]>();
  const add = (m: Map<string, ScopeDevice[]>, k: string, d: ScopeDevice) => { const a = m.get(k); if (a) a.push(d); else m.set(k, [d]); };
  for (const d of devices) {
    byUuid.set(String(d.uuid).toLowerCase(), d);
    add(byName, effectiveDeviceName(d).trim().toLowerCase(), d);
    if (d.hostname) add(byHost, d.hostname.trim().toLowerCase(), d);
  }

  const rows: PreviewRow[] = [];
  let empty = 0;
  for (const r of input) {
    if (r.newName === '') { empty++; continue; }
    const row: PreviewRow = {
      line: r.line, status: 'ok', warnings: [],
      input: { uuid: r.uuid, oldName: r.oldName, newName: r.newName },
      matchedBy: null, deviceId: null, uuid: null, hostname: null, currentName: null, newName: null,
      invalidReason: null, candidates: null,
    };
    let dev: ScopeDevice | undefined;
    if (r.uuid) {
      dev = byUuid.get(r.uuid.toLowerCase());
      if (dev) row.matchedBy = 'uuid'; else row.status = 'not_found';
    } else if (r.oldName) {
      const k = r.oldName.toLowerCase();
      const byN = byName.get(k) ?? [];
      const byH = byN.length === 0 ? (byHost.get(k) ?? []) : [];
      const hits = byN.length > 0 ? byN : byH;
      if (hits.length === 1) { dev = hits[0]; row.matchedBy = byN.length > 0 ? 'name' : 'hostname'; }
      else if (hits.length > 1) { row.status = 'ambiguous'; row.candidates = hits.length; }
      else row.status = 'not_found';
    } else {
      row.status = 'missing_key';
    }
    if (dev) {
      row.deviceId = dev.id;
      row.uuid = dev.uuid;
      row.hostname = dev.hostname;
      row.currentName = effectiveDeviceName(dev);
      const v = validateDeviceDisplayName(r.newName);
      if (!v.ok) { row.status = 'invalid_name'; row.invalidReason = v.reason; }
      else {
        row.newName = v.value;
        if (v.value === row.currentName) row.status = 'unchanged';
      }
    }
    rows.push(row);
  }

  // The same device twice in the file: none of those rows is applied.
  const perDevice = new Map<number, PreviewRow[]>();
  for (const r of rows) if (r.deviceId !== null) { const a = perDevice.get(r.deviceId); if (a) a.push(r); else perDevice.set(r.deviceId, [r]); }
  for (const list of perDevice.values()) if (list.length > 1) for (const r of list) r.status = 'duplicate';

  // Warnings (names are not unique in Obliance: informative only).
  const okRows = rows.filter((r) => r.status === 'ok');
  const renamed = new Map(okRows.map((r) => [r.deviceId!, r.newName!]));
  const finalCount = new Map<string, number>();
  for (const d of devices) {
    const k = (renamed.get(d.id) ?? effectiveDeviceName(d)).trim().toLowerCase();
    finalCount.set(k, (finalCount.get(k) ?? 0) + 1);
  }
  const newCount = new Map<string, number>();
  for (const r of okRows) { const k = r.newName!.toLowerCase(); newCount.set(k, (newCount.get(k) ?? 0) + 1); }
  for (const r of okRows) {
    const k = r.newName!.toLowerCase();
    if ((newCount.get(k) ?? 0) > 1) r.warnings.push('duplicate_new_name');
    else if ((finalCount.get(k) ?? 0) > 1) r.warnings.push('name_in_use');
  }

  const counts = { total: input.length, empty, ok: 0, unchanged: 0, not_found: 0, ambiguous: 0, invalid_name: 0, duplicate: 0, missing_key: 0, warnings: 0 } as PreviewResult['counts'];
  for (const r of rows) { counts[r.status]++; if (r.warnings.length) counts.warnings++; }

  // Store the plan (ok rows only) behind a random token.
  const now = Date.now();
  sweep(now);
  for (const [k, v] of previews) if (v.userId === caller.userId) previews.delete(k); // one live preview per user
  if (previews.size >= MAX_STORED_PREVIEWS) {
    const oldest = [...previews.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt)[0];
    if (oldest) previews.delete(oldest[0]);
  }
  const token = crypto.randomBytes(24).toString('base64url');
  const plan = new Map<number, PlanEntry>();
  const devById = new Map(devices.map((d) => [d.id, d]));
  for (const r of okRows) {
    const d = devById.get(r.deviceId!)!;
    plan.set(r.line, { line: r.line, deviceId: d.id, from: d.display_name ?? null, to: r.newName! });
  }
  const expiresAt = now + BULK_RENAME_PREVIEW_TTL_MS;
  previews.set(token, {
    userId: caller.userId, sessionTenantId: caller.sessionTenantId, targetTenantId,
    expiresAt, plan, previewRows: rows.length, busy: false,
  });

  return { token, expiresAt: new Date(expiresAt).toISOString(), targetTenantId, delimiter, headerDetected, rows, counts };
}

// ─── Apply ───────────────────────────────────────────────────────────────────

export class BulkRenameConflict extends Error {
  constructor(public lines: number[]) { super('changed since preview'); }
}

export interface ApplyResult {
  batchId: string;
  targetTenantId: number;
  renamed: Array<{ deviceId: number; line: number; from: string | null; to: string }>;
  unchanged: number;
}

export async function apply(
  caller: BulkRenameCaller,
  token: unknown,
  lines: unknown,
  ip: string | null,
): Promise<ApplyResult> {
  sweep();
  const entry = typeof token === 'string' ? previews.get(token) : undefined;
  // Unknown, expired, another user's or another session tenant's preview:
  // one answer.
  if (!entry || entry.userId !== caller.userId || entry.sessionTenantId !== caller.sessionTenantId) {
    throw new AppError(404, 'Preview expired — import the file again', 'bulk_rename_preview_expired');
  }
  if (entry.busy) throw new AppError(409, 'This preview is already being applied', 'bulk_rename_busy');
  if (!Array.isArray(lines) || lines.length === 0) {
    throw new AppError(400, 'Nothing selected', 'bulk_rename_nothing_selected');
  }
  const picked: PlanEntry[] = [];
  const seen = new Set<number>();
  for (const l of lines) {
    const p = typeof l === 'number' ? entry.plan.get(l) : undefined;
    if (!p || seen.has(p.line)) throw new AppError(400, 'Invalid selection', 'bulk_rename_invalid_selection');
    seen.add(p.line);
    picked.push(p);
  }
  // The caller's rights now (role / team changes since the preview).
  const target = await resolveTargetTenant(caller, entry.targetTenantId);
  const ids = picked.map((p) => p.deviceId);
  const scope = await scopeIds(caller, target, ids);

  entry.busy = true;
  const batchId = crypto.randomUUID();
  try {
    const result = await db.transaction(async (trx) => {
      const current = await trx('devices')
        .whereIn('id', ids)
        .andWhere('tenant_id', target)
        .forUpdate()
        .select('id', 'hostname', 'display_name') as Array<{ id: number; hostname: string; display_name: string | null }>;
      const curById = new Map(current.map((c) => [c.id, c]));
      const conflicts: number[] = [];
      const todo: Array<PlanEntry & { hostname: string }> = [];
      let unchanged = 0;
      for (const p of picked) {
        const c = curById.get(p.deviceId);
        if (!c || (scope !== 'all' && !scope.has(p.deviceId))) { conflicts.push(p.line); continue; }
        const now = c.display_name ?? null;
        if (now === p.to) { unchanged++; continue; }                       // already applied (idempotent)
        if ((now ?? '') !== (p.from ?? '')) { conflicts.push(p.line); continue; } // renamed by someone else since
        todo.push({ ...p, from: now, hostname: c.hostname });
      }
      if (conflicts.length > 0) throw new BulkRenameConflict(conflicts.sort((a, b) => a - b));

      const at = new Date();
      for (let i = 0; i < todo.length; i += 500) {
        const chunk = todo.slice(i, i + 500);
        const values = chunk.map(() => '(?::int, ?::text)').join(', ');
        const pairs: unknown[] = [];
        for (const t of chunk) pairs.push(t.deviceId, t.to);
        // Bindings follow the placeholders: updated_at, the VALUES pairs, tenant.
        await trx.raw(
          `UPDATE devices AS d SET display_name = v.name, updated_at = ?
             FROM (VALUES ${values}) AS v(id, name)
            WHERE d.id = v.id AND d.tenant_id = ?`,
          [at, ...pairs, target] as any[],
        );
        const audits = chunk.map((t) => ({
          tenant_id: target,
          user_id: caller.userId,
          device_id: t.deviceId,
          action: 'device.rename',
          resource_type: 'device',
          resource_path: String(t.deviceId),
          details: JSON.stringify({ from: t.from, to: t.to, hostname: t.hostname, via: 'bulk_rename', batchId }),
          ip_address: ip,
        }));
        await trx('audit_logs').insert(audits);
      }
      const batchDetails = {
        batchId, renamed: todo.length, unchanged, selected: picked.length, previewRows: entry.previewRows,
        targetTenantId: target,
      };
      await trx('audit_logs').insert({
        tenant_id: target, user_id: caller.userId, device_id: null, action: 'device.bulk_rename',
        resource_type: 'device', resource_path: null, details: JSON.stringify(batchDetails), ip_address: ip,
      });
      if (target !== caller.sessionTenantId) {
        // A master-tenant admin acting on another tenant: trace in both logs.
        await trx('audit_logs').insert({
          tenant_id: caller.sessionTenantId, user_id: caller.userId, device_id: null, action: 'device.bulk_rename',
          resource_type: 'device', resource_path: null, details: JSON.stringify(batchDetails), ip_address: ip,
        });
      }
      return { todo, unchanged };
    });
    previews.delete(token as string);
    return {
      batchId,
      targetTenantId: target,
      renamed: result.todo.map((t) => ({ deviceId: t.deviceId, line: t.line, from: t.from, to: t.to })),
      unchanged: result.unchanged,
    };
  } finally {
    entry.busy = false;
  }
}
