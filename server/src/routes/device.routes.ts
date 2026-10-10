import { Router } from 'express';
import dns from 'dns/promises';
import { deviceService, getAgentVersion } from '../services/device.service';
import { customMetricService } from '../services/customMetric.service';
import { customSectionService } from '../services/customSection.service';
import { commandService } from '../services/command.service';
import { requireRole, requireDeviceRead, requireDeviceWrite, requireTenantCapability } from '../middleware/rbac';
import { permissionService } from '../services/permission.service';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import { launchChromium } from '../utils/chromium';
import { SocketEvents, isMasterTenant } from '@obliance/shared';
import { scenarioService } from '../services/scenario.service';
import { parseRequestDeviceId } from '../services/deviceScope.service';
import { emitDeviceEvents } from '../services/deviceAudience.service';
import { hasGlobalView, isGodView } from '../utils/globalView';
import { logger } from '../utils/logger';

const router = Router();

// Master tenant god view: platform administrators only (utils/globalView.ts).
// A caller that is not a platform admin (a master-tenant admin holding
// devices.manage, an approver, a plain member…) reaches a device of its
// session's tenant only: any other device answers like an unknown one (404),
// on the master tenant too — same rule as resolveRequestDevice
// (deviceScope.service.ts). Runs before the guards of every /:id route below,
// including the ones added later (E13).
router.param('id', async (req, res, next, raw) => {
  try {
    if (req.session.role === 'admin' || !/^[0-9]+$/.test(String(raw))) return next();
    const id = parseRequestDeviceId(String(raw));
    const own = id !== null && await db('devices').where({ id, tenant_id: req.tenantId! }).first('id');
    if (!own) return res.status(404).json({ error: 'Device not found' });
    next();
  } catch (err) { next(err); }
});

type ActionDevice = { id: number; tenant_id: number; hostname: string | null; display_name: string | null };

/**
 * The device a state-changing route acts on: one of the session's tenant, or
 * of any tenant in the platform admin's god view. The action then runs IN THE
 * DEVICE'S TENANT (its row is updated, its commands are queued and its
 * restriction matrix applies there): before, a god-view action answered 200 /
 * 204 with no effect on the row (filtered by the master tenant id).
 */
async function actionDevice(req: import('express').Request, id: number): Promise<ActionDevice | null> {
  if (!Number.isInteger(id) || id <= 0) return null;
  const q = db('devices').where({ id });
  if (!hasGlobalView(req)) q.where({ tenant_id: req.tenantId! });
  return (await q.first('id', 'tenant_id', 'hostname', 'display_name')) as ActionDevice | undefined ?? null;
}

/** Audit of an action on a device: in the session's tenant and, when the
 *  device lives in another one (god view), in the device's tenant too — its
 *  own admins see what was done to their machine. */
async function auditDeviceAction(
  req: import('express').Request,
  deviceTenantId: number,
  action: string,
  extras: { deviceId?: number; resourceType?: string; resourcePath?: string; details?: Record<string, unknown> },
): Promise<void> {
  try {
    const { auditService } = await import('../services/audit.service');
    await auditService.logReq(req, action, extras);
    if (deviceTenantId !== req.tenantId) {
      await auditService.logReqAs(req, deviceTenantId, action, {
        ...extras, details: { ...(extras.details ?? {}), initiatedFromTenantId: req.tenantId },
      });
    }
  } catch { /* audit is best effort */ }
}

// ── Static / collection routes (must come before /:id routes) ─────────────────

// GET /api/devices
router.get('/', async (req, res, next) => {
  try {
    const { groupId, includeSubgroups, status, approvalStatus, search, osType, osName, osVersion, page, pageSize, sortBy, sortOrder, ungrouped, staleHours, pendingUpdates, prereqsMissing, tags, tenantIds } = req.query as any;

    // Tags arrive either as repeated query params (`?tags=a&tags=b`)
    // → already an array — or as a comma-separated string. Normalise.
    let tagsArr: string[] | undefined;
    if (Array.isArray(tags)) tagsArr = tags.map(String).filter(Boolean);
    else if (typeof tags === 'string' && tags.length > 0) tagsArr = tags.split(',').map((t) => t.trim()).filter(Boolean);

    // Same parsing rules for `tenantIds` (master only — service drops
    // it for non-master callers).
    let tenantIdsArr: number[] | undefined;
    if (Array.isArray(tenantIds)) tenantIdsArr = tenantIds.map((v) => parseInt(String(v))).filter(Number.isFinite);
    else if (typeof tenantIds === 'string' && tenantIds.length > 0) {
      tenantIdsArr = tenantIds.split(',').map((v: string) => parseInt(v.trim())).filter(Number.isFinite);
    }

    // osName / osVersion accept either a single value (legacy single-
    // select callers) or a comma-separated list / repeated param
    // (multi-select picker in DeviceTable). Service normalises both
    // shapes into a WHERE IN clause.
    const parseStringList = (raw: unknown): string[] | undefined => {
      if (Array.isArray(raw)) return raw.map(String).filter(Boolean);
      if (typeof raw === 'string' && raw.length > 0) return raw.split(',').map((s) => s.trim()).filter(Boolean);
      return undefined;
    };
    const osNames = parseStringList(osName);
    const osVersions = parseStringList(osVersion);

    const result = await deviceService.getDevices(req.tenantId!, {
      groupId: groupId ? parseInt(groupId) : undefined,
      includeSubgroups: includeSubgroups === 'true',
      status, approvalStatus, search, osType,
      osName: osNames,
      osVersion: osVersions,
      page: page ? parseInt(page) : undefined,
      pageSize: pageSize ? parseInt(pageSize) : undefined,
      sortBy, sortOrder,
      ungrouped: ungrouped === 'true' || ungrouped === true,
      staleHours: staleHours ? parseInt(staleHours) : undefined,
      pendingUpdates: pendingUpdates === 'true' || pendingUpdates === '1' || pendingUpdates === true,
      prereqsMissing: prereqsMissing === 'true' || prereqsMissing === '1' || prereqsMissing === true,
      tags: tagsArr,
      tenantIds: tenantIdsArr,
    });

    // Filter by visible devices for non-admins. The visibility set
    // now includes pre-approval devices "claimed" via their API key's
    // default group + devices in the catch-all `ungrouped` scope —
    // see permissionService.getVisibleDeviceIds for the full ruleset.
    if (req.session.role !== 'admin') {
      const visible = await permissionService.getVisibleDeviceIds(req.session.userId!, false);
      if (Array.isArray(visible)) {
        const visibleSet = new Set(visible);
        result.items = result.items.filter((d: any) => visibleSet.has(d.id));
        result.total = result.items.length;
      }
    }

    res.json({ data: result });
  } catch (err) { next(err); }
});

// GET /api/devices/export
router.get('/export', async (req, res, next) => {
  try {
    const { format, groupId, includeSubgroups, status, approvalStatus, search, osType, sortBy, sortOrder, ungrouped } = req.query as any;
    const fmt = (format ?? 'csv').toString().toLowerCase();
    if (!['csv', 'xlsx', 'pdf'].includes(fmt)) {
      return res.status(400).json({ error: 'Invalid format (csv|xlsx|pdf)' });
    }

    let devices = await deviceService.exportDevices(req.tenantId!, {
      groupId: groupId ? parseInt(groupId) : undefined,
      includeSubgroups: includeSubgroups === 'true',
      status, approvalStatus, search, osType, sortBy, sortOrder,
      ungrouped: ungrouped === 'true' || ungrouped === true,
    });

    // Non-admins: filter to visible devices only
    if (req.session.role !== 'admin') {
      const visible = await permissionService.getVisibleDeviceIds(req.session.userId!, false);
      if (Array.isArray(visible)) {
        const visibleSet = new Set(visible);
        devices = devices.filter((d: any) => visibleSet.has(d.id));
      }
    }

    const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
    const baseName = `obliance-devices-${ts}`;

    // Rows for the export — stable column order. `pdf: false` keeps a column
    // out of the (width-constrained) PDF while still exporting it to CSV/XLSX,
    // so the spreadsheet holds the full micro-inventory and the PDF stays
    // readable.
    const columns: Array<{ header: string; key: string; width: number; pdf?: boolean }> = [
      { header: 'Hostname',       key: 'hostname',      width: 24 },
      { header: 'Display Name',   key: 'displayName',   width: 24 },
      { header: 'Status',         key: 'status',        width: 12 },
      { header: 'OS',             key: 'osName',        width: 18 },
      { header: 'OS Version',     key: 'osVersion',     width: 16, pdf: false },
      { header: 'Architecture',   key: 'osArch',        width: 10, pdf: false },
      { header: 'Agent Version',  key: 'agentVersion',  width: 12, pdf: false },
      { header: 'Group',          key: 'groupName',     width: 20 },
      // ── Micro-inventory: capacity (total) + current + peak (max) ──────────
      { header: 'CPU Model',       key: 'cpuModel',     width: 30, pdf: false },
      { header: 'CPU Cores',       key: 'cpuCores',     width: 9 },
      { header: 'CPU % Now',       key: 'cpuPct',       width: 9,  pdf: false },
      { header: 'CPU % Max',       key: 'cpuPeak',      width: 9 },
      { header: 'RAM Total (GB)',  key: 'ramTotalGb',   width: 12 },
      { header: 'RAM Used (GB)',   key: 'ramUsedGb',    width: 12, pdf: false },
      { header: 'RAM % Now',       key: 'ramPct',       width: 9,  pdf: false },
      { header: 'RAM % Max',       key: 'ramPeak',      width: 9 },
      { header: 'Disk Total (GB)', key: 'diskTotalGb',  width: 13 },
      { header: 'Disk Used (GB)',  key: 'diskUsedGb',   width: 13, pdf: false },
      { header: 'Disk % Now',      key: 'diskPct',      width: 9,  pdf: false },
      { header: 'Disk % Max',      key: 'diskPeak',     width: 9 },
      { header: 'Disks',           key: 'diskCount',    width: 7,  pdf: false },
      { header: 'GPU',             key: 'gpu',          width: 26, pdf: false },
      { header: 'Peak Since',      key: 'peakSince',    width: 22, pdf: false },
      // ── Network / identity ────────────────────────────────────────────────
      { header: 'Local IP',       key: 'ipLocal',       width: 16 },
      { header: 'Public IP',      key: 'ipPublic',      width: 16, pdf: false },
      { header: 'MAC Address',    key: 'macAddress',    width: 18, pdf: false },
      { header: 'Last Seen',      key: 'lastSeenAt',    width: 22 },
      { header: 'Last User',      key: 'lastLoggedInUser', width: 18, pdf: false },
      { header: 'Agent UUID',     key: 'uuid',          width: 38, pdf: false },
    ];

    // Round helpers — blank (not 0) when a value is unknown, so an offline
    // device that never reported metrics doesn't read as "0 GB / 0 %".
    const r1 = (n: number) => (Number.isFinite(n) ? Math.round(n * 10) / 10 : '');
    const r0 = (n: number) => (Number.isFinite(n) ? Math.round(n) : '');

    const rows = devices.map((d: any) => {
      const mt = d.latestMetrics || {};
      const cpu = mt.cpu || {};
      const mem = mt.memory || {};
      const disks: any[] = Array.isArray(mt.disks) ? mt.disks : [];
      const peak = d.peakMetrics || null;

      // RAM: prefer live (more precise) then fall back to static inventory.
      const ramTotalGb = mem.totalMb ? mem.totalMb / 1024 : (d.ramTotalGb ?? NaN);
      const ramUsedGb  = mem.usedMb ? mem.usedMb / 1024 : NaN;
      // Disk: sum capacity/used across mounts; "now" = the fullest mount.
      const diskTotalGb = disks.reduce((s, dk) => s + (Number(dk.totalGb) || 0), 0);
      const diskUsedGb  = disks.reduce((s, dk) => s + (Number(dk.usedGb) || 0), 0);
      const diskPctNow  = disks.reduce((mx, dk) => Math.max(mx, Number(dk.percent) || 0), NaN);
      const gpu = Array.isArray(mt.gpus) ? mt.gpus.map((g: any) => g.model).filter(Boolean).join(', ') : '';

      return {
        hostname:         d.hostname ?? '',
        displayName:      d.displayName ?? '',
        status:           d.status ?? '',
        osName:           d.osName ?? d.osType ?? '',
        osVersion:        d.osVersion ?? '',
        osArch:           d.osArch ?? '',
        agentVersion:     d.agentVersion ?? '',
        groupName:        d.groupName ?? '',
        cpuModel:         d.cpuModel ?? cpu.model ?? '',
        cpuCores:         d.cpuCores ?? (Array.isArray(cpu.cores) ? cpu.cores.length : '') ?? '',
        cpuPct:           r0(Number(cpu.percent)),
        cpuPeak:          peak ? r0(Number(peak.cpu)) : '',
        ramTotalGb:       r1(ramTotalGb),
        ramUsedGb:        r1(ramUsedGb),
        ramPct:           r0(Number(mem.percent)),
        ramPeak:          peak ? r0(Number(peak.ram)) : '',
        diskTotalGb:      disks.length ? r1(diskTotalGb) : '',
        diskUsedGb:       disks.length ? r1(diskUsedGb) : '',
        diskPct:          r0(diskPctNow),
        diskPeak:         peak ? r0(Number(peak.disk)) : '',
        diskCount:        disks.length || '',
        gpu,
        peakSince:        peak?.since ?? '',
        ipLocal:          d.ipLocal ?? '',
        ipPublic:         d.ipPublic ?? '',
        macAddress:       d.macAddress ?? '',
        lastSeenAt:       d.lastSeenAt ?? '',
        lastLoggedInUser: d.lastLoggedInUser ?? '',
        uuid:             d.uuid ?? '',
      };
    });

    const ExcelJS = (await import('exceljs')).default;

    if (fmt === 'csv') {
      const wb = new ExcelJS.Workbook();
      const ws = wb.addWorksheet('Devices');
      ws.columns = columns;
      rows.forEach((r) => ws.addRow(r));
      const buffer = await wb.csv.writeBuffer();
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.csv"`);
      return res.send(Buffer.from(buffer as any));
    }

    if (fmt === 'xlsx') {
      const wb = new ExcelJS.Workbook();
      wb.creator = 'Obliance';
      wb.created = new Date();
      const ws = wb.addWorksheet('Devices');
      ws.columns = columns;
      ws.getRow(1).font = { bold: true };
      ws.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F2937' } };
      ws.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
      rows.forEach((r) => ws.addRow(r));
      ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
      const buffer = await wb.xlsx.writeBuffer();
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.xlsx"`);
      return res.send(Buffer.from(buffer as any));
    }

    // PDF via playwright (renders an HTML table to PDF). Curated column subset
    // (drop `pdf: false`) so the page stays readable — the full inventory is in
    // the CSV/XLSX exports.
    const pdfColumns = columns.filter((c) => c.pdf !== false);
    const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
    const headHtml = pdfColumns.map((c) => `<th>${escapeHtml(c.header)}</th>`).join('');
    const rowsHtml = rows.map((r) =>
      `<tr>${pdfColumns.map((c) => `<td>${escapeHtml(String((r as any)[c.key] ?? ''))}</td>`).join('')}</tr>`
    ).join('');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Devices</title><style>
body { font-family: -apple-system, Segoe UI, sans-serif; font-size: 9px; color: #111; margin: 20px; }
h1 { font-size: 14px; margin: 0 0 12px; }
.meta { font-size: 8px; color: #666; margin-bottom: 12px; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; }
th { background: #1f2937; color: white; font-weight: 600; }
tr:nth-child(even) td { background: #f9fafb; }
</style></head><body>
<h1>Obliance — Devices export</h1>
<div class="meta">${devices.length} devices · generated ${new Date().toISOString()}</div>
<table><thead><tr>${headHtml}</tr></thead><tbody>${rowsHtml}</tbody></table>
</body></html>`;

    const browser = await launchChromium();
    try {
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'domcontentloaded' });
      const pdf = await page.pdf({ format: 'A4', landscape: true, margin: { top: '15mm', bottom: '15mm', left: '10mm', right: '10mm' }, printBackground: true });
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.pdf"`);
      return res.send(pdf);
    } finally {
      await browser.close();
    }
  } catch (err) { next(err); }
});

// GET /api/devices/summary
router.get('/summary', async (req, res, next) => {
  try {
    const summary = await deviceService.getFleetSummary(req.tenantId!);
    res.json({ data: summary });
  } catch (err) { next(err); }
});

// GET /api/devices/fleet-timeseries?days=14
// Returns daily online/offline/total/pendingUpdates/stale72/critical for the
// last N days. Used by the dashboard hero sparklines and the "Activité du
// parc" chart. The current-day point is always synthesized from live state
// (no waiting for the nightly snapshot job).
router.get('/fleet-timeseries', async (req, res, next) => {
  try {
    const days = Math.min(parseInt(String(req.query.days ?? '14')) || 14, 90);
    const series = await deviceService.getFleetTimeseries(req.tenantId!, days);
    res.json({ data: series });
  } catch (err) { next(err); }
});

// GET /api/devices/fleet-hourly?hours=24
// Hourly granularity timeseries for the dashboard "Activité du parc" 24h
// view. Returns one point per hour (capped 7d), each with total / online /
// offline / pending_updates / stale_72h.
router.get('/fleet-hourly', async (req, res, next) => {
  try {
    const hours = Math.min(168, Math.max(2, parseInt(String(req.query.hours ?? '24')) || 24));
    const series = await deviceService.getFleetHourlySeries(req.tenantId!, hours);
    res.json({ data: series });
  } catch (err) { next(err); }
});

// GET /api/devices/agent-versions
// Top N agent versions by device count. Used by the dashboard "Top versions
// agent" mini chart so admins spot devices stuck on old auto-update cycles.
router.get('/agent-versions', async (req, res, next) => {
  try {
    const versions = await deviceService.getAgentVersionDistribution(req.tenantId!);
    res.json({ data: versions });
  } catch (err) { next(err); }
});

// ── "Update all agents" (dashboard) ─────────────────────────────────────────
// Every OUTDATED agent of the scope (approved, modern agent, not suspended /
// being uninstalled, version ≠ the one this server ships): the master tenant
// targets every tenant's agents, any other tenant only its own. Queued like
// any agent update (services/agentUpdateRollout.service.ts): no expiry
// (offline agents are updated when they come back), one per device, paced
// fleet-wide, each row carrying the DEVICE's tenant.
//
// The scope is the session's CURRENT tenant, which another tab can switch:
// the client sends back the scope of the preview it confirmed
// ({scopeTenantId, allTenants}) and the action is refused (409) when the
// session's tenant no longer matches — "this tenant only" never silently
// becomes "every tenant".

/** 400/409 when the confirmed scope is missing or no longer the session's. */
function checkConfirmedScope(req: any, res: any): boolean {
  const body = (req.body ?? {}) as { scopeTenantId?: unknown; allTenants?: unknown };
  const scopeTenantId = Number(body.scopeTenantId);
  if (!Number.isInteger(scopeTenantId) || typeof body.allTenants !== 'boolean') {
    res.status(400).json({ error: 'scopeTenantId and allTenants (from the preview) are required — reload the dashboard.', code: 'scope_required' });
    return false;
  }
  if (scopeTenantId !== req.tenantId || body.allTenants !== isMasterTenant(req.tenantId)) {
    res.status(409).json({ error: 'The selected tenant changed since the confirmation (another tab?) — reload the dashboard and try again.', code: 'scope_changed' });
    return false;
  }
  return true;
}

/** Master-scope action: one summary row in each affected tenant's own audit
 *  log too (their admins do not see the master's). */
async function auditPerTenant(req: any, action: string, byTenant: Array<{ tenantId: number } & Record<string, unknown>>, extra: Record<string, unknown>): Promise<void> {
  try {
    const { auditService } = await import('../services/audit.service');
    for (const { tenantId, ...counts } of byTenant) {
      if (tenantId === req.tenantId) continue;
      await auditService.logReqAs(req, tenantId, action, {
        resourceType: 'device',
        details: { scope: 'all_tenants', initiatedFromTenantId: req.tenantId, ...extra, ...counts },
      });
    }
  } catch {}
}

// GET /api/devices/update-all-agents/preview — figures for the confirmation
// (and the dashboard buttons: eligible count, updates still waiting).
router.get('/update-all-agents/preview', requireRole('admin'), async (req, res, next) => {
  try {
    const { agentUpdateRollout } = await import('../services/agentUpdateRollout.service');
    res.json({ data: await agentUpdateRollout.preview(req.tenantId!) });
  } catch (err) { next(err); }
});

// POST /api/devices/update-all-agents  { scopeTenantId, allTenants, expectedTargets? }
// Restriction 'command.update_agent' as on every update path: 'sensitive' →
// step-up, 'restricted' → an approval that stores only the scope (the tenant
// of the request) and re-resolves the outdated set when it is executed —
// never a device list. On the master tenant the level is the STRICTEST of the
// master's and of every tenant owning a target (a sub-tenant's own policy is
// never bypassed from above); the approval stays in the master tenant (its
// scope). The device scope of a restriction entry is not evaluated (the
// target set is only known at execution): any update_agent restriction of a
// concerned tenant gates the fleet-wide action.
router.post('/update-all-agents', requireRole('admin'), async (req, res, next) => {
  try {
    if (!checkConfirmedScope(req, res)) return;
    const { agentUpdateRollout } = await import('../services/agentUpdateRollout.service');
    const preview = await agentUpdateRollout.preview(req.tenantId!);
    if (!preview.latestVersion) {
      return res.status(409).json({ error: 'Cannot determine the latest agent version (agent/VERSION missing).' });
    }
    // The fleet grew a lot since the confirmation (e.g. another version
    // published): ask again rather than update far more than announced.
    const expected = Number((req.body ?? {}).expectedTargets);
    if (Number.isInteger(expected) && expected >= 0 && preview.targets > expected * 2 + 50) {
      return res.status(409).json({ error: `The number of outdated agents changed (${preview.targets} now, ${expected} confirmed) — reload the dashboard and confirm again.`, code: 'targets_changed', targets: preview.targets });
    }
    if (preview.targets === 0) return res.json({ data: { ...preview, queued: 0, byTenant: [] } });

    const scope = preview.allTenants ? 'all_tenants' : 'tenant';
    const levelTenantIds = preview.allTenants ? await agentUpdateRollout.outdatedTenantIds(req.tenantId!) : undefined;
    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'command.update_agent',
      approvalRequestType: 'batch_command',
      approvalDescription: preview.allTenants
        ? `update_agent on every outdated agent of every tenant (${preview.targets} now, re-evaluated on approval) → ${preview.latestVersion}`
        : `update_agent on every outdated agent of this tenant (${preview.targets} now, re-evaluated on approval) → ${preview.latestVersion}`,
      approvalPayload: { action: 'update_all_agents', params: { scope } },
      ...(levelTenantIds ? { levelTenantIds, approvalInRequestTenant: true } : {}),
    });
    if (!approved) return;

    const result = await agentUpdateRollout.updateAllOutdated(req.tenantId!, req.session.userId);
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.update_all_agents', {
        resourceType: 'device',
        details: {
          scope, scopeTenantId: req.tenantId!, targetVersion: result.latestVersion,
          targets: result.targets, queued: result.queued, alreadyQueued: result.alreadyQueued,
          online: result.online, offline: result.offline,
          ...(result.frozen ? { frozen: result.frozen } : {}),
          ...(result.allTenants ? { tenants: result.byTenant.length } : {}),
        },
      });
    } catch {}
    if (result.allTenants) await auditPerTenant(req, 'device.update_all_agents', result.byTenant, { targetVersion: result.latestVersion });
    res.json({ data: result });
  } catch (err) { next(err); }
});

// POST /api/devices/update-all-agents/cancel  { scopeTenantId, allTenants }
// "Stop the rollout": cancels every agent update still WAITING in the scope
// (master tenant: every tenant) — whatever queued it. Updates already handed
// to an agent cannot be recalled. An emergency stop: admin only, audited, no
// restriction gate (it only prevents actions).
router.post('/update-all-agents/cancel', requireRole('admin'), async (req, res, next) => {
  try {
    if (!checkConfirmedScope(req, res)) return;
    const { agentUpdateRollout } = await import('../services/agentUpdateRollout.service');
    const r = await agentUpdateRollout.cancelPending(req.tenantId!, req.session.userId);
    const allTenants = isMasterTenant(req.tenantId!);
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.update_all_agents_cancel', {
        resourceType: 'device',
        details: { scope: allTenants ? 'all_tenants' : 'tenant', scopeTenantId: req.tenantId!, cancelled: r.cancelled },
      });
    } catch {}
    if (allTenants) await auditPerTenant(req, 'device.update_all_agents_cancel', r.byTenant, {});
    res.json({ data: { cancelled: r.cancelled, allTenants } });
  } catch (err) { next(err); }
});

// GET /api/devices/os-facets
// Grouped facets used by the /devices 3-tier OS filter (family → name → build).
// Returns one row per (osType, osName, osVersion) triplet with a count, so the
// client can render dropdowns showing only options that actually have devices.
router.get('/os-facets', async (req, res, next) => {
  try {
    const facets = await deviceService.getOsFacets(req.tenantId!);
    res.json({ data: facets });
  } catch (err) { next(err); }
});

// GET /api/devices/tags
// Distinct tag list for the tenant with per-tag device counts. Drives the
// /devices tag-filter chip popover so admins pick from existing tags
// (typo-free) rather than retyping. Returns [{ tag, count }] desc by count.
router.get('/tags', async (req, res, next) => {
  try {
    const tags = await deviceService.getTagFacets(req.tenantId!);
    res.json({ data: tags });
  } catch (err) { next(err); }
});

// GET /api/devices/disk-saturated?threshold=0
// Devices whose latest hardware snapshot reports any disk above their
// resolved per-device threshold. The optional `threshold` query
// param is a floor — useful when the dashboard wants a single "show me
// anything ≥ N" override regardless of per-group/per-device settings.
router.get('/disk-saturated', async (req, res, next) => {
  try {
    const threshold = Math.min(Math.max(parseInt(String(req.query.threshold ?? '0')) || 0, 0), 99);
    const result = await deviceService.getDiskSaturation(req.tenantId!, threshold);
    res.json({ data: result });
  } catch (err) { next(err); }
});

// GET /api/devices/group-stats — stats per group for dashboard
router.get('/group-stats', async (req, res, next) => {
  try {
    const tenantId = req.tenantId!;
    // Cross-tenant aggregate: the platform admin's god view only (E13).
    const isMaster = hasGlobalView(req);

    // Device counts per group + status. Master sees the aggregate
    // across every tenant; child tenants stay scoped.
    const deviceQ = db('devices')
      .where({ approval_status: 'approved' })
      .whereNot({ status: 'pending_uninstall' })
      .select('group_id', 'status')
      .count('* as count')
      .groupBy('group_id', 'status');
    if (!isMaster) deviceQ.where({ tenant_id: tenantId });
    const deviceRows = await deviceQ;

    // Compliance scores per group (latest per device). On master we
    // drop the tenant filter on both sides of the JOIN/sub-select —
    // everything flows through `compliance_results` rows already
    // tied to the right device's tenant.
    const tenantFilterCompliance = isMaster ? '' : 'AND d.tenant_id = ?';
    const tenantFilterComplianceSub = isMaster ? '' : 'WHERE tenant_id = ?';
    const complianceParams = isMaster ? [] : [tenantId, tenantId];
    const complianceRows = await db.raw(`
      SELECT d.group_id,
             ROUND(AVG(cr.compliance_score)::numeric, 1) as avg_score,
             COUNT(DISTINCT cr.policy_id) as policy_count
      FROM compliance_results cr
      JOIN devices d ON d.id = cr.device_id
      WHERE d.approval_status = 'approved' ${tenantFilterCompliance}
        AND cr.id IN (
          SELECT DISTINCT ON (device_id, policy_id) id
          FROM compliance_results
          ${tenantFilterComplianceSub}
          ORDER BY device_id, policy_id, checked_at DESC
        )
      GROUP BY d.group_id
    `, complianceParams);

    // Pending updates per group
    const tenantFilterUpdates = isMaster ? '' : 'WHERE d.tenant_id = ? AND du.status = \'available\'';
    const updateWhere = isMaster ? `WHERE du.status = 'available'` : tenantFilterUpdates;
    const updateParams = isMaster ? [] : [tenantId];
    const updateRows = await db.raw(`
      SELECT d.group_id, COUNT(DISTINCT du.device_id) as devices_with_updates
      FROM device_updates du
      JOIN devices d ON d.id = du.device_id
      ${updateWhere}
      GROUP BY d.group_id
    `, updateParams);

    // Group metadata (parent + sortOrder feed the dashboard's hierarchical
    // "Vue par groupe" — root → children indented by depth, ordered by the
    // admin-defined sort_order rather than device count).
    // On master tenant we also pull `tenant_id` + tenant name so the
    // dashboard can bucket groups under their owning tenant (mirroring
    // the sidebar grouping). Without this, master shows a flat mix of
    // "DC" / "Caisses" / etc. from every tenant — unreadable.
    const groupsQ = db('device_groups as g')
      .leftJoin('tenants as t', 't.id', 'g.tenant_id')
      .select('g.id', 'g.name', 'g.parent_id', 'g.sort_order', 'g.tenant_id', 't.name as tenant_name');
    if (!isMaster) groupsQ.where({ 'g.tenant_id': tenantId });
    const groups = await groupsQ as Array<{
      id: number; name: string; parent_id: number | null; sort_order: number;
      tenant_id: number; tenant_name: string | null;
    }>;

    // Build stats map
    const statsMap = new Map<number | null, any>();

    const getOrCreate = (gid: number | null) => {
      if (!statsMap.has(gid)) {
        statsMap.set(gid, {
          groupId: gid, groupName: null, parentId: null, sortOrder: 0,
          tenantId: null, tenantName: null,
          online: 0, offline: 0, warning: 0, critical: 0, total: 0,
          complianceScore: null, policyCount: 0, pendingUpdates: 0,
        });
      }
      return statsMap.get(gid)!;
    };

    for (const row of deviceRows) {
      const s = getOrCreate(Number(row.group_id));
      const count = parseInt(String(row.count));
      s.total += count;
      if (row.status === 'online') s.online += count;
      else if (row.status === 'offline') s.offline += count;
      else if (row.status === 'warning') s.warning += count;
      else if (row.status === 'update_error') s.warning += count;
      else if (row.status === 'critical') s.critical += count;
    }

    for (const row of (complianceRows.rows ?? complianceRows)) {
      const s = getOrCreate(row.group_id);
      s.complianceScore = parseFloat(row.avg_score);
      s.policyCount = parseInt(row.policy_count);
    }

    for (const row of (updateRows.rows ?? updateRows)) {
      const s = getOrCreate(row.group_id);
      s.pendingUpdates = parseInt(row.devices_with_updates);
    }

    // Make sure every group has a stats row even if it has no devices —
    // the hierarchical render still wants the empty group to appear.
    for (const g of groups) getOrCreate(g.id);

    // Set group names + parent + sortOrder + tenant info
    const groupMap = new Map(groups.map((g) => [g.id, g]));
    for (const [gid, stats] of statsMap) {
      if (gid != null) {
        const g = groupMap.get(gid);
        stats.groupName = g?.name ?? 'Unknown';
        stats.parentId = g?.parent_id ?? null;
        stats.sortOrder = g?.sort_order ?? 0;
        stats.tenantId = g?.tenant_id ?? null;
        stats.tenantName = g?.tenant_name ?? null;
      }
    }

    // Pre-sort by (parentId nulls first, then sortOrder) so the client can
    // build the tree in linear order without a second pass.
    res.json({ data: Array.from(statsMap.values()).sort((a: any, b: any) => {
      if ((a.parentId ?? -1) !== (b.parentId ?? -1)) return (a.parentId ?? -1) - (b.parentId ?? -1);
      if (a.sortOrder !== b.sortOrder) return a.sortOrder - b.sortOrder;
      return (a.groupName ?? '').localeCompare(b.groupName ?? '');
    }) });
  } catch (err) { next(err); }
});

// POST /api/devices/bulk/approve
router.post('/bulk/approve', requireTenantCapability('agent_config:approval'), async (req, res, next) => {
  try {
    const { ids, deviceIds } = req.body ?? {};
    const raw: unknown[] = Array.isArray(ids) ? ids : Array.isArray(deviceIds) ? deviceIds : [];
    const requested = [...new Set(raw.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
    // The session's tenant, or — platform admin's god view — each device in
    // its own tenant (before, the master's god view approved nothing there).
    const q = db('devices').whereIn('id', requested.length ? requested : [0]);
    if (!hasGlobalView(req)) q.where({ tenant_id: req.tenantId! });
    const rows = await q.select('id', 'tenant_id') as Array<{ id: number; tenant_id: number }>;
    const byTenant = new Map<number, number[]>();
    for (const r of rows) byTenant.set(r.tenant_id, [...(byTenant.get(r.tenant_id) ?? []), r.id]);
    for (const [tenantId, tenantIds] of byTenant) {
      await deviceService.bulkApprove(tenantIds, tenantId, req.session.userId!);
      for (const id of tenantIds) {
        await auditDeviceAction(req, tenantId, 'device.approved', {
          deviceId: id, resourceType: 'device', resourcePath: String(id), details: { bulk: true },
        });
      }
    }
    res.json({ success: true, count: rows.length });
  } catch (err) { next(err); }
});

// DELETE /api/devices/bulk/delete
// Only devices of the request's tenant (ids of another tenant are ignored,
// nothing of theirs is touched), and the `device.delete` restriction applies
// as on DELETE /api/devices/:id: step-up when 'sensitive', one approval for
// the whole batch when 'restricted'.
router.delete('/bulk/delete', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const { ids, deviceIds } = req.body ?? {};
    const raw: unknown[] = Array.isArray(ids) ? ids : Array.isArray(deviceIds) ? deviceIds : [];
    const requested = [...new Set(raw.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
    // The session's tenant only — or, in the platform admin's god view, each
    // device in its own tenant (god-view actions really act in the device's
    // tenant, audited in both).
    const globalView = hasGlobalView(req);
    const ownedQ = db('devices').whereIn('id', requested.length ? requested : [0]);
    if (!globalView) ownedQ.where({ tenant_id: req.tenantId! });
    const ownedRows = await ownedQ.select('id', 'tenant_id') as Array<{ id: number; tenant_id: number }>;
    const owned = ownedRows.map((r) => Number(r.id));
    if (owned.length === 0) return res.json({ success: true, deleted: 0 });
    const otherTenants = [...new Set(ownedRows.map((r) => Number(r.tenant_id)))].filter((t) => t !== req.tenantId);

    const { applyRestriction } = await import('../services/restriction.service');
    const { deviceList } = await import('../services/approvalDescribe');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'device.delete',
      deviceIds: owned,
      approvalRequestType: 'batch_command',
      approvalDescription: `Delete ${owned.length} device(s) — ${await deviceList(req.tenantId!, owned)}`,
      approvalPayload: { action: 'delete_devices', deviceIds: owned },
      // God view over other tenants: the strictest level of every tenant
      // concerned; the approval stays in the master tenant (its executor
      // re-resolves each device's tenant).
      ...(otherTenants.length ? { levelTenantIds: otherTenants, approvalInRequestTenant: true } : {}),
    });
    if (!approved) return;

    const byTenant = new Map<number, number[]>();
    for (const r of ownedRows) byTenant.set(Number(r.tenant_id), [...(byTenant.get(Number(r.tenant_id)) ?? []), Number(r.id)]);
    const deleted: number[] = [];
    for (const [tenantId, tenantIds] of byTenant) {
      const done = await deviceService.bulkDelete(tenantIds, tenantId);
      deleted.push(...done);
      if (done.length) {
        await auditDeviceAction(req, tenantId, 'device.bulk_deleted', {
          resourceType: 'device', resourcePath: done.join(','),
          details: { count: done.length, deviceIds: done },
        });
      }
    }
    res.json({ success: true, deleted: deleted.length });
  } catch (err) { next(err); }
});

// POST /api/devices/batch/transfer — move N devices to another tenant in
// one shot. All devices must currently belong to `req.tenantId` and the
// caller must be admin in both source and target (or platform admin).
// Honours the tenant's `device.transfer_tenant` restriction policy — if
// the action is Sensitive the whole batch prompts for TOTP once; if
// Restricted the batch hits the approvals queue as a single request.
router.post('/batch/transfer', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const { deviceIds, targetTenantId, targetApiKeyId } = req.body as {
      deviceIds: number[]; targetTenantId: number; targetApiKeyId: number;
    };
    if (!Array.isArray(deviceIds) || deviceIds.length === 0) {
      return res.status(400).json({ error: 'deviceIds required' });
    }
    if (!targetTenantId || !targetApiKeyId) {
      return res.status(400).json({ error: 'targetTenantId and targetApiKeyId required' });
    }
    if (targetTenantId === req.tenantId!) {
      return res.status(400).json({ error: 'Target tenant is the same as source' });
    }

    const userId = req.session.userId!;
    const isPlatformAdmin = req.session.role === 'admin';
    if (!isPlatformAdmin) {
      const [sourceMembership, targetMembership] = await Promise.all([
        db('user_tenants').where({ user_id: userId, tenant_id: req.tenantId!, role: 'admin' }).first(),
        db('user_tenants').where({ user_id: userId, tenant_id: targetTenantId, role: 'admin' }).first(),
      ]);
      if (!sourceMembership || !targetMembership) {
        return res.status(403).json({ error: 'You must be admin of both tenants' });
      }
    }

    const targetKey = await db('agent_api_keys')
      .where({ id: targetApiKeyId, tenant_id: targetTenantId })
      .first();
    if (!targetKey) return res.status(400).json({ error: 'Target API key not found in target tenant' });

    // Ensure every device belongs to the source tenant — prevents a
    // malicious admin from stuffing arbitrary device ids into the batch.
    const validDevices = await db('devices')
      .whereIn('id', deviceIds)
      .andWhere({ tenant_id: req.tenantId! })
      .select('id', 'hostname');
    if (validDevices.length === 0) {
      return res.status(404).json({ error: 'No matching devices in this tenant' });
    }

    // Gate via the transfer restriction policy. deviceIds drives scope
    // evaluation (e.g. "Sensitive only for prod group") — same semantics
    // as the single-device transfer.
    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'device.transfer_tenant',
      deviceIds: validDevices.map((d: any) => d.id),
      approvalRequestType: 'batch_command',
      approvalDescription: `Transfer to ${await (await import('../services/approvalDescribe')).tenantLabel(targetTenantId)} (agent key "${targetKey.name ?? targetApiKeyId}") — ${await (await import('../services/approvalDescribe')).deviceList(req.tenantId!, validDevices.map((d: any) => d.id))}`,
      // serverUrl: what the direct transfer writes into reconfigure_agent (the
      // executor prefers SERVER_URL when set). The API key itself is read at
      // execution, never kept in the request.
      approvalPayload: { action: 'transfer_tenant', deviceIds: validDevices.map((d: any) => d.id), params: { targetTenantId, targetApiKeyId, serverUrl: `${req.protocol}://${req.get('host')}` } },
    });
    if (!approved) return;

    const serverUrl = `${req.protocol}://${req.get('host')}`;

    const results = { transferred: 0, failed: 0 };
    const transferredIds: number[] = [];
    for (const device of validDevices) {
      try {
        await db.transaction(async (trx) => {
          // Enqueue the reconfigure command in the SOURCE tenant so the
          // agent (still on the old key) receives it on its next push.
          await trx('command_queue').insert({
            device_id: device.id,
            tenant_id: req.tenantId!,
            type: 'reconfigure_agent',
            payload: JSON.stringify({ apiKey: targetKey.key, serverUrl, targetTenantId }),
            priority: 'urgent',
            status: 'pending',
            expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
            created_by: userId,
          });

          await trx('devices').where({ id: device.id }).update({
            tenant_id: targetTenantId,
            api_key_id: targetApiKeyId,
            group_id: null,
            schedule_alert: null,
            updated_at: new Date(),
          });

          await trx('device_custom_metrics').where({ device_id: device.id }).delete();
          await trx('software_compliance_results').where({ device_id: device.id }).delete();
          await trx('command_queue')
            .where({ device_id: device.id, tenant_id: req.tenantId! })
            .whereIn('status', ['pending', 'sent'])
            .whereNot({ type: 'reconfigure_agent' })
            .update({ status: 'cancelled', finished_at: new Date() });
        });
        results.transferred++;
        transferredIds.push(device.id);
      } catch (err) {
        logger.error({ err, deviceId: device.id }, 'bulk transfer: failed for device');
        results.failed++;
      }
    }

    // New tenant, no group = a different alerts switch (`notify`) chain:
    // silently re-baseline the alertable level (and, when it drops to ok,
    // mark read the metric alerts left in the source tenant's inbox).
    if (transferredIds.length > 0) {
      const { metricAlertRebaseline } = await import('../services/metricAlertRebaseline.service');
      metricAlertRebaseline.schedule({ kind: 'devices', deviceIds: transferredIds }, 'tenant transfer');
    }

    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.bulk_transferred', {
        resourceType: 'device',
        resourcePath: validDevices.map((d: any) => d.id).join(','),
        details: { fromTenantId: req.tenantId, toTenantId: targetTenantId, count: validDevices.length, transferred: results.transferred, failed: results.failed },
      });
    } catch {}

    res.json({ data: results });
  } catch (err) { next(err); }
});

// POST /api/devices/batch/change-group — move N devices to a new group in one shot.
// Body: { deviceIds: number[], groupId: number | null }
// Fires the 'group_join' scenario trigger for each device whose group actually
// changed, matching the single-device PATCH flow.
router.post('/batch/change-group', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const { deviceIds, groupId } = req.body as { deviceIds: number[]; groupId: number | null };
    if (!Array.isArray(deviceIds) || deviceIds.length === 0) {
      return res.status(400).json({ error: 'deviceIds required' });
    }
    // Validate group if provided (null = ungrouped).
    if (groupId !== null && groupId !== undefined) {
      const grp = await db('device_groups').where({ id: groupId, tenant_id: req.tenantId! }).first();
      if (!grp) return res.status(404).json({ error: 'Group not found' });
    }
    const normalized = groupId === undefined ? null : groupId;

    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'device.bulk_group_change',
      deviceIds,
      approvalRequestType: 'batch_command',
      approvalDescription: `Move to ${await (await import('../services/approvalDescribe')).groupLabel(req.tenantId!, normalized)} — ${await (await import('../services/approvalDescribe')).deviceList(req.tenantId!, deviceIds)}`,
      approvalPayload: { action: 'change_group', deviceIds, params: { groupId: normalized } },
    });
    if (!approved) return;

    // Capture previous groupIds so we only fire triggers when the group changed.
    const prev = await db('devices')
      .whereIn('id', deviceIds)
      .andWhere({ tenant_id: req.tenantId! })
      .select('id', 'group_id');
    const prevById = new Map(prev.map((p: any) => [p.id, p.group_id]));

    await db('devices')
      .whereIn('id', deviceIds)
      .andWhere({ tenant_id: req.tenantId! })
      .update({ group_id: normalized, updated_at: new Date() });

    let changedCount = 0;
    const changedIds: number[] = [];
    for (const id of deviceIds) {
      if (prevById.get(id) !== normalized) {
        changedCount++;
        changedIds.push(id);
        if (normalized !== null) {
          scenarioService.fireTrigger('group_join', id, req.tenantId!, { groupId: normalized })
            .catch(err => logger.error({ err, deviceId: id }, 'group_join trigger failed'));
        }
      }
    }
    // The new group chain may mute / unmute metric alerts (`notify`):
    // silently re-baseline the alertable level of the moved devices.
    if (changedIds.length > 0) {
      const { metricAlertRebaseline } = await import('../services/metricAlertRebaseline.service');
      metricAlertRebaseline.schedule({ kind: 'devices', deviceIds: changedIds }, 'bulk group change');
    }

    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.bulk_group_changed', {
        resourceType: 'device',
        resourcePath: deviceIds.join(','),
        details: { count: deviceIds.length, changed: changedCount, toGroupId: normalized },
      });
    } catch {}

    res.json({ data: { updated: deviceIds.length, changed: changedCount } });
  } catch (err) { next(err); }
});

// POST /api/devices/batch — batch action by group or device IDs.
// When 2-step approval is enabled AND the action is destructive
// (reboot/shutdown/restart_agent/sleep), a pending_approvals row is
// created instead of direct dispatch.
router.post('/batch', requireRole('admin'), async (req, res, next) => {
  try {
    const { groupId, deviceIds, action } = req.body as {
      groupId?: number; deviceIds?: number[];
      action: 'restart_agent' | 'reboot' | 'shutdown' | 'sleep' | 'scan_inventory' | 'scan_updates' | 'check_compliance' | 'update_agent';
    };
    if (!action) return res.status(400).json({ error: 'action required' });

    let ids: number[] = deviceIds ?? [];
    if (groupId && !deviceIds?.length) {
      const rows = await db('devices')
        .where({ tenant_id: req.tenantId!, group_id: groupId, approval_status: 'approved' })
        .whereNot({ status: 'suspended' })
        .select('id');
      ids = rows.map((r: any) => r.id);
    }
    if (!ids.length) return res.json({ data: { dispatched: 0 } });

    // Gate destructive actions via the per-action restriction policy. update_agent
    // is included so the batch path honours the same restriction matrix as the
    // single-command path (POST /api/commands) — otherwise an admin who set
    // command.update_agent to 'sensitive'/'restricted' would have it bypassed here.
    const destructive = ['reboot', 'shutdown', 'restart_agent', 'sleep', 'update_agent'].includes(action);
    if (destructive) {
      const { applyRestriction } = await import('../services/restriction.service');
      const approved = await applyRestriction(res, {
        req,
        actionKey: `command.${action}`,
        deviceIds: ids,
        approvalRequestType: 'batch_command',
        approvalDescription: `${action} on ${await (await import('../services/approvalDescribe')).deviceList(req.tenantId!, ids)}`,
        approvalPayload: { action, deviceIds: ids },
      });
      if (!approved) return;
    }

    // update_agent: queued without expiry (offline devices get it when they
    // come back), one per device, paced and version-checked at delivery
    // (services/agentUpdateRollout.service.ts); one bulk INSERT per 500
    // devices. Skipped: legacy (Go 1.20) agents (no self-update — a ghost
    // command), devices not approved / suspended / being uninstalled,
    // agents already on the current version, updates already queued.
    //   dispatched = queued for a device reachable now (next contact)
    //   queued     = queued for an offline device (when it comes back)
    if (action === 'update_agent') {
      const ver = getAgentVersion();
      if (!ver) {
        return res.status(409).json({ error: 'Cannot determine the latest agent version (agent/VERSION missing).' });
      }
      const { agentUpdateRollout, AGENT_REACHABLE_STATUSES } = await import('../services/agentUpdateRollout.service');
      const uniqueIds = [...new Set(ids.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
      const rows = await db('devices')
        .whereIn('id', uniqueIds)
        .where({ tenant_id: req.tenantId! })
        .select('id', 'tenant_id', 'status', 'approval_status', 'agent_flavor', 'agent_version') as
        Array<{ id: number; tenant_id: number; status: string; approval_status: string; agent_flavor: string | null; agent_version: string | null }>;
      const eligible = rows.filter((r) => r.agent_flavor !== 'legacy'
        && r.approval_status === 'approved'
        && !['suspended', 'pending_uninstall'].includes(r.status)
        && r.agent_version !== ver);
      const { created, frozenDeviceIds } = await agentUpdateRollout.enqueueBulk(eligible, { createdBy: req.session.userId, priority: 'normal' });
      const createdIds = new Set(created.map((c: any) => Number(c.device_id)));
      const dispatched = eligible.filter((r) => createdIds.has(r.id) && AGENT_REACHABLE_STATUSES.includes(r.status)).length;
      // frozen: left out by the update policy (counted in skipped too).
      return res.json({ data: { dispatched, queued: created.length - dispatched, skipped: uniqueIds.length - created.length, ...(frozenDeviceIds.length ? { frozen: frozenDeviceIds.length } : {}) } });
    }

    let dispatched = 0;
    for (const deviceId of ids) {
      await commandService.enqueue({
        deviceId,
        tenantId: req.tenantId!,
        type: action as any,
        priority: 'normal',
        createdBy: req.session.userId,
      });
      dispatched++;
    }
    res.json({ data: { dispatched } });
  } catch (err) { next(err); }
});

// ── Single-device routes (:id) ────────────────────────────────────────────────

// GET /api/devices/:id/update-policy — effective agent / ObliReach update
// policies of the device and where each comes from (platform, tenant, group,
// built-in default). Device-read gate; the device must be in the caller's
// tenant (master: any).
router.get('/:id/update-policy', requireDeviceRead(), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid device id' });
    const q = db('devices').where({ id });
    if (!hasGlobalView(req)) q.where({ tenant_id: req.tenantId! });
    const row = await q.first('id', 'tenant_id', 'group_id') as { id: number; tenant_id: number; group_id: number | null } | undefined;
    if (!row) return res.status(404).json({ error: 'Device not found' });
    const { updatePolicyService } = await import('../services/updatePolicy.service');
    res.json({ data: await updatePolicyService.resolveDevice(row) });
  } catch (err) { next(err); }
});

// GET /api/devices/:id
router.get('/:id', requireDeviceRead(), async (req, res, next) => {
  try {
    const device = await deviceService.getDeviceById(parseInt(req.params.id), req.tenantId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/live-metrics
// Toggles a "live mode" on the device — the agent pushes metrics every
// ~3 seconds until the window expires (default 60s, refreshed by every
// new request). Used by the device detail page so the user sees CPU
// actually moving instead of waiting for the next 60s push tick. With
// `mode: 'push_now'` the agent fires a single immediate push instead,
// which is what the manual refresh button hooks into.
router.post('/:id/live-metrics', requireDeviceRead('id'), async (req, res, next) => {
  try {
    // The device with the REST rules (deviceScope.service.ts): the session's
    // tenant, or any tenant for an admin on the master tenant (god view: its
    // device pages and the Oblireach Desktop's Info panel); a non-admin a
    // member of that tenant who sees the device. The command then goes to
    // the device's own tenant (before, the master's god view got sent:false).
    const { resolveRequestDevice } = await import('../services/deviceScope.service');
    const access = await resolveRequestDevice(req, req.params.id);
    if (!access.ok) return next(new AppError(access.status, access.error));
    const mode = (req.body?.mode === 'live' ? 'live' : 'push_now') as 'live' | 'push_now';
    const windowSec = mode === 'live'
      ? Math.max(5, Math.min(600, Number(req.body?.windowSec ?? 60) || 60))
      : undefined;
    const sent = await deviceService.requestLiveMetrics(access.device.id, access.device.tenant_id, mode, windowSec);
    res.json({ data: { sent, mode, windowSec } });
  } catch (err) { next(err); }
});

// PATCH /api/devices/:id
router.patch('/:id', requireDeviceWrite(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    // Display name (the pencil next to the device name): same rules as the
    // bulk rename (services/deviceName.ts). `null` and '' keep their meaning
    // (back to the hostname); a non-empty name is trimmed and validated.
    if (req.body && req.body.displayName !== undefined && req.body.displayName !== null && req.body.displayName !== '') {
      const { validateDeviceDisplayName } = await import('../services/deviceName');
      const v = validateDeviceDisplayName(req.body.displayName);
      if (!v.ok && v.reason !== 'empty') throw new AppError(400, `Invalid display name (${v.reason})`, `device_name_${v.reason}`);
      req.body.displayName = v.ok ? v.value : '';
    }
    // thresholdsOverride is stored verbatim in JSONB and read by the
    // threshold cascade on every push: validate it with the same schema as
    // the group / tenant / global layers (null or {} = clear the override).
    if (req.body && req.body.thresholdsOverride !== undefined) {
      if (req.body.thresholdsOverride === null) {
        req.body.thresholdsOverride = {};
      } else {
        const { metricThresholdsSchema } = await import('../validators/group.schema');
        const parsed = metricThresholdsSchema.safeParse(req.body.thresholdsOverride);
        if (!parsed.success) {
          const issues = parsed.error.errors.map((e) => `${e.path.join('.') || '<root>'}: ${e.message}`).join('; ');
          throw new AppError(400, `Invalid thresholdsOverride — ${issues}`);
        }
        req.body.thresholdsOverride = parsed.data;
      }
    }
    // A new group must be a group of the device's own tenant (null =
    // ungrouped): the closure would otherwise give that other tenant's teams
    // rights on this device. Same rule as POST /batch/change-group.
    if (req.body.groupId !== undefined && req.body.groupId !== null) {
      const owner = await db('devices').where({ id: deviceId }).first('tenant_id') as { tenant_id: number } | undefined;
      if (!owner) return res.status(404).json({ error: 'Device not found' });
      const groupId = Number(req.body.groupId);
      const grp = Number.isInteger(groupId)
        ? await db('device_groups').where({ id: groupId, tenant_id: owner.tenant_id }).first('id')
        : undefined;
      if (!grp) return res.status(404).json({ error: 'Group not found' });
    }
    // Check if group is changing so we can fire a scenario trigger
    const hadGroupChange = req.body.groupId !== undefined;
    const device = await deviceService.updateDevice(deviceId, req.tenantId!, req.body);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    // Fire scenario trigger when device joins a new group
    if (hadGroupChange && device.groupId) {
      // The device's own tenant's scenarios (god view: not the master's).
      scenarioService.fireTrigger('group_join', deviceId, device.tenantId ?? req.tenantId!, { groupId: device.groupId }).catch(err => {
        logger.error({ err, deviceId }, 'Failed to fire group_join scenario trigger');
      });
    }
    res.json({ data: device });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/thresholds-resolved — threshold cascade of the device
// with the origin (layer + name) of every value. `?scope=parent` stops above
// the device's own override: what the device inherits (device editor:
// placeholders + greyed alerts switch), group chain or tenant when ungrouped.
router.get('/:id/thresholds-resolved', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const q = db('devices').where({ id: deviceId }).first('id');
    if (!hasGlobalView(req)) q.where({ tenant_id: req.tenantId! });
    if (!(await q)) return res.status(404).json({ error: 'Device not found' });
    const { thresholdService } = await import('../services/threshold.service');
    const resolved = await thresholdService.resolveForDevice(deviceId, { includeDevice: req.query.scope !== 'parent' });
    res.json({ data: resolved });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/metrics/history — windowed CPU/RAM avg·peak·min + disk
// usage/delta over 24h / 7d / 30d, from the pre-aggregated metric buckets.
router.get('/:id/metrics/history', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const history = await deviceService.getDeviceMetricsHistory(deviceId, req.tenantId!);
    res.json({ data: history });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/custom-metrics
router.get('/:id/custom-metrics', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const metrics = await customMetricService.listForDevice(deviceId, req.tenantId!);
    res.json({ data: metrics });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/disk-health — SMART per-disk snapshot for this device
router.get('/:id/disk-health', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const { diskHealthService } = await import('../services/diskHealth.service');
    const disks = await diskHealthService.listForDevice(deviceId, req.tenantId!);
    res.json({ data: disks });
  } catch (err) { next(err); }
});

// ── Rewind time-machine ─────────────────────────────────────────────────────
// Accepts ISO strings or epoch-ms in from/to/ts query params.
const parseRewindTs = (v: unknown): Date | null => {
  if (v == null || v === '') return null;
  const s = String(v);
  const d = new Date(/^\d+$/.test(s) ? Number(s) : s);
  return isNaN(d.getTime()) ? null : d;
};

// GET /api/devices/:id/rewind/range — scrubber bounds + where detail exists
router.get('/:id/rewind/range', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const { rewindService } = await import('../services/rewind.service');
    res.json({ data: await rewindService.getRange(deviceId, req.tenantId!) });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/rewind/series?from=&to= — CPU/RAM/Disk timeseries
router.get('/:id/rewind/series', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const to = parseRewindTs(req.query.to) ?? new Date();
    const from = parseRewindTs(req.query.from) ?? new Date(to.getTime() - 24 * 60 * 60 * 1000);
    const { rewindService } = await import('../services/rewind.service');
    res.json({ data: await rewindService.getSeries(deviceId, req.tenantId!, from, to) });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/rewind/at?ts= — processes + services nearest an instant
router.get('/:id/rewind/at', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const at = parseRewindTs(req.query.ts) ?? new Date();
    const { rewindService } = await import('../services/rewind.service');
    res.json({ data: await rewindService.getSnapshotAt(deviceId, req.tenantId!, at) });
  } catch (err) { next(err); }
});

// ── Change events (Blame Ribbon source) ─────────────────────────────────────
// Read-through union over the tables Obliance already writes: what changed on
// this device in a window. Same guard as the Rewind routes above — a weaker one
// here would be a permission bypass, since this exposes per-device history.
//
// The service also filters per CALLER (a non-admin does not see another user's
// audit rows), so the session identity is passed through rather than assumed.
router.get('/:id/change-events', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const { changeEventService, changeEventsQuerySchema } = await import('../services/changeEvent.service');
    const parsed = changeEventsQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid query' });
    }
    res.json({
      data: await changeEventService.getTimeline(deviceId, req.tenantId!, {
        ...parsed.data,
        callerUserId: req.session.userId!,
        callerIsAdmin: req.session.role === 'admin',
      }),
    });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/change-events/summary?from=&to= — counts per kind
router.get('/:id/change-events/summary', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const { changeEventService, changeEventsSummaryQuerySchema } = await import('../services/changeEvent.service');
    const parsed = changeEventsSummaryQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid query' });
    }
    res.json({
      data: await changeEventService.getSummary(deviceId, req.tenantId!, {
        ...parsed.data,
        callerUserId: req.session.userId!,
        callerIsAdmin: req.session.role === 'admin',
      }),
    });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/custom-sections — list sections that apply to this device
router.get('/:id/custom-sections', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const sections = await customSectionService.listForDevice(deviceId, req.tenantId!);
    res.json({ data: sections });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/services
router.get('/:id/services', requireDeviceRead(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const device = await db('devices')
      .where({ id: deviceId, tenant_id: req.tenantId! })
      .select('latest_services')
      .first();
    if (!device) return res.status(404).json({ error: 'Device not found' });
    const services = device.latest_services ?? [];
    res.json({ data: services });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/approve
router.post('/:id/approve', requireTenantCapability('agent_config:approval'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    // In the device's tenant (god view included): its row, its scenarios.
    const target = await actionDevice(req, id);
    if (!target) return res.status(404).json({ error: 'Device not found' });
    const device = await deviceService.approveDevice(id, target.tenant_id, req.session.userId!);
    // Fire scenario trigger for newly approved agent
    if (device) {
      scenarioService.fireTrigger('agent_approved', device.id, target.tenant_id).catch(err => {
        logger.error({ err, deviceId: device.id }, 'Failed to fire agent_approved scenario trigger');
      });
      await auditDeviceAction(req, target.tenant_id, 'device.approved', {
        deviceId: id, resourceType: 'device', resourcePath: String(id),
        details: { hostname: device.hostname },
      });
    }
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/refuse
router.post('/:id/refuse', requireTenantCapability('agent_config:approval'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const target = await actionDevice(req, id);
    if (!target) return res.status(404).json({ error: 'Device not found' });
    const device = await deviceService.refuseDevice(id, target.tenant_id);
    if (device) {
      await auditDeviceAction(req, target.tenant_id, 'device.refused', {
        deviceId: id, resourceType: 'device', resourcePath: String(id),
        details: { hostname: device.hostname },
      });
    }
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/suspend
router.post('/:id/suspend', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const target = await actionDevice(req, id);
    if (!target) return res.status(404).json({ error: 'Device not found' });
    const device = await deviceService.suspendDevice(id, target.tenant_id);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    await auditDeviceAction(req, target.tenant_id, 'device.suspended', {
      deviceId: id, resourceType: 'device', resourcePath: String(id),
      details: { hostname: device.hostname },
    });
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/unsuspend
router.post('/:id/unsuspend', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const target = await actionDevice(req, id);
    if (!target) return res.status(404).json({ error: 'Device not found' });
    const device = await deviceService.unsuspendDevice(id, target.tenant_id);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    await auditDeviceAction(req, target.tenant_id, 'device.unsuspended', {
      deviceId: id, resourceType: 'device', resourcePath: String(id),
      details: { hostname: device.hostname },
    });
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/duplicate-id/acknowledge
// Admin confirms they've seen the "duplicate agent ID suspected" warning.
// Trims the identity-fingerprints buffer to its latest entry and clears
// the flag — if duplication continues, the next ~2-3 alternating pushes
// will re-flag automatically. Any tenant member with device-write on
// this device can ack (no platform-admin gate — the fix lives outside
// Obliance and the owning team should be able to silence the noise).
router.post('/:id/duplicate-id/acknowledge', requireDeviceWrite(), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const target = await actionDevice(req, id);
    if (!target) return res.status(404).json({ error: 'Device not found' });
    await deviceService.acknowledgeDuplicateAgentId(id, target.tenant_id);
    await auditDeviceAction(req, target.tenant_id, 'device.duplicate_id_acknowledged', {
      deviceId: id, resourceType: 'device', resourcePath: String(id),
    });
    res.json({ data: { ok: true } });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/privacy-mode/enable — send enable_privacy_mode command to agent
router.post('/:id/privacy-mode/enable', requireRole('admin'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const device = await deviceService.getDeviceById(id, req.tenantId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });

    const { applyRestriction } = await import('../services/restriction.service');
    const deviceTenantId = device.tenantId ?? req.tenantId!;
    const approved = await applyRestriction(res, {
      req, actionKey: 'command.enable_privacy_mode', deviceIds: [id], deviceTenantId,
      approvalRequestType: 'batch_command',
      approvalDescription: `Enable privacy mode on ${device.hostname}`,
      approvalPayload: { action: 'enable_privacy_mode', deviceIds: [id] },
    });
    if (!approved) return;

    const cmd = await commandService.enqueue({
      deviceId: id,
      tenantId: deviceTenantId,
      type: 'enable_privacy_mode' as any,
      priority: 'high',
      expiresInSeconds: 300,
      createdBy: req.session.userId,
    });
    await auditDeviceAction(req, deviceTenantId, 'command.enable_privacy_mode', {
      deviceId: id, resourceType: 'command', resourcePath: cmd.id,
      details: { hostname: device.hostname },
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/privacy-mode/disable — send disable_privacy_mode command to agent
router.post('/:id/privacy-mode/disable', requireRole('admin'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const device = await deviceService.getDeviceById(id, req.tenantId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });

    // If a privacy-gate password is set, refuse here. Callers must use
    // /api/devices/:id/privacy/disable-with-password which verifies the
    // password on the agent first.
    if ((device as any).privacyPasswordSet) {
      return next(new AppError(423, 'Privacy password is set — use /privacy/disable-with-password'));
    }

    const { applyRestriction } = await import('../services/restriction.service');
    const deviceTenantId = device.tenantId ?? req.tenantId!;
    const approved = await applyRestriction(res, {
      req, actionKey: 'command.disable_privacy_mode', deviceIds: [id], deviceTenantId,
      approvalRequestType: 'batch_command',
      approvalDescription: `Disable privacy mode on ${device.hostname}`,
      approvalPayload: { action: 'disable_privacy_mode', deviceIds: [id] },
    });
    if (!approved) return;

    const cmd = await commandService.enqueue({
      deviceId: id,
      tenantId: deviceTenantId,
      type: 'disable_privacy_mode',
      priority: 'high',
      expiresInSeconds: 300,
      createdBy: req.session.userId,
    });
    await auditDeviceAction(req, deviceTenantId, 'command.disable_privacy_mode', {
      deviceId: id, resourceType: 'command', resourcePath: cmd.id,
      details: { hostname: device.hostname },
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/airgap/enable — enable airgap mode on device
router.post('/:id/airgap/enable', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const device = await deviceService.getDeviceById(id, req.tenantId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });

    // Resolve server hostname to IPs so the agent knows which IPs to allow
    const serverUrl = process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
    const hostname = new URL(serverUrl).hostname;
    let serverIPs: string[] = [];
    try { serverIPs.push(...await dns.resolve4(hostname)); } catch {}
    try { serverIPs.push(...await dns.resolve6(hostname)); } catch {}

    const deviceTenantId = device.tenantId ?? req.tenantId!;
    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req, actionKey: 'command.enable_airgap', deviceIds: [id], deviceTenantId,
      approvalRequestType: 'batch_command',
      approvalDescription: `Enable airgap on ${device.hostname}`,
      // The allow-list the agent keeps open (server IPs), as the direct path sends it.
      approvalPayload: { action: 'enable_airgap', deviceIds: [id], params: { serverIPs } },
    });
    if (!approved) return;

    await commandService.enqueue({
      deviceId: id,
      tenantId: deviceTenantId,
      type: 'enable_airgap' as any,
      payload: { serverIPs },
      priority: 'high',
      expiresInSeconds: 300,
      createdBy: req.session.userId,
    });

    await db('devices').where({ id, tenant_id: deviceTenantId }).update({
      airgap_enabled: true,
      airgap_enabled_at: new Date(),
      updated_at: new Date(),
    });

    await auditDeviceAction(req, deviceTenantId, 'command.enable_airgap', {
      deviceId: id, resourceType: 'device', resourcePath: String(id),
      details: { hostname: device.hostname },
    });

    emitDeviceEvents(id, deviceTenantId, [[SocketEvents.DEVICE_UPDATED, { id, airgapEnabled: true, airgapEnabledAt: new Date().toISOString() }]]);
    res.json({ data: { success: true } });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/airgap/disable — disable airgap mode on device
router.post('/:id/airgap/disable', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const device = await deviceService.getDeviceById(id, req.tenantId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });

    const deviceTenantId = device.tenantId ?? req.tenantId!;
    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req, actionKey: 'command.disable_airgap', deviceIds: [id], deviceTenantId,
      approvalRequestType: 'batch_command',
      approvalDescription: `Disable airgap on ${device.hostname}`,
      approvalPayload: { action: 'disable_airgap', deviceIds: [id] },
    });
    if (!approved) return;

    await commandService.enqueue({
      deviceId: id,
      tenantId: deviceTenantId,
      type: 'disable_airgap' as any,
      priority: 'high',
      expiresInSeconds: 300,
      createdBy: req.session.userId,
    });

    await db('devices').where({ id, tenant_id: deviceTenantId }).update({
      airgap_enabled: false,
      airgap_enabled_at: null,
      updated_at: new Date(),
    });

    await auditDeviceAction(req, deviceTenantId, 'command.disable_airgap', {
      deviceId: id, resourceType: 'device', resourcePath: String(id),
      details: { hostname: device.hostname },
    });

    emitDeviceEvents(id, deviceTenantId, [[SocketEvents.DEVICE_UPDATED, { id, airgapEnabled: false, airgapEnabledAt: null }]]);
    res.json({ data: { success: true } });
  } catch (err) { next(err); }
});

// ── Migration: reduced legacy agent → full agent (nt6 MSI) ─────────────────
// services/legacyMigration.service.ts. Platform admin + write on the device
// (admins pass requireDeviceWrite; kept for the day the rule widens). The
// restriction level of "Update agent" applies (sensitive → step-up;
// restricted → refused: no approval executor for this action). The API key
// never leaves the device (the script reads the one the agent uses).
async function migrateOneLegacy(req: any, id: number): Promise<{ ok: true; data: any } | { ok: false; status: number; body: any; headers?: Record<string, string> }> {
  const { legacyMigrationService } = await import('../services/legacyMigration.service');
  const scope = req.tenantId as number;
  const q = db('devices').where({ id });
  if (!isGodView(scope)) q.where({ tenant_id: scope });
  const dev = await q.first('id', 'tenant_id', 'hostname');
  if (!dev) return { ok: false, status: 404, body: { error: 'Device not found' } };
  const r = await legacyMigrationService.request(id, scope, req.session.userId ?? null);
  if (!r.ok) return { ok: false, status: r.status, body: { error: r.error, code: r.code } };
  try {
    const { auditService } = await import('../services/audit.service');
    const extras = { deviceId: id, resourceType: 'command', resourcePath: r.commandId, details: { hostname: r.hostname, commandId: r.commandId } };
    await auditService.logReq(req, 'device.migrate_legacy_agent', extras);
    if (r.tenantId !== scope) await auditService.logReqAs(req, r.tenantId, 'device.migrate_legacy_agent', { ...extras, details: { ...extras.details, initiatedFromTenantId: scope } });
  } catch { /* audit is best effort */ }
  emitDeviceEvents(id, r.tenantId, [[SocketEvents.DEVICE_UPDATED, { id, legacyMigration: r.state }]]);
  return { ok: true, data: { commandId: r.commandId, legacyMigration: r.state } };
}

async function migrationRestriction(req: any, res: any, deviceIds: number[], deviceTenantId?: number): Promise<boolean> {
  const { restrictionService } = await import('../services/restriction.service');
  // No approvalRequestType: 'restricted' answers 403 (no executor for it).
  const outcome = await restrictionService.enforce({ req, actionKey: 'command.update_agent', deviceIds, deviceTenantId });
  if (outcome.ok) return true;
  for (const [k, v] of Object.entries(((outcome as any).headers ?? {}) as Record<string, string>)) res.setHeader(k, v);
  res.status((outcome as any).status).json((outcome as any).body);
  return false;
}

// POST /api/devices/bulk/migrate-legacy-agent { deviceIds } — the same, per device
router.post('/bulk/migrate-legacy-agent', requireRole('admin'), async (req, res, next) => {
  try {
    const raw = (req.body as { deviceIds?: unknown })?.deviceIds;
    const ids = Array.isArray(raw) ? [...new Set(raw.map(Number).filter((n) => Number.isInteger(n) && n > 0))].slice(0, 500) : [];
    if (!ids.length) return res.status(400).json({ error: 'deviceIds required' });
    const q = db('devices').whereIn('id', ids).where({ agent_flavor: 'legacy' });
    if (!hasGlobalView(req)) q.where({ tenant_id: req.tenantId! });
    const rows = await q.select('id', 'tenant_id') as Array<{ id: number; tenant_id: number }>;
    if (!rows.length) return res.status(404).json({ error: 'No legacy agent among these devices' });
    const tenants = [...new Set(rows.map((r) => r.tenant_id))];
    const { restrictionService } = await import('../services/restriction.service');
    const outcome = await restrictionService.enforce({ req, actionKey: 'command.update_agent', deviceIds: rows.map((r) => r.id), levelTenantIds: tenants.filter((t) => t !== req.tenantId) });
    if (!outcome.ok) {
      for (const [k, v] of Object.entries(((outcome as any).headers ?? {}) as Record<string, string>)) res.setHeader(k, v);
      return res.status((outcome as any).status).json((outcome as any).body);
    }
    const results: Array<{ deviceId: number; ok: boolean; error?: string; code?: string }> = [];
    for (const r of rows) {
      const one = await migrateOneLegacy(req, r.id);
      results.push(one.ok ? { deviceId: r.id, ok: true } : { deviceId: r.id, ok: false, error: one.body?.error, code: one.body?.code });
    }
    res.json({ data: { queued: results.filter((r) => r.ok).length, skipped: ids.length - results.filter((r) => r.ok).length, results } });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/migrate-legacy-agent
router.post('/:id/migrate-legacy-agent', requireRole('admin'), requireDeviceWrite(), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid device ID' });
    const q = db('devices').where({ id });
    if (!hasGlobalView(req)) q.where({ tenant_id: req.tenantId! });
    const dev = await q.first('id', 'tenant_id');
    if (!dev) return res.status(404).json({ error: 'Device not found' });
    if (!(await migrationRestriction(req, res, [id], dev.tenant_id))) return;
    const r = await migrateOneLegacy(req, id);
    if (!r.ok) return res.status(r.status).json(r.body);
    res.json({ data: r.data });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/legacy-migration — the migration state (command outcome folded in)
router.get('/:id/legacy-migration', requireDeviceRead(), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const q = db('devices').where({ id });
    if (!hasGlobalView(req)) q.where({ tenant_id: req.tenantId! });
    const dev = await q.first('id', 'legacy_migration');
    if (!dev) return res.status(404).json({ error: 'Device not found' });
    const { legacyMigrationService } = await import('../services/legacyMigration.service');
    res.json({ data: await legacyMigrationService.view(dev.legacy_migration, dev.id) });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/uninstall — mark as pending_uninstall + send uninstall command to agent.
// Routed through 2-step approval when the tenant has opted in.
router.post('/:id/uninstall', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const existing = await deviceService.getDeviceById(id, req.tenantId!);
    if (!existing) return res.status(404).json({ error: 'Device not found' });

    const name = existing.displayName || existing.hostname || `#${id}`;
    // God view: the device's tenant (its matrix too, its row, its queue).
    const deviceTenantId = existing.tenantId ?? req.tenantId!;
    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'command.uninstall_agent',
      deviceIds: [id],
      deviceTenantId,
      approvalRequestType: 'device_uninstall',
      approvalDescription: `Uninstall agent from ${name}`,
      approvalPayload: { deviceId: id },
    });
    if (!approved) return;

    const device = await deviceService.initiateUninstall(id, deviceTenantId);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    commandService.enqueue({
      deviceId: id, tenantId: deviceTenantId,
      type: 'uninstall_agent', payload: {},
      priority: 'urgent', expiresInSeconds: 600,
      createdBy: req.session.userId,
    }).catch(() => { /* ignore enqueue errors */ });
    await auditDeviceAction(req, deviceTenantId, 'device.uninstall_requested', {
      deviceId: id, resourceType: 'device', resourcePath: String(id),
      details: { hostname: existing.hostname, displayName: existing.displayName },
    });
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/cancel-uninstall — abort a pending uninstall, restore to offline
router.post('/:id/cancel-uninstall', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const target = await actionDevice(req, id);
    if (!target) return res.status(404).json({ error: 'Device not found' });
    const device = await deviceService.cancelUninstall(id, target.tenant_id);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    await auditDeviceAction(req, target.tenant_id, 'device.uninstall_cancelled', {
      deviceId: id, resourceType: 'device', resourcePath: String(id),
      details: { hostname: device.hostname },
    });
    res.json({ data: device });
  } catch (err) { next(err); }
});

// GET /api/devices/transfer/candidates — tenant-level list, same body
// shape as the per-device variant below. Used by the bulk transfer UI
// where no single deviceId is relevant.
router.get('/transfer/candidates', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const userId = req.session.userId!;
    const isPlatformAdmin = req.session.role === 'admin';

    let tenantsQ = db('tenants').select('id', 'name', 'slug').orderBy('name');
    if (!isPlatformAdmin) {
      tenantsQ = tenantsQ
        .join('user_tenants', 'user_tenants.tenant_id', 'tenants.id')
        .where({ 'user_tenants.user_id': userId, 'user_tenants.role': 'admin' })
        .select('tenants.id', 'tenants.name', 'tenants.slug');
    }
    const tenants = (await tenantsQ).filter((t: any) => t.id !== req.tenantId!);

    if (tenants.length === 0) return res.json({ data: [] });

    const keys = await db('agent_api_keys')
      .whereIn('tenant_id', tenants.map((t: any) => t.id))
      .select('id', 'tenant_id', 'name', 'default_group_id');
    const keysByTenant = new Map<number, any[]>();
    for (const k of keys) {
      if (!keysByTenant.has(k.tenant_id)) keysByTenant.set(k.tenant_id, []);
      keysByTenant.get(k.tenant_id)!.push({ id: k.id, label: k.name, defaultGroupId: k.default_group_id ?? null });
    }

    res.json({
      data: tenants.map((t: any) => ({
        tenantId: t.id, tenantName: t.name, tenantSlug: t.slug,
        apiKeys: keysByTenant.get(t.id) ?? [],
      })),
    });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/transfer/candidates — list the tenants the caller
// can transfer INTO (must be admin there, or platform admin) along with
// their API keys. Excludes the current tenant.
router.get('/:id/transfer/candidates', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const userId = req.session.userId!;
    const isPlatformAdmin = req.session.role === 'admin';

    let tenantsQ = db('tenants').select('id', 'name', 'slug').orderBy('name');
    if (!isPlatformAdmin) {
      // Only tenants where the user has admin membership.
      tenantsQ = tenantsQ
        .join('user_tenants', 'user_tenants.tenant_id', 'tenants.id')
        .where({ 'user_tenants.user_id': userId, 'user_tenants.role': 'admin' })
        .select('tenants.id', 'tenants.name', 'tenants.slug');
    }
    const tenants = (await tenantsQ).filter((t: any) => t.id !== req.tenantId!);

    if (tenants.length === 0) {
      return res.json({ data: [] });
    }

    const keys = await db('agent_api_keys')
      .whereIn('tenant_id', tenants.map((t: any) => t.id))
      .select('id', 'tenant_id', 'name', 'default_group_id');

    const keysByTenant = new Map<number, any[]>();
    for (const k of keys) {
      if (!keysByTenant.has(k.tenant_id)) keysByTenant.set(k.tenant_id, []);
      keysByTenant.get(k.tenant_id)!.push({
        id: k.id,
        label: k.name,        // client contract is still `label`
        defaultGroupId: k.default_group_id ?? null,
      });
    }

    res.json({
      data: tenants.map((t: any) => ({
        tenantId: t.id,
        tenantName: t.name,
        tenantSlug: t.slug,
        apiKeys: keysByTenant.get(t.id) ?? [],
      })),
    });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/transfer — move a device from the current tenant
// to another tenant. Caller must be admin in BOTH tenants (or platform
// admin). The device's tenant_id + api_key_id are updated, group_id is
// cleared, and a `reconfigure_agent` command is enqueued so the agent
// picks up the new API key on its next push.
//
// Body: { targetTenantId: number, targetApiKeyId: number }
router.post('/:id/transfer', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const { targetTenantId, targetApiKeyId } = req.body as { targetTenantId: number; targetApiKeyId: number };
    if (!targetTenantId || !targetApiKeyId) {
      return res.status(400).json({ error: 'targetTenantId and targetApiKeyId required' });
    }
    if (targetTenantId === req.tenantId!) {
      return res.status(400).json({ error: 'Target tenant is the same as source' });
    }

    const userId = req.session.userId!;
    const isPlatformAdmin = req.session.role === 'admin';
    // Platform admin bypasses tenant-level admin check. Otherwise the
    // caller must be an admin in BOTH the source and the destination.
    if (!isPlatformAdmin) {
      const [sourceMembership, targetMembership] = await Promise.all([
        db('user_tenants').where({ user_id: userId, tenant_id: req.tenantId!, role: 'admin' }).first(),
        db('user_tenants').where({ user_id: userId, tenant_id: targetTenantId, role: 'admin' }).first(),
      ]);
      if (!sourceMembership || !targetMembership) {
        return res.status(403).json({ error: 'You must be admin of both tenants' });
      }
    }

    const device = await db('devices').where({ id: deviceId, tenant_id: req.tenantId! }).first();
    if (!device) return res.status(404).json({ error: 'Device not found' });

    const targetKey = await db('agent_api_keys').where({ id: targetApiKeyId, tenant_id: targetTenantId }).first();
    if (!targetKey) return res.status(400).json({ error: 'Target API key not found in target tenant' });

    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'device.transfer_tenant',
      deviceIds: [deviceId],
      approvalRequestType: 'device_uninstall',
      approvalDescription: `Transfer ${device.hostname} to ${await (await import('../services/approvalDescribe')).tenantLabel(targetTenantId)} (agent key "${targetKey.name ?? targetApiKeyId}")`,
      approvalPayload: { deviceId, targetTenantId, targetApiKeyId, serverUrl: `${req.protocol}://${req.get('host')}` },
    });
    if (!approved) return;

    const serverUrl = `${req.protocol}://${req.get('host')}`;

    await db.transaction(async (trx) => {
      // Enqueue the reconfigure command in the SOURCE tenant's queue so the
      // agent still picks it up on its next push (it's still using the old
      // API key). Payload carries the new key + server URL so the agent can
      // rewrite its config.json and start authenticating against the target.
      await trx('command_queue').insert({
        device_id: deviceId,
        tenant_id: req.tenantId!,
        type: 'reconfigure_agent',
        payload: JSON.stringify({
          apiKey: targetKey.key,
          serverUrl,
          targetTenantId,
        }),
        priority: 'urgent',
        status: 'pending',
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
        created_by: userId,
      });

      // Move the device record.
      await trx('devices').where({ id: deviceId }).update({
        tenant_id: targetTenantId,
        api_key_id: targetApiKeyId,
        group_id: null,
        schedule_alert: null,
        updated_at: new Date(),
      });

      // Clear cross-tenant artefacts that would otherwise point at the
      // old tenant's schedules / compliance lists.
      await trx('device_custom_metrics').where({ device_id: deviceId }).delete();
      await trx('software_compliance_results').where({ device_id: deviceId }).delete();

      // Cancel any still-pending commands from the source tenant.
      await trx('command_queue')
        .where({ device_id: deviceId, tenant_id: req.tenantId! })
        .whereIn('status', ['pending', 'sent'])
        .whereNot({ type: 'reconfigure_agent' })
        .update({ status: 'cancelled', finished_at: new Date() });
    });

    // New tenant, no group = a different alerts switch (`notify`) chain:
    // silently re-baseline the alertable level (see bulk transfer above).
    {
      const { metricAlertRebaseline } = await import('../services/metricAlertRebaseline.service');
      metricAlertRebaseline.schedule({ kind: 'devices', deviceIds: [deviceId] }, 'tenant transfer');
    }

    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.transferred', {
        deviceId,
        resourceType: 'device',
        resourcePath: String(deviceId),
        details: {
          fromTenantId: req.tenantId,
          toTenantId: targetTenantId,
          targetApiKeyId,
          hostname: device.hostname,
        },
      });
    } catch {}

    res.json({ data: { ok: true } });
  } catch (err) { next(err); }
});

// DELETE /api/devices/:id
router.delete('/:id', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const existing = await deviceService.getDeviceById(id, req.tenantId!);
    if (!existing) return res.status(404).json({ error: 'Device not found' });

    // God view: deleted in the device's tenant (its restriction matrix too).
    const deviceTenantId = existing.tenantId ?? req.tenantId!;
    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'device.delete',
      deviceIds: [id],
      deviceTenantId,
      approvalRequestType: 'device_uninstall',
      approvalDescription: `Delete device ${existing.displayName || existing.hostname || `#${id}`}`,
      approvalPayload: { deviceId: id, deleteOnly: true },
    });
    if (!approved) return;

    await deviceService.deleteDevice(id, deviceTenantId);
    // No device_id column here: the row is gone and audit_logs.device_id
    // references devices — the insert failed (silently) on that key, and
    // a deletion was never journaled. The id is in resource_path + details.
    await auditDeviceAction(req, deviceTenantId, 'device.deleted', {
      resourceType: 'device', resourcePath: String(id),
      details: { deviceId: id, hostname: existing?.hostname, displayName: existing?.displayName },
    });
    res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
