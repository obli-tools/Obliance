import { Router } from 'express';
import { db } from '../db';
import { hyperVService } from '../services/hyperV.service';
import { hypervViewableHostIds } from '../services/hyperVAudience.service';
import { commandService } from '../services/command.service';
import { applyRestriction } from '../services/restriction.service';
import { AppError } from '../middleware/errorHandler';
import { launchChromium } from '../utils/chromium';
import type { VmAction } from '@obliance/shared';
import { vmMatchesSearch, isMasterTenant } from '@obliance/shared';

const router = Router();

// Map each VM action to (capability tier, restriction key). Power actions
// need hyperv:power; everything heavier needs hyperv:manage. The restriction
// key drives the per-tenant 2FA / double-admin gate.
const ACTION_META: Record<VmAction, { cap: 'hyperv:power' | 'hyperv:manage'; restrictionKey: string }> = {
  start:              { cap: 'hyperv:power',  restrictionKey: 'hyperv.vm_start' },
  stop:               { cap: 'hyperv:power',  restrictionKey: 'hyperv.vm_stop' },
  shutdown:           { cap: 'hyperv:power',  restrictionKey: 'hyperv.vm_shutdown' },
  restart:            { cap: 'hyperv:power',  restrictionKey: 'hyperv.vm_restart' },
  save:               { cap: 'hyperv:power',  restrictionKey: 'hyperv.vm_save' },
  pause:              { cap: 'hyperv:power',  restrictionKey: 'hyperv.vm_save' },
  resume:             { cap: 'hyperv:power',  restrictionKey: 'hyperv.vm_save' },
  checkpoint_create:  { cap: 'hyperv:manage', restrictionKey: 'hyperv.vm_checkpoint' },
  checkpoint_apply:   { cap: 'hyperv:manage', restrictionKey: 'hyperv.vm_checkpoint_apply' },
  checkpoint_delete:  { cap: 'hyperv:manage', restrictionKey: 'hyperv.vm_checkpoint_delete' },
  edit:               { cap: 'hyperv:manage', restrictionKey: 'hyperv.vm_edit' },
  create:             { cap: 'hyperv:manage', restrictionKey: 'hyperv.vm_create' },
  delete:             { cap: 'hyperv:manage', restrictionKey: 'hyperv.vm_delete' },
};

// Every host-scoped route: the REST device rules (deviceScope.service
// resolveRequestDevice: the session's tenant, any tenant for an admin on the
// master one = god view; a non-admin must be a member of that tenant and see
// the device) + the capability on that host. Until 2026-10 these routes only
// had requireDeviceRead (no tenant check: a team grant in another tenant, or
// a platform admin on a child tenant, reached any host by id).
async function hostScope(req: import('express').Request, rawId: unknown, capability: 'hyperv:view' | 'hyperv:power' | 'hyperv:manage') {
  const { resolveRequestDevice } = await import('../services/deviceScope.service');
  const access = await resolveRequestDevice(req, rawId, { capability, capabilityError: `${capability} capability required` });
  if (!access.ok) throw new AppError(access.status, access.error);
  return access.device;
}

// The tenant-wide VM list (grid + export). Platform admins: the session's
// tenant, every tenant on the master one (god view) or with ?tenantId=all
// (the Oblireach Desktop's multi-server mode, as GET /reach/overview: what a
// switch to the master tenant already gives them). Other users: the
// session's tenant only (?tenantId ignored), and only the hosts on which
// they hold hyperv:view (hypervViewableHostIds: one bulk check, no N+1).
async function vmListScope(req: import('express').Request): Promise<{ tenantId: number | null; hostIds?: number[]; all: boolean }> {
  const tenantId = req.tenantId!;
  if (req.session.role === 'admin') {
    const all = isMasterTenant(tenantId) || req.query.tenantId === 'all';
    return { tenantId: all ? null : tenantId, all };
  }
  return { tenantId, hostIds: await hypervViewableHostIds(req.session.userId!, tenantId), all: false };
}

// GET /api/hyperv/devices/:id/vms — VM list for one host.
router.get('/devices/:id/vms', async (req, res, next) => {
  try {
    const device = await hostScope(req, req.params.id, 'hyperv:view');
    const vms = await hyperVService.listForDevice(device.id);
    res.json({ data: vms });
  } catch (err) { next(err); }
});

// POST /api/hyperv/devices/:id/refresh — ask the host agent to re-enumerate.
// Manual one-shot (button) — goes through the durable command queue so it
// shows in task history, AND is pushed at once on the live command channel
// (it used to wait for the agent's next poll: "Sent" for minutes).
router.post('/devices/:id/refresh', async (req, res, next) => {
  try {
    const host = await hostScope(req, req.params.id, 'hyperv:view');
    const id = host.id;
    // The host's tenant (god view: the master session acts on a child tenant's host).
    const cmd = await commandService.enqueue({
      deviceId: id, tenantId: Number(host.tenant_id), type: 'hyperv_list_vms' as any,
      priority: 'high', expiresInSeconds: 300, createdBy: req.session.userId,
    });
    const { agentHub } = await import('../services/agentHub.service');
    if (agentHub.push(id, { type: 'command', id: cmd.id, commandType: 'hyperv_list_vms', payload: {} })) {
      try {
        await db('command_queue').where({ id: cmd.id, status: 'pending' })
          .update({ status: 'sent', sent_at: new Date(), updated_at: new Date() });
      } catch { /* re-delivered by the next poll */ }
    }
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// VM console helper (FreeRDP + H.264 bundle, ~50 MB download / ~130 MB
// unpacked) — services/vmConsole.service.ts. Same right as opening a
// console: the 'remote' capability (resolveRequestDevice).
async function consoleScope(req: import('express').Request) {
  const { resolveRequestDevice } = await import('../services/deviceScope.service');
  const access = await resolveRequestDevice(req, req.params.id, {
    capability: 'remote', capabilityError: 'Remote access not permitted for your team',
  });
  if (!access.ok) throw new AppError(access.status, access.error);
  const { isMasterTenant } = await import('@obliance/shared');
  return { device: access.device, scope: { tenantId: req.tenantId!, isMaster: access.isAdmin && isMasterTenant(req.tenantId!) } };
}

// GET /api/hyperv/devices/:id/console-status — installed / version / error,
// the install task in flight (progress), the last one, the policy.
router.get('/devices/:id/console-status', async (req, res, next) => {
  try {
    const { device, scope } = await consoleScope(req);
    const { consoleStatus } = await import('../services/vmConsole.service');
    res.json({ data: await consoleStatus(device.id, scope) });
  } catch (err) { next(err); }
});

// POST /api/hyperv/devices/:id/install-console { force?: boolean } — install
// (or repair: force) the helper NOW. A real task (Tasks tab: Pending → Sent →
// Running with progress → Success / Failure / Timeout); one per device — a
// click during an install returns the running task (alreadyRunning).
router.post('/devices/:id/install-console', async (req, res, next) => {
  try {
    const { device, scope } = await consoleScope(req);
    const force = req.body?.force === true;
    const { requestManualInstall } = await import('../services/vmConsole.service');
    const out = await requestManualInstall(device.id, scope, req.session.userId!, force);
    if (out.created) {
      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'hyperv.console_install', {
          deviceId: device.id, resourceType: 'command', resourcePath: out.command.id,
          details: { force, delivered: out.delivered },
        });
      } catch { /* audit never blocks */ }
    }
    res.status(out.created ? 202 : 200).json({ data: { command: out.command, delivered: out.delivered, alreadyRunning: !out.created } });
  } catch (err) { next(err); }
});

// POST /api/hyperv/devices/:id/live — live heartbeat from an open Hyper-V
// view. Pushes an EPHEMERAL enumerate over the WS command channel (instant,
// no command-queue row → no task-history spam; `hyperv_list_vms` is on the
// noisy-ephemeral denylist in command.service). The client calls this on a
// short interval while the view is open so external changes (a VM started
// directly on the host) surface within a few seconds. Falls back to nothing
// when the agent isn't connected on the WS channel — the periodic GET still
// shows the last-known state.
router.post('/devices/:id/live', async (req, res, next) => {
  try {
    const id = (await hostScope(req, req.params.id, 'hyperv:view')).id;
    const { agentHub } = await import('../services/agentHub.service');
    const { randomUUID } = await import('crypto');
    const delivered = agentHub.push(id, {
      type: 'command', id: randomUUID(), commandType: 'hyperv_list_vms', payload: {},
    });
    res.json({ data: { delivered } });
  } catch (err) { next(err); }
});

// POST /api/hyperv/devices/:id/vms/:vmId/thumbnail — request a fresh console
// frame. Ephemeral WS push (no history); the frame returns via the
// HYPERV_THUMBNAIL Socket.io broadcast. Read-only console preview (layer A).
router.post('/devices/:id/vms/:vmId/thumbnail', async (req, res, next) => {
  try {
    const id = (await hostScope(req, req.params.id, 'hyperv:view')).id;
    const vmId = String(req.params.vmId);
    const width = Math.min(1280, Math.max(160, parseInt(String(req.body?.width ?? '640'), 10) || 640));
    const height = Math.min(1024, Math.max(120, parseInt(String(req.body?.height ?? '480'), 10) || 480));
    const { agentHub } = await import('../services/agentHub.service');
    const { randomUUID } = await import('crypto');
    const delivered = agentHub.push(id, {
      type: 'command', id: randomUUID(), commandType: 'hyperv_console_thumbnail', payload: { vmId, width, height },
    });
    // Serve the cached frame (if any) for an immediate first paint.
    const { hyperVConsoleStore } = await import('../services/hyperVConsole.service');
    const cached = hyperVConsoleStore.get(id, vmId);
    res.json({ data: { delivered, cached } });
  } catch (err) { next(err); }
});

// GET /api/hyperv/vms[?tenantId=all] — tenant-wide grid (Dashboard tab,
// Oblireach Desktop). Scope: vmListScope (non-admins: the hosts on which
// they hold hyperv:view, no longer every host they can see). With
// ?tenantId= the answer also carries scope: { all } (all = every tenant).
router.get('/vms', async (req, res, next) => {
  try {
    const scope = await vmListScope(req);
    const vms = await hyperVService.listForTenant(scope.tenantId, scope.hostIds);
    res.json({ data: vms, ...(req.query.tenantId !== undefined ? { scope: { all: scope.all } } : {}) });
  } catch (err) { next(err); }
});

// POST /api/hyperv/devices/:id/vms/:vmId/action — run an action on a VM.
// Gated by (capability tier) + (per-tenant restriction matrix), then enqueued
// as a single hyperv_control command the host agent executes.
router.post('/devices/:id/vms/:vmId/action', async (req, res, next) => {
  try {
    const vmId = String(req.params.vmId);
    const action = String(req.body?.action) as VmAction;
    const params = (req.body?.params && typeof req.body.params === 'object') ? req.body.params : {};

    // Own keys only ('toString', '__proto__' are not actions).
    const meta = Object.prototype.hasOwnProperty.call(ACTION_META, action) ? ACTION_META[action] : undefined;
    if (!meta) return res.status(400).json({ error: `Unknown VM action: ${action}` });

    const host = await hostScope(req, req.params.id, meta.cap);
    const id = host.id;
    const hostTenantId = Number(host.tenant_id); // (god view: the host's tenant, not the session's)

    // Ownership: the VM must exist on this host within the caller's tenant
    // (except 'create' which has no existing VM yet).
    let vmName = vmId;
    if (action !== 'create') {
      const vm = await hyperVService.getVM(id, vmId, hostTenantId);
      if (!vm) return res.status(404).json({ error: 'VM not found on this host' });
      vmName = vm.name;
    }

    // Restriction gate (2FA / double-admin per the tenant matrix). The
    // approval keeps the VM parameters without any secret-named field (none
    // is expected: a junk one is dropped, never a reason to skip the second
    // administrator) and shows them to the reviewer.
    const { scrubSecrets } = await import('../services/approvalSecrets');
    const { fields } = await import('../services/approvalDescribe');
    const approvalParams = scrubSecrets(params as Record<string, unknown>).clean;
    const approved = await applyRestriction(res, {
      req,
      actionKey: meta.restrictionKey,
      deviceIds: [id],
      approvalRequestType: 'batch_command',
      approvalDescription: `Hyper-V ${action} on VM "${vmName}"${Object.keys(approvalParams).length ? ` (${fields(approvalParams)})` : ''}`,
      approvalPayload: { action: 'hyperv_control', deviceIds: [id], params: { action, vmId, params: approvalParams } },
    });
    if (!approved) return;

    const cmd = await commandService.enqueue({
      deviceId: id, tenantId: hostTenantId, type: 'hyperv_control' as any,
      payload: { action, vmId, params },
      priority: 'high', expiresInSeconds: 300, createdBy: req.session.userId,
    });

    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, `hyperv.${action}`, {
        deviceId: id, resourceType: 'command', resourcePath: cmd.id,
        details: { vmId, vmName, action },
      });
    } catch {}

    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// GET /api/hyperv/export?format=csv|xlsx|pdf[&deviceId=<hostId>] — micro-inventory
// of allocated VM resources (vCPU / assigned RAM) + everything we already
// persist. `deviceId` scopes to one host; omit it for the tenant-wide grid.
// Disk allocation is intentionally absent (not reported by the agent yet).
router.get('/export', async (req, res, next) => {
  try {
    const { format, deviceId } = req.query as any;
    const fmt = (format ?? 'csv').toString().toLowerCase();
    if (!['csv', 'xlsx', 'pdf'].includes(fmt)) {
      return res.status(400).json({ error: 'Invalid format (csv|xlsx|pdf)' });
    }

    let vms;
    if (deviceId) {
      // Single host (same rules as GET /devices/:id/vms). listForTenant([id])
      // joins the host name (listForDevice does not), which the user flagged
      // as required in the export.
      const device = await hostScope(req, deviceId, 'hyperv:view');
      vms = await hyperVService.listForTenant(Number(device.tenant_id), [device.id]);
    } else {
      // Tenant-wide grid: exactly GET /vms's scope.
      const scope = await vmListScope(req);
      vms = await hyperVService.listForTenant(scope.tenantId, scope.hostIds);
    }

    // Honour the grid's active filters so the export contains exactly the rows
    // the user sees (not the whole inventory). Mirrors HyperVVmTable: host tag
    // filter (OR semantics) + search on VM name / host name (case-insensitive).
    const tagsRaw = req.query.tags;
    const tags = Array.isArray(tagsRaw)
      ? tagsRaw.map(String)
      : (typeof tagsRaw === 'string' && tagsRaw ? tagsRaw.split(',').map((s) => s.trim()).filter(Boolean) : []);
    if (tags.length) {
      vms = vms.filter((v: any) => Array.isArray(v.hostTags) && v.hostTags.some((tg: string) => tags.includes(tg)));
    }
    // Same matcher as the client grid (name / host / IP / MAC) — imported from
    // @obliance/shared so the export can't silently drift from what the user
    // filtered on screen.
    const search = (typeof req.query.search === 'string' ? req.query.search : '').trim();
    if (search) {
      vms = vms.filter((v: any) => vmMatchesSearch(v, search));
    }

    const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
    const baseName = `obliance-hyperv-vms-${ts}`;

    const GiB = 1024 ** 3;
    const r1 = (n: number) => (Number.isFinite(n) ? Math.round(n * 10) / 10 : '');
    const fmtUptime = (sec: number | null) => {
      if (!sec || sec <= 0) return '';
      const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
      return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
    };

    // `pdf: false` → CSV/XLSX only (keeps the PDF readable). Host is column 2
    // and always populated.
    const columns: Array<{ header: string; key: string; width: number; pdf?: boolean }> = [
      { header: 'VM Name',           key: 'name',         width: 28 },
      { header: 'Host',              key: 'hostName',     width: 24 },
      { header: 'State',             key: 'state',        width: 12 },
      { header: 'vCPU',              key: 'cpuCount',     width: 8 },
      { header: 'RAM Assigned (GB)', key: 'ramGb',        width: 16 },
      { header: 'Dynamic Memory',    key: 'dynamicMemory', width: 14, pdf: false },
      { header: 'RAM Demand (GB)',   key: 'ramDemandGb',  width: 15, pdf: false },
      { header: 'Generation',        key: 'generation',   width: 11 },
      { header: 'Guest OS',          key: 'guestOs',      width: 24 },
      { header: 'CPU % Now',         key: 'cpuPct',       width: 9,  pdf: false },
      { header: 'Uptime',            key: 'uptime',       width: 12, pdf: false },
      { header: 'Checkpoints',       key: 'checkpointCount', width: 11 },
      { header: 'IP Addresses',      key: 'ipAddresses',  width: 26, pdf: false },
      { header: 'MAC Addresses',     key: 'macAddresses', width: 26, pdf: false },
      { header: 'Heartbeat',         key: 'heartbeat',    width: 18, pdf: false },
      { header: 'Integration Svc',   key: 'integrationServicesVersion', width: 14, pdf: false },
      { header: 'Config Version',    key: 'configVersion', width: 12, pdf: false },
      { header: 'Status',            key: 'statusText',   width: 22, pdf: false },
      { header: 'Auto Start',        key: 'automaticStart', width: 14, pdf: false },
      { header: 'Auto Stop',         key: 'automaticStop', width: 14, pdf: false },
      { header: 'Notes',             key: 'notes',        width: 30, pdf: false },
      { header: 'Updated',           key: 'updatedAt',    width: 22, pdf: false },
      { header: 'VM Id',             key: 'vmId',         width: 38, pdf: false },
    ];

    const rows = vms.map((v: any) => ({
      name:            v.name ?? '',
      hostName:        v.hostName ?? (v.hostDeviceId ? `#${v.hostDeviceId}` : ''),
      state:           v.state ?? '',
      cpuCount:        v.cpuCount ?? '',
      ramGb:           v.memoryBytes != null ? r1(v.memoryBytes / GiB) : '',
      dynamicMemory:   v.dynamicMemory ? 'Yes' : 'No',
      ramDemandGb:     v.memoryDemandBytes != null ? r1(v.memoryDemandBytes / GiB) : '',
      generation:      v.generation ?? '',
      guestOs:         v.guestOs ?? '',
      cpuPct:          v.cpuUsagePercent != null ? v.cpuUsagePercent : '',
      uptime:          fmtUptime(v.uptimeSeconds),
      checkpointCount: v.checkpointCount ?? 0,
      ipAddresses:     Array.isArray(v.ipAddresses) ? v.ipAddresses.join(', ') : '',
      macAddresses:    Array.isArray(v.macAddresses) ? v.macAddresses.join(', ') : '',
      heartbeat:       v.heartbeat ?? '',
      integrationServicesVersion: v.integrationServicesVersion ?? '',
      configVersion:   v.configVersion ?? '',
      statusText:      v.statusText ?? '',
      automaticStart:  v.automaticStart ?? '',
      automaticStop:   v.automaticStop ?? '',
      notes:           v.notes ?? '',
      updatedAt:       v.updatedAt ?? '',
      vmId:            v.vmId ?? '',
    }));

    const ExcelJS = (await import('exceljs')).default;

    if (fmt === 'csv') {
      const wb = new ExcelJS.Workbook();
      const ws = wb.addWorksheet('VMs');
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
      const ws = wb.addWorksheet('VMs');
      ws.columns = columns;
      ws.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
      ws.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F2937' } };
      rows.forEach((r) => ws.addRow(r));
      ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
      const buffer = await wb.xlsx.writeBuffer();
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.xlsx"`);
      return res.send(Buffer.from(buffer as any));
    }

    // PDF via playwright — curated column subset (drop `pdf: false`).
    const pdfColumns = columns.filter((c) => c.pdf !== false);
    const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
    const headHtml = pdfColumns.map((c) => `<th>${escapeHtml(c.header)}</th>`).join('');
    const rowsHtml = rows.map((r) =>
      `<tr>${pdfColumns.map((c) => `<td>${escapeHtml(String((r as any)[c.key] ?? ''))}</td>`).join('')}</tr>`
    ).join('');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Hyper-V VMs</title><style>
body { font-family: -apple-system, Segoe UI, sans-serif; font-size: 9px; color: #111; margin: 20px; }
h1 { font-size: 14px; margin: 0 0 12px; }
.meta { font-size: 8px; color: #666; margin-bottom: 12px; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; }
th { background: #1f2937; color: white; font-weight: 600; }
tr:nth-child(even) td { background: #f9fafb; }
</style></head><body>
<h1>Obliance — Hyper-V VMs export</h1>
<div class="meta">${vms.length} VMs · generated ${new Date().toISOString()}</div>
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

export default router;
