// Bulk rename ("name replacer") — /api/bulk-rename/*
// Mounted on the tenant router (requireAuth + requireTenant). See
// services/bulkRename.service.ts for the rules (tenant isolation, scope,
// stored preview).
//
// Access: platform admin, or a user whose tenant role carries
// `devices.manage` (the capability of every other bulk device action:
// batch change-group / transfer / delete). On top of it a non-admin only
// reaches the devices his teams give him WRITE access to — the rule of the
// single rename (PATCH /api/devices/:id → requireDeviceWrite).
//
//  GET  /export?targetTenantId=&delimiter=,|;      → CSV (UTF-8 + BOM)
//  POST /preview?targetTenantId=[&delimiter=]      body: the CSV (Content-Type text/csv, ≤ 2 MB)
//  POST /apply   { token, lines: number[] }        → applies the stored preview
import express, { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { SocketEvents } from '@obliance/shared';
import { requireTenantCapability } from '../middleware/rbac';
import { AppError } from '../middleware/errorHandler';
import { clientIp } from '../utils/clientIp';
import { logger } from '../utils/logger';
import {
  BULK_RENAME_MAX_BYTES, BulkRenameConflict, apply, buildExport, parseDelimiter, preview, resolveTargetTenant,
  type BulkRenameCaller,
} from '../services/bulkRename.service';
import { emitDeviceEvents } from '../services/deviceAudience.service';

const router = Router();

router.use(requireTenantCapability('devices.manage'));

const callerOf = (req: Request): BulkRenameCaller => ({
  userId: req.session.userId!,
  isAdmin: req.session.role === 'admin',
  sessionTenantId: req.tenantId!,
});

// CSV body: text/csv only (a cross-site form cannot send it without a CORS
// preflight). The global express.json parser ignores it; the limit here is
// the 2 MB of the feature.
const csvText = express.text({ type: ['text/csv'], limit: BULK_RENAME_MAX_BYTES, defaultCharset: 'utf-8' });
function csvBody(req: Request, res: Response, next: NextFunction): void {
  if (!req.is('text/csv')) { next(new AppError(415, 'Send the file as text/csv', 'bulk_rename_content_type')); return; }
  csvText(req, res, (err?: any) => {
    if (err) {
      if (err.type === 'entity.too.large') { next(new AppError(413, 'File too large (max 2 MB)', 'bulk_rename_too_large')); return; }
      next(new AppError(400, 'Unreadable file', 'bulk_rename_unreadable'));
      return;
    }
    next();
  });
}

router.get('/export', async (req, res, next) => {
  try {
    const caller = callerOf(req);
    const target = await resolveTargetTenant(caller, req.query.targetTenantId);
    const delim = parseDelimiter(req.query.delimiter);
    const { csv, count, tenantSlug } = await buildExport(caller, target, delim);
    const safeSlug = tenantSlug.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60) || String(target);
    const ts = new Date().toISOString().slice(0, 10);
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReqAs(req, target, 'device.bulk_rename_export', {
        resourceType: 'device', details: { count, delimiter: delim === '\t' ? 'tab' : delim, sessionTenantId: caller.sessionTenantId },
      });
    } catch { /* audit never breaks the request */ }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="obliance-devices-rename-${safeSlug}-${ts}.csv"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send(csv);
  } catch (err) { next(err); }
});

router.post('/preview', csvBody, async (req, res, next) => {
  try {
    const caller = callerOf(req);
    const target = await resolveTargetTenant(caller, req.query.targetTenantId);
    const text = typeof req.body === 'string' ? req.body : '';
    const hint = req.query.delimiter ? parseDelimiter(req.query.delimiter) : null;
    const result = await preview(caller, target, text, hint);
    res.setHeader('Cache-Control', 'no-store');
    res.json({ data: result });
  } catch (err) { next(err); }
});

router.post('/apply', async (req, res, next) => {
  try {
    const caller = callerOf(req);
    const result = await apply(caller, req.body?.token, req.body?.lines, clientIp(req) || null);
    // Live update, the way PATCH /devices/:id does it: the device's readers
    // only (its tenant; platform admins in the master god view), never the
    // whole room. Partial payload: the new name only.
    try {
      for (const r of result.renamed) {
        const payload = { id: r.deviceId, deviceId: r.deviceId, displayName: r.to };
        emitDeviceEvents(r.deviceId, result.targetTenantId, [[SocketEvents.DEVICE_UPDATED, payload]]);
      }
    } catch (err) { logger.debug({ err }, 'bulk rename: socket not ready'); }
    res.json({ data: { batchId: result.batchId, renamed: result.renamed.length, unchanged: result.unchanged } });
  } catch (err) {
    if (err instanceof BulkRenameConflict) {
      return res.status(409).json({
        success: false,
        error: 'Some devices changed since the preview — import the file again',
        code: 'bulk_rename_conflict',
        lines: err.lines,
      });
    }
    next(err);
  }
});

export default router;
