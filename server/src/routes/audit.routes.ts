import { Router, type Request } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireAnyTenantCapability } from '../middleware/rbac';
import { auditService } from '../services/audit.service';
import { isMasterTenant } from '@obliance/shared';

const router = Router();

router.use(requireAuth);

// Read routes: admin, or a non-admin granted `supervision:read` (same
// capability that already unlocks Reports/History/Remote-sessions —
// Oblireach Desktop's Logs > Console/Alarm tabs read this). Still
// tenant-scoped by auditService.list (a non-master's filterTenantId is
// silently dropped server-side). The master tenant's cross-tenant feed is
// for platform admins only (N1): any other reader there (a master-tenant
// admin, a `supervision:read` holder) gets the master tenant's own entries.
const requireAuditRead = requireAnyTenantCapability('supervision:read');
const globalView = (req: Request): boolean => req.session.role === 'admin' && isMasterTenant(req.tenantId!);

// GET /api/audit-log?action=user.&userId=...&since=...&until=...&limit=100&offset=0
router.get('/', requireAuditRead, async (req, res, next) => {
  try {
    const parseDate = (v: any): Date | undefined => {
      if (!v || typeof v !== 'string') return undefined;
      const d = new Date(v);
      return isNaN(d.getTime()) ? undefined : d;
    };
    const { items, total } = await auditService.list({
      tenantId: req.tenantId!,
      action: (req.query.action as string) || undefined,
      userId: req.query.userId ? parseInt(req.query.userId as string) : undefined,
      deviceId: req.query.deviceId ? parseInt(req.query.deviceId as string) : undefined,
      resourceType: (req.query.resourceType as string) || undefined,
      search: (req.query.search as string) || undefined,
      since: parseDate(req.query.since),
      until: parseDate(req.query.until),
      limit: req.query.limit ? parseInt(req.query.limit as string) : 100,
      offset: req.query.offset ? parseInt(req.query.offset as string) : 0,
      // Master-only narrow filter — service drops it for non-master.
      filterTenantId: req.query.filterTenantId ? parseInt(req.query.filterTenantId as string) : undefined,
      globalView: globalView(req),
    });
    res.json({ data: { items, total } });
  } catch (err) { next(err); }
});

// GET /api/audit-log/distinct-actions — for filter dropdown in UI
router.get('/distinct-actions', requireAuditRead, async (req, res, next) => {
  try {
    const { db } = await import('../db');
    const isMaster = globalView(req);
    const q = db('audit_logs').distinct('action').orderBy('action', 'asc');
    if (!isMaster) {
      q.where({ tenant_id: req.tenantId! });
    } else if (req.query.filterTenantId) {
      // Master narrowed to one tenant via the chip filter — limit the
      // distinct-actions list to actions that actually appear in that
      // tenant's logs, otherwise the dropdown surfaces actions the
      // user can't drill into without clearing the filter.
      q.where({ tenant_id: parseInt(String(req.query.filterTenantId), 10) });
    }
    const rows = await q;
    res.json({ data: rows.map((r: any) => r.action) });
  } catch (err) { next(err); }
});

// No DELETE: the audit log is append-only. There is deliberately no way to
// clear it from the app (accountability records must not be one click — or one approval — away from deletion). Only a tenant's own
// deletion removes its rows (CASCADE).

export default router;
