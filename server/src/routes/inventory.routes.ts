import { Router, Request, Response, NextFunction } from 'express';
import { inventoryService } from '../services/inventory.service';
import { permissionService } from '../services/permission.service';
import { AppError } from '../middleware/errorHandler';
import { resolveRequestDevice } from '../services/deviceScope.service';

const router = Router();

// Every inventory route: the device must be one the caller may read, in the
// session's tenant (the master tenant's admins: every tenant, the god view) —
// resolveRequestDevice, the same rule as the remote-session routes. Before,
// an admin was waved through for any device id of any tenant. 404 for a
// device out of reach (never 403: no existence leak).
router.param('deviceId', async (req: Request, _res: Response, next: NextFunction, val: string) => {
  try {
    const access = await resolveRequestDevice(req, val);
    if (!access.ok) return next(new AppError(access.status, access.error));
    (req as any).inventoryDevice = access.device;
    next();
  } catch (err) { next(err); }
});

router.get('/:deviceId/hardware', async (req, res, next) => {
  try {
    const hw = await inventoryService.getHardware((req as any).inventoryDevice.id);
    if (!hw) return res.status(404).json({ error: 'No hardware inventory' });
    res.json({ data: hw });
  } catch (err) { next(err); }
});

router.get('/:deviceId/software', async (req, res, next) => {
  try {
    const items = await inventoryService.getSoftware(
      (req as any).inventoryDevice.id, req.query.search as string
    );
    res.json({ data: { items, total: items.length } });
  } catch (err) { next(err); }
});

// Starting a scan acts on the device: write access (read was enough before),
// and the command carries the device's own tenant.
router.post('/:deviceId/scan', async (req, res, next) => {
  try {
    const dev = (req as any).inventoryDevice as { id: number; tenant_id: number };
    if (req.session.role !== 'admin' && !(await permissionService.canWriteDevice(req.session.userId!, dev.id, false))) {
      return next(new AppError(403, 'Insufficient permissions'));
    }
    const cmd = await inventoryService.triggerScan(dev.id, dev.tenant_id, req.session.userId!);
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

export default router;
