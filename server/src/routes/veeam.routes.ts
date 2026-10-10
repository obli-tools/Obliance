import { Router } from 'express';
import { veeamService, veeamViewableHostIds } from '../services/veeam.service';
import { commandService } from '../services/command.service';
import { applyRestriction } from '../services/restriction.service';
import { AppError } from '../middleware/errorHandler';
import type { BackupJobAction } from '@obliance/shared';
import { isMasterTenant } from '@obliance/shared';

const router = Router();

// Map each job action to its restriction key. All control actions need the
// veeam:control capability; the restriction key drives the per-tenant 2FA /
// double-admin gate (stop + disable default to 'sensitive', the rest 'none').
const ACTION_META: Record<BackupJobAction, { restrictionKey: string }> = {
  start:   { restrictionKey: 'veeam.job_start' },
  stop:    { restrictionKey: 'veeam.job_stop' },
  retry:   { restrictionKey: 'veeam.job_retry' },
  enable:  { restrictionKey: 'veeam.job_enable' },
  disable: { restrictionKey: 'veeam.job_disable' },
};

// Every host-scoped route: the REST device rules (deviceScope.service
// resolveRequestDevice: the session's tenant, any tenant for an admin on the
// master one = god view; a non-admin must be a member of that tenant and see
// the device) + the capability on that host. Until 2026-10 these routes only
// had the device read middleware (no tenant check: a team grant in another
// tenant, or a platform admin on a child tenant, reached any host by id) —
// same fix as hyperv.routes.ts hostScope.
async function hostScope(req: import('express').Request, rawId: unknown, capability: 'veeam:view' | 'veeam:control') {
  const { resolveRequestDevice } = await import('../services/deviceScope.service');
  const access = await resolveRequestDevice(req, rawId, { capability, capabilityError: `${capability} capability required` });
  if (!access.ok) throw new AppError(access.status, access.error);
  return access.device;
}

// GET /api/veeam/devices/:id/jobs — job list for one host.
router.get('/devices/:id/jobs', async (req, res, next) => {
  try {
    const device = await hostScope(req, req.params.id, 'veeam:view');
    const jobs = await veeamService.listForDevice(device.id);
    res.json({ data: jobs });
  } catch (err) { next(err); }
});

// POST /api/veeam/devices/:id/refresh — ask the host agent to re-enumerate.
// Manual one-shot (button) — goes through the durable command queue so it
// shows in task history.
router.post('/devices/:id/refresh', async (req, res, next) => {
  try {
    const device = await hostScope(req, req.params.id, 'veeam:view');
    const id = device.id;
    const cmd = await commandService.enqueue({
      deviceId: id, tenantId: Number(device.tenant_id), type: 'veeam_list_jobs' as any,
      priority: 'high', expiresInSeconds: 120, createdBy: req.session.userId,
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/veeam/devices/:id/live — live heartbeat from an open Backups view.
// Pushes an EPHEMERAL enumerate over the WS command channel (instant, no
// command-queue row → no task-history spam; `veeam_list_jobs` is on the
// noisy-ephemeral denylist in command.service). The client calls this on a
// short interval while the view is open so external changes (a job started
// directly in the Veeam console) surface within a few seconds.
router.post('/devices/:id/live', async (req, res, next) => {
  try {
    const device = await hostScope(req, req.params.id, 'veeam:view');
    const id = device.id;
    const { agentHub } = await import('../services/agentHub.service');
    const { randomUUID } = await import('crypto');
    const delivered = agentHub.push(id, {
      type: 'command', id: randomUUID(), commandType: 'veeam_list_jobs', payload: {},
    });
    res.json({ data: { delivered } });
  } catch (err) { next(err); }
});

// GET /api/veeam/jobs — tenant-wide grid (Dashboard tab). Platform admins:
// the session's tenant, every tenant on the master one (god view). Other
// users: the session's tenant only (a non-admin on the master tenant is NOT
// god view), and only the hosts on which they hold veeam:view
// (veeamViewableHostIds: one bulk check, no N+1). Until 2026-10 non-admins
// got the jobs of every host they could see, capability or not, and a
// non-admin on the master tenant those of every tenant.
router.get('/jobs', async (req, res, next) => {
  try {
    const tenantId = req.tenantId!;
    const jobs = req.session.role === 'admin'
      ? await veeamService.listForTenant(isMasterTenant(tenantId) ? null : tenantId)
      : await veeamService.listForTenant(tenantId, await veeamViewableHostIds(req.session.userId!, tenantId));
    res.json({ data: jobs });
  } catch (err) { next(err); }
});

// POST /api/veeam/devices/:id/jobs/:jobId/action — run an action on a job.
// Gated by (veeam:control capability) + (per-tenant restriction matrix), then
// enqueued as a single veeam_control command the host agent executes.
router.post('/devices/:id/jobs/:jobId/action', async (req, res, next) => {
  try {
    const jobId = String(req.params.jobId);
    const action = String(req.body?.action) as BackupJobAction;

    // Own keys only ('toString', '__proto__' are not actions).
    const meta = Object.prototype.hasOwnProperty.call(ACTION_META, action) ? ACTION_META[action] : undefined;
    if (!meta) return res.status(400).json({ error: `Unknown backup job action: ${action}` });

    const device = await hostScope(req, req.params.id, 'veeam:control');
    const id = device.id;

    // Ownership: the job must exist on this host, in the host's tenant.
    const job = await veeamService.getJob(id, jobId, Number(device.tenant_id));
    if (!job) return res.status(404).json({ error: 'Backup job not found on this host' });

    // Restriction gate (2FA / double-admin per the tenant matrix).
    const approved = await applyRestriction(res, {
      req,
      actionKey: meta.restrictionKey,
      deviceIds: [id],
      approvalRequestType: 'batch_command',
      approvalDescription: `Veeam ${action} on job "${job.name}"`,
      approvalPayload: { action: 'veeam_control', deviceIds: [id], params: { action, jobId } },
    });
    if (!approved) return;

    const cmd = await commandService.enqueue({
      deviceId: id, tenantId: Number(device.tenant_id), type: 'veeam_control' as any,
      payload: { action, jobId },
      priority: 'high', expiresInSeconds: 300, createdBy: req.session.userId,
    });

    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, `veeam.${action}`, {
        deviceId: id, resourceType: 'command', resourcePath: cmd.id,
        details: { jobId, jobName: job.name, action },
      });
    } catch {}

    res.json({ data: cmd });
  } catch (err) { next(err); }
});

export default router;
