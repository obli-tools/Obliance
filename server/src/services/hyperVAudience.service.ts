import { db } from '../db';
import { devicesWithCapability, emitToDeviceAudience, socketMayReceiveDevice, type DeviceAudienceRule } from './deviceAudience.service';

/**
 * Who may see the Hyper-V data of a host — the SAME rules as the REST routes
 * (hyperv.routes.ts: resolveRequestDevice + capability 'hyperv:view'):
 *
 *   - platform admin: the host's tenant, or the master tenant (god view);
 *   - other users: session tenant = the host's tenant, member of it, the host
 *     visible to their teams AND 'hyperv:view' granted on it.
 *
 * Used for the live Socket.io events that carry VM data (HYPERV_VMS_UPDATED:
 * the full VM list; HYPERV_THUMBNAIL: a VM console frame). Until 2026-10 they
 * went to the whole `tenant:<id>` room: every member of the tenant got them,
 * capability or not, host visible or not.
 *
 * Thin Hyper-V layer over the generic deviceAudience.service (also used by
 * Veeam, command results, service lists…).
 */
const HYPERV_RULE: DeviceAudienceRule = { capability: 'hyperv:view', masterGodView: true };

/**
 * The hosts (of the tenant `tenantId`) whose VMs a NON-admin may list: those
 * holding VMs in that tenant, visible to the user's teams, with 'hyperv:view'
 * granted. A constant number of queries (no per-host check). Not a member of
 * the tenant → none.
 */
export async function hypervViewableHostIds(userId: number, tenantId: number): Promise<number[]> {
  const rows = await db('device_virtual_machines as vm')
    .join('devices as d', 'd.id', 'vm.host_device_id')
    .where('vm.tenant_id', tenantId)
    .where('d.tenant_id', tenantId)
    .distinct('vm.host_device_id') as Array<{ host_device_id: number }>;
  return devicesWithCapability(userId, tenantId, rows.map((r) => Number(r.host_device_id)), 'hyperv:view');
}

/** May a socket (identity frozen at handshake, role re-read live) receive this host's Hyper-V data? */
export async function socketMayViewHost(
  ident: { userId: number; tenantId: number | null },
  hostDeviceId: number,
  hostTenantId: number,
): Promise<boolean> {
  return socketMayReceiveDevice(ident, hostDeviceId, hostTenantId, HYPERV_RULE);
}

/**
 * Emit a Hyper-V event about `hostDeviceId` to the authorised sockets only:
 * the sockets of the host's tenant room and of the master tenant room (god
 * view: its admins see every tenant's VMs, as GET /api/hyperv/vms does),
 * each one checked (one check per user and tenant per call). Never throws.
 * Returns the number of sockets reached.
 */
export async function emitToHyperVViewers(hostDeviceId: number, hostTenantId: number, event: string, payload: unknown): Promise<number> {
  return emitToDeviceAudience(hostDeviceId, hostTenantId, [[event, payload]], HYPERV_RULE);
}
