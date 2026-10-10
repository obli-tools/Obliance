import apiClient from './client';
import type { VirtualMachine, VmAction, Command, VmConsoleStatus } from '@obliance/shared';

interface ApiResponse<T> { data?: T; error?: string }

export const hypervApi = {
  /** VMs hosted on a single device. */
  async listForDevice(deviceId: number): Promise<VirtualMachine[]> {
    const res = await apiClient.get<ApiResponse<VirtualMachine[]>>(`/hyperv/devices/${deviceId}/vms`);
    return res.data.data ?? [];
  },

  /** Tenant-wide VM grid (Dashboard tab). */
  async listForTenant(): Promise<VirtualMachine[]> {
    const res = await apiClient.get<ApiResponse<VirtualMachine[]>>('/hyperv/vms');
    return res.data.data ?? [];
  },

  /** Ask the host agent to re-enumerate its VMs (durable, shows in history). */
  async refresh(deviceId: number): Promise<void> {
    await apiClient.post(`/hyperv/devices/${deviceId}/refresh`);
  },

  /** Install (force: repair) the interactive VM-console helper on the host:
   *  a real task (Tasks tab). alreadyRunning: an install was in flight — it
   *  is the one returned. */
  async installConsole(deviceId: number, force = false): Promise<{ command: Command | null; delivered: boolean; alreadyRunning: boolean }> {
    const res = await apiClient.post<{ data?: { command: Command; delivered: boolean; alreadyRunning: boolean } }>(
      `/hyperv/devices/${deviceId}/install-console`, force ? { force: true } : {},
    );
    return res.data.data ?? { command: null, delivered: false, alreadyRunning: false };
  },

  /** Helper install state of a host: installed / version / error, task in flight, policy. */
  async consoleStatus(deviceId: number): Promise<VmConsoleStatus> {
    const res = await apiClient.get<{ data: VmConsoleStatus }>(`/hyperv/devices/${deviceId}/console-status`);
    return res.data.data;
  },

  /** Live heartbeat — ephemeral WS enumerate, no task-history row. Called on
   *  a short interval while a Hyper-V view is open. */
  async live(deviceId: number): Promise<void> {
    await apiClient.post(`/hyperv/devices/${deviceId}/live`);
  },

  /** Request a fresh console thumbnail (read-only preview, layer A). The
   *  frame arrives via the HYPERV_THUMBNAIL socket event; a cached frame (if
   *  any) is returned synchronously for an immediate first paint. */
  async requestThumbnail(deviceId: number, vmId: string, width = 640, height = 480): Promise<{ delivered: boolean; cached: { pngBase64: string; width: number; height: number } | null }> {
    const res = await apiClient.post<{ data?: { delivered: boolean; cached: any } }>(
      `/hyperv/devices/${deviceId}/vms/${encodeURIComponent(vmId)}/thumbnail`,
      { width, height },
    );
    return res.data.data ?? { delivered: false, cached: null };
  },

  /** Run an action on a VM. Returns the response data — when the action is
   *  gated by the restriction matrix the server replies 202 with
   *  { status: 'pending_approval' } (axios treats it as success), and the
   *  2FA interceptor handles the 401 twoFactorRequired case transparently. */
  async action(deviceId: number, vmId: string, action: VmAction, params?: Record<string, unknown>): Promise<any> {
    const res = await apiClient.post<ApiResponse<any>>(
      `/hyperv/devices/${deviceId}/vms/${encodeURIComponent(vmId)}/action`,
      { action, params },
    );
    return res.data.data ?? res.data;
  },

  /** Export the VM inventory (allocated vCPU/RAM + host + everything stored).
   *  Pass `deviceId` to scope to one host; omit for the tenant-wide grid.
   *  `tags`/`search` mirror the grid's active filters so the export contains
   *  exactly the rows currently displayed (not the whole inventory). */
  async export(
    format: 'csv' | 'xlsx' | 'pdf',
    opts: { deviceId?: number; tags?: string[]; search?: string } = {},
  ): Promise<{ blob: Blob; filename: string }> {
    const params: Record<string, any> = { format };
    if (opts.deviceId) params.deviceId = opts.deviceId;
    if (opts.tags && opts.tags.length) params.tags = opts.tags.join(',');
    if (opts.search && opts.search.trim()) params.search = opts.search.trim();
    const res = await apiClient.get('/hyperv/export', {
      params,
      responseType: 'blob',
    });
    const cd = res.headers['content-disposition'] || res.headers['Content-Disposition'] || '';
    const match = /filename="([^"]+)"/.exec(cd);
    const filename = match ? match[1] : `obliance-hyperv-vms.${format}`;
    return { blob: res.data as Blob, filename };
  },
};
