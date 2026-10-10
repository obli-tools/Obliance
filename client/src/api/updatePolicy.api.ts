import apiClient from './client';
import type { AgentUpdatePolicy, DeviceUpdatePolicies, UpdatePolicyLevelView } from '@obliance/shared';

interface ApiResponse<T> { data?: T; error?: string; }

/** Agent update policies (platform → tenant → group cascade). The platform
 *  level is app_config ('agent_update_policy' / 'oblireach_update_policy',
 *  appConfigApi.setConfig); the tenant and group levels live here. */
export const updatePolicyApi = {
  async getTenant(): Promise<UpdatePolicyLevelView> {
    const res = await apiClient.get<ApiResponse<UpdatePolicyLevelView>>('/tenants/current/update-policy');
    return res.data.data!;
  },
  async setTenant(patch: { agentUpdatePolicy?: AgentUpdatePolicy | null; oblireachUpdatePolicy?: AgentUpdatePolicy | null }): Promise<UpdatePolicyLevelView> {
    const res = await apiClient.put<ApiResponse<UpdatePolicyLevelView>>('/tenants/current/update-policy', patch);
    return res.data.data!;
  },
  async getGroup(groupId: number): Promise<UpdatePolicyLevelView> {
    const res = await apiClient.get<ApiResponse<UpdatePolicyLevelView>>(`/groups/${groupId}/update-policy`);
    return res.data.data!;
  },
  /** Saved through PUT /groups/:id (group write permission). */
  async setGroup(groupId: number, patch: { agentUpdatePolicy?: AgentUpdatePolicy | null; oblireachUpdatePolicy?: AgentUpdatePolicy | null }): Promise<void> {
    await apiClient.put(`/groups/${groupId}`, patch);
  },
  async getDevice(deviceId: number): Promise<DeviceUpdatePolicies> {
    const res = await apiClient.get<{ data: DeviceUpdatePolicies }>(`/devices/${deviceId}/update-policy`);
    return res.data.data;
  },
};
