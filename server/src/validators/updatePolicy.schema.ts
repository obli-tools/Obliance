import { z } from 'zod';

/** One level of the agent update policy cascade: a value, or null = inherit. */
export const updatePolicyValueSchema = z.enum(['auto', 'manual', 'frozen']).nullable();

/** PUT /api/tenants/current/update-policy (each field optional: absent = unchanged). */
export const updatePolicyLevelSchema = z.object({
  agentUpdatePolicy: updatePolicyValueSchema.optional(),
  oblireachUpdatePolicy: updatePolicyValueSchema.optional(),
  vmconsoleInstallPolicy: updatePolicyValueSchema.optional(),
}).strict();

export type UpdatePolicyLevelInput = z.infer<typeof updatePolicyLevelSchema>;
