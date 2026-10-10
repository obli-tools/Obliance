import { z } from 'zod';
import { SCRIPT_PARAM_LIMITS } from '@obliance/shared';

// Shape of the script parameter definitions a script editor sends (POST /
// PATCH /api/scripts). The semantic rules (name format, case-insensitive
// uniqueness, options of select / multiselect, default fitting the type, no
// default for a secret) are checked by normalizeScriptParameterDefinitions
// (shared/src/scriptParameters.ts) right after this schema.

const scalar = z.union([z.string(), z.number(), z.boolean()]);

export const scriptParameterDefinitionSchema = z.object({
  // Read-only fields echoed back by a client that edits a loaded script.
  id: z.number().optional(),
  scriptId: z.number().optional(),
  sortOrder: z.number().optional(),
  name: z.string().max(200),
  label: z.string().max(1000).nullish(),
  description: z.string().max(10000).nullish(),
  type: z.string().max(50),
  options: z.array(z.union([z.string(), z.number()])).max(1000).nullish(),
  defaultValue: z.union([scalar, z.array(z.string())]).nullish(),
  required: z.boolean().nullish(),
}).strict();

export const scriptParameterDefinitionsSchema = z.array(scriptParameterDefinitionSchema).max(SCRIPT_PARAM_LIMITS.maxParameters * 4);
