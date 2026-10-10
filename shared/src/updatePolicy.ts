// ─── Agent update policy (ported from Obliguard C17-1) ──────────────────────
//
// TYPES ONLY (the runtime resolver lives in server/src/utils/updatePolicy.ts:
// the server runs against shared/dist, rebuilt only by a release build).
//
// Two policies, same model, resolved independently:
//   'agent'     — the Obliance agent itself (update_agent, agentUpdateRollout);
//   'oblireach' — the ObliReach agent Obliance installs and keeps aligned
//                 (push-response `oblireach` block + ObliReach's own `update`).
//
// Values:
//   'auto'   — updated automatically when this server ships a newer build;
//   'manual' — never automatically, only through an explicit action (device
//              page, bulk selection, "update all agents");
//   'frozen' — never updated, explicit actions are refused too.
//
// Levels (cascade): platform (app_config) → tenant → group chain (nearest
// ancestor with an explicit value). NULL / absent = inherit.
//   - 'frozen' at ANY level is absolute (platform = fleet-wide kill-switch,
//     tenant = every group of the tenant, group = its whole subtree; the
//     highest one is reported as the source);
//   - otherwise the nearest explicit value wins (group chain, then tenant,
//     then platform);
//   - nothing set anywhere: 'manual' for the agent (today's behaviour: agent
//     updates are admin-triggered), 'auto' for ObliReach (today's behaviour:
//     kept aligned automatically).

export type AgentUpdatePolicy = 'auto' | 'manual' | 'frozen';

/** 'vmconsole': the Hyper-V VM console helper bundle (install policy:
 *  'auto' = pre-installed on confirmed Hyper-V hosts, 'manual' = on demand —
 *  first console opening or "Install now" — the built-in default, 'frozen' =
 *  never installed, the explicit action refused too). */
export type UpdatePolicyKind = 'agent' | 'oblireach' | 'vmconsole';

/** 'unresolved': the cascade could not be read (database error) — automatic
 *  updates are held and explicit actions refused until it can (fail closed). */
export type UpdatePolicySource = 'global' | 'tenant' | 'group' | 'default' | 'unresolved';

export interface ResolvedUpdatePolicy {
  policy: AgentUpdatePolicy;
  source: UpdatePolicySource;
  /** The group that sets the effective policy (source 'group'). */
  sourceGroupId: number | null;
  sourceGroupName?: string | null;
}

export interface DeviceUpdatePolicies {
  agent: ResolvedUpdatePolicy;
  oblireach: ResolvedUpdatePolicy;
  vmconsole: ResolvedUpdatePolicy;
}

/** Explicit values of one level (null = inherit). */
export interface UpdatePolicyOverrides {
  agentUpdatePolicy: AgentUpdatePolicy | null;
  oblireachUpdatePolicy: AgentUpdatePolicy | null;
  vmconsoleInstallPolicy: AgentUpdatePolicy | null;
}

/** GET of a level's editor: its own values + what it inherits. */
export interface UpdatePolicyLevelView extends UpdatePolicyOverrides {
  /** Effective values with no own value at this level (the parent levels). */
  inherited: DeviceUpdatePolicies;
  /** Effective values at this level (own values applied). */
  effective: DeviceUpdatePolicies;
  /** May the caller edit this level? */
  canEdit: boolean;
}
