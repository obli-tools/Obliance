import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { RefreshCw, Snowflake, Hand, Loader2 } from 'lucide-react';
import type {
  AgentUpdatePolicy, UpdatePolicyKind, ResolvedUpdatePolicy, DeviceUpdatePolicies, UpdatePolicyLevelView, AppConfigData,
} from '@obliance/shared';
import { updatePolicyApi } from '@/api/updatePolicy.api';
import { appConfigApi } from '@/api/appConfig.api';
import { getSocket } from '@/socket/socketClient';
import { cn } from '@/utils/cn';

// Agent update policies (ported from Obliguard): Automatic / Manual / Frozen,
// platform → tenant → group cascade, for the Obliance agent and ObliReach.
// Server: services/updatePolicy.service.ts.

/** Built-in default when nothing is set anywhere (mirror of the server). */
export const DEFAULT_UPDATE_POLICY: Record<UpdatePolicyKind, AgentUpdatePolicy> = { agent: 'manual', oblireach: 'auto', vmconsole: 'manual' };
// 'vmconsole': install policy of the Hyper-V VM console helper (same cascade,
// own labels: Automatic = pre-installed on Hyper-V hosts, On demand, Disabled).
const KINDS: UpdatePolicyKind[] = ['agent', 'oblireach', 'vmconsole'];
const FIELD: Record<UpdatePolicyKind, 'agentUpdatePolicy' | 'oblireachUpdatePolicy' | 'vmconsoleInstallPolicy'> = {
  agent: 'agentUpdatePolicy',
  oblireach: 'oblireachUpdatePolicy',
  vmconsole: 'vmconsoleInstallPolicy',
};
const CONFIG_KEY: Record<UpdatePolicyKind, 'agent_update_policy' | 'oblireach_update_policy' | 'vmconsole_install_policy'> = {
  agent: 'agent_update_policy',
  oblireach: 'oblireach_update_policy',
  vmconsole: 'vmconsole_install_policy',
};

type T = ReturnType<typeof useTranslation>['t'];

export function policyLabel(t: T, p: AgentUpdatePolicy, kind?: UpdatePolicyKind): string {
  if (kind === 'vmconsole') {
    switch (p) {
      case 'auto': return t('updatePolicy.vmconsolePolicy.auto', 'Automatic (pre-installed)');
      case 'manual': return t('updatePolicy.vmconsolePolicy.manual', 'On demand');
      default: return t('updatePolicy.vmconsolePolicy.frozen', 'Disabled');
    }
  }
  switch (p) {
    case 'auto': return t('updatePolicy.policy.auto') || 'Automatic';
    case 'manual': return t('updatePolicy.policy.manual') || 'Manual';
    default: return t('updatePolicy.policy.frozen') || 'Frozen';
  }
}

export function kindLabel(t: T, k: UpdatePolicyKind): string {
  if (k === 'vmconsole') return t('updatePolicy.kind.vmconsole', 'VM console (Hyper-V)');
  return k === 'agent'
    ? (t('updatePolicy.kind.agent') || 'Obliance agent')
    : (t('updatePolicy.kind.oblireach') || 'ObliReach');
}

export function sourceLabel(t: T, r: ResolvedUpdatePolicy): string {
  switch (r.source) {
    case 'global': return t('updatePolicy.source.global') || 'platform setting';
    case 'tenant': return t('updatePolicy.source.tenant') || 'tenant setting';
    case 'group': return t('updatePolicy.source.group', { name: r.sourceGroupName ?? `#${r.sourceGroupId}` }) || `group "${r.sourceGroupName ?? r.sourceGroupId}"`;
    case 'default': return t('updatePolicy.source.default') || 'built-in default';
    default: return t('updatePolicy.source.unresolved') || 'unreadable';
  }
}

function policyIcon(p: AgentUpdatePolicy) {
  if (p === 'auto') return <RefreshCw size={12} />;
  if (p === 'manual') return <Hand size={12} />;
  return <Snowflake size={12} />;
}

/** Small badge: effective policy (+ its source in the tooltip). */
export function UpdatePolicyBadge({ resolved, kind, showKind = false }: { resolved: ResolvedUpdatePolicy; kind: UpdatePolicyKind; showKind?: boolean }) {
  const { t } = useTranslation();
  const tone = resolved.policy === 'frozen'
    ? 'bg-sky-500/15 text-sky-400'
    : resolved.policy === 'auto' ? 'bg-green-500/15 text-green-400' : 'bg-bg-tertiary text-text-secondary';
  const title = `${kindLabel(t, kind)} — ${policyLabel(t, resolved.policy, kind)} (${sourceLabel(t, resolved)})`;
  return (
    <span title={title} className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium', tone)}>
      {policyIcon(resolved.policy)}
      {showKind ? `${kindLabel(t, kind)} : ` : ''}{policyLabel(t, resolved.policy, kind)}
    </span>
  );
}

const selectCls = 'shrink-0 rounded-md border border-border bg-bg-tertiary px-3 py-1.5 text-sm text-text-primary disabled:opacity-50 coarse:min-h-10';

/** Select of one level: Inherit (+ inherited value) / Automatic / Manual / Frozen. */
function PolicySelect({
  id, kind, value, inherited, allowInherit, disabled, onChange,
}: {
  id: string;
  kind: UpdatePolicyKind;
  value: AgentUpdatePolicy | null;
  inherited: ResolvedUpdatePolicy | null;
  allowInherit: boolean;
  disabled?: boolean;
  onChange: (v: AgentUpdatePolicy | null) => void;
}) {
  const { t } = useTranslation();
  const inheritText = inherited
    ? `${t('updatePolicy.inherit') || 'Inherit'} (${policyLabel(t, inherited.policy, kind)} — ${sourceLabel(t, inherited)})`
    : (t('updatePolicy.inherit') || 'Inherit');
  return (
    <select
      id={id}
      value={value ?? 'inherit'}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value === 'inherit' ? null : e.target.value as AgentUpdatePolicy)}
      className={selectCls}
    >
      {allowInherit && <option value="inherit">{inheritText}</option>}
      <option value="auto">{policyLabel(t, 'auto', kind)}</option>
      <option value="manual">{policyLabel(t, 'manual', kind)}</option>
      <option value="frozen">{policyLabel(t, 'frozen', kind)}</option>
    </select>
  );
}

function kindDescription(t: T, k: UpdatePolicyKind): string {
  if (k === 'vmconsole') {
    return t('updatePolicy.vmconsoleDesc', 'Interactive console of the Hyper-V VMs (component of about 50 MB, Hyper-V hosts only). Automatic: installed in advance and kept at the version of this server. On demand: installed at the first console opening or with "Install now". Disabled: never installed, the console is unavailable.');
  }
  return k === 'agent'
    ? (t('updatePolicy.agentDesc') || 'Automatic: every outdated agent is updated as soon as this server ships a new version (paced rollout). Manual: only through the "Update the agent" actions. Frozen: never, even the manual actions are refused.')
    : (t('updatePolicy.oblireachDesc') || 'Automatic: ObliReach is kept at the version shipped by this server. Manual: an installed ObliReach is only updated with the "Update ObliReach" action (a first install still happens). Frozen: the installed ObliReach is never updated.');
}

/** A frozen value higher up makes this level's own value irrelevant. */
function frozenAbove(inherited: ResolvedUpdatePolicy | null): boolean {
  return !!inherited && inherited.policy === 'frozen' && inherited.source !== 'default';
}

/** Editor body shared by the tenant and group levels. */
function LevelEditor({
  view, saving, onSave, idPrefix,
}: {
  view: UpdatePolicyLevelView;
  saving: boolean;
  onSave: (kind: UpdatePolicyKind, v: AgentUpdatePolicy | null) => void;
  idPrefix: string;
}) {
  const { t } = useTranslation();
  return (
    <div className="divide-y divide-border">
      {KINDS.map((k) => {
        const inherited = view.inherited[k];
        const locked = frozenAbove(inherited);
        return (
          <div key={k} className="flex flex-col gap-3 py-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <label htmlFor={`${idPrefix}-${k}`} className="text-sm font-medium text-text-primary">{kindLabel(t, k)}</label>
              <p className="text-xs text-text-muted mt-0.5">{kindDescription(t, k)}</p>
              <p className="text-xs text-text-secondary mt-1 flex items-center gap-2">
                {t('updatePolicy.effective') || 'Effective:'} <UpdatePolicyBadge resolved={view.effective[k]} kind={k} />
                <span className="text-text-muted">({sourceLabel(t, view.effective[k])})</span>
              </p>
              {locked && (
                <p className="text-xs text-sky-400 mt-1">
                  {t('updatePolicy.frozenAbove', { source: sourceLabel(t, inherited) }) || `Frozen by the ${sourceLabel(t, inherited)}: a value set here has no effect.`}
                </p>
              )}
            </div>
            <PolicySelect
              id={`${idPrefix}-${k}`}
              kind={k}
              value={view[FIELD[k]]}
              inherited={inherited}
              allowInherit
              disabled={saving || !view.canEdit}
              onChange={(v) => onSave(k, v)}
            />
          </div>
        );
      })}
      {!view.canEdit && (
        <p className="pt-3 text-xs text-text-muted">{t('updatePolicy.readOnly') || 'Read only: you do not have the right to change this setting.'}</p>
      )}
    </div>
  );
}

function errorText(t: T, err: unknown): string {
  const data = (err as { response?: { data?: { error?: string; code?: string } } })?.response?.data;
  if (data?.code === 'update_policy_frozen') return t('updatePolicy.errors.frozen') || 'Updates are frozen for this device (update policy).';
  if (data?.code === 'update_policy_unresolved') return t('updatePolicy.errors.unresolved') || 'The update policy could not be read, please try again.';
  return data?.error || t('settings.failedUpdate') || 'Update failed';
}

/** Translated message of a refused update (409 update_policy_frozen / 503), or null. */
export function updatePolicyErrorText(t: T, err: unknown): string | null {
  const code = (err as { response?: { data?: { code?: string } } })?.response?.data?.code;
  return code === 'update_policy_frozen' || code === 'update_policy_unresolved' ? errorText(t, err) : null;
}

// ── Platform level (Settings, platform admins) ────────────────────────────

export function GlobalUpdatePolicySection() {
  const { t } = useTranslation();
  const [cfg, setCfg] = useState<AppConfigData | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    appConfigApi.getConfig().then(setCfg).catch(() => setCfg(null));
  }, []);

  const save = async (k: UpdatePolicyKind, v: AgentUpdatePolicy | null) => {
    if (!v) return;
    if (v === 'auto' && k === 'agent' && !window.confirm(
      t('updatePolicy.confirmGlobalAuto') || 'Every outdated agent of every tenant (unless a tenant or group says otherwise) will be updated automatically. Continue?',
    )) return;
    setSaving(true);
    try {
      const r = await appConfigApi.setConfig(CONFIG_KEY[k], v);
      if (r.pendingApproval) {
        toast.success(t('users.sentForApproval') || 'Sent for approval to a second administrator');
        return;
      }
      setCfg((prev) => (prev ? { ...prev, [CONFIG_KEY[k]]: v } : prev));
      toast.success(t('updatePolicy.saved') || 'Update policy saved');
    } catch (err) {
      toast.error(errorText(t, err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div className="flex items-center gap-2 mb-4">
        <RefreshCw size={18} className="text-accent" />
        <h2 className="text-lg font-semibold text-text-primary">{t('updatePolicy.globalTitle') || 'Agent updates (all tenants)'}</h2>
      </div>
      <div className="rounded-lg bg-bg-secondary p-4">
        <p className="text-xs text-text-muted mb-2">
          {t('updatePolicy.globalHelp') || 'Default policy of the whole platform. A tenant or a group can override it, except when it is Frozen here: Frozen at any level always wins over the levels below.'}
        </p>
        <div className="divide-y divide-border">
          {KINDS.map((k) => {
            const own = (cfg?.[CONFIG_KEY[k]] ?? null) as AgentUpdatePolicy | null;
            return (
              <div key={k} className="flex flex-col gap-3 py-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <label htmlFor={`upd-global-${k}`} className="text-sm font-medium text-text-primary">{kindLabel(t, k)}</label>
                  <p className="text-xs text-text-muted mt-0.5">{kindDescription(t, k)}</p>
                  {cfg && own == null && (
                    <p className="text-xs text-text-secondary mt-1">
                      {t('updatePolicy.builtInDefault', { value: policyLabel(t, DEFAULT_UPDATE_POLICY[k], k) }) || `Not set: built-in default (${policyLabel(t, DEFAULT_UPDATE_POLICY[k], k)}).`}
                    </p>
                  )}
                </div>
                <PolicySelect
                  id={`upd-global-${k}`}
                  kind={k}
                  value={own ?? DEFAULT_UPDATE_POLICY[k]}
                  inherited={null}
                  allowInherit={false}
                  disabled={saving || !cfg}
                  onChange={(v) => void save(k, v)}
                />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Tenant level (Policies → Agent updates) ───────────────────────────────

export function TenantUpdatePolicyCard() {
  const { t } = useTranslation();
  const [view, setView] = useState<UpdatePolicyLevelView | null>(null);
  const [saving, setSaving] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    updatePolicyApi.getTenant().then(setView).catch(() => setFailed(true));
  }, []);

  const save = async (k: UpdatePolicyKind, v: AgentUpdatePolicy | null) => {
    setSaving(true);
    try {
      setView(await updatePolicyApi.setTenant({ [FIELD[k]]: v }));
      toast.success(t('updatePolicy.saved') || 'Update policy saved');
    } catch (err) {
      toast.error(errorText(t, err));
    } finally {
      setSaving(false);
    }
  };

  if (failed) return <p className="text-sm text-text-muted">{t('updatePolicy.loadFailed') || 'The update policy could not be loaded.'}</p>;
  if (!view) return <Loader2 className="w-5 h-5 animate-spin text-text-muted" />;
  return (
    <div className="rounded-lg bg-bg-secondary p-4">
      <h3 className="text-base font-semibold text-text-primary">{t('updatePolicy.tenantTitle') || 'Agent updates of this tenant'}</h3>
      <p className="text-xs text-text-muted mt-0.5">
        {t('updatePolicy.tenantHelp') || 'Applies to every device of this tenant; a group can override it (sub-groups inherit from their parent group). Frozen here freezes the whole tenant.'}
      </p>
      <LevelEditor view={view} saving={saving} onSave={(k, v) => void save(k, v)} idPrefix="upd-tenant" />
    </div>
  );
}

// ── Group level (group edit page) ─────────────────────────────────────────

export function GroupUpdatePolicySection({ groupId }: { groupId: number }) {
  const { t } = useTranslation();
  const [view, setView] = useState<UpdatePolicyLevelView | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    updatePolicyApi.getGroup(groupId).then(setView).catch(() => setView(null));
  }, [groupId]);
  useEffect(() => { load(); }, [load]);

  const save = async (k: UpdatePolicyKind, v: AgentUpdatePolicy | null) => {
    setSaving(true);
    try {
      await updatePolicyApi.setGroup(groupId, { [FIELD[k]]: v });
      load();
      toast.success(t('updatePolicy.saved') || 'Update policy saved');
    } catch (err) {
      toast.error(errorText(t, err));
    } finally {
      setSaving(false);
    }
  };

  if (!view) return null;
  return (
    <div className="rounded-lg bg-bg-secondary p-4">
      <h3 className="text-sm font-semibold text-text-primary">{t('updatePolicy.groupTitle') || 'Agent updates'}</h3>
      <p className="text-xs text-text-muted mt-0.5">
        {t('updatePolicy.groupHelp') || 'Applies to the devices of this group and of its sub-groups. Inherit: the value of the parent group, then of the tenant, then of the platform. Frozen freezes the whole subtree.'}
      </p>
      <LevelEditor view={view} saving={saving} onSave={(k, v) => void save(k, v)} idPrefix={`upd-group-${groupId}`} />
    </div>
  );
}

// ── Device level (read only: effective policies + source) ─────────────────

/** Effective policies of a device, refreshed when a level changes (socket). */
export function useDeviceUpdatePolicies(deviceId: number | null | undefined): DeviceUpdatePolicies | null {
  const [pol, setPol] = useState<DeviceUpdatePolicies | null>(null);
  useEffect(() => {
    if (!deviceId) return;
    let cancelled = false;
    const load = () => {
      updatePolicyApi.getDevice(deviceId).then((p) => { if (!cancelled) setPol(p); }).catch(() => { /* hidden */ });
    };
    load();
    const socket = getSocket();
    const onChanged = () => load();
    socket?.on('update_policy:changed', onChanged);
    return () => { cancelled = true; socket?.off('update_policy:changed', onChanged); };
  }, [deviceId]);
  return pol;
}

export function DeviceUpdatePolicyInfo({ policies, hyperV = false }: { policies: DeviceUpdatePolicies | null; hyperV?: boolean }) {
  const { t } = useTranslation();
  if (!policies) return null;
  // The VM console install policy only means something on a Hyper-V host.
  const kinds = KINDS.filter((k) => (k !== 'vmconsole' || hyperV) && policies[k]);
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
      <span>{t('updatePolicy.deviceLabel') || 'Update policy:'}</span>
      {kinds.map((k) => (
        <span key={k} className="inline-flex items-center gap-1">
          <UpdatePolicyBadge resolved={policies[k]} kind={k} showKind />
          <span>({sourceLabel(t, policies[k])})</span>
        </span>
      ))}
    </div>
  );
}
