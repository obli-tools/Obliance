import { useEffect, useState, useCallback, useRef } from 'react';
import {
 Plus, RefreshCw, Edit, Trash2, ChevronDown, ChevronUp,
 CheckCircle, XCircle, AlertTriangle, Activity, X,
 Monitor, Wrench, ShieldCheck, ShieldX, ShieldAlert,
 ToggleLeft, ToggleRight, ChevronRight,
 ArrowUp, ArrowDown, Search, Package, Upload, HardDrive,
 ExternalLink, Copy, KeyRound, Terminal, Ban, Layers, Cpu,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { softwareComplianceApi, softwareRepoApi, type SoftwareComplianceHistoryBatch } from '@/api/softwareCompliance.api';
import { GroupTreeMultiSelect, useGroupTreeIndex } from '@/components/automation/GroupTreeMultiSelect';
import { countGroupTargets } from '@/components/automation/groupTargetSelection';
import { useAuthStore } from '@/store/authStore';
import { useDeviceStore } from '@/store/deviceStore';
import type {
 SoftwareComplianceList, SoftwareComplianceEntry, SoftwareEntryAlternative,
 SoftwareComplianceResult, SoftwareComplianceEntryResult,
 SoftwareMatchType, SoftwareInstallSource, SoftwareListType,
 KnownSoftwareApp,
 SoftwareRepoPackage, SoftwareRepoSettings, DistroScope,
} from '@obliance/shared';
import { PACKAGE_MANAGER_PLATFORM } from '@obliance/shared';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { PageContainer } from '@/components/common/PageContainer';
import { IconButton } from '@/components/common/IconButton';
import { Modal } from '@/components/common/Modal';
import { ActionMenu } from '@/components/common/ActionMenu';
import { useConfirm, usePrompt } from '@/components/common/ConfirmDialog';
import { useIsCoarsePointer } from '@/hooks/useMediaQuery';
import { useClickOutside } from '@/hooks/useClickOutside';
import { copyText } from '@/utils/clipboard';
import { isAndroidApp } from '@/native/bridge';
import { DeviceFilterSelect } from './CompliancePage';
import {
 OsVersionFields, CONCRETE_PLATFORMS, platformLabel, emptyOsCondition, describeOsCondition,
 osConditionFromApi, osConditionToApi, osConditionHasBounds,
 type OsConditionForm, type ConcretePlatform,
} from '@/components/softwareCompliance/OsConditionEditor';

type Tab = 'results' | 'lists' | 'history' | 'repository';

const MATCH_TYPES: SoftwareMatchType[] = ['exact', 'contains', 'regex'];
const INSTALL_SOURCES: SoftwareInstallSource[] = ['winget', 'choco', 'apt', 'yum', 'dnf', 'brew', 'pkg', 'snap', 'flatpak', 'msi', 'custom'];
const PLATFORMS = ['all', 'windows', 'linux', 'macos', 'freebsd'] as const;

function scoreColor(score: number): string {
 if (score >= 80) return 'text-green-400';
 if (score >= 50) return 'text-yellow-400';
 return 'text-red-400';
}
function scoreBg(score: number): string {
 if (score >= 80) return 'bg-green-400';
 if (score >= 50) return 'bg-yellow-400';
 return 'bg-red-400';
}
function scoreIcon(score: number) {
 if (score >= 80) return ShieldCheck;
 if (score >= 50) return ShieldAlert;
 return ShieldX;
}

function entryStatusIcon(status: SoftwareComplianceEntryResult['status']) {
 switch (status) {
 case 'compliant': return <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />;
 case 'non_compliant': return <XCircle className="w-4 h-4 text-red-400 shrink-0" />;
 case 'remediated': return <RefreshCw className="w-4 h-4 text-yellow-400 shrink-0" />;
 case 'remediation_failed': return <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0" />;
 default: return <AlertTriangle className="w-4 h-4 text-text-muted shrink-0" />;
 }
}

function entryStatusColor(status: SoftwareComplianceEntryResult['status']) {
 switch (status) {
 case 'compliant': return 'text-green-400';
 case 'non_compliant': return 'text-red-400';
 case 'remediated': return 'text-yellow-400';
 case 'remediation_failed': return 'text-orange-400';
 default: return 'text-text-muted';
 }
}

// ── Entry editor card ────────────────────────────────────────────────────────

interface SourceFormData {
 packageManager: SoftwareInstallSource | '';
 packageId: string;
 msiUrl: string;
 repoPackageId: number | null;
 installScript: string;
 msiParams: string;
 platformScope: DistroScope;
}

/** One alternative of an entry: detection fields, install sources, OS condition. */
interface AlternativeFormData {
 name: string;
 matchType: SoftwareMatchType;
 publisher: string;
 minVersion: string;
 maxVersion: string;
 sources: SourceFormData[];
 /** Remediation uses this alternative only on matching devices. null = any device. */
 osCondition: OsConditionForm | null;
 fromInventory?: boolean;
}

/** An entry = 1..N alternatives ("OR"), in remediation order. */
interface EntryFormData {
 /** Display label, used when the entry has several alternatives ("Passly"). */
 label: string;
 alternatives: AlternativeFormData[];
}

const MAX_ALTERNATIVES = 10;

function makeEmptySource(): SourceFormData {
 return { packageManager: '', packageId: '', msiUrl: '', repoPackageId: null, installScript: '', msiParams: '', platformScope: 'any' };
}

function makeEmptyAlternative(): AlternativeFormData {
 return { name: '', matchType: 'contains', publisher: '', minVersion: '', maxVersion: '', sources: [], osCondition: null };
}

function makeEmptyEntry(): EntryFormData {
 return { label: '', alternatives: [makeEmptyAlternative()] };
}

/** Small OS/distro icon badges for entry cards */
const PLATFORM_ICONS: Record<string, { label: string; color: string }> = {
 windows: { label: 'Win', color: 'bg-blue-400/10 text-blue-400 border-blue-400/20' },
 macos: { label: 'Mac', color: 'bg-gray-400/10 text-gray-300 border-gray-400/20' },
 debian: { label: 'Deb', color: 'bg-red-400/10 text-red-400 border-red-400/20' },
 rhel: { label: 'RHEL', color: 'bg-red-500/10 text-red-500 border-red-500/20' },
 fedora: { label: 'Fed', color: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
 arch: { label: 'Arch', color: 'bg-cyan-400/10 text-cyan-400 border-cyan-400/20' },
 suse: { label: 'SUSE', color: 'bg-green-400/10 text-green-400 border-green-400/20' },
 freebsd: { label: 'BSD', color: 'bg-red-400/10 text-red-400 border-red-400/20' },
};

function PlatformBadges({ sources }: { sources: SourceFormData[] }) {
 const seen = new Set<string>();
 for (const s of sources) {
 if (!s.packageManager) continue;
 const scope = s.platformScope !== 'any' ? s.platformScope : PACKAGE_MANAGER_PLATFORM[s.packageManager];
 if (scope && scope !== 'any') seen.add(scope);
 }
 if (seen.size === 0) return null;
 return (
 <div className="flex items-center gap-0.5">
 {Array.from(seen).map(p => {
 const icon = PLATFORM_ICONS[p];
 if (!icon) return null;
 return (
 <span key={p} className={clsx('text-[9px] px-1 py-0.5 rounded border font-medium', icon.color)}>
 {icon.label}
 </span>
 );
 })}
 </div>
 );
}

function makeAlternativeFromKnownApp(app: KnownSoftwareApp): AlternativeFormData {
 let pm: SoftwareInstallSource | '' = '';
 const src = (app.source ?? '').toLowerCase();
 if (src === 'winget') pm = 'winget';
 else if (src === 'chocolatey' || src === 'choco') pm = 'choco';
 else if (src === 'dpkg' || src === 'apt') pm = 'apt';
 else if (src === 'rpm' || src === 'dnf') pm = 'dnf';
 else if (src === 'yum') pm = 'yum';
 else if (src === 'brew' || src === 'homebrew') pm = 'brew';
 else if (src === 'pkg') pm = 'pkg';
 else if (src === 'snap') pm = 'snap';
 else if (src === 'flatpak') pm = 'flatpak';

 const sources: SourceFormData[] = [];
 if (pm) {
 sources.push({
 packageManager: pm,
 packageId: app.packageId ?? '',
 msiUrl: '',
 repoPackageId: null,
 installScript: '',
 msiParams: '',
 platformScope: PACKAGE_MANAGER_PLATFORM[pm] ?? 'any',
 });
 }

 return {
 name: app.name,
 matchType: 'contains',
 publisher: app.publisher ?? '',
 minVersion: '',
 maxVersion: '',
 sources,
 osCondition: null,
 fromInventory: true,
 };
}

function makeEntryFromKnownApp(app: KnownSoftwareApp): EntryFormData {
 return { label: '', alternatives: [makeAlternativeFromKnownApp(app)] };
}

/** Detection fields + install sources + OS condition of one alternative. */
// .msi packages of the software repository, for the MSI sources (cached a
// minute: every alternative of the editor reads it).
let repoMsiCache: { at: number; p: Promise<SoftwareRepoPackage[]> } | null = null;
function useRepoMsiPackages(): SoftwareRepoPackage[] {
 const [pkgs, setPkgs] = useState<SoftwareRepoPackage[]>([]);
 useEffect(() => {
 let alive = true;
 if (!repoMsiCache || Date.now() - repoMsiCache.at > 60_000) {
 repoMsiCache = {
 at: Date.now(),
 p: softwareRepoApi.list()
 .then(list => list.filter(p => p.platform === 'windows' && /\.msi$/i.test(p.filename)))
 .catch(() => []),
 };
 }
 repoMsiCache.p.then(list => { if (alive) setPkgs(list); });
 return () => { alive = false; };
 }, []);
 return pkgs;
}

function AlternativeFields({
 alt, onChange, isBlacklist, defaultPlatform,
}: {
 alt: AlternativeFormData;
 onChange: (a: AlternativeFormData) => void;
 isBlacklist: boolean;
 /** Platform proposed for a new OS condition (the list's, else Windows). */
 defaultPlatform: ConcretePlatform;
}) {
 const { t } = useTranslation();
 const set = (patch: Partial<AlternativeFormData>) => onChange({ ...alt, ...patch });
 const repoMsis = useRepoMsiPackages();

 const installLabel = isBlacklist
 ? t('softwareCompliance.uninstallMethod')
 : t('softwareCompliance.installSource');

 return (
 <div className="space-y-2">
 <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
 {/* Match Type */}
 <div className="space-y-0.5">
 <label className="text-[10px] font-semibold text-text-muted uppercase tracking-wider">
 {t('softwareCompliance.matchType')}
 </label>
 <select
 value={alt.matchType}
 onChange={e => set({ matchType: e.target.value as SoftwareMatchType })}
 className="w-full px-2 py-1.5 text-sm bg-bg-secondary rounded text-text-primary focus:outline-none focus:border-accent"
 >
 {MATCH_TYPES.map(m => (
 <option key={m} value={m}>{t(`softwareCompliance.matchTypes.${m}`)}</option>
 ))}
 </select>
 </div>
 {/* Publisher */}
 <div className="space-y-0.5">
 <label className="text-[10px] font-semibold text-text-muted uppercase tracking-wider">
 {t('softwareCompliance.publisher')}
 </label>
 <input
 value={alt.publisher}
 onChange={e => set({ publisher: e.target.value })}
 placeholder={t('softwareCompliance.optionalPlaceholder', 'Optional')}
 className="w-full px-2 py-1.5 text-sm bg-bg-secondary rounded text-text-primary focus:outline-none focus:border-accent"
 />
 </div>
 {/* Min / Max Version side by side */}
 <div className="flex gap-2">
 <div className="flex-1 space-y-0.5">
 <label className="text-[10px] font-semibold text-text-muted uppercase tracking-wider">
 {t('softwareCompliance.minVersion')}
 </label>
 <input
 value={alt.minVersion}
 onChange={e => set({ minVersion: e.target.value })}
 placeholder={t('softwareCompliance.minVersionPlaceholder', 'e.g. 100.0')}
 autoCapitalize="off" autoCorrect="off" spellCheck={false}
 className="w-full px-2 py-1.5 text-sm bg-bg-secondary rounded text-text-primary focus:outline-none focus:border-accent"
 />
 </div>
 <div className="flex-1 space-y-0.5">
 <label className="text-[10px] font-semibold text-text-muted uppercase tracking-wider">
 {t('softwareCompliance.maxVersion')}
 </label>
 <input
 value={alt.maxVersion}
 onChange={e => set({ maxVersion: e.target.value })}
 placeholder={t('softwareCompliance.maxVersionPlaceholder', 'e.g. 120.0')}
 autoCapitalize="off" autoCorrect="off" spellCheck={false}
 className="w-full px-2 py-1.5 text-sm bg-bg-secondary rounded text-text-primary focus:outline-none focus:border-accent"
 />
 </div>
 </div>
 </div>

 {/* ── Sources (multi-package-manager) ─── */}
 <div className="space-y-1.5">
 <div className="flex items-center justify-between">
 <label className="text-[10px] font-semibold text-text-muted uppercase tracking-wider">{installLabel}</label>
 <button
 type="button"
 onClick={() => set({ sources: [...alt.sources, makeEmptySource()] })}
 className="text-[10px] text-accent hover:text-accent-hover transition-colors flex items-center gap-0.5 coarse:min-h-10 coarse:px-2 coarse:text-xs"
 >
 <Plus className="w-3 h-3" /> {t('softwareCompliance.addSource')}
 </button>
 </div>
 {alt.sources.length === 0 && (
 <p className="text-xs text-text-muted italic py-1">{t('softwareCompliance.noSource')}</p>
 )}
 {alt.sources.map((src, si) => {
 const updateSrc = (patch: Partial<SourceFormData>) => {
 const next = [...alt.sources];
 next[si] = { ...next[si], ...patch };
 // Auto-set platformScope when changing package manager
 if (patch.packageManager && patch.packageManager !== src.packageManager) {
 next[si].platformScope = PACKAGE_MANAGER_PLATFORM[patch.packageManager as SoftwareInstallSource] ?? 'any';
 }
 set({ sources: next });
 };
 const removeSrc = () => set({ sources: alt.sources.filter((_, i) => i !== si) });
 const scopeIcon = PLATFORM_ICONS[src.platformScope];
 return (
 <div key={si} className="flex items-start gap-1.5 p-2 rounded bg-bg-secondary/50 border border-transparent/50">
 <div className="flex-1 grid grid-cols-1 sm:grid-cols-3 gap-1.5">
 {/* Package Manager */}
 <select
 value={src.packageManager}
 onChange={e => updateSrc({ packageManager: e.target.value as SoftwareInstallSource | '', packageId: '', installScript: '' })}
 className="px-2 py-1 text-xs bg-bg-secondary rounded text-text-primary focus:outline-none focus:border-accent"
 >
 <option value="">—</option>
 {INSTALL_SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
 </select>
 {/* Package ID */}
 {src.packageManager && src.packageManager !== 'custom' && src.packageManager !== 'msi' && (
 <input
 value={src.packageId}
 onChange={e => updateSrc({ packageId: e.target.value })}
 placeholder={t('softwareCompliance.entry.installId', 'Package ID')}
 autoCapitalize="off" autoCorrect="off" spellCheck={false}
 className="px-2 py-1 text-xs bg-bg-secondary rounded font-mono text-text-primary focus:outline-none focus:border-accent"
 />
 )}
 {/* MSI from the software repository (install only) */}
 {src.packageManager === 'msi' && !isBlacklist && (
 <select
 value={src.repoPackageId ?? ''}
 onChange={e => updateSrc({ repoPackageId: e.target.value ? Number(e.target.value) : null })}
 aria-label={t('softwareCompliance.msiOrigin') || 'MSI package'}
 className="px-2 py-1 text-xs bg-bg-secondary rounded text-text-primary focus:outline-none focus:border-accent min-w-0"
 >
 <option value="">{t('softwareCompliance.msiFromUrl') || 'URL / UNC path'}</option>
 {repoMsis.map(p => (
 <option key={p.id} value={p.id}>{t('softwareCompliance.msiFromRepo', { name: p.displayName || p.filename }) || `Repository: ${p.displayName || p.filename}`}</option>
 ))}
 {src.repoPackageId != null && !repoMsis.some(p => p.id === src.repoPackageId) && (
 <option value={src.repoPackageId}>{t('softwareCompliance.msiFromRepoId', { id: src.repoPackageId }) || `Repository package #${src.repoPackageId}`}</option>
 )}
 </select>
 )}
 {/* MSI URL */}
 {src.packageManager === 'msi' && (isBlacklist || src.repoPackageId == null) && (
 <input
 value={src.msiUrl}
 onChange={e => updateSrc({ msiUrl: e.target.value })}
 placeholder={t('softwareCompliance.msiUrlPlaceholder', 'URL, UNC path, or select from repo')}
 autoCapitalize="off" autoCorrect="off" spellCheck={false}
 className="px-2 py-1 text-xs bg-bg-secondary rounded font-mono text-text-primary focus:outline-none focus:border-accent"
 />
 )}
 {/* MSI install parameters (properties), passed as typed */}
 {src.packageManager === 'msi' && !isBlacklist && (
 <div className="sm:col-span-3 space-y-0.5 min-w-0">
 <input
 value={src.msiParams}
 onChange={e => updateSrc({ msiParams: e.target.value })}
 placeholder={t('softwareCompliance.msiParamsPlaceholder') || 'Install parameters, e.g. SERVERURL="https://…" APIKEY="…"'}
 aria-label={t('softwareCompliance.msiParams') || 'Install parameters'}
 autoCapitalize="off" autoCorrect="off" spellCheck={false}
 className="w-full px-2 py-1 text-xs bg-bg-secondary rounded font-mono text-text-primary focus:outline-none focus:border-accent"
 />
 <p className="text-[10px] text-text-muted">
 {t('softwareCompliance.msiParamsHint') || 'MSI properties passed to msiexec as typed; /quiet /norestart are added unless you set them.'}
 </p>
 </div>
 )}
 {/* Platform scope badge */}
 {scopeIcon && (
 <span className={clsx('text-[9px] px-1.5 py-1 rounded border font-medium self-center w-fit', scopeIcon.color)}>
 {scopeIcon.label}
 </span>
 )}
 </div>
 <IconButton
 label={t('softwareCompliance.removeEntry')}
 icon={<X className="w-3.5 h-3.5" />}
 size="xs"
 variant="plain"
 onClick={removeSrc}
 className="hover:text-red-400 shrink-0 mt-0.5"
 />
 </div>
 );
 })}
 {/* Inline custom script for any source that is 'custom' */}
 {alt.sources.some(s => s.packageManager === 'custom') && (
 <textarea
 value={alt.sources.find(s => s.packageManager === 'custom')?.installScript ?? ''}
 onChange={e => {
 const next = alt.sources.map(s => s.packageManager === 'custom' ? { ...s, installScript: e.target.value } : s);
 set({ sources: next });
 }}
 placeholder={t('softwareCompliance.scriptPlaceholder', 'PowerShell or Bash script...')}
 rows={2}
 autoCapitalize="off" autoCorrect="off" spellCheck={false}
 className="w-full px-2 py-1.5 text-xs bg-bg-secondary rounded font-mono text-text-primary focus:outline-none focus:border-accent resize-y"
 />
 )}
 </div>

 {/* ── OS condition (remediation only) ─── */}
 {alt.osCondition ? (
 <div className="space-y-1.5 p-2 rounded bg-bg-secondary/50">
 <div className="flex flex-wrap items-center gap-2">
 <Cpu className="w-3.5 h-3.5 text-text-muted shrink-0" />
 <label className="text-[10px] font-semibold text-text-muted uppercase tracking-wider">
 {t('softwareCompliance.osCond.title') || 'OS condition'}
 </label>
 <select
 value={alt.osCondition.platform}
 onChange={e => set({ osCondition: emptyOsCondition(e.target.value as ConcretePlatform) })}
 aria-label={t('softwareCompliance.platform')}
 className="px-2 py-1 text-xs bg-bg-secondary rounded text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
 >
 {CONCRETE_PLATFORMS.map(p => <option key={p} value={p}>{platformLabel(p)}</option>)}
 </select>
 <IconButton
 label={t('softwareCompliance.osCond.remove') || 'Remove the OS condition'}
 icon={<X className="w-3.5 h-3.5" />}
 size="xs"
 variant="plain"
 onClick={() => set({ osCondition: null })}
 className="hover:text-red-400 ml-auto"
 />
 </div>
 <OsVersionFields value={alt.osCondition} onChange={c => set({ osCondition: c })} />
 <p className="text-[11px] text-text-muted">
 {t('softwareCompliance.osCond.altHint') || 'Remediation only uses this alternative on matching devices; detection accepts it everywhere.'}
 </p>
 </div>
 ) : (
 <button
 type="button"
 onClick={() => set({ osCondition: emptyOsCondition(defaultPlatform) })}
 className="text-[11px] text-text-muted hover:text-accent transition-colors flex items-center gap-1 coarse:min-h-10"
 >
 <Cpu className="w-3 h-3" /> {t('softwareCompliance.osCond.add') || 'OS condition'}
 </button>
 )}
 </div>
 );
}

function EntryEditorCard({
 entry, index, total, onChange, onDelete, onMoveUp, onMoveDown, isBlacklist, defaultPlatform, onPickFromInventory,
}: {
 entry: EntryFormData;
 index: number;
 total: number;
 onChange: (e: EntryFormData) => void;
 onDelete: () => void;
 onMoveUp: () => void;
 onMoveDown: () => void;
 isBlacklist: boolean;
 defaultPlatform: ConcretePlatform;
 /** Opens the inventory picker; the chosen app becomes a new alternative. */
 onPickFromInventory: () => void;
}) {
 const { t } = useTranslation();
 const alts = entry.alternatives;
 const multi = alts.length > 1;
 const [expanded, setExpanded] = useState(!alts[0]?.name);
 const set = (patch: Partial<EntryFormData>) => onChange({ ...entry, ...patch });
 const setAlt = (i: number, a: AlternativeFormData) => set({ alternatives: alts.map((x, j) => j === i ? a : x) });
 const moveAlt = (i: number, dir: -1 | 1) => {
 const target = i + dir;
 if (target < 0 || target >= alts.length) return;
 const next = [...alts];
 [next[i], next[target]] = [next[target], next[i]];
 set({ alternatives: next });
 };
 const removeAlt = (i: number) => {
 const next = alts.filter((_, j) => j !== i);
 // Back to a single alternative: its name is the entry's name again.
 set({ alternatives: next, label: next.length > 1 ? entry.label : '' });
 };
 const addAlt = () => {
 if (alts.length >= MAX_ALTERNATIVES) return;
 setExpanded(true);
 set({
 alternatives: [...alts, makeEmptyAlternative()],
 label: entry.label || alts[0]?.name || '',
 });
 };
 const allSources = alts.flatMap(a => a.sources);
 const fromInventory = alts.some(a => a.fromInventory);
 const headerValue = multi ? entry.label : (alts[0]?.name ?? '');

 return (
 <div className="rounded-lg bg-bg-tertiary/40 overflow-hidden">
 {/* Card header */}
 {/* Below sm the row wraps: index + chevron + name on the first line,
 badges and the move / delete buttons on the second. */}
 <div
 className="flex items-center gap-2 px-3 py-2.5 cursor-pointer hover:bg-bg-tertiary transition-colors max-sm:flex-wrap"
 onClick={() => setExpanded(!expanded)}
 >
 <span className="text-xs text-text-muted shrink-0 w-5 text-center">{index + 1}</span>
 {expanded
 ? <ChevronUp className="w-3.5 h-3.5 text-text-muted shrink-0" />
 : <ChevronDown className="w-3.5 h-3.5 text-text-muted shrink-0" />
 }
 <input
 value={headerValue}
 onChange={e => {
 e.stopPropagation();
 if (multi) set({ label: e.target.value });
 else setAlt(0, { ...alts[0], name: e.target.value });
 }}
 onClick={e => e.stopPropagation()}
 placeholder={multi
 ? (t('softwareCompliance.alt.labelPlaceholder') || 'Entry name, e.g. Passly')
 : t('softwareCompliance.entryNamePlaceholder', 'e.g. Google Chrome')}
 aria-label={multi ? (t('softwareCompliance.alt.label') || 'Entry name') : t('softwareCompliance.entryName')}
 className="flex-1 px-2 py-1 text-sm bg-bg-secondary rounded text-text-primary focus:outline-none focus:border-accent min-w-0 max-sm:min-w-[60%]"
 />
 {multi && (
 <span className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/20 shrink-0 whitespace-nowrap">
 <Layers className="w-3 h-3" />
 {t('softwareCompliance.alt.count', { count: alts.length }) || `${alts.length} alternatives`}
 </span>
 )}
 <PlatformBadges sources={allSources} />
 {fromInventory && (
 <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-400/10 text-blue-400 border border-blue-400/20 shrink-0 whitespace-nowrap">
 {t('softwareCompliance.fromInventoryBadge')}
 </span>
 )}
 <div className="flex items-center gap-0.5 shrink-0 max-sm:ml-auto coarse:gap-1">
 <IconButton
 label={t('softwareCompliance.moveUp')}
 icon={<ArrowUp className="w-3.5 h-3.5" />}
 size="sm"
 onClick={e => { e.stopPropagation(); onMoveUp(); }}
 disabled={index === 0}
 className="hover:bg-bg-secondary disabled:opacity-30"
 />
 <IconButton
 label={t('softwareCompliance.moveDown')}
 icon={<ArrowDown className="w-3.5 h-3.5" />}
 size="sm"
 onClick={e => { e.stopPropagation(); onMoveDown(); }}
 disabled={index === total - 1}
 className="hover:bg-bg-secondary disabled:opacity-30"
 />
 <IconButton
 label={t('common.delete')}
 icon={<X className="w-4 h-4" />}
 size="sm"
 variant="danger"
 onClick={e => { e.stopPropagation(); onDelete(); }}
 />
 </div>
 </div>

 {/* Card body — collapsible */}
 {expanded && (
 <div className="px-3 pb-3 pt-1 space-y-2">
 {!multi ? (
 <AlternativeFields
 alt={alts[0]}
 onChange={a => setAlt(0, a)}
 isBlacklist={isBlacklist}
 defaultPlatform={defaultPlatform}
 />
 ) : (
 <>
 <p className="text-[11px] text-text-muted flex items-start gap-1.5">
 <Layers className="w-3.5 h-3.5 shrink-0 mt-px" />
 {isBlacklist
 ? (t('softwareCompliance.alt.hintBlacklist') || 'Non-compliant when any alternative is detected; the remediation removes those that match the device\'s OS.')
 : (t('softwareCompliance.alt.hintWhitelist') || 'Compliant when any alternative is detected. The remediation tries the alternatives that match the device\'s OS, in this order, and stops at the first one installed and detected.')}
 </p>
 <div>
 {alts.map((a, ai) => (
 <div key={ai}>
 {ai > 0 && (
 <div className="flex items-center gap-2 py-1.5" aria-hidden>
 <div className="flex-1 h-px bg-border" />
 <span className="text-[10px] font-bold tracking-widest text-accent px-2 py-0.5 rounded-full bg-accent/10 border border-accent/20">
 {t('softwareCompliance.alt.or') || 'OR'}
 </span>
 <div className="flex-1 h-px bg-border" />
 </div>
 )}
 <div className="rounded-lg bg-bg-secondary/40 border border-border/40 overflow-hidden">
 <div className="flex items-center gap-2 px-2.5 py-2 bg-bg-secondary/60 max-sm:flex-wrap">
 <span className="text-[10px] font-semibold text-text-muted uppercase tracking-wider shrink-0 whitespace-nowrap">
 {t('softwareCompliance.alt.alternative', { n: ai + 1 }) || `Alternative ${ai + 1}`}
 </span>
 <input
 value={a.name}
 onChange={e => setAlt(ai, { ...a, name: e.target.value })}
 placeholder={t('softwareCompliance.alt.namePlaceholder') || 'Software name as detected, e.g. Passly Agent'}
 aria-label={t('softwareCompliance.entryName')}
 className="flex-1 px-2 py-1 text-sm bg-bg-secondary rounded text-text-primary focus:outline-none focus:ring-1 focus:ring-accent min-w-0 max-sm:min-w-[60%]"
 />
 {a.osCondition && osConditionHasBounds(a.osCondition) && (
 <span className="text-[10px] px-1.5 py-0.5 rounded bg-bg-tertiary text-text-muted border border-border/50 shrink-0 whitespace-nowrap max-w-[14rem] truncate">
 {describeOsCondition(osConditionToApi(a.osCondition), t, true)}
 </span>
 )}
 <div className="flex items-center gap-0.5 shrink-0 max-sm:ml-auto coarse:gap-1">
 <IconButton
 label={t('softwareCompliance.alt.moveUp') || 'Try earlier'}
 icon={<ArrowUp className="w-3.5 h-3.5" />}
 size="xs"
 onClick={() => moveAlt(ai, -1)}
 disabled={ai === 0}
 className="hover:bg-bg-tertiary disabled:opacity-30"
 />
 <IconButton
 label={t('softwareCompliance.alt.moveDown') || 'Try later'}
 icon={<ArrowDown className="w-3.5 h-3.5" />}
 size="xs"
 onClick={() => moveAlt(ai, 1)}
 disabled={ai === alts.length - 1}
 className="hover:bg-bg-tertiary disabled:opacity-30"
 />
 <IconButton
 label={t('softwareCompliance.alt.remove') || 'Remove this alternative'}
 icon={<X className="w-3.5 h-3.5" />}
 size="xs"
 variant="danger"
 onClick={() => removeAlt(ai)}
 />
 </div>
 </div>
 <div className="p-2.5">
 <AlternativeFields
 alt={a}
 onChange={x => setAlt(ai, x)}
 isBlacklist={isBlacklist}
 defaultPlatform={defaultPlatform}
 />
 </div>
 </div>
 </div>
 ))}
 </div>
 </>
 )}

 {/* Add an alternative ("OR") */}
 {alts.length < MAX_ALTERNATIVES && (
 <div className="flex flex-wrap items-center gap-2 pt-1">
 <button
 type="button"
 onClick={addAlt}
 className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg border border-dashed border-accent/40 text-accent hover:bg-accent/10 transition-colors coarse:min-h-10"
 >
 <Plus className="w-3.5 h-3.5" />
 {t('softwareCompliance.alt.add') || 'Add an alternative (OR)'}
 </button>
 <button
 type="button"
 onClick={() => { setExpanded(true); onPickFromInventory(); }}
 className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg border border-dashed border-border text-text-muted hover:text-accent hover:border-accent/40 transition-colors coarse:min-h-10"
 >
 <Package className="w-3.5 h-3.5" />
 {t('softwareCompliance.alt.fromInventory') || 'Alternative from inventory'}
 </button>
 </div>
 )}
 </div>
 )}
 </div>
 );
}

// ── Known Apps Modal ──────────────────────────────────────────────────────────

function KnownAppsModal({
 open,
 onClose,
 onSelect,
 platform,
}: {
 open: boolean;
 onClose: () => void;
 onSelect: (app: KnownSoftwareApp) => void;
 platform: string;
}) {
 const { t } = useTranslation();
 const coarse = useIsCoarsePointer();
 const [apps, setApps] = useState<KnownSoftwareApp[]>([]);
 const [search, setSearch] = useState('');
 const [loading, setLoading] = useState(false);
 const searchRef = useRef<HTMLInputElement>(null);

 useEffect(() => {
 if (!open) return;
 setSearch('');
 }, [open, platform]);

 // The server returns the 500 most installed apps: a search is sent to it
 // (debounced) so an app installed on a single machine is found as well.
 useEffect(() => {
 if (!open) return;
 let cancelled = false;
 setLoading(true);
 const osType = platform === 'all' ? undefined : platform === 'macos' ? 'macos' : platform;
 const timer = setTimeout(() => {
 softwareComplianceApi.getKnownApps(osType, search.trim())
 .then((a) => { if (!cancelled) setApps(a); })
 .catch(() => { if (!cancelled) setApps([]); })
 .finally(() => { if (!cancelled) setLoading(false); });
 }, search.trim() ? 300 : 0);
 return () => { cancelled = true; clearTimeout(timer); };
 }, [open, platform, search]);

 // Autofocus only with a mouse — on touch it pops the keyboard over half of
 // a list that is mostly browsed, not searched.
 useEffect(() => {
 if (open && !coarse) setTimeout(() => searchRef.current?.focus(), 100);
 }, [open, coarse]);

 if (!open) return null;

 const filtered = search.trim()
 ? apps.filter(a => a.name.toLowerCase().includes(search.toLowerCase()) || (a.publisher ?? '').toLowerCase().includes(search.toLowerCase()))
 : apps;

 // Group by OS when platform is 'all'
 const isAll = platform === 'all';
 const sections = isAll
 ? (['windows', 'linux', 'macos', 'freebsd'] as const).map(os => ({
 os,
 label: os === 'windows' ? 'Windows' : os === 'linux' ? 'Linux' : os === 'macos' ? 'macOS' : 'FreeBSD',
 apps: filtered.filter(a => a.osType === os),
 })).filter(s => s.apps.length > 0)
 : [{ os: platform, label: '', apps: filtered }];

 const renderApp = (app: KnownSoftwareApp, i: number) => (
 <button
 key={`${app.name}-${app.source}-${i}`}
 onClick={() => { onSelect(app); onClose(); }}
 className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-bg-secondary transition-colors text-left group"
 >
 <Package className="w-4 h-4 text-text-muted shrink-0 group-hover:text-accent transition-colors" />
 <div className="flex-1 min-w-0">
 <p className="text-sm font-medium text-text-primary truncate">{app.name}</p>
 <div className="flex items-center gap-2 mt-0.5">
 {app.publisher && <span className="text-xs text-text-muted truncate">{app.publisher}</span>}
 {app.source && (
 <span className="text-[10px] px-1.5 py-0.5 rounded bg-bg-tertiary border border-transparent text-text-muted shrink-0">
 {app.source}
 </span>
 )}
 </div>
 </div>
 <span className="text-xs text-text-muted shrink-0">
 {t('softwareCompliance.installedOn', { count: app.deviceCount })}
 </span>
 </button>
 );

 return (
 <Modal
 open={open}
 onClose={onClose}
 title={t('softwareCompliance.fromInventory')}
 size="md"
 className="bg-bg-primary sm:max-h-[80dvh] sm:supports-[not(height:100dvh)]:max-h-[80vh]"
 bodyClassName="p-0"
 >
 <div className="sticky top-0 z-10 bg-bg-primary px-4 py-3">
 <div className="flex items-center gap-2 px-3 py-2 bg-bg-secondary rounded-lg">
 <Search className="w-3.5 h-3.5 text-text-muted shrink-0" />
 <input
 ref={searchRef}
 value={search}
 onChange={e => setSearch(e.target.value)}
 placeholder={t('softwareCompliance.searchApps')}
 autoCapitalize="off" autoCorrect="off" spellCheck={false}
 className="flex-1 min-w-0 text-sm bg-transparent text-text-primary focus:outline-none"
 />
 </div>
 </div>

 <div className="p-2">
 {loading ? (
 <div className="flex items-center justify-center py-12">
 <RefreshCw className="w-5 h-5 animate-spin text-text-muted" />
 </div>
 ) : filtered.length === 0 ? (
 <div className="text-center py-12 text-text-muted">
 <Package className="w-8 h-8 mx-auto mb-2 opacity-50" />
 <p className="text-sm">{t('softwareCompliance.noKnownApps')}</p>
 </div>
 ) : (
 <div className="space-y-1">
 {sections.map(section => (
 <div key={section.os}>
 {isAll && (
 <div className="flex items-center gap-2 px-2 py-1.5 mt-2 first:mt-0">
 <span className="text-[10px] font-bold text-text-muted uppercase tracking-wider">{section.label}</span>
 <span className="text-[10px] text-text-muted">({section.apps.length})</span>
 </div>
 )}
 {section.apps.map((app, i) => renderApp(app, i))}
 </div>
 ))}
 </div>
 )}
 </div>
 </Modal>
 );
}

// ── List form ─────────────────────────────────────────────────────────────────

interface ListFormData {
 name: string;
 description: string;
 listType: SoftwareListType;
 targetType: 'group' | 'all';
 targetIds: number[];
 /** Groups of targetIds limited to their direct devices (no auto sub-groups). */
 targetManualGroupIds: number[];
 targetPlatform: typeof PLATFORMS[number];
 /** Version restriction of targetPlatform (its platform follows targetPlatform). */
 osCondition: OsConditionForm | null;
 autoRemediate: boolean;
 enabled: boolean;
 entries: EntryFormData[];
}

const defaultListForm: ListFormData = {
 name: '', description: '', listType: 'whitelist', targetType: 'all', targetIds: [], targetManualGroupIds: [],
 targetPlatform: 'all', osCondition: null, autoRemediate: false, enabled: true, entries: [],
};

/** Form alternatives ← API entry (older payloads: the entry itself is the only alternative). */
function entryToForm(e: SoftwareComplianceEntry): EntryFormData {
 const alts: SoftwareEntryAlternative[] = e.alternatives?.length
 ? e.alternatives
 : [{ id: e.id, name: e.name, matchType: e.matchType, publisher: e.publisher, minVersion: e.minVersion, maxVersion: e.maxVersion, sources: e.sources ?? [], osCondition: e.osCondition ?? null }];
 return {
 label: alts.length > 1 ? (e.label ?? '') : '',
 alternatives: alts.map(a => ({
 name: a.name,
 matchType: a.matchType,
 publisher: a.publisher ?? '',
 minVersion: a.minVersion ?? '',
 maxVersion: a.maxVersion ?? '',
 osCondition: osConditionFromApi(a.osCondition),
 sources: (a.sources ?? []).map(s => ({
 packageManager: s.packageManager || '' as SoftwareInstallSource | '',
 packageId: s.packageId ?? '',
 msiUrl: s.msiUrl ?? '',
 repoPackageId: s.repoPackageId ?? null,
 installScript: s.installScript ?? '',
 msiParams: s.msiParams ?? '',
 platformScope: s.platformScope ?? 'any' as DistroScope,
 })),
 })),
 };
}

/** API entry ← form: top-level fields = first alternative (older agents / clients). */
function formToEntry(e: EntryFormData, i: number) {
 const alternatives = e.alternatives.map(a => ({
 name: a.name.trim(),
 matchType: a.matchType,
 publisher: a.publisher || null,
 minVersion: a.minVersion || null,
 maxVersion: a.maxVersion || null,
 osCondition: osConditionToApi(a.osCondition),
 sources: a.sources.filter(s => s.packageManager).map((s, si) => ({
 packageManager: s.packageManager,
 packageId: s.packageId || null,
 msiUrl: s.msiUrl || null,
 repoPackageId: s.repoPackageId,
 installScript: s.installScript || null,
 msiParams: s.msiParams || null,
 platformScope: s.platformScope,
 sortOrder: si,
 })),
 }));
 const first = alternatives[0];
 return {
 ...first,
 label: alternatives.length > 1 ? (e.label.trim() || null) : null,
 // Legacy fields from first source for backward compat
 installSource: (first.sources[0]?.packageManager || null) as SoftwareInstallSource | null,
 installId: first.sources[0]?.packageId || null,
 installScript: first.sources[0]?.installScript || null,
 msiUrl: first.sources[0]?.msiUrl || null,
 msiParams: first.sources[0]?.msiParams || null,
 sortOrder: i,
 alternatives,
 };
}

/** Result line: alternative detected + server-driven remediation progress. */
function AlternativeResultInfo({ er }: { er: SoftwareComplianceEntryResult }) {
 const { t } = useTranslation();
 const rem = er.remediation;
 const count = er.alternativeCount ?? 1;
 if (!rem && !(count > 1 && er.alternativeName)) return null;
 const outcomeLabel = (o: string) => t(`softwareCompliance.alt.outcome.${o}`) || o.replace(/_/g, ' ');
 let remText: string | null = null;
 if (rem) {
 const vars = { index: rem.alternativeIndex ?? '?', name: rem.alternativeName ?? '' };
 if (rem.state === 'installing') remText = t('softwareCompliance.alt.rem.installing', vars) || `Remediation: installing alternative ${vars.index} — ${vars.name}`;
 else if (rem.state === 'succeeded') remText = t('softwareCompliance.alt.rem.succeeded', vars) || `Installed by the remediation: alternative ${vars.index} — ${vars.name}`;
 else if (rem.state === 'exhausted') remText = rem.retryAfter
 ? (rem.retryNumber && rem.maxRetries
 ? (t('softwareCompliance.alt.rem.exhaustedRetry', { date: new Date(rem.retryAfter).toLocaleString(), n: rem.retryNumber, max: rem.maxRetries }) || `Remediation: every eligible alternative failed — retry ${rem.retryNumber}/${rem.maxRetries} after ${new Date(rem.retryAfter).toLocaleString()}`)
 : (t('softwareCompliance.alt.rem.exhausted', { date: new Date(rem.retryAfter).toLocaleString() }) || `Remediation: every eligible alternative failed — next attempt after ${new Date(rem.retryAfter).toLocaleString()}`))
 : (t('softwareCompliance.alt.rem.exhaustedNoDate') || 'Remediation: every eligible alternative failed');
 else if (rem.state === 'failed') remText = t('softwareCompliance.alt.rem.failed', { max: rem.maxRetries ?? 3 }) || `Install failed: every alternative failed, ${rem.maxRetries ?? 3} retries included — use Remediate to try again`;
 else if (rem.state === 'no_eligible') remText = t('softwareCompliance.alt.rem.noEligible') || 'Remediation: no alternative can be installed on this device (OS conditions / install method)';
 }
 return (
 <div className="mt-1 space-y-1">
 {count > 1 && er.alternativeName && (
 <p className="text-xs text-text-muted flex items-center gap-1 min-w-0">
 <Layers className="w-3 h-3 shrink-0 text-accent" />
 <span className="break-words">
 {t('softwareCompliance.alt.detected', { index: er.alternativeIndex ?? '?', count, name: er.alternativeName }) || `Alternative ${er.alternativeIndex}/${count}: ${er.alternativeName}`}
 </span>
 </p>
 )}
 {remText && (
 <p className={clsx('text-xs flex items-start gap-1',
 rem?.state === 'succeeded' ? 'text-green-400' : rem?.state === 'installing' ? 'text-blue-400' : 'text-orange-400')}>
 <Wrench className={clsx('w-3 h-3 shrink-0 mt-0.5', rem?.state === 'installing' && 'animate-pulse')} />
 <span className="break-words">{remText}</span>
 </p>
 )}
 {rem && rem.attempts.length > 0 && rem.state !== 'no_eligible' && (
 <div className="flex flex-wrap gap-1">
 {rem.attempts.map((a, i) => (
 <span
 key={i}
 title={a.detail ?? undefined}
 className={clsx('text-[10px] px-1.5 py-0.5 rounded border',
 a.outcome === 'succeeded' ? 'bg-green-400/10 text-green-400 border-green-400/20'
 : a.outcome === 'pending' || a.outcome === 'installed' ? 'bg-blue-400/10 text-blue-400 border-blue-400/20'
 : 'bg-orange-400/10 text-orange-400 border-orange-400/20')}
 >
 {`#${a.alternativeIndex ?? '?'} · ${outcomeLabel(a.outcome)}`}
 </span>
 ))}
 </div>
 )}
 </div>
 );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function SoftwareCompliancePage({ embedded }: { embedded?: boolean } = {}) {
 const { t } = useTranslation();
 const confirm = useConfirm();
 const coarse = useIsCoarsePointer();
 const { isAdmin: _isAdmin } = useAuthStore();
 const deviceMap = useDeviceStore(s => s.devices);
 const devices = Array.from(deviceMap.values());
 const [activeTab, setActiveTab] = useState<Tab>('results');
 const [lists, setLists] = useState<SoftwareComplianceList[]>([]);
 const [results, setResults] = useState<SoftwareComplianceResult[]>([]);
 const [isLoading, setIsLoading] = useState(true);
 const [filterDeviceId, setFilterDeviceId] = useState<number | ''>('');
 const [showForm, setShowForm] = useState(false);
 const [editingList, setEditingList] = useState<SoftwareComplianceList | null>(null);
 const [form, setForm] = useState<ListFormData>(defaultListForm);
 // Group tree, for the normalized "N group(s)" count of the list rows.
 const { index: groupIndex } = useGroupTreeIndex();
 const [isSaving, setIsSaving] = useState(false);
 const [expandedResultId, setExpandedResultId] = useState<number | null>(null);
 const [remediatingEntries, setRemediatingEntries] = useState<Set<string>>(new Set());

 const load = useCallback(async () => {
 setIsLoading(true);
 try {
 const [listsData, resultsData] = await Promise.all([
 softwareComplianceApi.listLists(),
 softwareComplianceApi.listResults({ page: 1 }),
 ]);
 setLists(listsData);
 setResults(resultsData.items);
 } catch {
 toast.error(t('softwareCompliance.failedLoad'));
 } finally {
 setIsLoading(false);
 }
 }, [t]);

 const loadResults = useCallback(async (deviceId?: number) => {
 setIsLoading(true);
 try {
 const resultsData = await softwareComplianceApi.listResults({ page: 1, deviceId });
 setResults(resultsData.items);
 } catch {
 toast.error(t('softwareCompliance.failedLoad'));
 } finally {
 setIsLoading(false);
 }
 }, [t]);

 useEffect(() => { load(); }, [load]);

 useEffect(() => {
 loadResults(filterDeviceId !== '' ? filterDeviceId : undefined);
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [filterDeviceId]);

 // ── List CRUD ─────────────────────────────────────────────────────────────

 const handleOpenCreate = () => {
 setForm(defaultListForm);
 setEditingList(null);
 setShowForm(true);
 };

 const listToForm = (list: SoftwareComplianceList) => ({
 name: list.name,
 description: list.description ?? '',
 listType: list.listType,
 targetType: list.targetType,
 targetIds: list.targetIds ?? [],
 targetManualGroupIds: list.targetManualGroupIds ?? [],
 targetPlatform: list.targetPlatform ?? 'all',
 osCondition: list.targetPlatform && list.targetPlatform !== 'all'
 ? (osConditionFromApi(list.osCondition) ?? emptyOsCondition(list.targetPlatform))
 : null,
 autoRemediate: list.autoRemediate,
 enabled: list.enabled,
 entries: (list.entries ?? []).map(entryToForm),
 });

 const handleOpenEdit = (list: SoftwareComplianceList) => {
 setForm(listToForm(list));
 setEditingList(list);
 setShowForm(true);
 setActiveTab('lists');
 };

 // A new list prefilled from an existing one (entries, alternatives,
 // sources, targets): nothing is saved until "Save".
 const handleDuplicate = (list: SoftwareComplianceList) => {
 const copy = listToForm(list);
 setForm({ ...copy, name: t('softwareCompliance.copyName', { name: list.name }) || `${list.name} (copy)` });
 setEditingList(null);
 setShowForm(true);
 setActiveTab('lists');
 };

 const handleSave = async () => {
 if (!form.name.trim()) { toast.error(t('softwareCompliance.nameRequired')); return; }
 if (form.entries.some(e => e.alternatives.some(a => !a.name.trim()))) {
 toast.error(t('softwareCompliance.alt.nameRequired') || 'Every entry and alternative needs a software name');
 return;
 }
 setIsSaving(true);
 try {
 const entries = form.entries.map(formToEntry);
 const payload = {
 name: form.name,
 description: form.description || null,
 listType: form.listType,
 targetType: form.targetType,
 targetIds: form.targetIds,
 targetManualGroupIds: form.targetType === 'group' ? form.targetManualGroupIds : [],
 targetPlatform: form.targetPlatform,
 osCondition: form.targetPlatform !== 'all' ? osConditionToApi(form.osCondition) : null,
 autoRemediate: form.autoRemediate,
 enabled: form.enabled,
 entries,
 };
 if (editingList) {
 await softwareComplianceApi.updateList(editingList.id, payload as any);
 toast.success(t('softwareCompliance.listUpdated'));
 } else {
 await softwareComplianceApi.createList(payload as any);
 toast.success(t('softwareCompliance.listCreated'));
 }
 setShowForm(false);
 setEditingList(null);
 await load();
 } catch {
 toast.error(t('softwareCompliance.failedSave'));
 } finally {
 setIsSaving(false);
 }
 };

 const handleDelete = async (id: number) => {
 if (!(await confirm({ message: t('softwareCompliance.confirmDelete'), danger: true }))) return;
 try {
 await softwareComplianceApi.deleteList(id);
 toast.success(t('softwareCompliance.listDeleted'));
 await load();
 } catch {
 toast.error(t('softwareCompliance.failedDelete'));
 }
 };

 const handleToggleEnabled = async (list: SoftwareComplianceList) => {
 try {
 await softwareComplianceApi.updateList(list.id, { enabled: !list.enabled });
 toast.success(list.enabled ? t('softwareCompliance.listDisabled') : t('softwareCompliance.listEnabled'));
 await load();
 } catch {
 toast.error(t('softwareCompliance.failedSave'));
 }
 };

 // ── Remediation ────────────────────────────────────────────────────────────

 const handleRemediate = async (deviceId: number, listId: number, entryIds: number[]) => {
 // Remediation installs / uninstalls software right away; the icon buttons
 // are small — on touch, ask first (desktop unchanged).
 if (coarse && !(await confirm({
 title: t('compliance.remediateConfirmTitle', 'Run remediation?'),
 message: t('softwareCompliance.remediateConfirm', { count: entryIds.length, defaultValue: 'Run the remediation for {{count}} entry(ies) on this device now?' }),
 confirmLabel: t('softwareCompliance.remediate'),
 }))) return;
 const keys = entryIds.map(id => `${deviceId}:${listId}:${id}`);
 setRemediatingEntries(prev => { const s = new Set(prev); keys.forEach(k => s.add(k)); return s; });
 try {
 await softwareComplianceApi.remediate(deviceId, listId, entryIds);
 toast.success(t('softwareCompliance.remediationSent', { count: entryIds.length }));
 } catch (err) {
 const code = (err as { response?: { data?: { code?: string } } })?.response?.data?.code;
 toast.error(code === 'SW_NO_ELIGIBLE_ALTERNATIVE'
 ? (t('softwareCompliance.alt.noEligibleToast') || 'No alternative of this entry can be installed on this device')
 : t('softwareCompliance.remediationFailed'));
 } finally {
 setRemediatingEntries(prev => { const s = new Set(prev); keys.forEach(k => s.delete(k)); return s; });
 }
 };

 const handleRemediateAll = async (result: SoftwareComplianceResult) => {
 const failingEntryIds = result.results
 .filter(er => er.status === 'non_compliant')
 .map(er => er.entryId);
 if (failingEntryIds.length === 0) { toast.error(t('softwareCompliance.noRemediable')); return; }
 await handleRemediate(result.deviceId, result.listId, failingEntryIds);
 };

 const handleScanList = async (list: SoftwareComplianceList) => {
 try {
 const r = await softwareComplianceApi.scanList(list.id);
 if (r.enqueued === 0) {
 toast(t('softwareCompliance.scanNoTargets', 'No online target devices'));
 } else {
 toast.success(t('softwareCompliance.scanEnqueued', { count: r.enqueued, defaultValue_one: 'Scan enqueued on {{count}} device', defaultValue_other: 'Scan enqueued on {{count}} devices' }));
 }
 // Refresh results after a delay to give agents time to report.
 setTimeout(load, 8000);
 } catch {
 toast.error(t('softwareCompliance.scanFailed', 'Scan failed'));
 }
 };

 const handleTriggerCheck = async (deviceId: number, listId?: number) => {
 try {
 await softwareComplianceApi.triggerCheck(deviceId, listId);
 toast.success(t('softwareCompliance.checkTriggered'));
 } catch (err) {
 const code = (err as { response?: { data?: { code?: string } } })?.response?.data?.code;
 toast.error(code === 'SW_LIST_OUT_OF_SCOPE'
 ? (t('softwareCompliance.osCond.outOfScope') || 'This device is outside the platform / OS versions of the list')
 : t('softwareCompliance.checkFailed'));
 }
 };

 // ── Entry CRUD ────────────────────────────────────────────────────────────

 const [showAddMenu, setShowAddMenu] = useState(false);
 const [showKnownApps, setShowKnownApps] = useState(false);
 const addMenuRef = useRef<HTMLDivElement>(null);

 // Close dropdown on outside click / tap
 useClickOutside(addMenuRef, () => setShowAddMenu(false), showAddMenu);

 // Inventory picker target: a new entry (null) or a new alternative of entry N.
 const [inventoryTarget, setInventoryTarget] = useState<number | null>(null);
 const addEntry = () => setForm(f => ({ ...f, entries: [...f.entries, makeEmptyEntry()] }));
 const addEntryFromApp = (app: KnownSoftwareApp) => {
 if (inventoryTarget === null) {
 setForm(f => ({ ...f, entries: [...f.entries, makeEntryFromKnownApp(app)] }));
 return;
 }
 const target = inventoryTarget;
 setForm(f => ({
 ...f,
 entries: f.entries.map((e, i) => {
 if (i !== target) return e;
 const picked = makeAlternativeFromKnownApp(app);
 // A blank single alternative is filled rather than followed by a second one.
 if (e.alternatives.length === 1 && !e.alternatives[0].name.trim()) return { ...e, alternatives: [picked] };
 if (e.alternatives.length >= MAX_ALTERNATIVES) return e;
 return { label: e.label || e.alternatives[0].name, alternatives: [...e.alternatives, picked] };
 }),
 }));
 };
 const defaultAltPlatform: ConcretePlatform = form.targetPlatform !== 'all' ? form.targetPlatform : 'windows';
 const updateEntry = (index: number, entry: EntryFormData) =>
 setForm(f => ({ ...f, entries: f.entries.map((e, i) => i === index ? entry : e) }));
 const deleteEntry = (index: number) =>
 setForm(f => ({ ...f, entries: f.entries.filter((_, i) => i !== index) }));
 const moveEntry = (index: number, direction: -1 | 1) => {
 setForm(f => {
 const entries = [...f.entries];
 const target = index + direction;
 if (target < 0 || target >= entries.length) return f;
 [entries[index], entries[target]] = [entries[target], entries[index]];
 return { ...f, entries };
 });
 };

 // ── Summary ────────────────────────────────────────────────────────────────

 const avgScore = results.length > 0
 ? results.reduce((sum, r) => sum + r.complianceScore, 0) / results.length
 : null;
 const passingCount = results.filter(r => r.complianceScore >= 80).length;
 const warningCount = results.filter(r => r.complianceScore >= 50 && r.complianceScore < 80).length;
 const failingCount = results.filter(r => r.complianceScore < 50).length;

 const refreshButton = (
 <button onClick={load} aria-label={t('common.refresh')} className="p-2 text-text-muted hover:text-text-primary hover:bg-bg-secondary rounded-lg transition-colors coarse:min-h-10 coarse:min-w-10">
 <RefreshCw className={clsx('w-4 h-4', isLoading && 'animate-spin')} />
 </button>
 );

 return (
 <PageContainer embedded={embedded} className="space-y-6">
 {/* Header */}
 {!embedded && <div className="flex items-center justify-between">
 <div>
 <h1 className="text-2xl font-bold text-text-primary">{t('softwareCompliance.title')}</h1>
 <p className="text-sm text-text-muted mt-0.5">{t('softwareCompliance.description')}</p>
 </div>
 {refreshButton}
 </div>}

 {/* Summary cards */}
 <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
 <div className="p-4 bg-bg-secondary rounded-xl">
 <div className="flex items-center gap-3">
 <div className={clsx('p-2 rounded-lg', avgScore !== null ? (avgScore >= 80 ? 'bg-green-400/10' : avgScore >= 50 ? 'bg-yellow-400/10' : 'bg-red-400/10') : 'bg-bg-tertiary')}>
 <Activity className={clsx('w-4 h-4', avgScore !== null ? scoreColor(avgScore) : 'text-text-muted')} />
 </div>
 <div>
 <p className={clsx('text-xl font-bold', avgScore !== null ? scoreColor(avgScore) : 'text-text-muted')}>
 {avgScore !== null ? `${avgScore.toFixed(0)}%` : '\u2014'}
 </p>
 <p className="text-xs text-text-muted">{t('softwareCompliance.avgScore')}</p>
 </div>
 </div>
 </div>
 <div className="p-4 bg-bg-secondary rounded-xl flex items-center gap-3">
 <div className="p-2 rounded-lg bg-green-400/10"><CheckCircle className="w-4 h-4 text-green-400" /></div>
 <div>
 <p className="text-xl font-bold text-text-primary">{passingCount}</p>
 <p className="text-xs text-text-muted">{t('softwareCompliance.passing')}</p>
 </div>
 </div>
 <div className="p-4 bg-bg-secondary rounded-xl flex items-center gap-3">
 <div className="p-2 rounded-lg bg-yellow-400/10"><AlertTriangle className="w-4 h-4 text-yellow-400" /></div>
 <div>
 <p className="text-xl font-bold text-text-primary">{warningCount}</p>
 <p className="text-xs text-text-muted">{t('softwareCompliance.warning')}</p>
 </div>
 </div>
 <div className="p-4 bg-bg-secondary rounded-xl flex items-center gap-3">
 <div className="p-2 rounded-lg bg-red-400/10"><XCircle className="w-4 h-4 text-red-400" /></div>
 <div>
 <p className="text-xl font-bold text-text-primary">{failingCount}</p>
 <p className="text-xs text-text-muted">{t('softwareCompliance.failing')}</p>
 </div>
 </div>
 </div>

 {/* Tabs + filter */}
 <div className="flex items-center justify-between gap-4 flex-wrap">
 <SegmentedTabs<Tab>
 tabs={[
 { id: 'results', label: t('softwareCompliance.tabResults', 'Results') },
 { id: 'lists', label: t('softwareCompliance.tabLists', 'Lists') },
 { id: 'history', label: t('softwareCompliance.tabHistory', 'History') },
 { id: 'repository', label: t('softwareCompliance.tabRepository', 'Repository') },
 ]}
 value={activeTab}
 onChange={setActiveTab}
 className="max-w-full"
 />
 <div className="flex items-center gap-2 flex-wrap min-w-0 max-w-full">
 {activeTab === 'results' && (
 <DeviceFilterSelect
 devices={devices}
 value={filterDeviceId}
 onChange={setFilterDeviceId}
 allLabel={t('softwareCompliance.allDevices')}
 />
 )}
 {/* The page is only ever mounted embedded, where the header (and its
 refresh button) is hidden. */}
 {embedded && refreshButton}
 </div>
 </div>

 {/* ── Results tab ── */}
 {activeTab === 'results' && (
 <div className="space-y-3">
 {isLoading ? (
 <div className="flex items-center justify-center h-48">
 <RefreshCw className="w-5 h-5 animate-spin text-text-muted" />
 </div>
 ) : results.length === 0 ? (
 <div className="p-12 text-center text-text-muted bg-bg-secondary rounded-xl">
 <ShieldCheck className="w-10 h-10 mx-auto mb-3 opacity-50" />
 <p className="font-medium text-text-primary mb-1">{t('softwareCompliance.noResults')}</p>
 <p className="text-sm">{t('softwareCompliance.noResultsDesc')}</p>
 </div>
 ) : results.map((result) => {
 const expanded = expandedResultId === result.id;
 const ScoreIcon = scoreIcon(result.complianceScore);
 const compliantCount = result.results.filter(r => r.status === 'compliant').length;
 const nonCompliantCount = result.results.filter(r => r.status === 'non_compliant').length;
 const total = result.results.length;

 return (
 <div key={result.id} className="bg-bg-secondary rounded-xl overflow-hidden">
 <div
 className="flex items-center gap-3 sm:gap-4 px-4 py-3 cursor-pointer hover:bg-bg-tertiary transition-colors max-sm:flex-wrap max-sm:gap-y-2"
 onClick={() => setExpandedResultId(expanded ? null : result.id)}
 >
 <div className={clsx('p-2 rounded-lg', result.complianceScore >= 80 ? 'bg-green-400/10' : result.complianceScore >= 50 ? 'bg-yellow-400/10' : 'bg-red-400/10')}>
 <ScoreIcon className={clsx('w-4 h-4', scoreColor(result.complianceScore))} />
 </div>
 <div className="flex-1 min-w-0">
 <div className="flex items-center gap-2 flex-wrap">
 <div className="flex items-center gap-1.5">
 <Monitor className="w-3.5 h-3.5 text-text-muted shrink-0" />
 <span className="text-sm font-medium text-text-primary break-all">
 {result.deviceName ?? t('softwareCompliance.deviceId', { id: result.deviceId })}
 </span>
 </div>
 {result.list && (
 <>
 <span className={clsx(
 'text-xs px-2 py-0.5 rounded-full border font-medium',
 result.list.listType === 'whitelist'
 ? 'text-green-400 bg-green-400/10 border-green-400/30'
 : 'text-red-400 bg-red-400/10 border-red-400/30',
 )}>
 {result.list.listType}
 </span>
 <span className="text-xs px-2 py-0.5 bg-bg-tertiary rounded-full text-text-muted">
 {result.list.name}
 </span>
 </>
 )}
 </div>
 <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1">
 <div className="flex-1 max-w-48 min-w-[3rem] h-1.5 bg-bg-tertiary rounded-full overflow-hidden">
 <div
 className={clsx('h-full rounded-full transition-all', scoreBg(result.complianceScore))}
 style={{ width: `${result.complianceScore}%` }}
 />
 </div>
 <span className={clsx('text-sm font-bold', scoreColor(result.complianceScore))}>
 {result.complianceScore.toFixed(0)}%
 </span>
 <span className="text-xs text-text-muted">
 {t('softwareCompliance.compliantCount', { count: compliantCount, total, defaultValue: '{{count}}/{{total}} compliant' })}
 </span>
 {/* The date column is hidden below sm — keep it on the stats line there. */}
 <span className="text-xs text-text-muted sm:hidden">
 {new Date(result.checkedAt).toLocaleDateString()}
 </span>
 </div>
 </div>
 {/* Below sm the actions take their own line under the device name. */}
 <div className="flex items-center gap-2 shrink-0 max-sm:basis-full max-sm:justify-end">
 <span className="text-xs text-text-muted hidden sm:block">
 {new Date(result.checkedAt).toLocaleDateString()}
 </span>
 {nonCompliantCount > 0 && (
 <button
 onClick={(e) => { e.stopPropagation(); handleRemediateAll(result); }}
 className="flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-lg bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 transition-colors coarse:min-h-10"
 title={t('softwareCompliance.fixAll')}
 >
 <Wrench className="w-3 h-3" />
 {t('softwareCompliance.fixAll')}
 </button>
 )}
 <IconButton
 label={t('softwareCompliance.rerun')}
 icon={<>
 <RefreshCw className="w-3.5 h-3.5" />
 {/* Touch: visible label (the meaning was only in a hover tooltip). */}
 <span className="hidden coarse:inline text-xs">{t('softwareCompliance.rerun')}</span>
 </>}
 variant="accent"
 onClick={(e) => { e.stopPropagation(); handleTriggerCheck(result.deviceId, result.listId); }}
 className="hover:bg-bg-tertiary gap-1 coarse:px-2.5"
 />
 {expanded ? <ChevronUp className="w-4 h-4 text-text-muted" /> : <ChevronDown className="w-4 h-4 text-text-muted" />}
 </div>
 </div>

 {expanded && result.results.length > 0 && (() => {
 const nonCompliant = result.results.filter(er => er.status === 'non_compliant');
 return (
 <div className=" bg-bg-tertiary/50">
 {nonCompliant.length > 0 && (
 <div className="flex items-center gap-2 px-4 py-2 bg-bg-tertiary/80">
 <button
 onClick={(e) => { e.stopPropagation(); handleRemediateAll(result); }}
 className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 transition-colors coarse:min-h-10"
 >
 <Wrench className="w-3.5 h-3.5" />
 {t('softwareCompliance.remediateAllCount', { count: nonCompliant.length })}
 </button>
 </div>
 )}
 <div className="divide-y divide-border">
 {result.results.map((er) => {
 const isRemediating = remediatingEntries.has(`${result.deviceId}:${result.listId}:${er.entryId}`);
 return (
 <div key={er.entryId} className="flex items-start gap-3 px-4 py-2.5 max-sm:flex-wrap">
 <div className="shrink-0 mt-0.5">
 {entryStatusIcon(er.status)}
 </div>
 <div className="flex-1 min-w-0">
 <p className="text-xs font-medium text-text-primary">
 {er.entryName}
 </p>
 {er.matchedSoftware && (
 <p className="text-xs text-text-muted mt-0.5">
 {t('softwareCompliance.matched')}: <span className="font-mono break-all">{er.matchedSoftware}</span>
 {er.matchedVersion && <span className="ml-1">v{er.matchedVersion}</span>}
 </p>
 )}
 {er.detail && (
 <p className="text-xs text-text-muted/60 mt-0.5">{er.detail}</p>
 )}
 <AlternativeResultInfo er={er} />
 </div>
 {/* Below sm the status / action cluster takes its own line. */}
 <div className="flex items-center gap-1.5 shrink-0 max-sm:basis-full max-sm:justify-end">
 {er.remediationTriggered && (
 <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
 {t('softwareCompliance.remediatedBadge')}
 </span>
 )}
 <span className={clsx('text-xs font-medium', entryStatusColor(er.status))}>
 {er.status.replace('_', ' ')}
 </span>
 {er.status === 'non_compliant' && (
 <IconButton
 label={t('softwareCompliance.remediate')}
 onClick={(e) => { e.stopPropagation(); handleRemediate(result.deviceId, result.listId, [er.entryId]); }}
 disabled={isRemediating}
 size="sm"
 variant="primary"
 className="gap-1 disabled:opacity-50 coarse:px-2.5"
 icon={<>
 <Wrench className={clsx('w-3.5 h-3.5', isRemediating && 'animate-spin')} />
 {/* Touch: visible label (the meaning was only in a hover tooltip). */}
 <span className="hidden coarse:inline text-xs">{t('softwareCompliance.remediate')}</span>
 </>}
 />
 )}
 </div>
 </div>
 );
 })}
 </div>
 </div>
 );
 })()}
 </div>
 );
 })}
 </div>
 )}

 {/* ── History tab ── */}
 {activeTab === 'history' && (
 <SoftwareHistoryTab />
 )}

 {/* ── Lists tab ── */}
 {activeTab === 'lists' && (
 <div className="space-y-4">
 {/* List form */}
 {showForm && (
 <div className="bg-bg-secondary rounded-xl p-4 sm:p-6 space-y-4">
 <div className="flex flex-wrap items-center justify-between gap-2">
 <h2 className="text-lg font-semibold text-text-primary">
 {editingList ? t('softwareCompliance.editList') : t('softwareCompliance.newList')}
 </h2>
 <div className="flex gap-2">
 <button
 onClick={() => { setShowForm(false); setEditingList(null); }}
 className="px-4 py-2 text-sm text-text-muted hover:text-text-primary rounded-lg transition-colors"
 >
 {t('common.cancel')}
 </button>
 <button
 onClick={handleSave}
 disabled={isSaving}
 className="px-4 py-2 text-sm bg-accent text-white rounded-lg hover:bg-accent/80 disabled:opacity-50 transition-colors"
 >
 {isSaving ? t('common.saving') : t('common.save')}
 </button>
 </div>
 </div>

 {/* Basic fields */}
 <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
 <div className="space-y-1">
 <label className="text-xs font-medium text-text-muted uppercase">{t('softwareCompliance.listName')} *</label>
 <input
 value={form.name}
 onChange={(e) => setForm({ ...form, name: e.target.value })}
 placeholder={t('softwareCompliance.listNamePlaceholder')}
 className="w-full px-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary focus:outline-none focus:border-accent"
 />
 </div>
 <div className="space-y-1">
 <label className="text-xs font-medium text-text-muted uppercase">{t('softwareCompliance.listTypeLabel')}</label>
 <div className="flex gap-2">
 {(['whitelist', 'blacklist'] as SoftwareListType[]).map((lt) => (
 <button
 key={lt}
 type="button"
 onClick={() => setForm({ ...form, listType: lt })}
 className={clsx(
 'flex-1 py-2 text-sm rounded-lg border transition-colors',
 form.listType === lt
 ? lt === 'whitelist' ? 'bg-green-400/10 border-green-400 text-green-400' : 'bg-red-400/10 border-red-400 text-red-400'
 : 'border-transparent text-text-muted hover:border-accent/50',
 )}
 >
 {t(`softwareCompliance.types.${lt}`)}
 </button>
 ))}
 </div>
 </div>
 <div className="space-y-1">
 <label className="text-xs font-medium text-text-muted uppercase">{t('softwareCompliance.targetLabel')}</label>
 <div className="flex gap-2">
 {(['all', 'group'] as const).map((tt) => (
 <button
 key={tt}
 type="button"
 onClick={() => setForm({ ...form, targetType: tt, targetIds: [], targetManualGroupIds: [] })}
 className={clsx(
 'flex-1 py-2 text-sm rounded-lg border transition-colors',
 form.targetType === tt ? 'bg-accent/10 border-accent text-accent' : 'border-transparent text-text-muted hover:border-accent/50',
 )}
 >
 {tt === 'all' ? t('softwareCompliance.allDevices') : t('softwareCompliance.deviceGroup')}
 </button>
 ))}
 </div>
 </div>
 <div className="space-y-1">
 <label className="text-xs font-medium text-text-muted uppercase">{t('softwareCompliance.platform')}</label>
 <div className="flex flex-wrap gap-1">
 {PLATFORMS.map((p) => (
 <button
 key={p}
 type="button"
 onClick={() => setForm({
 ...form,
 targetPlatform: p,
 // Bounds of another OS mean nothing here: start over on a change.
 osCondition: p === 'all' ? null : (form.osCondition?.platform === p ? form.osCondition : emptyOsCondition(p)),
 })}
 className={clsx(
 'flex-1 py-2 text-xs rounded-lg border transition-colors',
 form.targetPlatform === p ? 'bg-accent/10 border-accent text-accent' : 'border-transparent text-text-muted hover:border-accent/50',
 )}
 >
 {p === 'all' ? t('common.all') : p === 'macos' ? 'macOS' : p === 'freebsd' ? 'FreeBSD' : p.charAt(0).toUpperCase() + p.slice(1)}
 </button>
 ))}
 </div>
 </div>
 {form.targetPlatform !== 'all' && form.osCondition && (
 <div className="space-y-1.5 md:col-span-2 p-3 rounded-lg bg-bg-tertiary/40">
 <div className="flex flex-wrap items-center justify-between gap-2">
 <label className="text-xs font-medium text-text-muted uppercase flex items-center gap-1.5">
 <Cpu className="w-3.5 h-3.5" />
 {t('softwareCompliance.osCond.versions') || 'Versions'}
 <span className="normal-case font-normal text-text-muted/80">· {platformLabel(form.targetPlatform)}</span>
 </label>
 <span className="text-[11px] text-text-muted">{t('softwareCompliance.osCond.inclusive') || 'Bounds included'}</span>
 </div>
 <OsVersionFields
 variant="list"
 value={form.osCondition}
 onChange={c => setForm(f => ({ ...f, osCondition: c }))}
 />
 <p className="text-[11px] text-text-muted">
 {t('softwareCompliance.osCond.listHint') || 'Devices outside these versions are not evaluated by the list (not counted as non-compliant).'}
 </p>
 </div>
 )}
 <div className="space-y-1 md:col-span-2">
 <label className="text-xs font-medium text-text-muted uppercase">{t('softwareCompliance.descriptionLabel')}</label>
 <textarea
 value={form.description}
 onChange={(e) => setForm({ ...form, description: e.target.value })}
 rows={2}
 className="w-full px-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary focus:outline-none focus:border-accent resize-y"
 />
 </div>
 {form.targetType === 'group' && (
 <div className="space-y-1 md:col-span-2">
 <label className="text-xs font-medium text-text-muted uppercase">{t('softwareCompliance.groups')}</label>
 <GroupTreeMultiSelect
 value={{ targetIds: form.targetIds, targetManualGroupIds: form.targetManualGroupIds }}
 onChange={(v) => setForm((f) => ({ ...f, ...v }))}
 />
 </div>
 )}
 </div>

 {/* Entries builder — card-based */}
 <div className=" pt-4 space-y-3">
 <div className="flex flex-wrap items-center justify-between gap-2">
 <h3 className="text-sm font-semibold text-text-primary">
 {t('softwareCompliance.entries')} <span className="text-text-muted font-normal">({form.entries.length})</span>
 </h3>
 <div className="relative" ref={addMenuRef}>
 <button
 onClick={() => setShowAddMenu(!showAddMenu)}
 aria-expanded={showAddMenu}
 className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-accent text-white rounded-lg hover:bg-accent/80 transition-colors coarse:min-h-10"
 >
 <Plus className="w-3.5 h-3.5" />
 {t('softwareCompliance.addApp')}
 <ChevronDown className="w-3 h-3" />
 </button>
 {showAddMenu && (
 <div className="absolute right-0 mt-1 w-48 bg-bg-primary rounded-lg shadow-xl z-30 overflow-hidden">
 <button
 onClick={() => { addEntry(); setShowAddMenu(false); }}
 className="w-full flex items-center gap-2 px-3 py-2.5 text-sm text-text-primary hover:bg-bg-secondary transition-colors text-left"
 >
 <Plus className="w-3.5 h-3.5 text-text-muted" />
 {t('softwareCompliance.customApp')}
 </button>
 <button
 onClick={() => { setInventoryTarget(null); setShowKnownApps(true); setShowAddMenu(false); }}
 className="w-full flex items-center gap-2 px-3 py-2.5 text-sm text-text-primary hover:bg-bg-secondary transition-colors text-left "
 >
 <Package className="w-3.5 h-3.5 text-text-muted" />
 {t('softwareCompliance.fromInventory')}
 </button>
 </div>
 )}
 </div>
 </div>

 {form.entries.length === 0 ? (
 <p className="text-sm text-text-muted text-center py-8 bg-bg-tertiary/30 rounded-lg border border-dashed border-transparent">
 {t('softwareCompliance.noEntries')}
 </p>
 ) : (
 <div className="space-y-2">
 {form.entries.map((entry, i) => (
 <EntryEditorCard
 key={i}
 entry={entry}
 index={i}
 total={form.entries.length}
 onChange={e => updateEntry(i, e)}
 onDelete={() => deleteEntry(i)}
 onMoveUp={() => moveEntry(i, -1)}
 onMoveDown={() => moveEntry(i, 1)}
 isBlacklist={form.listType === 'blacklist'}
 defaultPlatform={defaultAltPlatform}
 onPickFromInventory={() => { setInventoryTarget(i); setShowKnownApps(true); }}
 />
 ))}
 </div>
 )}
 </div>

 {/* Known Apps Modal */}
 <KnownAppsModal
 open={showKnownApps}
 onClose={() => setShowKnownApps(false)}
 onSelect={addEntryFromApp}
 platform={form.targetPlatform}
 />

 <div className="flex flex-wrap gap-4 pt-2 ">
 <label className="flex items-center gap-2 cursor-pointer">
 <input
 type="checkbox"
 checked={form.enabled}
 onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
 className="rounded"
 />
 <span className="text-sm text-text-primary">{t('softwareCompliance.listEnabledLabel')}</span>
 </label>
 <label className="flex items-center gap-2 cursor-pointer">
 <input
 type="checkbox"
 checked={form.autoRemediate}
 onChange={(e) => setForm({ ...form, autoRemediate: e.target.checked })}
 className="rounded"
 />
 <span className="text-sm text-text-primary">{t('softwareCompliance.autoRemediateLabel')}</span>
 </label>
 </div>
 </div>
 )}

 <div className="flex justify-end">
 <button
 onClick={handleOpenCreate}
 className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg hover:bg-accent/80 text-sm transition-colors"
 >
 <Plus className="w-4 h-4" />
 {t('softwareCompliance.newList')}
 </button>
 </div>

 {isLoading ? (
 <div className="flex items-center justify-center h-48">
 <RefreshCw className="w-5 h-5 animate-spin text-text-muted" />
 </div>
 ) : lists.length === 0 ? (
 <div className="p-12 text-center text-text-muted bg-bg-secondary rounded-xl">
 <ShieldCheck className="w-10 h-10 mx-auto mb-3 opacity-50" />
 <p className="font-medium text-text-primary mb-1">{t('softwareCompliance.noLists')}</p>
 <p className="text-sm">{t('softwareCompliance.noListsDesc')}</p>
 </div>
 ) : (
 <div className="space-y-3">
 {lists.map((list) => (
 <div key={list.id} className="p-4 bg-bg-secondary rounded-xl">
 <div className="flex items-start justify-between gap-4">
 <div className="flex-1 min-w-0">
 <div className="flex items-center gap-2 flex-wrap">
 <span className="text-sm font-medium text-text-primary">{list.name}</span>
 <span className={clsx(
 'text-xs px-2 py-0.5 rounded-full border font-medium',
 list.listType === 'whitelist'
 ? 'text-green-400 bg-green-400/10 border-green-400/30'
 : 'text-red-400 bg-red-400/10 border-red-400/30',
 )}>
 {list.listType}
 </span>
 {list.targetPlatform !== 'all' && (
 <span className="text-xs px-1.5 py-0.5 rounded bg-bg-tertiary border border-transparent">
 {platformLabel(list.targetPlatform)}
 {describeOsCondition(list.osCondition, t) && (
 <span className="text-text-muted"> · {describeOsCondition(list.osCondition, t)}</span>
 )}
 </span>
 )}
 <span className={clsx('text-xs px-2 py-0.5 rounded-full border font-medium',
 list.enabled ? 'text-green-400 bg-green-400/10 border-green-400/30' : 'text-gray-400 bg-gray-400/10 border-gray-400/30')}>
 {list.enabled ? t('softwareCompliance.enabled') : t('softwareCompliance.disabled')}
 </span>
 {list.autoRemediate && (
 <span className="text-xs px-2 py-0.5 rounded-full bg-blue-400/10 text-blue-400 border border-blue-400/30 font-medium">
 {t('softwareCompliance.autoRemediate')}
 </span>
 )}
 </div>
 {list.description && (
 <p className="text-xs text-text-muted mt-1">{list.description}</p>
 )}
 <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1.5 text-xs text-text-muted">
 <span>{t('softwareCompliance.target')}: <span className="text-text-primary">
 {list.targetType === 'all' ? t('softwareCompliance.allDevices') : t('compliance.groupCount', { count: countGroupTargets({ targetIds: list.targetIds ?? [], targetManualGroupIds: list.targetManualGroupIds ?? [] }, groupIndex), defaultValue: '{{count}} group(s)' })}
 </span></span>
 <span>{t('softwareCompliance.entries')}: <span className="text-text-primary">{list.entries?.length ?? 0}</span></span>
 {(list.entries ?? []).some(e => (e.alternatives?.length ?? 1) > 1) && (
 <span className="flex items-center gap-1">
 <Layers className="w-3 h-3" />
 {t('softwareCompliance.alt.entriesWithAlternatives', { count: (list.entries ?? []).filter(e => (e.alternatives?.length ?? 1) > 1).length }) || 'with alternatives'}
 </span>
 )}
 <span>{t('softwareCompliance.created')}: <span className="text-text-primary">{new Date(list.createdAt).toLocaleDateString()}</span></span>
 </div>
 </div>
 <div className="flex gap-1 shrink-0">
 {/* md+: the icon buttons. Phone: the same actions, labelled, in a "⋯" menu. */}
 <IconButton
 label={t('softwareCompliance.scanNow', 'Scan now on all targets')}
 icon={<RefreshCw className="w-4 h-4" />}
 variant="accent"
 onClick={() => handleScanList(list)}
 disabled={!list.enabled}
 className="max-md:hidden disabled:hover:text-text-muted"
 />
 <IconButton
 label={list.enabled ? t('softwareCompliance.disable') : t('softwareCompliance.enable')}
 icon={list.enabled
 ? <ToggleRight className="w-5 h-5 text-accent" />
 : <ToggleLeft className="w-5 h-5 text-text-muted" />}
 onClick={() => handleToggleEnabled(list)}
 className="max-md:hidden hover:bg-bg-tertiary"
 />
 <IconButton
 label={t('common.edit')}
 icon={<Edit className="w-4 h-4" />}
 onClick={() => handleOpenEdit(list)}
 className="max-md:hidden hover:bg-bg-tertiary"
 />
 <IconButton
 label={t('softwareCompliance.duplicate') || 'Duplicate'}
 icon={<Copy className="w-4 h-4" />}
 onClick={() => handleDuplicate(list)}
 className="max-md:hidden hover:bg-bg-tertiary"
 />
 <IconButton
 label={t('common.delete')}
 icon={<Trash2 className="w-4 h-4" />}
 variant="danger"
 onClick={() => handleDelete(list.id)}
 className="max-md:hidden"
 />
 <ActionMenu
 triggerClassName="md:hidden"
 sheetTitle={list.name}
 items={[
 { key: 'scan', icon: <RefreshCw className="w-4 h-4" />, label: t('softwareCompliance.scanNow', 'Scan now on all targets'), onClick: () => handleScanList(list), disabled: !list.enabled },
 { key: 'toggle', icon: list.enabled ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />, label: list.enabled ? t('softwareCompliance.disable') : t('softwareCompliance.enable'), onClick: () => handleToggleEnabled(list) },
 { key: 'edit', icon: <Edit className="w-4 h-4" />, label: t('common.edit'), onClick: () => handleOpenEdit(list) },
 { key: 'duplicate', icon: <Copy className="w-4 h-4" />, label: t('softwareCompliance.duplicate') || 'Duplicate', onClick: () => handleDuplicate(list) },
 { key: 'delete', icon: <Trash2 className="w-4 h-4" />, label: t('common.delete'), onClick: () => handleDelete(list.id), danger: true, separator: true },
 ]}
 />
 </div>
 </div>
 </div>
 ))}
 </div>
 )}
 </div>
 )}

 {/* ── Repository tab ───────────────────────────────────────────────── */}
 {activeTab === 'repository' && <RepoTab />}
 </PageContainer>
 );
}

// ── Repository helpers ──────────────────────────────────────────────────────

function formatBytes(n: number): string {
 if (n < 1024) return `${n} B`;
 const units = ['KB', 'MB', 'GB', 'TB'];
 let v = n / 1024, i = 0;
 while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
 return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Build a copy-paste ready download snippet for a package. The access key is
 *  never embedded — the user fills the placeholder once. */
function downloadSnippet(kind: 'ps' | 'sh', pkg: SoftwareRepoPackage): string {
 const origin = window.location.origin;
 const url = `${origin}/api/repo/download/${pkg.uuid}`;
 const name = pkg.filename;
 if (kind === 'ps') {
 return [
 '$RepoKey = "<VOTRE_CLE_DEPOT>"',
 `Invoke-WebRequest -Uri "${url}" \``,
 `  -Headers @{ 'X-Repo-Key' = $RepoKey } -OutFile "$env:TEMP\\${name}" -UseBasicParsing`,
 ].join('\n');
 }
 return [
 'REPO_KEY="<VOTRE_CLE_DEPOT>"',
 `curl -fSL -H "X-Repo-Key: $REPO_KEY" "${url}" -o "/tmp/${name}"`,
 ].join('\n');
}

/** Copy with the shared helper (Clipboard API → execCommand → native bridge). */
async function copyToClipboard(text: string, okMsg: string, failMsg: string) {
 if (await copyText(text)) toast.success(okMsg);
 else toast.error(failMsg);
}

/** Accept list for the package picker. Extensions alone make the Android
 * picker intent filter out everything, so on touch devices MIME types are
 * added (desktop keeps the extension-only filter). */
const PACKAGE_ACCEPT = '.msi,.exe,.deb,.rpm,.pkg,.dmg';
const PACKAGE_ACCEPT_TOUCH = [
 PACKAGE_ACCEPT,
 'application/x-msi', 'application/x-ms-installer', 'application/x-msdownload',
 'application/vnd.microsoft.portable-executable', 'application/x-dosexec',
 'application/vnd.debian.binary-package', 'application/x-debian-package',
 'application/x-rpm', 'application/x-redhat-package-manager',
 'application/x-newton-compatible-pkg', 'application/vnd.apple.installer+xml',
 'application/x-apple-diskimage', 'application/octet-stream',
].join(',');

// ── Repository Tab Component ────────────────────────────────────────────────
function RepoTab() {
 const { t } = useTranslation();
 const confirm = useConfirm();
 const prompt = usePrompt();
 const coarse = useIsCoarsePointer();
 const { isAdmin } = useAuthStore();
 const [packages, setPackages] = useState<SoftwareRepoPackage[]>([]);
 const [settings, setSettings] = useState<SoftwareRepoSettings | null>(null);
 const [loading, setLoading] = useState(true);
 const [uploading, setUploading] = useState(false);
 const [dragOver, setDragOver] = useState(false);
 const [uploadPlatform, setUploadPlatform] = useState<'windows' | 'linux' | 'macos'>('windows');
 const [revealedKey, setRevealedKey] = useState<string | null>(null);
 const [snippetFor, setSnippetFor] = useState<{ uuid: string; kind: 'ps' | 'sh' } | null>(null);
 const fileInputRef = useRef<HTMLInputElement>(null);

 const load = useCallback(async () => {
 setLoading(true);
 try {
 const [pkgs, s] = await Promise.all([softwareRepoApi.list(), softwareRepoApi.getSettings()]);
 setPackages(pkgs);
 setSettings(s);
 } catch { toast.error(t('softwareCompliance.repoLoadFailed') || 'Failed to load repository'); }
 finally { setLoading(false); }
 }, [t]);

 useEffect(() => { load(); }, [load]);

 const enabled = settings?.enabled !== false;
 const quotaBytes = settings?.quotaBytes ?? null;
 const usedBytes = settings?.usedBytes ?? 0;
 const quotaFull = quotaBytes != null && usedBytes >= quotaBytes;
 const usagePct = quotaBytes && quotaBytes > 0 ? Math.min(100, (usedBytes / quotaBytes) * 100) : 0;

 const handleUpload = async (file: File) => {
 setUploading(true);
 try {
 await softwareRepoApi.upload(file, uploadPlatform);
 toast.success(t('softwareCompliance.packageUploaded'));
 await load();
 } catch (err: any) {
 toast.error(err?.response?.data?.error || t('softwareCompliance.uploadFailed') || 'Upload failed');
 } finally { setUploading(false); }
 };

 const handleDrop = (e: React.DragEvent) => {
 e.preventDefault(); setDragOver(false);
 if (!enabled || quotaFull) return;
 const file = e.dataTransfer.files[0];
 if (file) handleUpload(file);
 };

 const handleDelete = async (id: number) => {
 if (!(await confirm({ message: t('softwareCompliance.confirmDeletePackage'), danger: true }))) return;
 try {
 await softwareRepoApi.delete(id);
 toast.success(t('softwareCompliance.packageDeleted'));
 await load();
 } catch { toast.error(t('common.error')); }
 };

 const handleToggleEnabled = async () => {
 try {
 const s = await softwareRepoApi.updateSettings({ enabled: !enabled });
 setSettings(s);
 toast.success(s.enabled ? (t('softwareCompliance.repoEnabled') || 'Repository enabled') : (t('softwareCompliance.repoDisabled') || 'Repository disabled'));
 } catch { toast.error(t('common.error')); }
 };

 const handleSetQuota = async () => {
 const current = quotaBytes != null ? String(Math.round(quotaBytes / 1024 / 1024)) : '';
 const input = await prompt({
 message: t('softwareCompliance.quotaPrompt', 'Storage quota in MB (empty = unlimited):'),
 defaultValue: current,
 inputType: 'number',
 confirmLabel: t('common.save'),
 });
 if (input === null) return;
 const trimmed = input.trim();
 const mb = trimmed === '' ? null : parseInt(trimmed, 10);
 if (mb !== null && (!Number.isFinite(mb) || mb < 0)) { toast.error(t('softwareCompliance.quotaInvalid') || 'Invalid quota'); return; }
 try {
 const s = await softwareRepoApi.updateSettings({ quotaBytes: mb === null ? null : mb * 1024 * 1024 });
 setSettings(s);
 toast.success(t('softwareCompliance.quotaSaved') || 'Quota saved');
 } catch { toast.error(t('common.error')); }
 };

 const handleGenerateKey = async () => {
 if (settings?.hasKey && !(await confirm({
 message: t('softwareCompliance.regenKeyConfirm', 'Replace the existing access key? Scripts using the old key will stop working.'),
 confirmLabel: t('softwareCompliance.regenKey', 'Regenerate'),
 danger: true,
 }))) return;
 try {
 const { key } = await softwareRepoApi.generateAccessKey();
 setRevealedKey(key);
 await load();
 toast.success(t('softwareCompliance.keyGenerated') || 'Access key generated');
 } catch { toast.error(t('common.error')); }
 };

 const handleRevokeKey = async () => {
 if (!(await confirm({
 message: t('softwareCompliance.revokeKeyConfirm', 'Revoke the access key? Scripts using it will stop working.'),
 confirmLabel: t('softwareCompliance.revokeKey', 'Revoke'),
 danger: true,
 }))) return;
 try {
 await softwareRepoApi.revokeAccessKey();
 setRevealedKey(null);
 await load();
 toast.success(t('softwareCompliance.keyRevoked') || 'Access key revoked');
 } catch { toast.error(t('common.error')); }
 };

 const platformLabel = (p: string) => p === 'windows' ? 'Windows' : p === 'linux' ? 'Linux' : p === 'macos' ? 'macOS' : p;

 return (
 <div className="space-y-4">
 {/* ── Depot status: usage / quota / enable toggle ── */}
 <div className="bg-bg-secondary rounded-xl p-4 space-y-3">
 <div className="flex items-center justify-between gap-3 flex-wrap">
 <div className="flex items-center gap-2">
 <HardDrive className="w-4 h-4 text-accent" />
 <span className="text-sm font-semibold text-text-primary">{t('softwareCompliance.repoStorage') || 'Repository storage'}</span>
 {!enabled && (
 <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-400/10 text-red-400 border border-red-400/30 font-medium">
 {t('softwareCompliance.disabled')}
 </span>
 )}
 </div>
 {isAdmin() && (
 <div className="flex items-center gap-1">
 <button
 onClick={handleSetQuota}
 className="text-xs px-2 py-1 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary transition-colors coarse:min-h-10"
 title={t('softwareCompliance.setQuota') || 'Set quota'}
 >
 {t('softwareCompliance.setQuota') || 'Set quota'}
 </button>
 <IconButton
 label={enabled ? (t('softwareCompliance.disable')) : (t('softwareCompliance.enable'))}
 icon={enabled ? <ToggleRight className="w-5 h-5 text-accent" /> : <ToggleLeft className="w-5 h-5 text-text-muted" />}
 onClick={handleToggleEnabled}
 className="hover:bg-bg-tertiary"
 />
 </div>
 )}
 </div>
 {/* Usage bar */}
 <div>
 <div className="flex items-center justify-between text-xs mb-1">
 <span className="text-text-muted">
 {formatBytes(usedBytes)}{quotaBytes != null ? ` / ${formatBytes(quotaBytes)}` : ` — ${t('softwareCompliance.unlimited') || 'unlimited'}`}
 <span className="ml-2 text-text-muted/70">({settings?.packageCount ?? packages.length} {t('softwareCompliance.packages') || 'packages'})</span>
 </span>
 {quotaBytes != null && <span className={clsx('font-medium', quotaFull ? 'text-red-400' : usagePct > 80 ? 'text-yellow-400' : 'text-text-muted')}>{usagePct.toFixed(0)}%</span>}
 </div>
 {quotaBytes != null && (
 <div className="h-1.5 bg-bg-tertiary rounded-full overflow-hidden">
 <div className={clsx('h-full rounded-full transition-all', quotaFull ? 'bg-red-400' : usagePct > 80 ? 'bg-yellow-400' : 'bg-accent')} style={{ width: `${usagePct}%` }} />
 </div>
 )}
 </div>
 </div>

 {/* ── Script access key ── */}
 {isAdmin() && (
 <div className="bg-bg-secondary rounded-xl p-4 space-y-2">
 <div className="flex items-center justify-between gap-3 flex-wrap">
 <div className="flex items-center gap-2">
 <KeyRound className="w-4 h-4 text-accent" />
 <span className="text-sm font-semibold text-text-primary">{t('softwareCompliance.accessKey') || 'Script access key'}</span>
 </div>
 <div className="flex items-center gap-1">
 <button
 onClick={handleGenerateKey}
 className="text-xs px-2.5 py-1 rounded-lg bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 transition-colors coarse:min-h-10"
 >
 {settings?.hasKey ? (t('softwareCompliance.regenKey') || 'Regenerate') : (t('softwareCompliance.generateKey') || 'Generate key')}
 </button>
 {settings?.hasKey && (
 <IconButton
 label={t('softwareCompliance.revokeKey', 'Revoke')}
 icon={<Ban className="w-4 h-4" />}
 variant="danger"
 onClick={handleRevokeKey}
 />
 )}
 </div>
 </div>
 <p className="text-xs text-text-muted">{t('softwareCompliance.accessKeyHint') || 'Scripts authenticate with this key to download packages (header X-Repo-Key). One key per tenant.'}</p>
 {revealedKey ? (
 <div className="flex items-center gap-2 px-3 py-2 bg-bg-tertiary rounded-lg">
 {/* select-all: one tap selects the whole key if the copy fails (shown once). */}
 <code className="flex-1 min-w-0 text-xs font-mono text-green-400 break-all select-all">{revealedKey}</code>
 <IconButton
 label={t('common.copy', 'Copy')}
 onClick={() => copyToClipboard(revealedKey, t('common.copied') || 'Copied', t('softwareCompliance.keyCopyFailed', 'Copy failed — select the key and copy it manually, it is only shown once.'))}
 size="sm"
 variant="plain"
 className="shrink-0 gap-1 coarse:px-3 coarse:bg-bg-secondary"
 icon={<>
 <Copy className="w-3.5 h-3.5" />
 <span className="hidden coarse:inline text-xs">{t('common.copy', 'Copy')}</span>
 </>}
 />
 </div>
 ) : settings?.hasKey ? (
 <div className="flex items-center gap-2 text-xs text-text-muted">
 <code className="font-mono text-text-primary">{settings.keyPrefix}…</code>
 <span className="text-text-muted/70">{t('softwareCompliance.keyHiddenHint') || '(shown once at generation — regenerate if lost)'}</span>
 </div>
 ) : (
 <p className="text-xs text-text-muted italic">{t('softwareCompliance.noKey') || 'No key yet. Generate one to let scripts pull packages.'}</p>
 )}
 </div>
 )}

 {/* Upload area */}
 <div
 className={clsx(
 'border-2 border-dashed rounded-xl p-4 sm:p-8 text-center transition-colors',
 (!enabled || quotaFull) ? 'border-transparent opacity-60' : dragOver ? 'border-accent bg-accent/5' : 'border-transparent hover:border-accent/40',
 )}
 onDragOver={e => { e.preventDefault(); if (enabled && !quotaFull) setDragOver(true); }}
 onDragLeave={() => setDragOver(false)}
 onDrop={handleDrop}
 >
 <Upload className="w-8 h-8 mx-auto mb-2 text-text-muted" />
 {!enabled ? (
 <p className="text-sm text-red-400 font-medium mb-1">{t('softwareCompliance.repoDisabledMsg') || 'The repository is disabled for this tenant.'}</p>
 ) : quotaFull ? (
 <p className="text-sm text-red-400 font-medium mb-1">{t('softwareCompliance.quotaFullMsg') || 'Storage quota reached — delete packages or raise the quota.'}</p>
 ) : (
 <p className="text-sm text-text-primary font-medium mb-1">
 {/* No drag & drop on touch — point at the Browse button instead. */}
 {coarse ? t('softwareCompliance.tapToChoose', 'Tap Browse to choose a package file') : t('softwareCompliance.dragDrop')}
 </p>
 )}
 <p className="text-xs text-text-muted mb-3">.msi, .exe, .deb, .rpm, .pkg, .dmg</p>
 <div className="flex flex-wrap items-center justify-center gap-2">
 <select
 value={uploadPlatform}
 onChange={e => setUploadPlatform(e.target.value as any)}
 aria-label={t('softwareCompliance.platform')}
 className="px-2 py-1.5 text-xs bg-bg-secondary rounded text-text-primary coarse:min-h-10"
 >
 <option value="windows">Windows</option>
 <option value="linux">Linux</option>
 <option value="macos">macOS</option>
 </select>
 <button
 onClick={() => fileInputRef.current?.click()}
 disabled={uploading || !enabled || quotaFull}
 className="px-4 py-1.5 text-xs bg-accent text-white rounded-lg hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed coarse:min-h-10 coarse:px-5 coarse:text-sm"
 >
 {uploading ? t('softwareCompliance.uploading') : t('softwareCompliance.browse')}
 </button>
 <input ref={fileInputRef} type="file" accept={coarse || isAndroidApp() ? PACKAGE_ACCEPT_TOUCH : PACKAGE_ACCEPT} className="hidden"
 onChange={e => { const f = e.target.files?.[0]; if (f) handleUpload(f); e.target.value = ''; }} />
 </div>
 </div>

 {/* Package list */}
 {loading ? (
 <div className="flex justify-center py-8"><RefreshCw className="w-5 h-5 animate-spin text-text-muted" /></div>
 ) : packages.length === 0 ? (
 <div className="text-center py-12 text-text-muted">
 <HardDrive className="w-8 h-8 mx-auto mb-2 opacity-50" />
 <p className="text-sm">{t('softwareCompliance.noPackages')}</p>
 </div>
 ) : (
 <div className="space-y-1">
 {packages.map(pkg => {
 const pi = PLATFORM_ICONS[pkg.platform === 'linux' ? 'debian' : pkg.platform];
 const showSnippet = snippetFor?.uuid === pkg.uuid;
 return (
 <div key={pkg.id} className="bg-bg-secondary rounded-lg overflow-hidden">
 <div className="flex items-center gap-3 px-4 py-3">
 <HardDrive className="w-4 h-4 text-text-muted shrink-0" />
 <div className="flex-1 min-w-0">
 <p className="text-sm font-medium text-text-primary truncate">{pkg.displayName || pkg.filename}</p>
 <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 mt-0.5">
 <span className="text-xs text-text-muted">{formatBytes(pkg.fileSize)}</span>
 {pi && <span className={clsx('text-[9px] px-1 py-0.5 rounded border font-medium', pi.color)}>{platformLabel(pkg.platform)}</span>}
 <span className="text-xs text-text-muted">{new Date(pkg.createdAt).toLocaleDateString()}</span>
 </div>
 </div>
 {/* Copy download command (PS / SH) */}
 <button
 onClick={() => setSnippetFor(showSnippet && snippetFor?.kind === 'ps' ? null : { uuid: pkg.uuid, kind: 'ps' })}
 className={clsx('p-1.5 rounded transition-colors coarse:min-h-10 coarse:min-w-10 coarse:inline-flex coarse:items-center coarse:justify-center', showSnippet && snippetFor?.kind === 'ps' ? 'text-accent bg-accent/10' : 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary')}
 title={t('softwareCompliance.copyPs') || 'PowerShell download command'}
 aria-label={t('softwareCompliance.copyPs') || 'PowerShell download command'}
 aria-pressed={showSnippet && snippetFor?.kind === 'ps'}
 >
 <Terminal className="w-4 h-4" />
 </button>
 <button
 onClick={() => setSnippetFor(showSnippet && snippetFor?.kind === 'sh' ? null : { uuid: pkg.uuid, kind: 'sh' })}
 className={clsx('p-1.5 rounded transition-colors text-[11px] font-mono w-7 h-7 flex items-center justify-center coarse:w-10 coarse:h-10', showSnippet && snippetFor?.kind === 'sh' ? 'text-accent bg-accent/10' : 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary')}
 title={t('softwareCompliance.copySh') || 'Bash download command'}
 aria-label={t('softwareCompliance.copySh') || 'Bash download command'}
 aria-pressed={showSnippet && snippetFor?.kind === 'sh'}
 >
 sh
 </button>
 <IconButton
 label={t('common.delete')}
 icon={<Trash2 className="w-4 h-4" />}
 variant="danger"
 onClick={() => handleDelete(pkg.id)}
 />
 </div>
 {showSnippet && (
 <div className="px-4 pb-3">
 <div className="relative">
 <pre className="text-[11px] text-text-primary font-mono bg-bg-tertiary rounded-lg p-3 pr-10 overflow-x-auto whitespace-pre coarse:pr-14 coarse:whitespace-pre-wrap coarse:break-all">{downloadSnippet(snippetFor!.kind, pkg)}</pre>
 <IconButton
 label={t('common.copy', 'Copy')}
 icon={<Copy className="w-3.5 h-3.5" />}
 size="sm"
 variant="plain"
 onClick={() => copyToClipboard(downloadSnippet(snippetFor!.kind, pkg), t('common.copied') || 'Copied', t('softwareCompliance.copyFailed', 'Copy failed'))}
 className="absolute top-2 right-2 bg-bg-secondary"
 />
 </div>
 {!settings?.hasKey && (
 <p className="text-[10px] text-yellow-400/80 mt-1">{t('softwareCompliance.snippetNeedsKey') || 'Generate an access key above and replace <VOTRE_CLE_DEPOT> in the command.'}</p>
 )}
 </div>
 )}
 </div>
 );
 })}
 </div>
 )}
 </div>
 );
}

// ── History tab — last 10 compliance batches with per-device drill-down ──
// Mirrors the UX of the schedule history in ScriptSchedulesPage: each batch
// is a collapsible card; clicking a device row reveals stdout/stderr.

function SoftwareHistoryTab() {
 const { t } = useTranslation();
 const [batches, setBatches] = useState<SoftwareComplianceHistoryBatch[]>([]);
 const [loading, setLoading] = useState(true);

 const load = useCallback(async (spinner = true) => {
 if (spinner) setLoading(true);
 try {
 const rows = await softwareComplianceApi.history({ limit: 20 });
 setBatches(rows);
 } catch {
 toast.error(t('common.error'));
 } finally {
 if (spinner) setLoading(false);
 }
 }, [t]);

 useEffect(() => { load(); }, [load]);

 return (
 <div className="space-y-4">
 <div className="flex items-center justify-between gap-2">
 <p className="text-xs text-text-muted">{t('softwareCompliance.historyHint', 'Last 20 scan & remediation batches. Click a batch to drill into device results.')}</p>
 <button
 onClick={() => load(true)}
 className="text-xs px-2 py-1 rounded text-text-muted hover:text-text-primary hover:border-accent/40 transition-colors shrink-0 coarse:min-h-10"
 >
 {t('common.refresh', 'Refresh')}
 </button>
 </div>
 {loading ? (
 <div className="flex justify-center py-8"><RefreshCw className="w-5 h-5 animate-spin text-text-muted" /></div>
 ) : batches.length === 0 ? (
 <div className="p-8 text-center text-sm text-text-muted bg-bg-secondary rounded-xl">
 {t('softwareCompliance.historyEmpty', 'No scan or remediation history yet. Run a scan on a list to populate this view.')}
 </div>
 ) : (
 <div className="space-y-2">
 {batches.map((batch) => <SoftwareHistoryBatchRow key={batch.batchId} batch={batch} />)}
 </div>
 )}
 </div>
 );
}

function SoftwareHistoryBatchRow({ batch }: { batch: SoftwareComplianceHistoryBatch }) {
 const { t } = useTranslation();
 const [open, setOpen] = useState(false);
 const [expandedId, setExpandedId] = useState<string | null>(null);

 const typeLabel = batch.type === 'check_software_compliance' ? t('softwareCompliance.history.scan', 'Scan')
 : batch.type === 'install_software' ? t('softwareCompliance.actions.install', 'Install')
 : t('softwareCompliance.actions.uninstall', 'Uninstall');
 const typeColor = batch.type === 'uninstall_software' ? 'text-red-400 border-red-400/30 bg-red-400/10'
 : batch.type === 'install_software' ? 'text-green-400 border-green-400/30 bg-green-400/10'
 : 'text-accent border-accent/30 bg-accent/10';

 const badge = (s: string) => {
 const c = s === 'success' ? 'text-green-400 border-green-400/30 bg-green-400/10'
 : s === 'failure' || s === 'timeout' ? 'text-red-400 border-red-400/30 bg-red-400/10'
 : 'text-blue-400 border-blue-400/30 bg-blue-400/10';
 return <span className={`shrink-0 px-1.5 py-0.5 rounded-full border font-medium capitalize text-[10px] ${c}`}>{s}</span>;
 };

 return (
 <div className="rounded-lg bg-bg-secondary overflow-hidden">
 {/* Below sm: two lines — badge + list name first, then date + counts
 (CSS order), instead of one line where the name gets 0 px. */}
 <button
 onClick={() => setOpen(v => !v)}
 aria-expanded={open}
 className="w-full flex items-center gap-2 text-xs px-3 py-2 text-left hover:bg-bg-tertiary/40 max-sm:flex-wrap max-sm:gap-y-1"
 >
 {open ? <ChevronDown className="w-3.5 h-3.5 text-text-muted shrink-0" />
 : <ChevronRight className="w-3.5 h-3.5 text-text-muted shrink-0" />}
 <span className={`shrink-0 px-2 py-0.5 rounded-full border font-medium text-[10px] ${typeColor}`}>{typeLabel}</span>
 <span className="text-text-muted shrink-0 max-sm:order-1 max-sm:pl-[1.375rem]">{new Date(batch.triggeredAt).toLocaleString()}</span>
 <span className="text-text-primary font-medium truncate flex-1 min-w-0 max-sm:basis-3/5">{batch.listName}</span>
 <span className="flex items-center gap-1.5 shrink-0 text-[11px] max-sm:order-2 max-sm:ml-auto">
 {batch.ok > 0 && <span className="text-green-400">{t('softwareCompliance.history.ok', { count: batch.ok, defaultValue: '{{count}} OK' })}</span>}
 {batch.fail > 0 && <span className="text-red-400">{t('softwareCompliance.history.failed', { count: batch.fail, defaultValue: '{{count}} failed' })}</span>}
 {batch.pending > 0 && <span className="text-blue-400">{t('softwareCompliance.history.pending', { count: batch.pending, defaultValue: '{{count}} pending' })}</span>}
 <span className="text-text-muted">({batch.total})</span>
 </span>
 </button>
 {open && (
 <div className="/30">
 {batch.items.map((r) => {
 const isExpanded = expandedId === r.id;
 return (
 <div key={r.id} className="/20 last:border-b-0">
 <div
 className="flex items-center gap-2 text-xs px-3 py-1.5 hover:bg-bg-tertiary/30 cursor-pointer"
 onClick={() => setExpandedId(isExpanded ? null : r.id)}
 >
 {isExpanded
 ? <ChevronDown className="w-3 h-3 text-text-muted shrink-0" />
 : <ChevronRight className="w-3 h-3 text-text-muted shrink-0" />}
 {badge(r.status)}
 <span className="text-text-primary truncate flex-1 min-w-0 font-medium max-sm:whitespace-normal max-sm:break-words">
 {r.deviceName}
 {r.entryName && <span className="text-text-muted font-normal"> — {r.entryName}</span>}
 </span>
 {r.exitCode != null && <span className="text-text-muted font-mono shrink-0">exit {r.exitCode}</span>}
 <Link
 to={`/devices/${r.deviceId}`}
 onClick={(e) => e.stopPropagation()}
 className="shrink-0 text-text-muted hover:text-accent p-0.5 rounded hover:bg-accent/10 transition-colors coarse:inline-flex coarse:min-h-10 coarse:min-w-10 coarse:items-center coarse:justify-center"
 title={t('softwareCompliance.history.openDevice', 'Open device')}
 aria-label={t('softwareCompliance.history.openDevice', 'Open device')}
 >
 <ExternalLink className="w-3.5 h-3.5" />
 </Link>
 </div>
 {isExpanded && (
 <div className="px-4 py-2 bg-[#0d0f14] /20 space-y-2">
 {r.stdout && (
 <div>
 <p className="text-[10px] text-green-400/70 uppercase font-medium mb-0.5">stdout</p>
 <pre className="text-[11px] text-green-300/90 font-mono whitespace-pre-wrap break-all max-h-40 overflow-y-auto scrollbar-thin">{r.stdout}</pre>
 </div>
 )}
 {r.stderr && (
 <div>
 <p className="text-[10px] text-red-400/70 uppercase font-medium mb-0.5">stderr</p>
 <pre className="text-[11px] text-red-300/90 font-mono whitespace-pre-wrap break-all max-h-40 overflow-y-auto scrollbar-thin">{r.stderr}</pre>
 </div>
 )}
 {!r.stdout && !r.stderr && (
 <p className="text-[10px] text-text-muted italic">{r.status === 'pending' || r.status === 'sent' ? t('softwareCompliance.history.awaiting', 'Awaiting agent reply…') : t('softwareCompliance.history.noOutput', 'No output captured.')}</p>
 )}
 </div>
 )}
 </div>
 );
 })}
 </div>
 )}
 </div>
 );
}
