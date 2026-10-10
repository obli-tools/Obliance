import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Download, Upload, AlertTriangle, CheckCircle2, RefreshCw, Info } from 'lucide-react';
import toast from 'react-hot-toast';
import { MASTER_TENANT_ID } from '@obliance/shared';
import { bulkRenameApi, type BulkRenameDelimiter, type BulkRenamePreview, type BulkRenamePreviewRow, type BulkRenameRowStatus } from '@/api/bulkRename.api';
import { useTenantStore } from '@/store/tenantStore';
import { useAuthStore } from '@/store/authStore';
import { useIsMasterTenant } from '@/hooks/useIsMasterTenant';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { Button } from '@/components/common/Button';
import { TableScroll } from '@/components/common/TableScroll';
import { saveBlob } from '@/utils/download';
import { cn } from '@/utils/cn';

// "Name replacer": export the devices of ONE tenant as CSV, let an AI (or a
// human) fill the new_name column from an external source (TeamViewer…),
// re-import, preview, apply. Only the Obliance display name changes — the
// machine's hostname is never touched. Server: routes/bulkRename.routes.ts.

const MAX_BYTES = 2 * 1024 * 1024;
const MAX_RENDERED_ROWS = 1000;

const STATUS_STYLE: Record<BulkRenameRowStatus, string> = {
 ok: 'bg-green-500/15 text-green-400',
 unchanged: 'bg-bg-tertiary text-text-muted',
 not_found: 'bg-yellow-500/15 text-yellow-400',
 ambiguous: 'bg-orange-500/15 text-orange-400',
 invalid_name: 'bg-red-500/15 text-red-400',
 duplicate: 'bg-red-500/15 text-red-400',
 missing_key: 'bg-yellow-500/15 text-yellow-400',
};

/** Excel on Windows often saves CSV in Windows-1252: try strict UTF-8 first. */
async function readCsvFile(file: File): Promise<string> {
 const buf = await file.arrayBuffer();
 try {
 return new TextDecoder('utf-8', { fatal: true }).decode(buf);
 } catch {
 return new TextDecoder('windows-1252').decode(buf);
 }
}

export function BulkRenamePanel() {
 const { t, i18n } = useTranslation();
 const confirm = useConfirm();
 const isMaster = useIsMasterTenant();
 const isAdmin = useAuthStore((s) => s.user?.role === 'admin');
 const currentTenantId = useTenantStore((s) => s.currentTenantId);
 const tenants = useTenantStore((s) => s.tenants);
 // The master tenant's admin must pick ONE tenant explicitly (no "all tenants").
 const canPickTenant = isMaster && isAdmin;
 const [pickedTenantId, setPickedTenantId] = useState<number | null>(null);
 const targetTenantId = canPickTenant ? pickedTenantId : currentTenantId;

 const [delimiter, setDelimiter] = useState<BulkRenameDelimiter>(i18n.language?.startsWith('en') ? ',' : ';');
 const [exporting, setExporting] = useState(false);
 const [importing, setImporting] = useState(false);
 const [applying, setApplying] = useState(false);
 const [preview, setPreview] = useState<BulkRenamePreview | null>(null);
 const [selected, setSelected] = useState<Set<number>>(new Set());
 const [issuesOnly, setIssuesOnly] = useState(false);
 const [conflictLines, setConflictLines] = useState<number[]>([]);
 const fileRef = useRef<HTMLInputElement>(null);

 // A preview belongs to one tenant: drop it when the tenant changes.
 useEffect(() => { setPreview(null); setSelected(new Set()); setConflictLines([]); }, [currentTenantId, pickedTenantId]);
 useEffect(() => { setPickedTenantId(null); }, [currentTenantId]);

 const errorText = (err: any): string => {
 const code: string | undefined = err?.response?.data?.code;
 if (code) {
 const k = `bulkRename.errors.${code}`;
 const tr = t(k);
 if (tr && tr !== k) return tr;
 }
 return err?.response?.data?.error || t('common.error', 'Error');
 };

 const handleExport = async () => {
 if (!targetTenantId) return;
 setExporting(true);
 try {
 const { blob, filename } = await bulkRenameApi.exportCsv(targetTenantId, delimiter);
 if (!(await saveBlob(blob, filename, 'text/csv'))) toast.error(t('common.error', 'Error'));
 } catch (err: any) {
 // responseType blob: the JSON error is inside a Blob.
 let msg = t('common.error', 'Error');
 try { const j = JSON.parse(await (err?.response?.data as Blob).text()); msg = errorText({ response: { data: j } }); } catch { /* keep generic */ }
 toast.error(msg);
 } finally {
 setExporting(false);
 }
 };

 const handleFile = async (file: File | undefined) => {
 if (!file || !targetTenantId) return;
 if (file.size > MAX_BYTES) { toast.error(t('bulkRename.errors.bulk_rename_too_large', 'File too large (max 2 MB)')); return; }
 setImporting(true);
 setConflictLines([]);
 try {
 const text = await readCsvFile(file);
 const p = await bulkRenameApi.preview(targetTenantId, text);
 setPreview(p);
 setSelected(new Set(p.rows.filter((r) => r.status === 'ok').map((r) => r.line)));
 setIssuesOnly(false);
 } catch (err) {
 setPreview(null);
 toast.error(errorText(err));
 } finally {
 setImporting(false);
 if (fileRef.current) fileRef.current.value = '';
 }
 };

 const okRows = useMemo(() => preview?.rows.filter((r) => r.status === 'ok') ?? [], [preview]);
 const shownRows = useMemo(() => {
 if (!preview) return [];
 return issuesOnly ? preview.rows.filter((r) => r.status !== 'ok' || r.warnings.length > 0) : preview.rows;
 }, [preview, issuesOnly]);

 const toggle = (line: number) => setSelected((prev) => {
 const next = new Set(prev);
 if (next.has(line)) next.delete(line); else next.add(line);
 return next;
 });

 const handleApply = async () => {
 if (!preview || selected.size === 0) return;
 const n = selected.size;
 const ok = await confirm({
 title: t('bulkRename.apply.confirmTitle', 'Rename devices'),
 message: t('bulkRename.apply.confirmMessage', { count: n, defaultValue: `Rename ${n} device(s)? Only the name shown in Obliance changes; the machine names are not modified.` }),
 confirmLabel: t('bulkRename.apply.button', { count: n, defaultValue: `Rename ${n} device(s)` }),
 });
 if (!ok) return;
 setApplying(true);
 try {
 const r = await bulkRenameApi.apply(preview.token, [...selected].sort((a, b) => a - b));
 toast.success(t('bulkRename.apply.done', { renamed: r.renamed, unchanged: r.unchanged, defaultValue: `${r.renamed} renamed, ${r.unchanged} already up to date` }));
 setPreview(null);
 setSelected(new Set());
 } catch (err: any) {
 const lines: number[] | undefined = err?.response?.data?.lines;
 if (err?.response?.status === 409 && Array.isArray(lines)) setConflictLines(lines);
 if (err?.response?.data?.code === 'bulk_rename_preview_expired') setPreview(null);
 toast.error(errorText(err));
 } finally {
 setApplying(false);
 }
 };

 const statusLabel = (s: BulkRenameRowStatus) => t(`bulkRename.status.${s}`, {
 ok: 'OK', unchanged: 'Unchanged', not_found: 'Not found', ambiguous: 'Ambiguous',
 invalid_name: 'Invalid name', duplicate: 'Duplicate in file', missing_key: 'No old name',
 }[s]);

 const rowDetail = (r: BulkRenamePreviewRow): string => {
 if (r.status === 'ambiguous') return t('bulkRename.detail.ambiguous', { count: r.candidates ?? 0, defaultValue: `${r.candidates} devices carry this name — use device_uuid` });
 if (r.status === 'invalid_name') return t(`bulkRename.detail.invalid.${r.invalidReason}`, {
 too_long: 'More than 500 characters', forbidden_chars: 'Contains control or direction characters', empty: 'Empty', not_string: 'Invalid',
 }[r.invalidReason ?? 'not_string']);
 if (r.status === 'duplicate') return t('bulkRename.detail.duplicate', 'The same device appears on several lines: none of them is applied');
 if (r.status === 'not_found') return t('bulkRename.detail.notFound', 'No device of this tenant matches');
 const w: string[] = [];
 if (r.warnings.includes('duplicate_new_name')) w.push(t('bulkRename.warning.duplicate_new_name', 'Same new name as another line'));
 if (r.warnings.includes('name_in_use')) w.push(t('bulkRename.warning.name_in_use', 'Name already used by another device'));
 if (r.matchedBy === 'hostname') w.push(t('bulkRename.detail.byHostname', 'Matched on the hostname'));
 return w.join(' · ');
 };

 const counts = preview?.counts;
 const childTenants = [...tenants].sort((a, b) => (a.id === MASTER_TENANT_ID ? -1 : b.id === MASTER_TENANT_ID ? 1 : a.name.localeCompare(b.name)));

 return (
 <div className="space-y-5">
 <div className="flex gap-2 p-3 rounded-lg bg-bg-secondary text-sm text-text-muted">
 <Info className="w-4 h-4 mt-0.5 shrink-0 text-accent" />
 <p>{t('bulkRename.intro', 'Export the devices of a tenant as CSV, fill the new_name column (by hand or with an AI and your other tools, e.g. TeamViewer), then import it back. Only the name shown in Obliance changes: the real machine name (hostname) is never modified.')}</p>
 </div>

 {canPickTenant && (
 <div className="space-y-1.5">
 <label className="block text-xs font-medium text-text-muted uppercase tracking-wider">{t('bulkRename.tenant.label', 'Tenant')}</label>
 <select
 value={pickedTenantId ?? ''}
 onChange={(e) => setPickedTenantId(e.target.value ? Number(e.target.value) : null)}
 className="w-full sm:w-80 bg-bg-tertiary border border-border rounded-md px-3 py-2 text-sm text-text-primary"
 >
 <option value="">{t('bulkRename.tenant.placeholder', 'Choose a tenant…')}</option>
 {childTenants.map((tn) => <option key={tn.id} value={tn.id}>{tn.name}</option>)}
 </select>
 <p className="text-xs text-text-muted">{t('bulkRename.tenant.hint', 'One tenant at a time: the export and the renaming never cover several tenants.')}</p>
 </div>
 )}

 <div className="grid gap-4 md:grid-cols-2">
 {/* Step 1 — export */}
 <div className="p-4 rounded-lg bg-bg-secondary space-y-3">
 <h3 className="font-medium text-text-primary">{t('bulkRename.export.title', '1. Export the devices')}</h3>
 <p className="text-sm text-text-muted">{t('bulkRename.export.description', 'One line per device with its identifiers (uuid, name, hostname, serial number, model, IP, MAC, last user, domain…) and an empty new_name column.')}</p>
 <div className="flex flex-wrap items-center gap-2">
 <label className="text-sm text-text-muted" htmlFor="bulk-rename-delim">{t('bulkRename.export.delimiter', 'Separator')}</label>
 <select
 id="bulk-rename-delim"
 value={delimiter}
 onChange={(e) => setDelimiter(e.target.value as BulkRenameDelimiter)}
 className="bg-bg-tertiary border border-border rounded-md px-2 py-1.5 text-sm text-text-primary"
 >
 <option value=";">{t('bulkRename.export.semicolon', 'Semicolon ( ; )')}</option>
 <option value=",">{t('bulkRename.export.comma', 'Comma ( , )')}</option>
 </select>
 <Button onClick={handleExport} disabled={!targetTenantId || exporting} loading={exporting} size="sm">
 <Download className="w-4 h-4 mr-1.5" />{t('bulkRename.export.button', 'Download CSV')}
 </Button>
 </div>
 </div>

 {/* Step 2 — import */}
 <div className="p-4 rounded-lg bg-bg-secondary space-y-3">
 <h3 className="font-medium text-text-primary">{t('bulkRename.import.title', '2. Import the names')}</h3>
 <p className="text-sm text-text-muted">{t('bulkRename.import.description', 'The completed export, or a two-column CSV: old_name;new_name (or device_uuid;new_name). Up to 10,000 lines / 2 MB. Nothing is renamed before you confirm the preview.')}</p>
 <input ref={fileRef} type="file" accept=".csv,text/csv" className="hidden" onChange={(e) => handleFile(e.target.files?.[0])} />
 <Button onClick={() => fileRef.current?.click()} disabled={!targetTenantId || importing} loading={importing} size="sm" variant="secondary">
 <Upload className="w-4 h-4 mr-1.5" />{t('bulkRename.import.button', 'Choose a CSV file…')}
 </Button>
 </div>
 </div>

 {preview && counts && (
 <div className="space-y-3">
 <div className="flex flex-wrap items-center gap-2 text-xs">
 <span className="px-2 py-1 rounded bg-bg-tertiary text-text-primary">{t('bulkRename.counts.total', { count: counts.total, defaultValue: `${counts.total} lines` })}</span>
 {(['ok', 'unchanged', 'not_found', 'ambiguous', 'invalid_name', 'duplicate', 'missing_key'] as BulkRenameRowStatus[])
 .filter((s) => counts[s] > 0)
 .map((s) => <span key={s} className={cn('px-2 py-1 rounded', STATUS_STYLE[s])}>{statusLabel(s)} · {counts[s]}</span>)}
 {counts.empty > 0 && <span className="px-2 py-1 rounded bg-bg-tertiary text-text-muted">{t('bulkRename.counts.empty', { count: counts.empty, defaultValue: `${counts.empty} without new name (ignored)` })}</span>}
 {counts.warnings > 0 && <span className="px-2 py-1 rounded bg-yellow-500/15 text-yellow-400">{t('bulkRename.counts.warnings', { count: counts.warnings, defaultValue: `${counts.warnings} warning(s)` })}</span>}
 </div>

 {conflictLines.length > 0 && (
 <div className="flex gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-sm text-red-400">
 <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
 <p>{t('bulkRename.conflict', { lines: conflictLines.slice(0, 20).join(', '), defaultValue: `These lines changed since the preview (device renamed or no longer reachable): ${conflictLines.slice(0, 20).join(', ')}. Import the file again.` })}</p>
 </div>
 )}

 <div className="flex flex-wrap items-center gap-3">
 <label className="flex items-center gap-2 text-sm text-text-muted">
 <input type="checkbox" checked={issuesOnly} onChange={(e) => setIssuesOnly(e.target.checked)} />
 {t('bulkRename.preview.issuesOnly', 'Show only lines needing attention')}
 </label>
 <button type="button" className="text-sm text-accent hover:underline" onClick={() => setSelected(new Set(okRows.map((r) => r.line)))}>
 {t('bulkRename.preview.selectAll', 'Select all')}
 </button>
 <button type="button" className="text-sm text-accent hover:underline" onClick={() => setSelected(new Set())}>
 {t('bulkRename.preview.selectNone', 'Select none')}
 </button>
 <div className="flex-1" />
 <Button variant="ghost" size="sm" onClick={() => { setPreview(null); setSelected(new Set()); setConflictLines([]); }}>
 <RefreshCw className="w-4 h-4 mr-1.5" />{t('bulkRename.preview.reset', 'Start over')}
 </Button>
 <Button onClick={handleApply} disabled={selected.size === 0 || applying} loading={applying}>
 <CheckCircle2 className="w-4 h-4 mr-1.5" />{t('bulkRename.apply.button', { count: selected.size, defaultValue: `Rename ${selected.size} device(s)` })}
 </Button>
 </div>

 <TableScroll className="bg-bg-secondary rounded-xl">
 <table className="w-full text-sm">
 <thead>
 <tr className="text-left text-xs text-text-muted uppercase tracking-wider border-b border-border">
 <th className="px-3 py-2 w-8" />
 <th className="px-3 py-2">{t('bulkRename.preview.line', 'Line')}</th>
 <th className="px-3 py-2">{t('bulkRename.preview.status', 'Status')}</th>
 <th className="px-3 py-2">{t('bulkRename.preview.current', 'Current name')}</th>
 <th className="px-3 py-2">{t('bulkRename.preview.new', 'New name')}</th>
 <th className="px-3 py-2">{t('bulkRename.preview.hostname', 'Hostname')}</th>
 <th className="px-3 py-2">{t('bulkRename.preview.details', 'Details')}</th>
 </tr>
 </thead>
 <tbody>
 {shownRows.slice(0, MAX_RENDERED_ROWS).map((r) => (
 <tr key={r.line} className={cn('border-b border-border/50', conflictLines.includes(r.line) && 'bg-red-500/10')}>
 <td className="px-3 py-1.5">
 {r.status === 'ok' && (
 <input
 type="checkbox"
 checked={selected.has(r.line)}
 onChange={() => toggle(r.line)}
 aria-label={t('bulkRename.preview.include', 'Include this line')}
 />
 )}
 </td>
 <td className="px-3 py-1.5 text-text-muted tabular-nums">{r.line}</td>
 <td className="px-3 py-1.5"><span className={cn('px-1.5 py-0.5 rounded text-xs whitespace-nowrap', STATUS_STYLE[r.status])}>{statusLabel(r.status)}</span></td>
 <td className="px-3 py-1.5 text-text-primary break-all">{r.currentName ?? r.input.oldName ?? r.input.uuid ?? '—'}</td>
 <td className="px-3 py-1.5 text-text-primary break-all">{r.newName ?? r.input.newName}</td>
 <td className="px-3 py-1.5 text-text-muted break-all">{r.hostname ?? ''}</td>
 <td className="px-3 py-1.5 text-xs text-text-muted">{rowDetail(r)}</td>
 </tr>
 ))}
 {shownRows.length === 0 && (
 <tr><td colSpan={7} className="px-3 py-6 text-center text-text-muted">{t('bulkRename.preview.empty', 'No line to show')}</td></tr>
 )}
 </tbody>
 </table>
 </TableScroll>
 {shownRows.length > MAX_RENDERED_ROWS && (
 <p className="text-xs text-text-muted">{t('bulkRename.preview.truncated', { shown: MAX_RENDERED_ROWS, total: shownRows.length, defaultValue: `Showing ${MAX_RENDERED_ROWS} of ${shownRows.length} lines (all selected lines are applied).` })}</p>
 )}
 <p className="text-xs text-text-muted">{t('bulkRename.preview.expires', { time: new Date(preview.expiresAt).toLocaleTimeString(), defaultValue: `This preview expires at ${new Date(preview.expiresAt).toLocaleTimeString()}.` })}</p>
 </div>
 )}
 </div>
 );
}
