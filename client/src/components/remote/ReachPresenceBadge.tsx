/**
 * Other operators connected to the same machine (presence, sent by the
 * Obliance relay — reachProtocol.ts parsePresence). A discreet badge in the
 * viewer toolbar (hidden while this viewer is alone), the list on click /
 * hover: name, client (Web / Desktop), since when, control or view only, and
 * whether they hid the remote screen.
 */
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Users, MonitorOff, Eye, MousePointer2 } from 'lucide-react';
import { clsx } from 'clsx';
import type { ReachPresenceOperator } from './reachProtocol';

function sinceText(iso: string, now: number, t: (k: string, d: string, o?: Record<string, unknown>) => string): string {
  const at = Date.parse(iso);
  if (!Number.isFinite(at)) return '';
  const min = Math.max(0, Math.floor((now - at) / 60000));
  if (min < 1) return t('reach.presence.sinceNow', 'Just joined');
  const d = min < 60
    ? t('reach.presence.sinceMin', '{{n}} min', { n: min })
    : t('reach.presence.sinceHour', '{{h}} h {{m}} min', { h: Math.floor(min / 60), m: min % 60 });
  return t('reach.presence.since', 'For {{d}}', { d });
}

export function ReachPresenceBadge({ others, className }: { others: ReachPresenceOperator[]; className?: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 30000);
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener('mousedown', onDown);
    return () => { window.clearInterval(timer); document.removeEventListener('mousedown', onDown); };
  }, [open]);

  if (others.length === 0) return null;
  const tf = t as unknown as (k: string, d: string, o?: Record<string, unknown>) => string;
  const names = others.map((o) => o.name).join(', ');
  const anyBlank = others.some((o) => o.blank);
  const title = t('reach.presence.badgeTitle', 'Also connected to this computer: {{names}}', { names });

  return (
    <div className={clsx('relative', className)} ref={ref} onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title={title}
        aria-label={title}
        aria-expanded={open}
        className={clsx(
          'flex items-center gap-1 px-2 py-1 text-xs border rounded transition-colors',
          anyBlank
            ? 'bg-sky-500/15 text-sky-400 border-sky-500/30 hover:bg-sky-500/25'
            : 'bg-amber-500/15 text-amber-400 border-amber-500/30 hover:bg-amber-500/25',
        )}
      >
        <Users className="w-3.5 h-3.5" />
        <span>{others.length}</span>
      </button>
      {open && (
        <div
          role="dialog"
          aria-label={t('reach.presence.listTitle', 'Other operators on this computer')}
          className="absolute right-0 top-full mt-1 z-50 w-72 max-h-80 overflow-y-auto rounded-lg border border-border bg-bg-secondary shadow-xl p-2"
        >
          <div className="px-1 pb-1.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted">
            {t('reach.presence.listTitle', 'Other operators on this computer')}
          </div>
          <ul className="space-y-1">
            {others.map((o) => (
              <li key={o.id} className="rounded px-2 py-1.5 bg-bg-tertiary/60">
                <div className="flex items-center gap-1.5 text-xs text-text-primary">
                  <span className="font-medium truncate" title={o.name}>{o.name}</span>
                  {o.sameUser && (
                    <span className="shrink-0 text-[10px] text-text-muted">{t('reach.presence.you', '(you, another window)')}</span>
                  )}
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-text-muted">
                  <span>{o.client === 'desktop' ? t('reach.presence.desktop', 'Oblireach Desktop') : t('reach.presence.web', 'Web')}</span>
                  {o.since && <span>{sinceText(o.since, now, tf)}</span>}
                  {o.control === true && (
                    <span className="inline-flex items-center gap-0.5"><MousePointer2 className="w-3 h-3" />{t('reach.presence.control', 'In control')}</span>
                  )}
                  {o.control === false && (
                    <span className="inline-flex items-center gap-0.5"><Eye className="w-3 h-3" />{t('reach.presence.viewOnly', 'View only')}</span>
                  )}
                  {o.blank && (
                    <span className="inline-flex items-center gap-0.5 text-sky-400"><MonitorOff className="w-3 h-3" />{t('reach.presence.blank', 'Remote screen hidden')}</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
