import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Settings2 } from 'lucide-react';
import { clsx } from 'clsx';
import type { Device, ServiceInfo, ServiceStartType } from '@obliance/shared';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';

type T = ReturnType<typeof useTranslation>['t'];

/** Human label of a list_services start type (Windows / systemd words). */
export function serviceStartTypeLabel(t: T, value: string | undefined | null): string {
  switch (value) {
    case 'auto': return t('deviceDetail.services.startType.auto', 'Automatic');
    case 'auto_delayed': return t('deviceDetail.services.startType.auto_delayed', 'Automatic (delayed start)');
    case 'manual': return t('deviceDetail.services.startType.manual', 'Manual');
    case 'disabled': return t('deviceDetail.services.startType.disabled', 'Disabled');
    case 'boot': return t('deviceDetail.services.startType.boot', 'Boot');
    case 'system': return t('deviceDetail.services.startType.system', 'System');
    case 'static': return t('deviceDetail.services.startType.static', 'Static');
    default: return value || '—';
  }
}

/** The agent's own services: the agent refuses to change their start type
 *  (service_start_type.go isProtectedService), the UI greys the action out. */
export function isProtectedAgentService(osType: Device['osType'], name: string): boolean {
  const n = name.trim().toLowerCase();
  if (osType === 'windows') return n === 'oblianceagent' || n === 'oblireachagent' || n === 'obliancewatchdog';
  const u = n.replace(/\.service$/, '');
  return u === 'obliance-agent' || u === 'obliance-watchdog' || u === 'obliance-watchdog.timer' || u === 'oblireach-agent';
}

/** Start types offered for the device's OS (delayed start: Windows only). */
export function serviceStartTypeChoices(osType: Device['osType']): ServiceStartType[] {
  return osType === 'windows' ? ['auto', 'auto_delayed', 'manual', 'disabled'] : ['auto', 'manual', 'disabled'];
}

function choiceHint(t: T, value: ServiceStartType, linux: boolean): string {
  if (linux) {
    switch (value) {
      case 'auto': return t('deviceDetail.services.startType.hint.linuxAuto', 'Started at boot (systemctl enable).');
      case 'manual': return t('deviceDetail.services.startType.hint.linuxManual', 'Not started at boot, can still be started by hand or as a dependency (systemctl disable).');
      case 'disabled': return t('deviceDetail.services.startType.hint.linuxDisabled', 'Cannot be started at all, not even as a dependency (systemctl mask).');
      default: return '';
    }
  }
  switch (value) {
    case 'auto': return t('deviceDetail.services.startType.hint.auto', 'Started with Windows.');
    case 'auto_delayed': return t('deviceDetail.services.startType.hint.autoDelayed', 'Started shortly after the other automatic services.');
    case 'manual': return t('deviceDetail.services.startType.hint.manual', 'Started on demand only.');
    case 'disabled': return t('deviceDetail.services.startType.hint.disabled', 'Cannot be started.');
    default: return '';
  }
}

export interface ServiceStartTypeDialogProps {
  device: Pick<Device, 'osType'>;
  /** The service being edited; null = closed. */
  service: ServiceInfo | null;
  onClose: () => void;
  /** Apply the start type; stopAfter = also stop the (running) service. */
  onApply: (service: ServiceInfo, startType: ServiceStartType, stopAfter: boolean) => void;
}

/**
 * Change the start type of a service (set_service_start_type, agent
 * 4.5.103+). Choosing "Disabled" turns the dialog into its own confirmation
 * (warning + red button) and offers to stop the service as well.
 */
export function ServiceStartTypeDialog({ device, service, onClose, onApply }: ServiceStartTypeDialogProps) {
  const { t } = useTranslation();
  const choices = serviceStartTypeChoices(device.osType);
  const current = service?.startType ?? '';
  const [selected, setSelected] = useState<ServiceStartType | null>(null);
  const [stopAfter, setStopAfter] = useState(false);

  useEffect(() => {
    setSelected(choices.includes(current as ServiceStartType) ? (current as ServiceStartType) : null);
    setStopAfter(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [service?.name, current]);

  if (!service) return null;
  const linux = device.osType === 'linux';
  const isRunning = service.status === 'running';
  const disabling = selected === 'disabled';
  const unchanged = !selected || selected === current;
  const apply = () => {
    if (!selected || unchanged) return;
    onApply(service, selected, disabling && isRunning && stopAfter);
  };

  return (
    <Modal
      open
      onClose={onClose}
      size="sm"
      phoneLayout="sheet"
      icon={<Settings2 className="w-4 h-4 text-text-muted" />}
      title={t('deviceDetail.services.startType.title', 'Start type')}
      footer={(
        <>
          <Button variant="secondary" size="sm" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button variant={disabling ? 'danger' : 'primary'} size="sm" onClick={apply} disabled={unchanged}>
            {disabling
              ? (isRunning && stopAfter
                ? t('deviceDetail.services.startType.disableAndStop', 'Disable and stop')
                : t('deviceDetail.services.startType.disable', 'Disable'))
              : t('deviceDetail.services.startType.apply', 'Apply')}
          </Button>
        </>
      )}
    >
      <div className="space-y-3">
        <div className="text-xs text-text-muted">
          <div className="font-mono text-text-primary break-all">{service.name}</div>
          {service.displayName && <div className="break-words">{service.displayName}</div>}
          <div className="mt-1">
            {t('deviceDetail.services.startType.current', 'Current: {{value}}', { value: serviceStartTypeLabel(t, current) })}
          </div>
        </div>

        <div role="radiogroup" aria-label={t('deviceDetail.services.startType.title', 'Start type')} className="space-y-1.5">
          {choices.map((c) => (
            <label
              key={c}
              className={clsx(
                'flex items-start gap-2 px-3 py-2 rounded-lg border cursor-pointer transition-colors coarse:min-h-10',
                selected === c ? 'border-accent/60 bg-accent/10' : 'border-transparent bg-bg-tertiary hover:bg-bg-hover',
              )}
            >
              <input
                type="radio"
                name="service-start-type"
                value={c}
                checked={selected === c}
                onChange={() => setSelected(c)}
                className="mt-0.5 accent-accent coarse:w-5 coarse:h-5"
              />
              <span className="min-w-0">
                <span className="block text-sm text-text-primary">
                  {serviceStartTypeLabel(t, c)}
                  {c === current && (
                    <span className="ml-2 text-[11px] text-text-muted">{t('deviceDetail.services.startType.currentBadge', '(current)')}</span>
                  )}
                </span>
                <span className="block text-xs text-text-muted">{choiceHint(t, c, linux)}</span>
              </span>
            </label>
          ))}
        </div>

        {disabling && !unchanged && (
          <div className="flex gap-2 p-3 rounded-lg border border-red-400/30 bg-red-400/10 text-xs text-red-400">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <div className="space-y-2 min-w-0">
              <p>
                {t('deviceDetail.services.startType.disableWarning',
                  'The service will no longer start, even on demand. Programs that depend on it may stop working.')}
              </p>
              {isRunning && (
                <label className="flex items-center gap-2 cursor-pointer text-text-primary coarse:min-h-10">
                  <input type="checkbox" checked={stopAfter} onChange={(e) => setStopAfter(e.target.checked)} className="accent-accent coarse:w-5 coarse:h-5" />
                  {t('deviceDetail.services.startType.stopToo', 'Also stop the service now')}
                </label>
              )}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}
