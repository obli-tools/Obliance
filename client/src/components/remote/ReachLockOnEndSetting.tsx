import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { profileApi } from '@/api/profile.api';
import { LOCK_ON_END_STORAGE_KEY, loadLockOnEndSetting, parseLockOnEndSetting, saveLockOnEndSetting } from './reachLockOnEnd';

/**
 * Setting "Propose to lock the session when the connection ends" (ObliReach
 * viewer — see reachLockOnEnd.ts). An account preference, also written to
 * this browser for the viewers. On by default.
 */
export function ReachLockOnEndSetting() {
  const { t } = useTranslation();
  const [on, setOn] = useState<boolean>(loadLockOnEndSetting);

  useEffect(() => {
    const onStorage = (ev: StorageEvent) => {
      if (ev.key === LOCK_ON_END_STORAGE_KEY) setOn(parseLockOnEndSetting(ev.newValue));
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  return (
    <label className="flex items-start gap-3 cursor-pointer">
      <input
        type="checkbox"
        checked={on}
        onChange={(e) => {
          const v = e.target.checked;
          setOn(v);
          saveLockOnEndSetting(v);
          profileApi.update({ preferences: { reachLockOnEnd: v } }).catch(() => toast.error(t('common.error')));
        }}
        className="accent-accent mt-0.5 shrink-0 coarse:h-5 coarse:w-5"
      />
      <div>
        <span className="text-sm text-text-primary">
          {t('reach.lockOnEnd.setting', 'Propose to lock the session when the connection ends')}
        </span>
        <p className="text-xs text-text-muted">
          {t('reach.lockOnEnd.settingHintAccount', 'When the remote Windows session was locked when you connected, it is locked again at the end of the connection (padlock button in the toolbar to change it for the current machine). Off: the session is never locked again and the button is hidden. Setting of your account.')}
        </p>
      </div>
    </label>
  );
}
