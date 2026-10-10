import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { oblireachDesktopVersion, oblireachDesktopDownload } from '../controllers/oblireachDesktop.controller';
import {
  flatpakrefHandler,
  flatpakrepoHandler,
  flatpakBundleHandler,
  flatpakRepoHandler,
  FLATPAK_APP_ID,
} from '../controllers/oblireachDesktopLinux.controller';

// Public routes — no auth. The desktop app polls `version` without
// credentials and the download URL is meant to be opened directly in
// the OS browser. Same for the Linux build (Flatpak): flatpak fetches the
// .flatpakref / repository without credentials; GPG signatures (verified by
// flatpak) carry the authenticity, not this server.

const router = Router();

router.get('/version', oblireachDesktopVersion);
router.get('/download', oblireachDesktopDownload);

// ── Linux (Flatpak) — oblireachDesktopLinux.controller.ts ──
router.get(`/flatpak/${FLATPAK_APP_ID}.flatpakref`, flatpakrefHandler);
router.get('/flatpak/oblireach.flatpakrepo', flatpakrepoHandler);
router.get('/flatpak/Oblireach.flatpak', flatpakBundleHandler);

// The OSTree repository is fetched file by file (config, summary, summary.sig,
// static deltas; individual objects when a delta is missing). It is skipped by
// the global apiLimiter (500 / 5 min / IP, shared with the login page — one
// fallback object pull would exhaust it) and gets its own, larger budget.
const flatpakRepoLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again later' },
});
router.get('/flatpak/repo/*', flatpakRepoLimiter, flatpakRepoHandler);

export default router;
