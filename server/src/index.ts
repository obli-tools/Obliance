import './env';
import { clientIp } from './utils/clientIp';
import http from 'http';
import type { IncomingMessage } from 'http';
import type { Duplex } from 'stream';
import { WebSocketServer } from 'ws';
import type { WebSocket } from 'ws';
import { config, defaultAdminPasswordError, isWeakAdminPassword, startupConfigErrors } from './config';
import { db } from './db';
import { createApp, getSessionMiddleware } from './app';
import { createSocketServer } from './socket';
import { logger } from './utils/logger';
import { generatePassword, hashPassword } from './utils/crypto';
import { deviceService } from './services/device.service';
import { setLiveAlertIO } from './services/liveAlert.service';
import { scheduleService } from './services/schedule.service';
import { commandService } from './services/command.service';
import { remoteService } from './services/remote.service';
import { agentHub } from './services/agentHub.service';
import { oblireachHub } from './services/oblireachHub.service';
import { obligateService } from './services/obligate.service';
import { deviceIdentityService } from './services/deviceIdentity.service';
import {
  agentKeyMayActForDevice,
  browserVerdictHttpStatus,
  isUuid,
  rejectUpgrade,
} from './services/remoteSessionSecurity';

async function main() {
  // Unsafe configuration (missing database URL, weak or missing session
  // secret; see config.ts): refuse to start before anything touches the
  // database.
  const configErrors = startupConfigErrors();
  if (configErrors.length > 0) {
    for (const message of configErrors) logger.fatal(message);
    logger.fatal('Unsafe configuration: refusing to start.');
    process.exit(1);
  }

  // Run database migrations
  logger.info('Running database migrations...');
  await db.migrate.latest();
  logger.info('Migrations complete');

  // Initial administrator, on a database that has none.
  await ensureDefaultAdmin();

  // Scenario accountability epoch (scenarioPermission.service): recorded
  // before any request can save / enable a scenario or a trigger can fire.
  const { initScenarioAccountability } = await import('./services/scenarioPermission.service');
  await initScenarioAccountability();

  // Create Express app and HTTP server
  const app = createApp();
  const server = http.createServer(app);

  // Attach Socket.io — this registers its own 'upgrade' listener on `server`
  const io = createSocketServer(server);

  // ── Remote tunnel WebSocket ──────────────────────────────────────────────
  // socket.io/engine.io registers an upgrade handler that destroys sockets whose
  // path doesn't match "/socket.io/".  To safely handle tunnel upgrades on
  // the same HTTP port we intercept ALL upgrade events, route /api/remote/*
  // paths to our own WS server, and forward everything else to socket.io's
  // original listeners.
  const remoteWss = new WebSocketServer({ noServer: true, maxPayload: 150 * 1024 * 1024 });

  // Capture and remove the upgrade listeners socket.io just registered so we
  // can act as the sole dispatcher.
  const sioUpgradeListeners = server.rawListeners('upgrade').slice();
  server.removeAllListeners('upgrade');

  // Session-token pattern: 64 hex chars produced by crypto.randomBytes(32)
  const BROWSER_RE    = /^\/api\/remote\/tunnel\/([0-9a-f]{64})$/;
  const AGENT_RE      = /^\/api\/remote\/agent-tunnel\/([0-9a-f]{64})$/;
  const AGENT_CMD_RE       = /^\/api\/agent\/ws$/;
  const OBLIREACH_CMD_RE   = /^\/api\/oblireach\/ws$/;

  server.on('upgrade', (request: IncomingMessage, socket: Duplex, head: Buffer) => {
    const pathname = new URL(request.url ?? '/', 'http://localhost').pathname;

    const clientIpOf = () => clientIp(request);

    // ── Browser remote tunnel ──────────────────────────────────────────────
    // SECURITY: the token in the URL is NOT a credential on its own. The
    // upgrade must carry the express-session cookie of the user who STARTED
    // the session (same cookie as the REST API / socket.io), and the session
    // must still be open. A refusal is a plain HTTP 401/403/404 written
    // BEFORE the handshake (never a 101 then a close): the client gets no
    // `open`, so a viewer's retry counter is not reset by a tunnel it may not
    // use. The in-process SSH bastion does not come through here (it calls
    // registerBrowserTunnel directly).
    const browserMatch = BROWSER_RE.exec(pathname);
    if (browserMatch) {
      const sessionToken = browserMatch[1];
      // Authenticate BEFORE accepting the WebSocket so the browser tunnel is
      // registered synchronously in the handleUpgrade callback (no window
      // where early browser frames could be dropped). Node removed its own
      // 'error' listener before emitting 'upgrade': guard the socket while
      // we wait, or a client reset during the lookup would crash the process.
      const onEarlyError = () => socket.destroy();
      socket.on('error', onEarlyError);
      remoteService.authorizeBrowserTunnel(request, sessionToken, getSessionMiddleware())
        .then((verdict) => {
          socket.removeListener('error', onEarlyError);
          if (socket.destroyed) return;
          if (!verdict.ok) {
            if (verdict.code === 4003) {
              logger.warn({ sessionId: verdict.sessionId, userId: verdict.userId, ip: clientIpOf(), reason: verdict.reason },
                'Browser remote tunnel refused');
            }
            if (verdict.notice) {
              // VM console already over: its owner gets the cause, then a 4004 close.
              const notice = verdict.notice;
              remoteWss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
                try { ws.send(JSON.stringify(notice)); } catch { /* closing */ }
                try { ws.close(4004, 'Session already closed'); } catch { /* closed */ }
              });
              logger.info({ sessionId: verdict.sessionId, userId: verdict.userId, code: notice.code }, 'Browser remote tunnel: VM console already over, cause sent');
              return;
            }
            rejectUpgrade(socket, browserVerdictHttpStatus(verdict), verdict.reason);
            return;
          }
          remoteWss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
            // (presence: a browser always sends an Origin on a WebSocket; the
            // Oblireach Desktop proxy strips it — the viewer may say otherwise)
            const clientHint = request.headers.origin ? 'web' as const : 'desktop' as const;
            remoteService.registerBrowserTunnel(sessionToken, ws, { sessionHash: verdict.sessionHash, isWebSocket: true, clientIp: clientIpOf(), clientHint });
            logger.info({ sessionId: verdict.sessionId, userId: verdict.userId }, 'Browser remote tunnel connected');
          });
        })
        .catch((err) => {
          logger.error(err, 'Browser remote tunnel setup error');
          socket.destroy();
        });
      return; // handled — do NOT forward to socket.io
    }

    // ── Agent remote tunnel ────────────────────────────────────────────────
    // SECURITY: the X-Api-Key must be the key the session's DEVICE is bound
    // to (same rule as the /api/agent/ws channel below), the session must
    // still be waiting for its agent, and only one agent may attach — a
    // second "agent" would otherwise receive every keystroke of the user.
    // Refused before the handshake, like the browser end.
    const agentMatch = AGENT_RE.exec(pathname);
    if (agentMatch) {
      const sessionToken = agentMatch[1];
      const apiKey = request.headers['x-api-key'] as string | undefined;
      const onEarlyError = () => socket.destroy();
      socket.on('error', onEarlyError);
      remoteService.authorizeAgentTunnel(apiKey, sessionToken)
        .then((verdict) => {
          socket.removeListener('error', onEarlyError);
          if (socket.destroyed) return;
          // Re-check in this tick: another agent may have attached while we
          // were reading the DB. handleUpgrade then calls back synchronously.
          if (verdict.ok && remoteService.hasLiveAgent(sessionToken)) {
            verdict = { ok: false, status: 409, reason: 'Agent already attached', sessionId: verdict.sessionId, deviceId: verdict.deviceId };
          }
          if (!verdict.ok) {
            if (verdict.status === 403 || verdict.status === 409) {
              logger.warn({ sessionId: verdict.sessionId, deviceId: verdict.deviceId, ip: clientIpOf(), reason: verdict.reason },
                'Agent remote tunnel refused');
            }
            rejectUpgrade(socket, verdict.status, verdict.reason);
            return;
          }
          const { sessionId, deviceId } = verdict;
          remoteWss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
            if (!remoteService.registerAgentTunnel(sessionToken, ws)) {
              ws.close(4009, 'Agent already attached');
              return;
            }
            logger.info({ sessionId, deviceId }, 'Agent remote tunnel connected');
          });
        })
        .catch((err) => {
          logger.error(err, 'Agent remote tunnel setup error');
          socket.destroy();
        });
      return; // handled — do NOT forward to socket.io
    }

    // ── Agent command channel ───────────────────────────────────────────────
    if (AGENT_CMD_RE.test(pathname)) {
      const apiKey = request.headers['x-api-key'] as string | undefined;
      remoteWss.handleUpgrade(request, socket, head, async (ws: WebSocket) => {
        try {
          if (!apiKey) { ws.close(4003, 'Missing X-Api-Key'); return; }
          // Note: no is_active check here — matches agentAuth middleware which also omits it.
          // is_active may be NULL on older keys; requiring true would silently block WS while
          // HTTP push (which uses agentAuth) succeeds — causing the agent to reconnect every 10s.
          const keyRow = await db('agent_api_keys').where({ key: apiKey }).first();
          if (!keyRow || keyRow.is_active === false) { ws.close(4003, 'Invalid API key'); return; }
          const deviceUuid = request.headers['x-device-uuid'] as string | undefined;
          // Identity v2: an agent switching to the shared ID dials with its
          // current ID (alias-aware lookup covers the switch itself) and
          // announces the target; the HTTP push does the re-keying.
          const identity = deviceIdentityService.parseHeaders(request as any);
          let device = deviceUuid
            ? await deviceIdentityService.findDevice(deviceUuid, keyRow.tenant_id)
            : await db('devices').where({ api_key_id: keyRow.id }).first();
          if (!device && identity) {
            device = await db('devices').where({ uuid: identity.target, tenant_id: keyRow.tenant_id }).first();
          }

          // SECURITY: if a device row exists but was registered with a
          // DIFFERENT api_key_id, the agent is presenting a UUID it
          // doesn't own. Treat as auth failure rather than silently
          // letting a foreign key claim the device. (The previous
          // behaviour would have re-attached the device to whichever
          // key talked to it last — an attacker who knew a target
          // device's UUID + had any valid API key in the same tenant
          // could intercept its command channel.)
          if (device && device.api_key_id != null && device.api_key_id !== keyRow.id) {
            ws.close(4003, 'Device/API-key mismatch');
            return;
          }

          // No device row yet — this can happen if the WS channel reaches the
          // server before the first HTTP push (fresh install, flaky HTTP, HTTPS
          // misconfig on an HTTP-only agent, etc.). Auto-register a minimal
          // pending row here so the device actually appears in the admin UI
          // for approval rather than silently spinning on 4004 forever.
          // Subsequent HTTP pushes will fill in hostname, OS, metrics.
          // Not for a v2 agent: its first push registers (or adopts) the row
          // under the shared ID; a row created here under the legacy ID would
          // be left behind as a pending orphan.
          if (!device && deviceUuid && !identity) {
            const { deviceId } = await deviceService.registerDevice({
              uuid: deviceUuid,
              hostname: deviceUuid,
              osType: 'other',
              apiKeyId: keyRow.id,
              tenantId: keyRow.tenant_id,
            });
            device = await db('devices').where({ id: deviceId }).first();
            logger.info({ deviceId, uuid: deviceUuid }, 'Auto-registered device via WS channel');
          }

          if (!device) { ws.close(4004, 'Device not found'); return; }
          await agentHub.register(device.id, device.tenant_id, ws, keyRow.id, device.uuid, clientIp(request));
        } catch (err) {
          logger.error(err, 'Agent command channel setup error');
          ws.close(4000, 'Internal error');
        }
      });
      return; // handled — do NOT forward to socket.io
    }

    // ── Oblireach agent command channel ────────────────────────────────────
    if (OBLIREACH_CMD_RE.test(pathname)) {
      const apiKey  = request.headers['x-api-key'] as string | undefined;
      const reqUrl  = new URL(request.url ?? '/', 'http://localhost');
      const devUuid = reqUrl.searchParams.get('uuid');
      remoteWss.handleUpgrade(request, socket, head, async (ws: WebSocket) => {
        try {
          if (!apiKey)  { ws.close(4003, 'Missing X-Api-Key'); return; }
          if (!devUuid) { ws.close(4000, 'Missing uuid query param'); return; }
          // No is_active check — matches agentAuth middleware (is_active may be NULL on older keys).
          const keyRow = await db('agent_api_keys').where({ key: apiKey }).first();
          if (!keyRow || keyRow.is_active === false) { ws.close(4003, 'Invalid API key'); return; }
          // SECURITY: this channel receives open_remote_tunnel (relay token +
          // privacy unlock token). If the uuid belongs to an enrolled device,
          // the key must be the one that device is bound to (same rule as
          // /api/agent/ws) — otherwise any key could claim another device's
          // channel. A uuid with no devices row (standalone ObliReach agent)
          // is still accepted: no session can target it, and oblireachHub.push
          // re-checks the key binding before sending anything sensitive.
          // Identity v2: the channel is filed under the device's current
          // devices.uuid even while this agent still reports a legacy ID.
          const reachClaim = deviceIdentityService.parseHeaders(request as any);
          const reachUuid = isUuid(devUuid)
            ? await deviceIdentityService.canonicalReachUuid(devUuid, reachClaim, keyRow.tenant_id)
            : devUuid;
          if (isUuid(reachUuid)) {
            const device = await db('devices').where({ uuid: reachUuid }).first('id', 'tenant_id', 'api_key_id');
            if (device && !agentKeyMayActForDevice(keyRow, device)) {
              logger.warn({ deviceId: device.id, apiKeyId: keyRow.id, ip: clientIpOf() }, 'ObliReach command channel refused: device/API-key mismatch');
              ws.close(4003, 'Device/API-key mismatch');
              return;
            }
          }
          await oblireachHub.register(reachUuid, keyRow.tenant_id, ws, keyRow.id, devUuid);
          oblireachHub.noteIdentityTarget(reachUuid, reachClaim?.target ?? null);
        } catch (err) {
          logger.error(err, 'ObliReach command channel setup error');
          ws.close(4000, 'Internal error');
        }
      });
      return; // handled — do NOT forward to socket.io
    }

    // ── Everything else → forward to socket.io's original listeners ─────────
    for (const listener of sioUpgradeListeners) {
      (listener as (...args: unknown[]) => void).call(server, request, socket, head);
    }
  });
  // ─────────────────────────────────────────────────────────────────────────

  // Initialize services that need the io instance
  deviceService.setIO(io);
  setLiveAlertIO(io);

  // Start background jobs
  scheduleService.start();    // Script scheduler + catch-up
  commandService.startCleanupJob();  // Expire timed-out commands

  // Native SMART disk-health collector (server-driven, zero agent change)
  import('./services/diskHealthCollector.service')
    .then(({ diskHealthCollector }) => diskHealthCollector.start())
    .catch((err) => logger.error(err, 'diskHealthCollector failed to start'));

  // Rewind time-machine process-snapshot collector (server-driven, zero agent change)
  import('./services/rewindCollector.service')
    .then(({ rewindCollector }) => rewindCollector.start())
    .catch((err) => logger.error(err, 'rewindCollector failed to start'));

  // Start device offline detection job (every 30s)
  setInterval(() => deviceService.checkOfflineDevices(), 30_000);

  // Expire pending_uninstall devices whose 10-min timer has elapsed (every 30s)
  setInterval(() => deviceService.expireUninstalls(), 30_000);

  // Start inventory retention job (every 6h) — software lists only; hardware
  // scans are pruned by retentionService (below)
  setInterval(() => deviceService.pruneInventory(), 6 * 60 * 60 * 1000);

  // Per-device metric-history retention (hourly ≤72h, daily ≤40d). The history
  // buckets are written incrementally on each push; this just prunes. Every 6h.
  deviceService.pruneMetricHistory().catch(() => {});
  setInterval(() => deviceService.pruneMetricHistory(), 6 * 60 * 60 * 1000);

  // Daily fleet snapshot for the dashboard hero deltas + timeseries chart.
  // Run once on boot (idempotent via onConflict merge) so a fresh deploy has
  // a "today" row right away, then every 24h. The chart synthesises today's
  // live point regardless, so the cadence isn't user-visible.
  deviceService.snapshotFleetDaily().catch(() => {});
  setInterval(() => deviceService.snapshotFleetDaily(), 24 * 60 * 60 * 1000);

  // Hourly fleet snapshot — feeds the 24h "Activité du parc" view. Run once
  // on boot (so the dashboard has at least 1 historical point right away)
  // and every hour after that. Retention is handled by the job itself
  // (7 days of hourly history, kept ~168 rows per tenant max).
  deviceService.snapshotFleetHourly().catch(() => {});
  setInterval(() => deviceService.snapshotFleetHourly(), 60 * 60 * 1000);

  // Data retention (services/retention.service.ts): batched purges of the
  // history tables (command_queue, script_executions, inventory, compliance,
  // scenario runs, notification log, remote sessions, …). First run 5 min
  // after boot, then every 6h, never overlapping.
  {
    const { retentionService } = require('./services/retention.service');
    retentionService.start();
  }

  // Expired "Trust this IP" 2FA entries — hourly (checks already ignore them).
  {
    const { tfaTrustService } = require('./services/tfaTrust.service');
    setInterval(() => {
      tfaTrustService.sweepExpired()
        .then((n: number) => { if (n > 0) logger.info({ count: n }, 'Expired 2FA trusted IPs swept'); })
        .catch(() => {});
    }, 60 * 60 * 1000);
  }

  // Maintenance windows: start/end notifications (every minute) + cleanup of
  // one-time windows ended more than 30 days ago (every 5 min).
  {
    const { maintenanceService } = require('./services/maintenance.service');
    maintenanceService.startJobs();
  }

  // Self-healing: purge orphaned records from tables whose device no longer exists (every 4h)
  deviceService.cleanOrphans().catch(() => {}); // run once at startup
  setInterval(() => deviceService.cleanOrphans(), 4 * 60 * 60 * 1000);

  // No relay survives a restart: sessions the previous run left 'active' are closed.
  await remoteService.closeOrphanedSessionsAtBoot()
    .catch((err) => logger.error(err, 'Closing remote sessions left active by the previous run failed'));

  // Clean up stale remote sessions (waiting/connecting with no activity) every 2 min
  remoteService.cleanupStaleSessions();                                    // run once at startup
  setInterval(() => remoteService.cleanupStaleSessions(), 2 * 60 * 1000); // then every 2 min

  // Device-bound 2FA periodic tasks:
  //  - hourly: delete challenges expired for more than 7 days;
  //  - daily, ONLY while the feature is on (runDailyTasks): revoke ('stale')
  //    keys unused for 180 days (time spent with the feature off does
  //    not count), refresh the Google attestation revocation list (no effect
  //    when unreachable) and revoke the keys whose chain it now marks
  //    revoked ('attestation_revoked'). Off: no sweep, no call to Google.
  // First run 2 min after start (never in the boot path).
  {
    const dk = () => import('./services/deviceKey/deviceKey.service');
    const hourly = () => dk().then(({ deviceKeyService }) => deviceKeyService.sweepChallenges())
      .catch((err) => logger.warn({ err }, 'device key challenge sweep failed'));
    const daily = () => dk().then(({ deviceKeyService }) => deviceKeyService.runDailyTasks())
      .catch((err) => logger.warn({ err }, 'device key daily tasks failed'));
    setTimeout(() => { void hourly(); void daily(); }, 2 * 60 * 1000);
    setInterval(() => { void hourly(); }, 60 * 60 * 1000);
    setInterval(() => { void daily(); }, 24 * 60 * 60 * 1000);
  }

  // Self-healing: reports left stuck in 'generating' by a mid-generation
  // restart never resolve on their own (generation is fire-and-forget). Mark
  // orphaned rows (>15 min) as errored — once at startup so pre-existing
  // zombies clear on deploy, then every 15 min for runtime crashes.
  const { reportService } = require('./services/report.service');
  reportService.sweepStaleGenerating().catch(() => {});                       // run once at startup
  setInterval(() => reportService.sweepStaleGenerating().catch(() => {}), 15 * 60 * 1000);

  // Two-step approvals: pending requests past their 30-min expiry become
  // 'expired' (audited 'approval.expired', APPROVAL_UPDATED pushed, sealed
  // executor data wiped) — once at startup, then every minute.
  {
    const { approvalService } = require('./services/approval.service');
    approvalService.startSweeper();
  }

  // SSH Bastion (ObliJump) — opt-in via .env; binds its own port only when
  // SSH_BASTION_ENABLED=true. No-op otherwise.
  const { startSshBastion } = require('./services/sshBastion/sshBastion.service');
  startSshBastion();

  // Sync built-in preset rules to existing policies (auto-update on deploy)
  const { complianceService } = require('./services/compliance.service');
  complianceService.syncPresetsToExistingPolicies()
    .then((n: number) => { if (n > 0) logger.info({ synced: n }, 'Compliance presets synced to existing policies'); })
    .catch(() => {});

  // Scheduled compliance checks — every 6h, skip devices checked within the window
  const COMPLIANCE_INTERVAL = 6 * 60 * 60 * 1000;
  setTimeout(() => complianceService.runScheduledChecks(COMPLIANCE_INTERVAL).catch(() => {}), 60_000); // first run 1 min after startup
  setInterval(() => complianceService.runScheduledChecks(COMPLIANCE_INTERVAL).catch(() => {}), COMPLIANCE_INTERVAL);

  // Scheduled software compliance checks — every 6h, same pattern
  const { softwareComplianceService } = require('./services/softwareCompliance.service');
  const SW_COMPLIANCE_INTERVAL = 6 * 60 * 60 * 1000;
  setTimeout(() => softwareComplianceService.runScheduledChecks(SW_COMPLIANCE_INTERVAL).catch(() => {}), 90_000); // first run 1.5 min after startup
  setInterval(() => softwareComplianceService.runScheduledChecks(SW_COMPLIANCE_INTERVAL).catch(() => {}), SW_COMPLIANCE_INTERVAL);

  // CVE catalog sync — daily refresh + fleet rescan. Pulls every
  // registered source (NVD KEV + NVD recent CRITICAL today, extensible
  // via CVE_SOURCES in cve.service.ts). Master tenant rescan covers
  // every child in one pass since device_cves is tenant-scoped at the
  // device level.
  setTimeout(async () => {
    try {
      const { cveService } = await import('./services/cve.service');
      await cveService.syncAllSources();
      await cveService.rescanFleet(1);
    } catch (err) { logger.error(err, 'CVE initial sync/rescan failed'); }
  }, 2 * 60_000);
  setInterval(async () => {
    try {
      const { cveService } = await import('./services/cve.service');
      await cveService.syncAllSources();
      await cveService.rescanFleet(1);
    } catch (err) { logger.error(err, 'CVE daily sync/rescan failed'); }
  }, 24 * 60 * 60 * 1000);

  // ── Scenarios v2 — boot migration + cron tick ──────────────────────────
  // Convert any leftover v1 (steps-based) scenarios to the new graph
  // model, then start a per-minute tick that fires schedule_cron triggers.
  // Both run with an exception barrier so a single broken scenario
  // doesn't take the boot down.
  (async () => {
    try {
      const { migrateAllV1Scenarios } = await import('./services/scenarioMigrate.service');
      await migrateAllV1Scenarios();
    } catch (err) { logger.error(err, 'Scenarios v2 boot migration failed'); }
    try {
      const { scenarioGraphCron } = await import('./services/scenarioGraphCron.service');
      scenarioGraphCron.start();
    } catch (err) { logger.error(err, 'Scenarios v2 cron scheduler failed to start'); }
    try {
      const { rearmWaitTimersOnBoot } = await import('./services/scenarioGraph.service');
      await rearmWaitTimersOnBoot();
    } catch (err) { logger.error(err, 'Scenarios v2 wait timer rearm failed'); }
  })();

  server.listen(config.port, () => {
    logger.info({ port: config.port, env: config.nodeEnv }, `Obliance RMM started`);

    // Indexes of the big tables, built in the background now that we serve
    // (never in a migration: services/backgroundIndexes.service.ts).
    const { startBackgroundIndexes } = require('./services/backgroundIndexes.service');
    startBackgroundIndexes();

    // Sync preference schemas with Obligate (non-blocking)
    obligateService.syncPreferenceSchemas().catch(() => {});
    obligateService.announceSelfInfo().catch(() => {});
    // Capability schemas USED to be pushed to Obligate so admins could
    // tick per-user capability boxes from there. Dropped: capabilities
    // live entirely in Obliance now (role = what / team = where), and
    // pushing them to Obligate created confusing user-level toggles
    // that didn't map to anything on the Obliance side. Obligate-side
    // cleanup is handled separately.
  });

  // Graceful shutdown
  const shutdown = async () => {
    logger.info('Shutting down...');
    scheduleService.stop();
    import('./services/diskHealthCollector.service')
      .then(({ diskHealthCollector }) => diskHealthCollector.stop())
      .catch(() => {});
    import('./services/rewindCollector.service')
      .then(({ rewindCollector }) => rewindCollector.stop())
      .catch(() => {});
    remoteWss.close();
    server.close(() => {
      db.destroy();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

/**
 * Initial administrator, created only while no administrator exists (fresh
 * database): DEFAULT_ADMIN_USERNAME with DEFAULT_ADMIN_PASSWORD when set,
 * else with a random password printed ONCE in the startup logs. Only its
 * hash is stored: it can never be shown again. Outside development, a weak
 * DEFAULT_ADMIN_PASSWORD stops the start here (defaultAdminPasswordError);
 * once an administrator exists, the variable is not used. Before, the
 * account was created (admin123 by default) whenever the username was free,
 * e.g. after the first administrator had been renamed. The account then
 * remains the break-glass access when Obligate is unreachable.
 */
async function ensureDefaultAdmin() {
  if (await db('users').where({ role: 'admin' }).first('id')) {
    if (config.defaultAdminPassword && isWeakAdminPassword(config.defaultAdminPassword)) {
      logger.warn('DEFAULT_ADMIN_PASSWORD holds a weak or default value; it is not used (an administrator exists): remove it from the environment.');
    }
    return;
  }
  const passwordError = defaultAdminPasswordError();
  if (passwordError) {
    logger.fatal(`${passwordError} Refusing to create the initial administrator: refusing to start.`);
    process.exit(1);
  }

  const username = config.defaultAdminUsername;
  if (await db('users').where({ username }).first('id')) {
    logger.warn(
      { username },
      'No administrator exists, but this username belongs to a non-admin account: no initial administrator ' +
      'created. Set DEFAULT_ADMIN_USERNAME to a free username to get one.',
    );
    return;
  }

  const generated = !config.defaultAdminPassword;
  const password = config.defaultAdminPassword || generatePassword();
  if (!generated && isWeakAdminPassword(password)) {
    logger.warn('The initial administrator gets a weak DEFAULT_ADMIN_PASSWORD (accepted in development only).');
  }
  const hash = await hashPassword(password);

  // All or nothing: a half-created account would keep a password nobody saw.
  await db.transaction(async (trx) => {
    const [user] = await trx('users').insert({
      username,
      password_hash: hash,
      display_name: 'Administrator',
      role: 'admin',
      is_active: true,
    }).returning('id');
    const userId = user?.id ?? user;
    // Ensure default tenant exists
    let tenant = await trx('tenants').where({ id: 1 }).first();
    if (!tenant) {
      [tenant] = await trx('tenants').insert({ name: 'Default', slug: 'default' }).returning('*');
    }
    await trx('user_tenants').insert({ user_id: userId, tenant_id: 1, role: 'admin' }).onConflict(['user_id','tenant_id']).ignore();
  });

  if (generated) {
    logger.warn(
      { username },
      `Initial administrator "${username}" created: sign in, change the password and enable two-factor ` +
      `authentication. Generated password, shown only this once: ${password}`,
    );
  } else {
    logger.info(
      { username },
      'Initial administrator created with DEFAULT_ADMIN_PASSWORD: change it and enable two-factor authentication at first sign-in',
    );
  }
}

main().catch((err) => {
  logger.error(err, 'Fatal error during startup');
  process.exit(1);
});
