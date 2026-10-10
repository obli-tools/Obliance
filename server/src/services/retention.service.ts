import type { Knex } from 'knex';
import { db } from '../db';
import { logger } from '../utils/logger';
import { LEGACY_MIGRATION_SOURCE } from './legacyMigration.service';
import { isIndexReady } from './backgroundIndexes.service';

/**
 * Data retention — periodic purge of the history tables that otherwise grow
 * without bound (a dev install with ~100 devices reached command_queue 7.5M
 * rows / 19 GB and script_executions 4.3M rows / 9.8 GB, which saturated
 * Postgres).
 *
 * ── Schedule (index.ts) ─────────────────────────────────────────────────────
 * First run 5 min after boot (never in the boot path), then every 6 h. A run
 * still in progress when the next tick fires is not doubled (in-process
 * guard). Several server processes may each run it: every delete is
 * idempotent, they only share the work.
 *
 * ── How rows are deleted ────────────────────────────────────────────────────
 * In batches: `DELETE FROM t WHERE id IN (SELECT id … LIMIT n)`, each batch
 * its own short statement (no long transaction, no long lock), a short pause
 * between batches, and per step a cap on the batches and on the time spent
 * in one run (MAX_BATCHES_PER_STEP / MAX_MS_PER_STEP). A backlog bigger than
 * that (first run on a large install) is worked off over the next runs.
 * Every select is served by an index (the missing ones are built in the
 * background after startup: backgroundIndexes.service.ts).
 * Each step has its own try/catch: one failing table never stops the others.
 *
 * ── Settings (app_config, read once per run; absent / invalid → default) ────
 *   command_retention_days          7   command_queue: finished commands
 *                                       (success | failure | timeout |
 *                                       cancelled) — never pending / sent /
 *                                       ack_running. Commands the device
 *                                       change timeline reads (update_agent,
 *                                       reboot, install/uninstall_software,
 *                                       install_update(s)) and legacy-agent
 *                                       migrations follow
 *                                       execution_retention_days instead.
 *   execution_retention_days       90   script_executions (finished ones)
 *   inventory_retention_days       90   device_inventory_hardware scans —
 *                                       the latest scan of each device is
 *                                       always kept (existing key, shared
 *                                       with deviceService.pruneInventory)
 *   compliance_retention_days      90   compliance_results /
 *                                       software_compliance_results — the
 *                                       latest result of each (device,
 *                                       policy) / (device, list) always kept
 *   scenario_run_retention_days    90   scenario_runs (finished ones; node /
 *                                       step runs go with them by CASCADE)
 *   notification_log_retention_days 30  notification_log
 *   remote_session_retention_days 365   remote_sessions (ended ones) +
 *                                       chat_messages
 * Fixed (no setting):
 *   pending_approvals       decided / expired more than 90 days ago
 *   password_reset_tokens   used or expired more than 1 day ago
 *   ssh_bastion_bans        expired more than 30 days ago (never an active or
 *                           permanent ban)
 *   ssh_bastion_ip_grants   expired more than 1 day ago
 *   ssh_bastion_grants      closed / revoked / errored more than 365 days ago
 *   device_updates          'installed' rows untouched for 365 days
 *   live_alerts             RESOLVED alerts older than 30 days (hidden from
 *                           every list already; active ones are never removed
 *                           here — the per-tenant 200-row trim caps the table)
 *
 * Not purged: audit_logs (kept by design).
 */

const BATCH_SIZE = 5000;
/** Scenario runs cascade to their node / step runs: smaller batches. */
const SCENARIO_BATCH_SIZE = 1000;
const MAX_BATCHES_PER_STEP = 200;
const MAX_MS_PER_STEP = 10 * 60 * 1000;
const PAUSE_BETWEEN_BATCHES_MS = 100;

const DAY_MS = 24 * 60 * 60 * 1000;

export const RETENTION_DEFAULTS = {
  command_retention_days: 7,
  execution_retention_days: 90,
  inventory_retention_days: 90,
  compliance_retention_days: 90,
  scenario_run_retention_days: 90,
  notification_log_retention_days: 30,
  remote_session_retention_days: 365,
} as const;

export type RetentionKey = keyof typeof RETENTION_DEFAULTS;
export type RetentionSettings = Record<RetentionKey, number>;

/** Commands the device change timeline (changeEvent.service) reads: kept as
 *  long as script executions, not the short command retention. Few rows. */
const TIMELINE_COMMAND_TYPES = [
  'update_agent', 'reboot', 'install_software', 'uninstall_software', 'install_update', 'install_updates',
];
const FINISHED_COMMAND_STATUSES = ['success', 'failure', 'timeout', 'cancelled'];
const FINISHED_EXECUTION_STATUSES = ['success', 'failure', 'timeout', 'skipped', 'cancelled'];
const FINISHED_SCENARIO_RUN_STATUSES = ['success', 'failure', 'timeout', 'cancelled'];
const ENDED_REMOTE_SESSION_STATUSES = ['closed', 'failed', 'timeout', 'expired'];

/** Index without which deleting commands is a disaster: each deleted
 *  command_queue row makes Postgres SET NULL script_executions.command_queue_id
 *  (FK ON DELETE SET NULL), a full scan of script_executions per row without
 *  it. Built in the background by backgroundIndexes.service.ts. */
const EXEC_COMMAND_FK_INDEX = 'idx_script_exec_command_queue_id';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const placeholders = (list: readonly unknown[]) => list.map(() => '?').join(', ');

function rowCount(r: any): number {
  return Number(r?.rowCount ?? 0);
}

/** One positive integer per key; absent, non-numeric, < 1 → default. */
export async function readRetentionSettings(): Promise<RetentionSettings> {
  const keys = Object.keys(RETENTION_DEFAULTS) as RetentionKey[];
  const out = { ...RETENTION_DEFAULTS } as RetentionSettings;
  try {
    const rows = await db('app_config').whereIn('key', keys).select('key', 'value') as Array<{ key: string; value: string | null }>;
    for (const r of rows) {
      const raw = String(r.value ?? '').trim();
      const n = /^\d+$/.test(raw) ? parseInt(raw, 10) : NaN;
      if (Number.isFinite(n) && n >= 1) out[r.key as RetentionKey] = n;
      else logger.warn({ key: r.key, value: r.value }, 'retention: invalid app_config value, default used');
    }
  } catch (err) {
    logger.warn({ err }, 'retention: app_config unreadable, defaults used');
  }
  return out;
}

/**
 * Batched delete: `DELETE FROM table WHERE id IN (<select> LIMIT n)` until a
 * batch deletes fewer than n rows, or the step's batch / time cap is hit.
 * `selectIds` selects the `id` column only, without LIMIT.
 */
async function batchDelete(table: string, selectIds: string, bindings: readonly Knex.RawBinding[], batchSize = BATCH_SIZE): Promise<{ deleted: number; capped: boolean }> {
  const started = Date.now();
  let deleted = 0;
  for (let batch = 0; ; batch++) {
    if (batch >= MAX_BATCHES_PER_STEP || Date.now() - started > MAX_MS_PER_STEP) return { deleted, capped: true };
    const r = await db.raw(`DELETE FROM ${table} WHERE id IN (${selectIds} LIMIT ${batchSize})`, bindings);
    const n = rowCount(r);
    deleted += n;
    if (n < batchSize) return { deleted, capped: false };
    await sleep(PAUSE_BETWEEN_BATCHES_MS);
  }
}

type StepResult = { deleted: number; capped?: boolean } | { skipped: string };

let running: Promise<void> | null = null;

export const retentionService = {
  /** One full retention pass. Concurrent calls share the run in progress. */
  run(): Promise<void> {
    if (running) {
      logger.info('retention: previous run still in progress — tick skipped');
      return running;
    }
    running = this._run().finally(() => { running = null; });
    return running;
  },

  async _run(): Promise<void> {
    const t0 = Date.now();
    const s = await readRetentionSettings();
    const cutoff = (days: number) => new Date(Date.now() - days * DAY_MS);
    const results: Record<string, StepResult> = {};

    const step = async (name: string, fn: () => Promise<StepResult>) => {
      const ts = Date.now();
      try {
        const r = await fn();
        results[name] = r;
        if ('deleted' in r && r.capped) {
          logger.info({ step: name, deleted: r.deleted, ms: Date.now() - ts }, 'retention: step capped, the rest is purged by the next runs');
        }
      } catch (err) {
        logger.error({ err, step: name }, 'retention: step failed');
        results[name] = { skipped: 'error' };
      }
    };

    // 1. script_executions first: the commands deleted next then have fewer
    //    executions to SET NULL.
    await step('script_executions', () => {
      const c = cutoff(s.execution_retention_days);
      return batchDelete('script_executions',
        `SELECT id FROM script_executions
          WHERE created_at < ? AND status::text IN (${placeholders(FINISHED_EXECUTION_STATUSES)})`,
        [c, ...FINISHED_EXECUTION_STATUSES]);
    });

    // 2. command_queue — finished commands only. created_at < cutoff is
    //    implied by the finish date (a command finishes after its creation)
    //    and lets the (status, created_at) index serve the select.
    await step('command_queue', async () => {
      if (!(await isIndexReady(EXEC_COMMAND_FK_INDEX))) {
        logger.warn(`retention: index ${EXEC_COMMAND_FK_INDEX} not built yet (backgroundIndexes.service) — command_queue not purged this run`);
        return { skipped: `index ${EXEC_COMMAND_FK_INDEX} missing` };
      }
      const keep = `(type::text IN (${placeholders(TIMELINE_COMMAND_TYPES)}) OR COALESCE(source_type, '') = ?)`;
      const select = (keepClause: string) => `SELECT id FROM command_queue
          WHERE status IN (${placeholders(FINISHED_COMMAND_STATUSES)})
            AND created_at < ?
            AND COALESCE(finished_at, updated_at, created_at) < ?
            AND ${keepClause}`;
      const short = cutoff(s.command_retention_days);
      const a = await batchDelete('command_queue', select(`NOT ${keep}`),
        [...FINISHED_COMMAND_STATUSES, short, short, ...TIMELINE_COMMAND_TYPES, LEGACY_MIGRATION_SOURCE]);
      const long = cutoff(Math.max(s.execution_retention_days, s.command_retention_days));
      const b = await batchDelete('command_queue', select(keep),
        [...FINISHED_COMMAND_STATUSES, long, long, ...TIMELINE_COMMAND_TYPES, LEGACY_MIGRATION_SOURCE]);
      return { deleted: a.deleted + b.deleted, capped: a.capped || b.capped };
    });

    // 3. device_inventory_hardware — old scans, the latest of each device kept.
    await step('device_inventory_hardware', () => batchDelete('device_inventory_hardware',
      `SELECT h.id FROM device_inventory_hardware h
        WHERE h.scanned_at < ?
          AND EXISTS (SELECT 1 FROM device_inventory_hardware n
                       WHERE n.device_id = h.device_id
                         AND (n.scanned_at > h.scanned_at OR (n.scanned_at = h.scanned_at AND n.id > h.id)))`,
      [cutoff(s.inventory_retention_days)], 1000));

    // 4. compliance results — the latest of each (device, policy|list) kept.
    await step('compliance_results', () => batchDelete('compliance_results',
      `SELECT r.id FROM compliance_results r
        WHERE r.checked_at < ?
          AND EXISTS (SELECT 1 FROM compliance_results n
                       WHERE n.device_id = r.device_id AND n.policy_id = r.policy_id
                         AND (n.checked_at > r.checked_at OR (n.checked_at = r.checked_at AND n.id > r.id)))`,
      [cutoff(s.compliance_retention_days)]));
    await step('software_compliance_results', () => batchDelete('software_compliance_results',
      `SELECT r.id FROM software_compliance_results r
        WHERE r.checked_at < ?
          AND EXISTS (SELECT 1 FROM software_compliance_results n
                       WHERE n.device_id = r.device_id AND n.list_id = r.list_id
                         AND (n.checked_at > r.checked_at OR (n.checked_at = r.checked_at AND n.id > r.id)))`,
      [cutoff(s.compliance_retention_days)]));

    // 5. scenario_runs — finished runs (pending / running never), node and
    //    step runs by ON DELETE CASCADE. Kept: non-cancelled agent_approved
    //    runs — their existence IS the one-shot dedup of that trigger
    //    (scenarioService.fireTrigger), at most one per (scenario, device).
    await step('scenario_runs', () => {
      const c = cutoff(s.scenario_run_retention_days);
      return batchDelete('scenario_runs',
        `SELECT id FROM scenario_runs
          WHERE created_at < ?
            AND COALESCE(finished_at, updated_at, created_at) < ?
            AND status::text IN (${placeholders(FINISHED_SCENARIO_RUN_STATUSES)})
            AND NOT (trigger_type::text = 'agent_approved' AND status::text <> 'cancelled')`,
        [c, c, ...FINISHED_SCENARIO_RUN_STATUSES], SCENARIO_BATCH_SIZE);
    });

    // 6. notification_log.
    await step('notification_log', () => batchDelete('notification_log',
      'SELECT id FROM notification_log WHERE created_at < ?',
      [cutoff(s.notification_log_retention_days)]));

    // 7. remote_sessions (ended ones) + chat_messages. No FK between them
    //    (chat_messages.chat_id is the in-memory chat's random id).
    await step('remote_sessions', () => {
      const c = cutoff(s.remote_session_retention_days);
      return batchDelete('remote_sessions',
        `SELECT id FROM remote_sessions
          WHERE created_at < ? AND COALESCE(ended_at, created_at) < ?
            AND status::text IN (${placeholders(ENDED_REMOTE_SESSION_STATUSES)})`,
        [c, c, ...ENDED_REMOTE_SESSION_STATUSES]);
    });
    await step('chat_messages', () => batchDelete('chat_messages',
      'SELECT id FROM chat_messages WHERE created_at < ?',
      [cutoff(s.remote_session_retention_days)]));

    // 8. Small tables (fixed retention).
    await step('pending_approvals', () => {
      // 'pending' rows are expired by approvalService.sweepExpired (audited) first.
      const c = cutoff(90);
      return batchDelete('pending_approvals',
        `SELECT id FROM pending_approvals
          WHERE expires_at < ? AND status <> 'pending'
            AND COALESCE(executed_at, reviewed_at, created_at) < ?`,
        [c, c]);
    });
    await step('password_reset_tokens', () => {
      const c = cutoff(1);
      return batchDelete('password_reset_tokens',
        'SELECT id FROM password_reset_tokens WHERE expires_at < ? OR used_at < ?',
        [c, c]);
    });
    await step('ssh_bastion_bans', () => batchDelete('ssh_bastion_bans',
      'SELECT id FROM ssh_bastion_bans WHERE expires_at IS NOT NULL AND expires_at < ?',
      [cutoff(30)]));
    await step('ssh_bastion_ip_grants', () => batchDelete('ssh_bastion_ip_grants',
      'SELECT id FROM ssh_bastion_ip_grants WHERE expires_at < ?',
      [cutoff(1)]));
    await step('ssh_bastion_grants', () => {
      const c = cutoff(365);
      return batchDelete('ssh_bastion_grants',
        `SELECT id FROM ssh_bastion_grants
          WHERE status IN ('closed', 'revoked', 'error') AND COALESCE(closed_at, created_at) < ?`,
        [c]);
    });
    await step('device_updates', () => {
      // A row still reported by the agent's scans has its updated_at refreshed
      // at each scan: only installed updates no longer reported go.
      const c = cutoff(365);
      return batchDelete('device_updates',
        `SELECT id FROM device_updates
          WHERE status = 'installed' AND updated_at < ? AND COALESCE(installed_at, updated_at) < ?`,
        [c, c]);
    });
    await step('live_alerts', () => batchDelete('live_alerts',
      'SELECT id FROM live_alerts WHERE resolved_at IS NOT NULL AND created_at < ?',
      [cutoff(30)]));

    const deleted: Record<string, number> = {};
    const skipped: Record<string, string> = {};
    let total = 0;
    for (const [name, r] of Object.entries(results)) {
      if ('deleted' in r) { deleted[name] = r.deleted; total += r.deleted; } else skipped[name] = r.skipped;
    }
    logger.info({ total, deleted, ...(Object.keys(skipped).length ? { skipped } : {}), settings: s, ms: Date.now() - t0 }, 'retention: run complete');
  },

  /** index.ts: first run 5 min after boot, then every 6 h. */
  start(): void {
    const tick = () => { this.run().catch((err) => logger.error({ err }, 'retention: run failed')); };
    setTimeout(tick, 5 * 60 * 1000).unref?.();
    setInterval(tick, 6 * 60 * 60 * 1000).unref?.();
  },
};
