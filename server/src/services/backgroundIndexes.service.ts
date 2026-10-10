import { db } from '../db';
import { logger } from '../utils/logger';

// Indexes on the big, busy tables (command_queue, script_executions…) are
// built HERE, in the background once the server is up — never in a migration.
// A migration runs before the server listens: on a large install (prod
// 2026-10-06: command_queue tens of GB) CREATE INDEX took long enough to keep
// Obliance down, and a restart in the middle left the knex migration lock set.
//
// Each run: for every index, valid → nothing; half-built (invalid, e.g. an
// interrupted build) → dropped; missing → CREATE INDEX CONCURRENTLY (no write
// lock, the server keeps serving). One index at a time, on one dedicated
// connection, under a Postgres advisory lock so several server processes never
// build in parallel. Failures are logged and retried on the next run.
//
// Code that would full-scan without an index checks isIndexReady() first.

const INDEXES: Array<[name: string, definition: string]> = [
  // Schedule "notify once": previous finished batch of a schedule — formerly migration 141.
  ['idx_script_exec_schedule_finished', 'script_executions (schedule_id, finished_at DESC) WHERE batch_id IS NOT NULL AND finished_at IS NOT NULL'],
  // Retention purges (retention.service.ts). The first one is required before
  // command_queue rows are deleted: script_executions.command_queue_id is
  // ON DELETE SET NULL, a full scan of script_executions per row without it.
  ['idx_script_exec_command_queue_id', 'script_executions (command_queue_id) WHERE command_queue_id IS NOT NULL'],
  ['idx_script_exec_created_at', 'script_executions (created_at)'],
  ['idx_scenario_runs_created_at', 'scenario_runs (created_at)'],
  // Scenario run batches (migration 146, consolidated output of one firing).
  ['idx_scenario_runs_batch', 'scenario_runs (scenario_id, batch_id) WHERE batch_id IS NOT NULL'],
  ['idx_compliance_results_checked_at', 'compliance_results (checked_at)'],
  ['idx_sw_compliance_results_checked_at', 'software_compliance_results (checked_at)'],
  ['idx_inventory_hw_scanned_at', 'device_inventory_hardware (scanned_at)'],
  ['idx_notification_log_created_at', 'notification_log (created_at)'],
  ['idx_remote_sessions_created_at', 'remote_sessions (created_at)'],
  ['idx_chat_messages_created_at', 'chat_messages (created_at)'],
  ['idx_device_updates_installed_updated_at', "device_updates (updated_at) WHERE status = 'installed'"],
];

// pg_try_advisory_lock key (arbitrary, constant): "Obliance background indexes".
const LOCK_KEY = 4_100_001;
const FIRST_RUN_DELAY_MS = 60_000;
const RERUN_EVERY_MS = 6 * 3600_000;

const ready = new Set<string>();

/** True once the index exists and is valid (cached after the first yes). */
export async function isIndexReady(name: string): Promise<boolean> {
  if (ready.has(name)) return true;
  const r = await db.raw(
    `SELECT i.indisvalid AS valid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
      WHERE c.relname = ? AND c.relkind = 'i'`,
    [name],
  );
  const ok = !!(r.rows ?? [])[0]?.valid;
  if (ok) ready.add(name);
  return ok;
}

let running = false;

async function runOnce(): Promise<void> {
  if (running) return;
  running = true;
  // One dedicated connection: the advisory lock is per session, and
  // CREATE INDEX CONCURRENTLY must run outside any transaction.
  const client = await (db.client as any).acquireConnection();
  let locked = false;
  try {
    const got = await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY]);
    locked = !!got.rows?.[0]?.ok;
    if (!locked) {
      logger.info('background indexes: another server process is building them — skipped');
      return;
    }
    for (const [name, def] of INDEXES) {
      try {
        const st = await client.query(
          `SELECT i.indisvalid AS valid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
            WHERE c.relname = $1 AND c.relkind = 'i'`,
          [name],
        );
        const row = st.rows?.[0];
        if (row?.valid) { ready.add(name); continue; }
        if (row && !row.valid) {
          logger.warn({ index: name }, 'background indexes: half-built index found — dropped, rebuilding');
          await client.query(`DROP INDEX CONCURRENTLY IF EXISTS ${name}`);
        }
        const t0 = Date.now();
        logger.info({ index: name }, 'background indexes: building (no write lock, the server keeps serving)');
        await client.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS ${name} ON ${def}`);
        ready.add(name);
        logger.info({ index: name, seconds: Math.round((Date.now() - t0) / 1000) }, 'background indexes: built');
      } catch (err) {
        logger.error({ err, index: name }, 'background indexes: build failed — retried on the next run');
      }
    }
  } catch (err) {
    logger.error({ err }, 'background indexes: run failed');
  } finally {
    if (locked) {
      try { await client.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]); } catch { /* session ends anyway */ }
    }
    (db.client as any).releaseConnection(client);
    running = false;
  }
}

// ── Compaction of small, constantly updated tables ─────────────────────────
// Migration 142 keeps them from bloating (fillfactor + eager autovacuum), but
// autovacuum cannot shrink a table that already did (only VACUUM FULL can,
// under an exclusive lock). Once a day: a table far above its normal size is
// rewritten — only if its lock is obtained within 5 s (else next day), so the
// pushes waiting on it are never held long. The big history tables are never
// compacted here (far too long under lock; the retention purge plus normal
// autovacuum make their space reusable).
const HOT_TABLES: Array<{ table: string; maxBytes: number; maxRows: number }> = [
  { table: 'devices', maxBytes: 64 * 1024 * 1024, maxRows: 10_000 },
  { table: 'oblireach_devices', maxBytes: 64 * 1024 * 1024, maxRows: 10_000 },
];
const COMPACT_EVERY_MS = 24 * 3600_000;
const COMPACT_FIRST_DELAY_MS = 15 * 60_000;

async function compactHotTables(): Promise<void> {
  for (const { table, maxBytes, maxRows } of HOT_TABLES) {
    const client = await (db.client as any).acquireConnection();
    try {
      const st = await client.query(
        `SELECT pg_total_relation_size(c.oid) AS bytes, COALESCE(s.n_live_tup, 0) AS rows
           FROM pg_class c LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
          WHERE c.relname = $1 AND c.relkind = 'r'`,
        [table],
      );
      const row = st.rows?.[0];
      if (!row) continue;
      const bytes = Number(row.bytes), rows = Number(row.rows);
      if (bytes <= maxBytes || rows > maxRows) continue;
      const t0 = Date.now();
      logger.warn({ table, mb: Math.round(bytes / 1048576), rows }, 'hot table bloated — compacting (VACUUM FULL)');
      await client.query(`SET lock_timeout = '5s'`);
      try {
        await client.query(`VACUUM (FULL, ANALYZE) ${table}`);
        const after = await client.query('SELECT pg_total_relation_size($1::regclass) AS bytes', [table]);
        logger.info({ table, seconds: Math.round((Date.now() - t0) / 1000),
          mbAfter: Math.round(Number(after.rows?.[0]?.bytes ?? 0) / 1048576) }, 'hot table compacted');
      } catch (err: any) {
        if (err?.code === '55P03') logger.info({ table }, 'hot table busy — compaction retried tomorrow');
        else throw err;
      } finally {
        await client.query('RESET lock_timeout').catch(() => {});
      }
    } catch (err) {
      logger.error({ err, table }, 'hot table compaction failed');
    } finally {
      (db.client as any).releaseConnection(client);
    }
  }
}

/** Started once the server listens (index.ts). */
export function startBackgroundIndexes(): void {
  setTimeout(() => { void runOnce(); }, FIRST_RUN_DELAY_MS).unref?.();
  setInterval(() => {
    if (INDEXES.every(([name]) => ready.has(name))) return;
    void runOnce();
  }, RERUN_EVERY_MS).unref?.();
  setTimeout(() => { void compactHotTables(); }, COMPACT_FIRST_DELAY_MS).unref?.();
  setInterval(() => { void compactHotTables(); }, COMPACT_EVERY_MS).unref?.();
}
