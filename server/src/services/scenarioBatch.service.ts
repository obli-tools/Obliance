import type { Knex } from 'knex';
import { db } from '../db';

// Scenario run batches + consolidated output of a script node.
//
// A batch = the runs ONE firing created on several devices. Since migration
// 146 manual triggers (POST /:id/trigger, editor "Run on devices") and every
// cron tick of a schedule trigger stamp a shared scenario_runs.batch_id.
// Single-device event triggers (session_login, machine_boot, metric_*,
// group_join…) keep batch_id NULL.
//
// Rows with a NULL batch_id (older rows + event triggers) get a synthetic key:
//  - the trigger_source batch marker when there is one ("manual:batch:…",
//    "graph-run:batch:…" — written since long before migration 146);
//  - else (trigger type, created_at truncated to the minute): e.g. the cron
//    runs of one tick, or the session_login runs of the same minute.
//
// Keys (URL-safe once encodeURIComponent'ed by the client):
//   b.<uuid>                 batch_id
//   m.<marker>               trigger_source marker (without "|__single_node")
//   t.<trigger_type>.<epoch minute>

/** Node types that send a command to an agent and store its stdout. */
export const SCRIPT_NODE_TYPES = ['run_script', 'run_command'] as const;

/** Most recent runs read to build the batch list (index scenario_id, created_at). */
const RUN_CAP = 5000;

const KEY_SQL = `CASE
  WHEN batch_id IS NOT NULL THEN 'b.' || batch_id::text
  WHEN trigger_source LIKE '%:batch:%' THEN 'm.' || split_part(trigger_source, '|', 1)
  ELSE 't.' || trigger_type::text || '.' || floor(extract(epoch from created_at) / 60)::bigint::text
END`;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface BatchScope {
  scenarioId: number;
  tenantId: number;
  /** Platform admin on the master tenant: every tenant's runs. */
  isMaster: boolean;
  /** Devices the caller may read ('all' = admin). */
  visible: number[] | 'all';
}

export interface BatchSummary {
  key: string;
  batchId: string | null;
  triggerType: string;
  startedAt: string | null;
  deviceCount: number;
  counts: { success: number; failed: number; running: number; cancelled: number };
}

export interface ConsolidatedNode { nodeId: number; type: string; label: string; runCount: number }

export interface ConsolidatedResult {
  batch: BatchSummary | null;
  scriptNodes: ConsolidatedNode[];
  nodeId: number | null;
  rows: Array<{
    deviceId: number; device: string; status: string;
    exitCode: number | null; stdout: string | null; stderr: string | null;
  }>;
}

/** Runs of the scenario the caller may see (tenant scope + device visibility). */
function scopedRuns(scope: BatchScope, alias = 'scenario_runs'): Knex.QueryBuilder {
  const q = db(alias === 'scenario_runs' ? 'scenario_runs' : `scenario_runs as ${alias}`)
    .where(`${alias}.scenario_id`, scope.scenarioId);
  if (!scope.isMaster) q.where(`${alias}.tenant_id`, scope.tenantId);
  if (scope.visible !== 'all') q.whereRaw(`${alias}.device_id = ANY(?::int[])`, [scope.visible]);
  return q;
}

/** Adds the conditions of a batch key; false = malformed key. */
function applyKey(q: Knex.QueryBuilder, key: string, alias: string): boolean {
  const c = (col: string) => `${alias}.${col}`;
  if (key.startsWith('b.')) {
    const id = key.slice(2);
    if (!UUID_RE.test(id)) return false;
    q.where(c('batch_id'), id);
    return true;
  }
  if (key.startsWith('m.')) {
    const marker = key.slice(2);
    if (!marker || marker.length > 200 || !marker.includes(':batch:')) return false;
    q.whereNull(c('batch_id'))
      .where(c('trigger_source'), 'like', '%:batch:%')
      .whereRaw(`split_part(${c('trigger_source')}, '|', 1) = ?`, [marker]);
    return true;
  }
  const m = /^t\.([a-z_]{1,64})\.(\d{1,12})$/.exec(key);
  if (!m) return false;
  const minute = Number(m[2]);
  const from = new Date(minute * 60_000);
  const to = new Date((minute + 1) * 60_000);
  q.whereNull(c('batch_id'))
    .where(function () {
      this.whereNull(c('trigger_source')).orWhere(c('trigger_source'), 'not like', '%:batch:%');
    })
    .whereRaw(`${c('trigger_type')}::text = ?`, [m[1]])
    .where(c('created_at'), '>=', from)
    .where(c('created_at'), '<', to);
  return true;
}

function toIso(v: unknown): string | null {
  if (v == null) return null;
  return v instanceof Date ? v.toISOString() : String(v);
}

function rowToSummary(r: any): BatchSummary {
  return {
    key: r.key,
    batchId: r.batch_id ?? null,
    triggerType: r.trigger_type,
    startedAt: toIso(r.started_at),
    deviceCount: Number(r.device_count) || 0,
    counts: {
      success: Number(r.success) || 0,
      failed: Number(r.failed) || 0,
      running: Number(r.running) || 0,
      cancelled: Number(r.cancelled) || 0,
    },
  };
}

const AGG_SELECT = [
  db.raw('min(batch_id::text) as batch_id'),
  db.raw('min(trigger_type::text) as trigger_type'),
  db.raw('min(coalesce(started_at, created_at)) as started_at'),
  db.raw('count(distinct device_id) as device_count'),
  db.raw("count(*) filter (where status = 'success') as success"),
  db.raw("count(*) filter (where status in ('failure', 'timeout')) as failed"),
  db.raw("count(*) filter (where status in ('pending', 'running')) as running"),
  db.raw("count(*) filter (where status = 'cancelled') as cancelled"),
  db.raw('count(*) as run_count'),
];

export const scenarioBatchService = {
  /** Recent batches of a scenario, newest first. */
  async listBatches(scope: BatchScope, limit = 30): Promise<BatchSummary[]> {
    if (scope.visible !== 'all' && scope.visible.length === 0) return [];
    const recent = scopedRuns(scope)
      .orderBy('created_at', 'desc')
      .limit(RUN_CAP)
      .select('id', 'batch_id', 'trigger_type', 'trigger_source', 'status', 'device_id', 'started_at', 'created_at');
    const keyed = db.from(recent.as('r0')).select('*', db.raw(`${KEY_SQL} as key`));
    const groups = await db.from(keyed.as('r'))
      .select('key', ...AGG_SELECT)
      .groupBy('key')
      .orderBy('started_at', 'desc') as any[];
    // The run cap may have cut the oldest batch: drop it rather than show it
    // with a partial device count.
    const fetched = groups.reduce((n, g) => n + (Number(g.run_count) || 0), 0);
    if (fetched >= RUN_CAP && groups.length > 1) groups.pop();
    return groups.slice(0, Math.max(1, Math.min(limit, 200))).map(rowToSummary);
  },

  /**
   * One row per device of the batch (its latest run) with the latest node run
   * of the chosen script node. Default node: the first script node of the
   * graph (top to bottom) that has a node run in the batch.
   * A run without a node run of that node: status 'pending' while the run is
   * still pending/running (no answer yet), else 'skipped' — the run ended
   * without reaching the node (an earlier node failed, a branch went
   * elsewhere, cancelled…); its error message, if any, is given as stderr.
   * null = malformed key.
   */
  async consolidated(scope: BatchScope, key: string, wantedNodeId?: number | null): Promise<ConsolidatedResult | null> {
    const nodes = await db('scenario_nodes')
      .where({ scenario_id: scope.scenarioId })
      .whereIn('type', SCRIPT_NODE_TYPES as unknown as string[])
      .orderBy([{ column: 'position_y' }, { column: 'position_x' }, { column: 'id' }])
      .select('id', 'type', 'label', 'config') as Array<{ id: number; type: string; label: string | null; config: any }>;

    const empty: ConsolidatedResult = { batch: null, scriptNodes: [], nodeId: null, rows: [] };
    if (scope.visible !== 'all' && scope.visible.length === 0) {
      return applyKey(db('scenario_runs'), key, 'scenario_runs') ? empty : null;
    }

    // Batch summary (also validates the key).
    const sumQ = scopedRuns(scope);
    if (!applyKey(sumQ, key, 'scenario_runs')) return null;
    const sum = await sumQ.select(...AGG_SELECT).first() as any;
    const batch = sum && Number(sum.run_count) > 0 ? rowToSummary({ ...sum, key }) : null;

    // Latest run per device of the batch.
    const runsQ = scopedRuns(scope, 'r');
    applyKey(runsQ, key, 'r');
    const runs = await runsQ
      .join('devices as d', 'd.id', 'r.device_id')
      .distinctOn('r.device_id')
      .orderBy([{ column: 'r.device_id' }, { column: 'r.created_at', order: 'desc' }])
      .select('r.id', 'r.device_id', 'r.status', 'r.error_message', 'd.display_name', 'd.hostname') as Array<{
        id: string; device_id: number; status: string; error_message: string | null;
        display_name: string | null; hostname: string | null;
      }>;

    const nodeIds = nodes.map((n) => n.id);
    const runIds = runs.map((r) => r.id);
    const nodeRuns = nodeIds.length && runIds.length
      ? await db('scenario_node_runs')
          .whereRaw('run_id = ANY(?::uuid[])', [runIds])
          .whereRaw('node_id = ANY(?::int[])', [nodeIds])
          .distinctOn(['run_id', 'node_id'])
          .orderBy([{ column: 'run_id' }, { column: 'node_id' }, { column: 'created_at', order: 'desc' }])
          .select('run_id', 'node_id', 'status', 'exit_code', 'stdout', 'stderr', 'error_message') as Array<{
            run_id: string; node_id: number; status: string; exit_code: number | null;
            stdout: string | null; stderr: string | null; error_message: string | null;
          }>
      : [];

    const runCount = new Map<number, number>();
    nodeRuns.forEach((nr) => runCount.set(nr.node_id, (runCount.get(nr.node_id) ?? 0) + 1));

    // Labels: node label, else the script name / command type.
    const scriptIds = nodes
      .map((n) => Number((typeof n.config === 'string' ? JSON.parse(n.config) : n.config ?? {}).scriptId))
      .filter((id) => Number.isInteger(id) && id > 0);
    const scriptNames = new Map<number, string>();
    if (scriptIds.length) {
      const rows = await db('scripts').whereIn('id', scriptIds).select('id', 'name') as Array<{ id: number; name: string }>;
      rows.forEach((s) => scriptNames.set(s.id, s.name));
    }
    const scriptNodes: ConsolidatedNode[] = nodes.map((n) => {
      const cfg = (typeof n.config === 'string' ? JSON.parse(n.config) : n.config) ?? {};
      const label = (n.label ?? '').trim()
        || (n.type === 'run_script' ? scriptNames.get(Number(cfg.scriptId)) : cfg.commandType)
        || `${n.type} #${n.id}`;
      return { nodeId: n.id, type: n.type, label: String(label), runCount: runCount.get(n.id) ?? 0 };
    });

    const nodeId = wantedNodeId != null && scriptNodes.some((n) => n.nodeId === wantedNodeId)
      ? wantedNodeId
      : (scriptNodes.find((n) => n.runCount > 0) ?? scriptNodes[0])?.nodeId ?? null;

    const byRun = new Map<string, (typeof nodeRuns)[number]>();
    nodeRuns.forEach((nr) => { if (nr.node_id === nodeId) byRun.set(nr.run_id, nr); });

    const rows = nodeId == null ? [] : runs.map((r) => {
      const device = (r.display_name || r.hostname || `#${r.device_id}`).trim();
      const nr = byRun.get(r.id);
      const live = r.status === 'pending' || r.status === 'running';
      if (nr && !live && (nr.status === 'running' || nr.status === 'pending')) {
        // The run ended (cancelled, timed out…) while waiting on this node.
        return {
          deviceId: r.device_id, device, status: r.status, exitCode: null,
          stdout: nr.stdout, stderr: nr.stderr || r.error_message || null,
        };
      }
      if (nr) {
        return {
          deviceId: r.device_id, device, status: nr.status, exitCode: nr.exit_code,
          stdout: nr.stdout, stderr: nr.stderr || nr.error_message || null,
        };
      }
      return {
        deviceId: r.device_id, device, status: live ? 'pending' : 'skipped', exitCode: null,
        stdout: null, stderr: live ? null : r.error_message,
      };
    });

    return { batch, scriptNodes, nodeId, rows };
  },
};
