/**
 * Remote screen resolution selector — the web viewer's side of the
 * `display_modes` feature (Oblireach repository — agent: agent/displaymode.go;
 * desktop: client-app/reach_resolution.go).
 *
 *   viewer → agent {type:'display_modes_get', id}
 *   agent → viewer {type:'display_modes', id, monitor, changeable, reason?,
 *                   current:{w,h,hz}, modes:[{w,h,hz,current?}]}
 *   viewer → agent {type:'display_mode_set', id, w, h, hz, keep}
 *   agent → viewer {type:'display_mode_result', id, ok, code?}
 *
 * Only sent to an agent that lists 'display_modes' in init.features (Windows
 * capture helper). An RDP session answers changeable:false, reason 'rdp'.
 * keep:false (the default) = the previous resolution comes back when the
 * session ends; keep:true = the chosen one stays.
 */

export interface ReachDisplayMode {
  w: number;
  h: number;
  /** Refresh rate in Hz (0 = unknown / hardware default). */
  hz: number;
  current: boolean;
}

export interface ReachDisplayModes {
  changeable: boolean;
  /** Why not changeable: 'rdp' | 'unavailable' | 'session_changed' | ''. */
  reason: string;
  /** Index of the monitor the change applies to (-1 unknown). */
  monitor: number;
  current: ReachDisplayMode | null;
  modes: ReachDisplayMode[];
}

export interface ReachDisplayModeResult {
  id: string;
  ok: boolean;
  code: string;
}

const int = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : 0);

function parseMode(v: unknown): ReachDisplayMode | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const w = int(o.w), h = int(o.h);
  if (w <= 0 || h <= 0) return null;
  const hz = int(o.hz);
  return { w, h, hz: hz > 0 ? hz : 0, current: o.current === true };
}

/** Normalises a `display_modes` answer (agent input: malformed modes dropped). */
export function parseDisplayModes(msg: Record<string, unknown>): ReachDisplayModes {
  const modes = Array.isArray(msg.modes)
    ? msg.modes.map(parseMode).filter((m): m is ReachDisplayMode => m !== null).slice(0, 200)
    : [];
  let current = parseMode(msg.current);
  if (current) current = { ...current, current: true };
  else current = modes.find((m) => m.current) ?? null;
  return {
    changeable: msg.changeable === true,
    reason: typeof msg.reason === 'string' ? msg.reason : '',
    monitor: typeof msg.monitor === 'number' ? msg.monitor : -1,
    current,
    modes,
  };
}

export function parseDisplayModeResult(msg: Record<string, unknown>): ReachDisplayModeResult {
  return {
    id: typeof msg.id === 'string' ? msg.id : '',
    ok: msg.ok === true,
    code: typeof msg.code === 'string' ? msg.code : '',
  };
}

/** '@ 144 Hz' only when the offered modes do not all share one refresh rate. */
export function showRefreshRates(modes: ReachDisplayMode[]): boolean {
  return new Set(modes.filter((m) => m.hz > 1).map((m) => m.hz)).size > 1;
}

let seq = 0;
/** A request id (the agent accepts 1..32 of [A-Za-z0-9_-]). */
export function nextDisplayModeId(): string {
  seq += 1;
  return `res${seq}`;
}
