/**
 * ObliReach viewer ↔ agent protocol — TypeScript copy of the contract
 * (Oblireach repository — Go: agent/protocol.go, client-app: constants in ui.go).
 *
 * Feature detection, not versions: the viewer only uses a behaviour when the
 * agent lists it in `init.features`. An agent never sends a new frame type or
 * push the viewer did not ask for. Old agents send no `features` at all.
 */

// ── Binary frame types (byte 0) ───────────────────────────────────────────────
export const FRAME = {
  JPEG: 0x01,
  H264: 0x02,
  VP9: 0x03,
  H265: 0x04,
  AV1: 0x05,
  /** Legacy audio: PCM s16le mono, 50 ms chunks, at init.audioRate. */
  AUDIO_PCM: 0x06,
  /** Audio v2: 20-byte header (see reachAudioPlayer.parseAudioV2) + fixed 20 ms frames. */
  AUDIO_V2: 0x07,
  /** viewer → agent: upload data `[0x20][tid u32 LE][seq u32 LE][data]`. */
  FILE_UP: 0x20,
  /** agent → viewer: download data, same layout. */
  FILE_DOWN: 0x21,
} as const;

export type ReachFeature =
  | 'view_gen'
  | 'mosaic'
  | 'clipboard_text'
  | 'clipboard_push'
  | 'clipboard_files'
  | 'file_upload'
  | 'file_download'
  | 'audio_v2'
  | 'session_follow'
  | 'error_codes'
  /** Key messages may carry `macMap` (Mac keyboard mapping, reachMacKeys.ts):
   *  macOS agents only. Absent: the field is never sent. */
  | 'key_map_mac'
  /** Accepts `{"type":"keepalive"}`: resets the agent's 10-minute inactivity
   *  timer, injects nothing, no answer (see reachKeepalive). Never sent to an
   *  agent that does not list it. */
  | 'keepalive'
  /** display_modes_get / display_mode_set: the remote screen's resolution
   *  among the modes Windows offers (reachDisplayModes.ts). Windows agents. */
  | 'display_modes'
  /** set_input_block freezes only the LOCAL user (Windows LL hooks). */
  | 'input_block_local'
  /** set_blank_screen: the remote screen shows an "Oblireach session in
   *  progress" page while the operator still sees the real desktop (Windows
   *  10 2004+ helper). init.blankScreen says why when it is not offered. */
  | 'blank_screen'
  /** session_lock_state / set_lock_on_end: the agent locks the Windows
   *  session again when the connection ends (reachLockOnEnd.ts). */
  | 'lock_on_end';

/** Viewer → agent: keeps a watched session open (agents with 'keepalive'). */
export const KEEPALIVE_MESSAGE = { type: 'keepalive' } as const;

export interface ReachMonitorInfo {
  /** Index after filtering (detached / clone-mode outputs removed). */
  index: number;
  name: string;
  /** Physical desktop pixels (the agent is per-monitor DPI aware). */
  x: number;
  y: number;
  width: number;
  height: number;
  primary?: boolean;
  dpi?: number;
  scale?: number;
  rotation?: number;
}

export interface ReachRect { x: number; y: number; w: number; h: number }

export interface ReachTile {
  index: number;
  /** In frame pixels — the space mouse x,y are sent in. */
  frame: ReachRect;
  /** In physical desktop coordinates. */
  desktop: ReachRect;
  rotation?: number;
  primary?: boolean;
}

export interface ReachView {
  mode: 'monitor' | 'mosaic';
  width: number;
  height: number;
  scale: number;
  tiles: ReachTile[];
}

export interface ReachSessionInfo {
  id?: number;
  state?: string;
  desktop?: string;
  user?: string;
}

export interface ReachInit {
  type: 'init';
  width: number;
  height: number;
  fps: number;
  /** Legacy "initial decoder" field: always 'h264' (a real switch follows as codec_switch). */
  codec?: string;
  codecActive?: string;
  codecs?: string[];
  extradata?: string;
  monitors?: ReachMonitorInfo[];
  /** Captured monitor, -1 in mosaic. */
  monitor?: number;
  audioRate?: number;
  audioAvail?: boolean;
  features?: string[];
  gen?: number;
  view?: ReachView;
  clipboard?: { text?: boolean; push?: boolean; files?: boolean; maxText?: number };
  files?: { upload?: boolean; download?: boolean; maxFile?: number; chunk?: number; window?: number };
  audio?: { codecs?: string[]; maxChannels?: number; rate?: number };
  session?: ReachSessionInfo;
  /** Added by the Obliance relay when the operator may not transfer files in
   *  this session (server reachFilesGate.ts): the file features are removed
   *  from `features` and this says why. Absent: nothing refused. */
  filesPolicy?: { allowed?: boolean; reason?: string };
  /** Blank screen availability on this agent (absent: an older agent). */
  blankScreen?: { available?: boolean; reason?: string };
}

/** Why file transfers are refused in this session ('restriction': the
 *  tenant's action restrictions on the file explorer's transfers). */
export type ReachFilesDenied = 'capability' | 'restriction' | 'privacy' | 'other';

/** The refusal the relay put in the init (reachFilesGate.ts), or null. */
export function filesDenied(init: Pick<ReachInit, 'filesPolicy'> | null | undefined): ReachFilesDenied | null {
  const p = init?.filesPolicy;
  if (!p || typeof p !== 'object' || p.allowed !== false) return null;
  return p.reason === 'capability' || p.reason === 'restriction' || p.reason === 'privacy' ? p.reason : 'other';
}

export type ReachErrorCode =
  // agent
  | 'helper_spawn_failed' | 'helper_timeout' | 'capture_init_failed' | 'encoder_init_failed'
  | 'session_not_found' | 'session_no_display' | 'session_logged_off' | 'session_switch_timeout' | 'privacy_mode' | 'internal'
  // the stream never delivered a picture and could not follow its session (not retried)
  | 'capture_unavailable'
  // relay (server)
  | 'agent_timeout' | 'agent_offline' | 'agent_error' | 'session_closed';

export interface ReachErrorMsg {
  type: 'error';
  code?: string;
  message?: string;
  retry?: boolean;
  /** Relay agent_error from a tunnel_failed: the agent's own code. */
  agentCode?: string;
}

export type ReachSessionStateName = 'starting' | 'switching' | 'live' | 'no_display';

export interface ReachSessionStateMsg {
  type: 'session_state';
  state: ReachSessionStateName;
  sessionId?: number;
  desktop?: string;
  user?: string;
  reason?: string;
  waitSec?: number;
}

/** capture_status no_frames reasons (the agent's no-picture watchdog). */
export type ReachCaptureStallReason = 'rdp_minimized' | 'rdp_disconnected' | 'capture_stalled';

/**
 * Agent → viewer: the stream is up but the capture gives no picture
 * (no_frames: an RDP session draws nothing while its client window is
 * minimised or disconnected), or gives one again (ok). Informational: the
 * viewer keeps the connection and never reconnects for it.
 */
export interface ReachCaptureStatusMsg {
  type: 'capture_status';
  state: 'no_frames' | 'ok';
  reason?: ReachCaptureStallReason | string;
  /** dxgi | gdi | magnification | mosaic */
  path?: string;
  /** The session is shown by a remote (RDP) client. */
  remote?: boolean;
}

/** What the viewer keeps of a capture_status no_frames. */
export interface ReachCaptureStall {
  reason: string;
  remote: boolean;
}

export type ReachViewErrorCode ='mosaic_unavailable' | 'monitor_not_found' | 'capture_failed' | 'too_large' | 'secure_desktop';

export interface ReachViewErrorMsg {
  type: 'view_error';
  code?: ReachViewErrorCode | string;
  message?: string;
  gen?: number;
}

export interface ReachClipboardContentMsg {
  type: 'clipboard_content';
  text?: string;
  origin?: 'request' | 'remote_change';
  id?: string;
  truncated?: boolean;
}

export interface ReachClipboardFile { idx: number; name: string; size: number; dir?: boolean }

/** Agent-side error codes after which no automatic retry makes sense. */
export const NO_RETRY_CODES: ReadonlySet<string> = new Set([
  'session_not_found', 'session_no_display', 'session_logged_off', 'privacy_mode', 'capture_unavailable',
  'agent_timeout', 'agent_offline', 'agent_error', 'session_closed',
  // VM console (server / agent codes): retrying opens a new session that fails the same way.
  'vm_console_agent_outdated', 'vm_console_unsupported', 'vm_console_os_unsupported', 'vm_console_agent_timeout', 'vm_console_ended',
]);

/** Features the agent advertised (empty for old agents). */
export function featureSet(init: Pick<ReachInit, 'features'> | null | undefined): Set<string> {
  return new Set(Array.isArray(init?.features) ? init!.features.filter((f) => typeof f === 'string') : []);
}

/**
 * True when the agent speaks the feature-detected protocol at all. A list
 * with only 'keepalive' is the direct capture path (macOS, Linux, Windows
 * interactive), which sent no features before the keepalive and implements
 * none of the rest: it stays a legacy agent (clipboard: "update the agent").
 */
export function isModernAgent(init: Pick<ReachInit, 'features'> | null | undefined): boolean {
  const f = init?.features;
  if (!Array.isArray(f)) return false;
  return f.length === 0 || f.some((x) => x !== 'keepalive');
}

const num = (v: unknown, d = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);

function rect(v: unknown): ReachRect | null {
  if (!v || typeof v !== 'object') return null;
  const r = v as Record<string, unknown>;
  const w = num(r.w);
  const h = num(r.h);
  if (w <= 0 || h <= 0) return null;
  return { x: num(r.x), y: num(r.y), w, h };
}

/** Validated view (tiles with a usable frame rect only), or null. */
export function parseView(v: unknown): ReachView | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const mode = o.mode === 'mosaic' ? 'mosaic' : o.mode === 'monitor' ? 'monitor' : null;
  if (!mode) return null;
  const tiles: ReachTile[] = [];
  if (Array.isArray(o.tiles)) {
    for (const t of o.tiles) {
      if (!t || typeof t !== 'object') continue;
      const tt = t as Record<string, unknown>;
      const frame = rect(tt.frame);
      if (!frame) continue;
      tiles.push({
        index: num(tt.index),
        frame,
        desktop: rect(tt.desktop) ?? frame,
        rotation: num(tt.rotation),
        primary: tt.primary === true,
      });
    }
  }
  return { mode, width: num(o.width), height: num(o.height), scale: num(o.scale, 1), tiles };
}

/** Monitor list with sane numbers (entries without a size dropped). */
export function parseMonitors(v: unknown): ReachMonitorInfo[] {
  if (!Array.isArray(v)) return [];
  const out: ReachMonitorInfo[] = [];
  for (const m of v) {
    if (!m || typeof m !== 'object') continue;
    const o = m as Record<string, unknown>;
    const width = num(o.width);
    const height = num(o.height);
    if (width <= 0 || height <= 0) continue;
    out.push({
      index: num(o.index, out.length),
      name: typeof o.name === 'string' ? o.name : '',
      x: num(o.x), y: num(o.y), width, height,
      primary: o.primary === true,
      dpi: typeof o.dpi === 'number' ? o.dpi : undefined,
      scale: typeof o.scale === 'number' ? o.scale : undefined,
      rotation: typeof o.rotation === 'number' ? o.rotation : undefined,
    });
  }
  return out;
}

// ── Blank screen (feature 'blank_screen') ─────────────────────────────────────
// viewer → agent {type:'set_blank_screen', on}; agent → viewer
// {type:'blank_screen_status', active, reason?}. The relay may answer itself
// (reason 'privacy': privacy mode on the device).

export type ReachBlankUnavailable = 'os_version' | 'platform' | 'no_user' | 'old_agent';

/** null when the blank screen can be offered, else why not. */
export function blankScreenUnavailable(init: Pick<ReachInit, 'features' | 'blankScreen'> | null | undefined): ReachBlankUnavailable | null {
  if (featureSet(init).has('blank_screen')) return null;
  const r = init?.blankScreen?.reason;
  if (r === 'os_version' || r === 'platform' || r === 'no_user') return r;
  return 'old_agent';
}

export interface ReachBlankStatusMsg {
  type: 'blank_screen_status';
  active?: boolean;
  /** Why it is off: operator | local_user | session_changed | privacy |
   *  os_version | failed | unsupported | watchdog. */
  reason?: string;
}

// ── Presence (sent by the Obliance relay, not the agent) ─────────────────────
// relay → viewer {type:'presence', v:1, self, operators:[…], event?};
// viewer → relay {type:'presence_state', client, viewOnly} (never forwarded).

export type ReachClientKind = 'web' | 'desktop';

export interface ReachPresenceOperator {
  id: string;
  name: string;
  client: ReachClientKind;
  since: string;
  /** true in control, false view only, null unknown. */
  control: boolean | null;
  blank: boolean;
  sameUser: boolean;
}

export interface ReachPresence {
  self: string;
  operators: ReachPresenceOperator[];
  event?: { kind: 'join' | 'leave' | 'update'; id: string };
}

/** Validated presence frame, or null. */
export function parsePresence(v: unknown): ReachPresence | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  if (o.type !== 'presence' || typeof o.self !== 'string' || !Array.isArray(o.operators)) return null;
  const operators: ReachPresenceOperator[] = [];
  for (const x of o.operators.slice(0, 50)) {
    if (!x || typeof x !== 'object') continue;
    const p = x as Record<string, unknown>;
    if (typeof p.id !== 'string' || typeof p.name !== 'string') continue;
    operators.push({
      id: p.id,
      name: p.name.slice(0, 80),
      client: p.client === 'desktop' ? 'desktop' : 'web',
      since: typeof p.since === 'string' ? p.since : '',
      control: typeof p.control === 'boolean' ? p.control : null,
      blank: p.blank === true,
      sameUser: p.sameUser === true,
    });
  }
  const out: ReachPresence = { self: o.self, operators };
  const e = o.event as Record<string, unknown> | undefined;
  if (e && typeof e === 'object' && typeof e.id === 'string' && (e.kind === 'join' || e.kind === 'leave' || e.kind === 'update')) {
    out.event = { kind: e.kind, id: e.id };
  }
  return out;
}

/** The other operators (everyone but this viewer). */
export function otherOperators(p: ReachPresence | null | undefined): ReachPresenceOperator[] {
  return p ? p.operators.filter((o) => o.id !== p.self) : [];
}
