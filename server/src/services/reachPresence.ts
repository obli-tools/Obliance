/**
 * ObliReach presence — who else is connected to the same machine.
 *
 * When several Oblireach viewers (Obliance web viewer,
 * Oblireach Desktop main or detached windows) are open on one device, each one
 * shows that another operator is there, WHO, from which client, since when,
 * whether that operator is in control or view only, and whether they blanked
 * the remote screen. Live (arrival / departure), no polling.
 *
 * Source of truth: the relays of THIS server (remote.service.ts). A viewer is
 * "present" from the moment its relay pairs (browser + agent ends attached,
 * protocol oblireach) until either end goes away. The relay pushes a
 * `{"type":"presence", …}` text frame to every viewer of the device whenever
 * the set changes — the agent never sees it, and an older viewer ignores an
 * unknown message type. A viewer that understands it answers
 * `{"type":"presence_state", client, viewOnly}` (intercepted by the relay,
 * never forwarded to the agent).
 *
 * Exposure rule: an operator who can see the machine sees the other operators
 * of THAT machine — display name (else username) and client kind only. Never
 * an e-mail, an IP, a user id, a tenant or the relay token (the token is the
 * relay key: each member gets an opaque random id instead). Members of other
 * devices are never mentioned.
 *
 * In memory, per server process. Oblireach Desktop in multi-server mode talks
 * to each machine's own Obliance server, so the presence a viewer gets is the
 * one of the server that carries the machine.
 */
import crypto from 'crypto';

export type ReachClientKind = 'web' | 'desktop';

export interface PresenceMember {
  /** Relay key — NEVER sent to any viewer. */
  token: string;
  /** Opaque id shown to viewers (random, per relay). */
  pid: string;
  deviceId: number;
  userId: number;
  name: string;
  client: ReachClientKind;
  /** ms epoch — when this viewer paired. */
  since: number;
  /** null until the viewer says (presence_state). */
  viewOnly: boolean | null;
  /** The agent confirmed this viewer's blank screen is on. */
  blank: boolean;
  /** Sends one JSON text frame to this viewer (errors swallowed). */
  send: (text: string) => void;
}

/** What a viewer learns about one operator of the machine. */
export interface PublicPresenceOperator {
  id: string;
  name: string;
  client: ReachClientKind;
  /** ISO time the operator connected. */
  since: string;
  /** true: in control; false: view only; null: not said (older viewer). */
  control: boolean | null;
  /** That operator's blank screen is on. */
  blank: boolean;
  /** The same user as the receiver (another window / client of theirs). */
  sameUser: boolean;
}

export interface PresenceMessage {
  type: 'presence';
  v: 1;
  /** The receiver's own id in `operators`. */
  self: string;
  operators: PublicPresenceOperator[];
  /** What changed (absent on the first snapshot). */
  event?: { kind: 'join' | 'leave' | 'update'; id: string };
}

/** Bound on members per device (a flood of relays never grows the frames). */
const MAX_PER_DEVICE = 50;
const NAME_MAX = 80;

function isInvisibleOrControl(c: number): boolean {
  return c <= 0x1f || (c >= 0x7f && c <= 0x9f) || (c >= 0x200b && c <= 0x200f)
    || (c >= 0x2028 && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c === 0xfeff;
}

export function cleanPresenceName(raw: unknown): string {
  const s = typeof raw === 'string' ? raw : '';
  // (control, zero-width and bidi-override characters become spaces)
  const clean = Array.from(s, (ch) => (isInvisibleOrControl(ch.codePointAt(0) ?? 0) ? ' ' : ch)).join('')
    .replace(/\s+/g, ' ').trim().slice(0, NAME_MAX);
  return clean || '?';
}

const PRESENCE_STATE_MARK = Buffer.from('presence_state');

/**
 * A viewer → relay `presence_state` frame, or null when this text frame is
 * something else (forwarded to the agent as usual). Small frames only.
 */
export function parsePresenceState(data: unknown, isBinary: boolean): { client?: ReachClientKind; viewOnly?: boolean } | null {
  if (isBinary || !Buffer.isBuffer(data) || data.length > 512 || data.indexOf(PRESENCE_STATE_MARK) < 0) return null;
  let msg: any;
  try { msg = JSON.parse(data.toString('utf8')); } catch { return null; }
  if (!msg || typeof msg !== 'object' || msg.type !== 'presence_state') return null;
  const out: { client?: ReachClientKind; viewOnly?: boolean } = {};
  if (msg.client === 'web' || msg.client === 'desktop') out.client = msg.client;
  if (typeof msg.viewOnly === 'boolean') out.viewOnly = msg.viewOnly;
  return out;
}

export class ReachPresenceRegistry {
  private byDevice = new Map<number, Map<string, PresenceMember>>();
  private byToken = new Map<string, PresenceMember>();

  /** A viewer paired. Re-joining the same token (its browser came back)
   *  keeps its id and time. Returns the member, or null when refused (cap). */
  join(m: Omit<PresenceMember, 'pid' | 'since' | 'blank' | 'viewOnly'> & { since?: number; viewOnly?: boolean | null }): PresenceMember | null {
    const prev = this.byToken.get(m.token);
    if (prev && prev.deviceId !== m.deviceId) this.leave(m.token);
    const kept = this.byToken.get(m.token);
    let set = this.byDevice.get(m.deviceId);
    if (!kept && set && set.size >= MAX_PER_DEVICE) return null;
    const member: PresenceMember = {
      token: m.token,
      pid: kept?.pid ?? crypto.randomBytes(6).toString('hex'),
      deviceId: m.deviceId,
      userId: m.userId,
      name: cleanPresenceName(m.name),
      client: kept?.client ?? m.client,
      since: kept?.since ?? m.since ?? Date.now(),
      viewOnly: kept?.viewOnly ?? m.viewOnly ?? null,
      blank: kept?.blank ?? false,
      send: m.send,
    };
    if (!set) { set = new Map(); this.byDevice.set(m.deviceId, set); }
    set.set(m.token, member);
    this.byToken.set(m.token, member);
    // The others learn the arrival; the newcomer (or a viewer whose browser
    // end came back) gets the snapshot, without an event.
    if (!kept) this.broadcast(m.deviceId, { kind: 'join', id: member.pid }, member.token);
    this.sendTo(member);
    return member;
  }

  /** The viewer's relay went away (either end). No-op when unknown. */
  leave(token: string): void {
    const m = this.byToken.get(token);
    if (!m) return;
    this.byToken.delete(token);
    const set = this.byDevice.get(m.deviceId);
    if (set) {
      set.delete(token);
      if (set.size === 0) this.byDevice.delete(m.deviceId);
    }
    this.broadcast(m.deviceId, { kind: 'leave', id: m.pid });
  }

  /** presence_state from the viewer: broadcast only on a real change. */
  update(token: string, patch: { client?: ReachClientKind; viewOnly?: boolean; blank?: boolean }): boolean {
    const m = this.byToken.get(token);
    if (!m) return false;
    let changed = false;
    if (patch.client && patch.client !== m.client) { m.client = patch.client; changed = true; }
    if (typeof patch.viewOnly === 'boolean' && patch.viewOnly !== m.viewOnly) { m.viewOnly = patch.viewOnly; changed = true; }
    if (typeof patch.blank === 'boolean' && patch.blank !== m.blank) { m.blank = patch.blank; changed = true; }
    if (changed) this.broadcast(m.deviceId, { kind: 'update', id: m.pid });
    return changed;
  }

  get(token: string): PresenceMember | undefined { return this.byToken.get(token); }

  /** The snapshot one member receives (its own view of the device). */
  messageFor(member: PresenceMember, event?: PresenceMessage['event']): PresenceMessage {
    const set = this.byDevice.get(member.deviceId);
    const operators: PublicPresenceOperator[] = [];
    if (set) {
      for (const o of set.values()) {
        operators.push({
          id: o.pid,
          name: o.name,
          client: o.client,
          since: new Date(o.since).toISOString(),
          control: o.viewOnly === null ? null : !o.viewOnly,
          blank: o.blank,
          sameUser: o.userId === member.userId && o.token !== member.token,
        });
      }
    }
    operators.sort((a, b) => a.since.localeCompare(b.since) || a.id.localeCompare(b.id));
    const msg: PresenceMessage = { type: 'presence', v: 1, self: member.pid, operators };
    if (event) msg.event = event;
    return msg;
  }

  private sendTo(member: PresenceMember, event?: PresenceMessage['event']): void {
    try { member.send(JSON.stringify(this.messageFor(member, event))); } catch { /* closing */ }
  }

  /** Everyone on the device gets the new snapshot (`skip`: already sent). */
  private broadcast(deviceId: number, event?: PresenceMessage['event'], skip?: string): void {
    const set = this.byDevice.get(deviceId);
    if (!set) return;
    for (const m of set.values()) {
      if (m.token === skip) continue;
      this.sendTo(m, event);
    }
  }

  /** Members of a device (tests / diagnostics). */
  membersOf(deviceId: number): PresenceMember[] {
    return [...(this.byDevice.get(deviceId)?.values() ?? [])];
  }

  get size(): number { return this.byToken.size; }
}

export const reachPresence = new ReachPresenceRegistry();

// ── Blank screen ("hide the remote screen") ─────────────────────────────────
// viewer → agent {type:'set_blank_screen', on}; agent → viewer
// {type:'blank_screen_status', active, reason?}. The relay reads both (it
// never rewrites the agent's): the request to refuse it under privacy mode
// and audit it, the status to keep the presence flag and the audit truthful.

const BLANK_REQ_MARK = Buffer.from('set_blank_screen');
const BLANK_STATUS_MARK = Buffer.from('blank_screen_status');

/** A viewer's set_blank_screen frame → its `on`, else null. */
export function parseBlankRequest(data: unknown, isBinary: boolean): { on: boolean } | null {
  if (isBinary || !Buffer.isBuffer(data) || data.length > 1024 || data.indexOf(BLANK_REQ_MARK) < 0) return null;
  let msg: any;
  try { msg = JSON.parse(data.toString('utf8')); } catch { return null; }
  if (!msg || typeof msg !== 'object' || msg.type !== 'set_blank_screen') return null;
  return { on: msg.on === true };
}

/** An agent's blank_screen_status frame → its state, else null. */
export function parseBlankStatus(data: unknown, isBinary: boolean): { active: boolean; reason?: string } | null {
  if (isBinary || !Buffer.isBuffer(data) || data.length > 2048 || data.indexOf(BLANK_STATUS_MARK) < 0) return null;
  let msg: any;
  try { msg = JSON.parse(data.toString('utf8')); } catch { return null; }
  if (!msg || typeof msg !== 'object' || msg.type !== 'blank_screen_status') return null;
  const reason = typeof msg.reason === 'string' && /^[a-z_]{1,32}$/.test(msg.reason) ? msg.reason : undefined;
  return reason ? { active: msg.active === true, reason } : { active: msg.active === true };
}

/** The relay's own answer when it refuses a blank screen (never forwarded). */
export function blankRefusal(reason: 'privacy'): string {
  return JSON.stringify({ type: 'blank_screen_status', active: false, reason });
}
