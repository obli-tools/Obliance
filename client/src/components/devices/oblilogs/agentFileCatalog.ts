/**
 * Obli* agents recognized on a device's Services tab, and the files each one
 * keeps by design (read-only survey of the agents' sources, 2026-10-08:
 * Obliance agent, ObliReach agent, Obliview agent, Obliguard agent, Oblimap
 * probe, shared device identity). The ONE place to update when an agent moves
 * or adds a file.
 *
 * - `files`: fixed names, always listed (greyed "absent" when missing).
 * - `patterns`: optional / rotated siblings, listed only when present in the
 *   directory listing (e.g. ObliReach's `oblireach-input.log.1`).
 * - Windows paths are the default %ProgramData% (C:\ProgramData): the agent's
 *   list_directory does not expand environment variables.
 * - None of the agents rotates its main log (append, unbounded): the viewer
 *   tails big files.
 */
import type { OsType } from '@obliance/shared';

export type AgentFileKind = 'log' | 'json' | 'text';
export type ObliAgentId = 'obliance' | 'oblireach' | 'obliview' | 'obliguard' | 'oblimap';
/** 'bsd' = FreeBSD (osType 'other' on the server). */
export type AgentOs = 'windows' | 'linux' | 'macos' | 'bsd';

export interface AgentFileSpec {
  name: string;
  kind: AgentFileKind;
  descKey: string;
  desc: string;
}

export interface AgentPatternSpec {
  re: RegExp;
  kind: AgentFileKind;
  descKey: string;
  desc: string;
}

export interface AgentDirSpec {
  dir: string;
  files: AgentFileSpec[];
  patterns?: AgentPatternSpec[];
}

export interface AgentNote {
  /** i18n key; `text` is the English fallback, with {{vars}}. */
  key: string;
  text: string;
  vars?: Record<string, string>;
}

export interface ObliAgentDef {
  id: ObliAgentId;
  /** Product name (never translated). */
  label: string;
  /** Service names as the agent's list_services reports them, lower-case,
   *  without a `.service` suffix: Windows SCM short name, systemd unit /
   *  SysV script, macOS launchd label, FreeBSD rc.d name. */
  serviceNames: string[];
  dirs: Partial<Record<AgentOs, AgentDirSpec[]>>;
  notes?: Partial<Record<AgentOs, AgentNote[]>>;
}

// ─── Shared building blocks ──────────────────────────────────────────────────

const f = (name: string, kind: AgentFileKind, descKey: string, desc: string): AgentFileSpec => ({ name, kind, descKey: `oblilogs.file.${descKey}`, desc });
const p = (re: RegExp, kind: AgentFileKind, descKey: string, desc: string): AgentPatternSpec => ({ re, kind, descKey: `oblilogs.file.${descKey}`, desc });

const CONFIG = f('config.json', 'json', 'config', 'Agent configuration (secrets masked)');
const AGENT_LOG = f('agent.log', 'log', 'agentLog', 'Agent log');

/** device-id.json: the identity shared by every Obli* agent (device_identity.go). */
const IDENTITY_WIN: AgentDirSpec = {
  dir: 'C:\\ProgramData\\Oblitools',
  files: [f('device-id.json', 'json', 'deviceId', 'Device identity shared by the Obli* agents')],
};
const IDENTITY_UNIX: AgentDirSpec = {
  dir: '/etc/oblitools',
  files: [f('device-id.json', 'json', 'deviceId', 'Device identity shared by the Obli* agents')],
};

const journalNote = (unit: string): AgentNote => ({
  key: 'oblilogs.note.journal',
  text: 'On Linux (systemd) this agent logs to the journal, not to a file: journalctl -u {{unit}}',
  vars: { unit },
});

// ─── Agents ──────────────────────────────────────────────────────────────────

const OBLIANCE_STATE_FILES: AgentFileSpec[] = [
  CONFIG,
  f('status.json', 'json', 'status', 'Agent status (version, read by the tray)'),
  f('privacy.json', 'json', 'privacy', 'Privacy mode state'),
  f('airgap.json', 'json', 'airgap', 'Airgap mode state'),
  f('remote-session.json', 'json', 'remoteSession', 'Active remote sessions (tray)'),
  f('watchdog.json', 'json', 'watchdog', 'Watchdog restart history'),
  f('oblireach-manager.json', 'json', 'oblireachManager', 'ObliReach installer manager state'),
];

const OBLIANCE: ObliAgentDef = {
  id: 'obliance',
  label: 'Obliance',
  serviceNames: ['oblianceagent', 'obliance-agent', 'obliance-watchdog', 'com.obliance.agent', 'com.obliance.tray', 'obliance_agent'],
  dirs: {
    windows: [
      {
        dir: 'C:\\ProgramData\\OblianceAgent',
        files: [AGENT_LOG, f('tray.log', 'log', 'trayLog', 'Tray icon log'), ...OBLIANCE_STATE_FILES],
        patterns: [p(/^agent-legacy\.log$/i, 'log', 'legacyLog', 'Legacy agent log (Windows Server 2008 R2)')],
      },
      {
        dir: 'C:\\Windows\\Temp',
        files: [],
        patterns: [p(/^obliance-(update|agent-install)\.log$/i, 'log', 'updateLog', 'Update / install log (msiexec)')],
      },
      IDENTITY_WIN,
    ],
    linux: [
      { dir: '/etc/obliance-agent', files: OBLIANCE_STATE_FILES },
      { dir: '/var/log', files: [], patterns: [p(/^obliance-agent\.log$/i, 'log', 'agentLog', 'Agent log')] },
      IDENTITY_UNIX,
    ],
    macos: [
      { dir: '/etc/obliance-agent', files: OBLIANCE_STATE_FILES },
      { dir: '/var/log', files: [f('obliance-agent.log', 'log', 'agentLog', 'Agent log')] },
      IDENTITY_UNIX,
    ],
    bsd: [
      { dir: '/etc/obliance-agent', files: OBLIANCE_STATE_FILES },
      { dir: '/var/log', files: [f('obliance-agent.log', 'log', 'agentLog', 'Agent log')] },
      IDENTITY_UNIX,
    ],
  },
  notes: { linux: [journalNote('obliance-agent')] },
};

const OBLIREACH_STATE_FILES: AgentFileSpec[] = [
  CONFIG,
  f('version.txt', 'text', 'version', 'Installed version'),
  f('update-state.json', 'json', 'updateState', 'Self-update state'),
];

const OBLIREACH: ObliAgentDef = {
  id: 'oblireach',
  label: 'ObliReach',
  // Windows only: on Linux / macOS ObliReach is a child process of the
  // Obliance agent (no service unit to recognize).
  serviceNames: ['oblireachagent'],
  dirs: {
    windows: [
      {
        dir: 'C:\\ProgramData\\OblireachAgent',
        files: [
          f('oblireach.log', 'log', 'oblireachLog', 'ObliReach agent log'),
          ...OBLIREACH_STATE_FILES,
          f('webview2-state.json', 'json', 'webview2', 'WebView2 runtime guard state'),
        ],
        patterns: [p(/^encoder-diag\.log$/i, 'log', 'encoderDiag', 'Video encoder diagnostics')],
      },
      {
        // The service runs as SYSTEM: its %TEMP% is C:\Windows\Temp.
        dir: 'C:\\Windows\\Temp',
        files: [],
        patterns: [
          p(/^oblireach-input\.log(\.1)?$/i, 'log', 'inputLog', 'Input diagnostics (rotated at 5 MB)'),
          p(/^oblireach-(helper|chat|mag|encoder-diag)\.log$/i, 'log', 'helperLog', 'Capture / chat helper log'),
          p(/^oblireach-helper-s\d+-pid\d+\.log$/i, 'log', 'helperLog', 'Capture / chat helper log'),
          p(/^oblireach-update.*\.log$/i, 'log', 'updateLog', 'Update / install log (msiexec)'),
        ],
      },
      IDENTITY_WIN,
    ],
    linux: [
      { dir: '/etc/oblireach-agent', files: [f('oblireach.log', 'log', 'oblireachLog', 'ObliReach agent log'), ...OBLIREACH_STATE_FILES] },
      IDENTITY_UNIX,
    ],
    macos: [
      { dir: '/etc/oblireach-agent', files: [f('oblireach.log', 'log', 'oblireachLog', 'ObliReach agent log'), ...OBLIREACH_STATE_FILES] },
      IDENTITY_UNIX,
    ],
  },
};

const OBLIVIEW: ObliAgentDef = {
  id: 'obliview',
  label: 'Obliview',
  serviceNames: ['obliviewagent', 'obliview-agent', 'com.obliview.agent', 'obliview_agent'],
  dirs: {
    windows: [
      { dir: 'C:\\ProgramData\\ObliviewAgent', files: [AGENT_LOG, CONFIG] },
      {
        dir: 'C:\\ProgramData\\ObliviewAgent\\update',
        files: [],
        patterns: [p(/^obliview-update\.log$/i, 'log', 'updateLog', 'Update / install log (msiexec)')],
      },
      IDENTITY_WIN,
    ],
    linux: [{ dir: '/etc/obliview-agent', files: [CONFIG] }, IDENTITY_UNIX],
    macos: [
      { dir: '/etc/obliview-agent', files: [CONFIG] },
      { dir: '/var/log', files: [f('obliview-agent.log', 'log', 'agentLog', 'Agent log')] },
      IDENTITY_UNIX,
    ],
    bsd: [{ dir: '/etc/obliview-agent', files: [CONFIG] }, IDENTITY_UNIX],
  },
  notes: { linux: [journalNote('obliview-agent')] },
};

const OBLIGUARD: ObliAgentDef = {
  id: 'obliguard',
  label: 'Obliguard',
  serviceNames: ['obliguardagent', 'obliguard-agent', 'com.obliguard.agent', 'obliguard_agent'],
  dirs: {
    windows: [
      { dir: 'C:\\ProgramData\\ObliguardAgent', files: [AGENT_LOG, CONFIG] },
      {
        dir: 'C:\\ProgramData\\ObliguardAgent\\update',
        files: [],
        patterns: [
          p(/^obliguard-update\.log$/i, 'log', 'updateLog', 'Update / install log (msiexec)'),
          p(/^update-result\.txt$/i, 'text', 'updateResult', 'Result of the last update'),
        ],
      },
      IDENTITY_WIN,
    ],
    linux: [{ dir: '/etc/obliguard-agent', files: [CONFIG] }, IDENTITY_UNIX],
    macos: [
      { dir: '/etc/obliguard-agent', files: [CONFIG] },
      { dir: '/var/log', files: [f('obliguard-agent.log', 'log', 'agentLog', 'Agent log')] },
      IDENTITY_UNIX,
    ],
    bsd: [
      { dir: '/etc/obliguard-agent', files: [CONFIG] },
      { dir: '/var/log', files: [f('obliguard-agent.log', 'log', 'agentLog', 'Agent log')] },
      IDENTITY_UNIX,
    ],
  },
  notes: { linux: [journalNote('obliguard-agent')] },
};

const OBLIMAP_UNIX: AgentDirSpec[] = [
  { dir: '/etc/oblimap-probe', files: [CONFIG] },
  { dir: '/var/log', files: [f('oblimap-probe.log', 'log', 'probeLog', 'Probe log')] },
  IDENTITY_UNIX,
];

const OBLIMAP: ObliAgentDef = {
  id: 'oblimap',
  label: 'Oblimap',
  serviceNames: ['oblimapprobe', 'oblimap-probe', 'com.oblimap.probe', 'oblimap_probe'],
  dirs: {
    windows: [
      { dir: 'C:\\ProgramData\\OblimapProbe', files: [f('probe.log', 'log', 'probeLog', 'Probe log'), CONFIG] },
      IDENTITY_WIN,
    ],
    linux: OBLIMAP_UNIX,
    macos: OBLIMAP_UNIX,
    bsd: OBLIMAP_UNIX,
  },
};

export const OBLI_AGENTS: readonly ObliAgentDef[] = [OBLIANCE, OBLIREACH, OBLIVIEW, OBLIGUARD, OBLIMAP];

const BY_SERVICE = new Map<string, ObliAgentDef>();
for (const a of OBLI_AGENTS) for (const n of a.serviceNames) BY_SERVICE.set(n, a);

/** The Obli* agent behind a service name of the Services tab, or null. */
export function obliAgentForService(serviceName: string): ObliAgentDef | null {
  const n = serviceName.trim().toLowerCase().replace(/\.service$/, '');
  return BY_SERVICE.get(n) ?? null;
}

export function agentOsOf(osType: OsType | string | undefined): AgentOs {
  if (osType === 'windows' || osType === 'linux' || osType === 'macos') return osType;
  return 'bsd';
}

/** The directories (and their files) to show for this agent on this OS. */
export function agentFilesFor(agent: ObliAgentDef, osType: OsType | string | undefined): AgentDirSpec[] {
  return agent.dirs[agentOsOf(osType)] ?? [];
}

/** Notes shown above the file list (e.g. Linux journal logging). */
export function agentNotesFor(agent: ObliAgentDef, osType: OsType | string | undefined): AgentNote[] {
  return agent.notes?.[agentOsOf(osType)] ?? [];
}

export function joinAgentPath(dir: string, name: string, sep: string): string {
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}
