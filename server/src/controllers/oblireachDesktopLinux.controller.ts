import type { NextFunction, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { config } from '../config';
import { logger } from '../utils/logger';

// ── Oblireach Desktop for Linux (Flatpak) — public distribution ─────────────
//
// Linux counterpart of the Windows MSI served by oblireachDesktop.controller.ts
// Every
// Obliance server hosts the same Linux build: an installation's origin is
// the server it was installed from.
//
//   GET /api/oblireach-desktop/flatpak/tools.obli.Oblireach.flatpakref
//         one-click install file (`flatpak install --user <url>`), generated
//         with this server's public URL and the repository's public GPG key
//   GET /api/oblireach-desktop/flatpak/oblireach.flatpakrepo
//         adds the repository as a remote (`flatpak remote-add --user …`)
//   GET /api/oblireach-desktop/flatpak/Oblireach.flatpak
//         single-file bundle (offline install); its embedded repo URL points
//         back at this server so the installation keeps receiving updates
//   GET /api/oblireach-desktop/flatpak/repo/*
//         static OSTree repository (archive mode), read-only files only
//
// All public, like the MSI: Flatpak fetches without credentials. Authenticity
// is NOT provided by this server: commits and the summary are GPG-signed on
// the build workstation (the private key never leaves it); Flatpak checks
// them against the public key carried by the .flatpakref / .flatpakrepo.
//
// Drop zone (written by the Oblireach Desktop Flatpak build, copied into
// the image by the server Dockerfile — every file is optional; anything
// missing → the Linux build is reported unavailable and these routes 404):
//
//   oblireach-desktop/linux/VERSION                  version of the Linux build
//   oblireach-desktop/linux/oblireach-desktop.gpg    public key (binary export
//                                                    or ASCII armor .asc)
//   oblireach-desktop/linux/repo/                    OSTree repo (config, summary,
//                                                    summary.sig, objects/, deltas/…)
//   oblireach-desktop/linux/bundles/<host>.flatpak   bundle whose repo URL is
//                                                    https://<host>/… (one per server)
//   oblireach-desktop/linux/Oblireach.flatpak        fallback bundle (other hosts)

export const FLATPAK_APP_ID = 'tools.obli.Oblireach';
export const FLATPAK_BRANCH = 'stable';
export const FLATHUB_RUNTIME_REPO = 'https://dl.flathub.org/repo/flathub.flatpakrepo';

const API_BASE = '/api/oblireach-desktop/flatpak';
export const FLATPAKREF_PATH = `${API_BASE}/${FLATPAK_APP_ID}.flatpakref`;
export const FLATPAKREPO_PATH = `${API_BASE}/oblireach.flatpakrepo`;
export const BUNDLE_PATH = `${API_BASE}/Oblireach.flatpak`;
export const REPO_PATH = `${API_BASE}/repo/`;

/** `<repo>/oblireach-desktop`. Same location as the MSI controller (Docker:
 *  /app/oblireach-desktop). OBLIREACH_DESKTOP_DIR overrides it (local tests). */
export function desktopRoot(): string {
  const override = (process.env.OBLIREACH_DESKTOP_DIR || '').trim();
  return override ? path.resolve(override) : path.resolve(__dirname, '../../../../oblireach-desktop');
}
const linuxDir = () => path.join(desktopRoot(), 'linux');
const repoDir = () => path.join(linuxDir(), 'repo');

// ── Public URL ──────────────────────────────────────────────────────────────

/** This server's public base URL (APP_URL, else a non-localhost CLIENT_ORIGIN —
 *  config.publicUrl), normalised; null when unset or not http(s). Never derived
 *  from request headers: the .flatpakref becomes the installation's origin. */
export function flatpakPublicBase(publicUrl: string = config.publicUrl): string | null {
  if (!publicUrl) return null;
  try {
    const u = new URL(publicUrl);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    if (u.username || u.password) return null;
    const p = u.pathname.replace(/\/+$/, '');
    return `${u.origin}${p}`;
  } catch {
    return null;
  }
}

/** Host part used for the per-server bundle and the suggested remote name. */
function publicHost(base: string): string {
  return new URL(base).hostname.toLowerCase();
}

/** Remote name suggested to Flatpak: one remote per Obliance server, so a
 *  machine never mixes two origins under the same name. */
export function suggestedRemoteName(base: string): string {
  const host = publicHost(base).replace(/[^a-z0-9.-]/g, '-').replace(/^[-.]+/, '');
  return `oblireach-${host || 'server'}`;
}

// ── Drop-zone reads ─────────────────────────────────────────────────────────

async function readText(file: string, max = 1024 * 1024): Promise<string | null> {
  try {
    const st = await fs.promises.stat(file);
    if (!st.isFile() || st.size === 0 || st.size > max) return null;
    return await fs.promises.readFile(file, 'utf-8');
  } catch {
    return null;
  }
}

async function fileStat(file: string): Promise<fs.Stats | null> {
  try {
    const st = await fs.promises.stat(file);
    return st.isFile() && st.size > 0 ? st : null;
  } catch {
    return null;
  }
}

async function readLinuxVersion(): Promise<string | null> {
  const raw = (await readText(path.join(linuxDir(), 'VERSION'), 256))?.trim();
  return raw && /^[0-9A-Za-z][0-9A-Za-z.+~-]{0,63}$/.test(raw) ? raw : null;
}

/** OpenPGP ASCII armor → binary; binary returned as is. null when it does not
 *  look like a public key (first packet: Public-Key, old or new format). */
export function publicKeyBytes(raw: Buffer): Buffer | null {
  let bin = raw;
  const text = raw.toString('latin1');
  if (text.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
    const m = text.match(/-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n([\s\S]*?)-----END PGP PUBLIC KEY BLOCK-----/);
    if (!m) return null;
    // Armor headers end at the first blank line; the CRC24 line starts with '='.
    const body = m[1].replace(/\r/g, '');
    const blank = body.indexOf('\n\n');
    const payload = (blank >= 0 && /^[A-Za-z-]+: /.test(body) ? body.slice(blank + 2) : body)
      .split('\n').filter((l) => l && !l.startsWith('=')).join('');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(payload)) return null;
    bin = Buffer.from(payload, 'base64');
  }
  if (bin.length < 32 || bin.length > 64 * 1024) return null;
  const tag = bin[0];
  const oldFormatPublicKey = (tag & 0xc0) === 0x80 && ((tag >> 2) & 0x0f) === 6;
  const newFormatPublicKey = tag === 0xc6;
  return oldFormatPublicKey || newFormatPublicKey ? bin : null;
}

async function readPublicKeyBase64(): Promise<string | null> {
  for (const name of ['oblireach-desktop.gpg', 'oblireach-desktop.asc']) {
    try {
      const file = path.join(linuxDir(), name);
      const st = await fs.promises.stat(file);
      if (!st.isFile() || st.size > 256 * 1024) continue;
      const bin = publicKeyBytes(await fs.promises.readFile(file));
      if (bin) return bin.toString('base64');
      logger.warn({ file }, 'oblireach-desktop: Linux repository public key unreadable');
    } catch { /* try next */ }
  }
  return null;
}

/** The repository is served only once it is complete and signed. */
async function repoReady(): Promise<boolean> {
  const [cfg, summary, sig] = await Promise.all([
    fileStat(path.join(repoDir(), 'config')),
    fileStat(path.join(repoDir(), 'summary')),
    fileStat(path.join(repoDir(), 'summary.sig')),
  ]);
  return !!(cfg && summary && sig);
}

/** Bundle for this server (repo URL baked in at build time), else the generic one. */
async function bundleFile(base: string | null): Promise<{ file: string; stat: fs.Stats } | null> {
  const candidates: string[] = [];
  if (base) candidates.push(path.join(linuxDir(), 'bundles', `${publicHost(base)}.flatpak`));
  candidates.push(path.join(linuxDir(), 'Oblireach.flatpak'));
  for (const file of candidates) {
    const stat = await fileStat(file);
    if (stat) return { file, stat };
  }
  return null;
}

// ── Generated files ─────────────────────────────────────────────────────────

export function buildFlatpakref(base: string, gpgKeyB64: string): string {
  return [
    '[Flatpak Ref]',
    `Name=${FLATPAK_APP_ID}`,
    `Branch=${FLATPAK_BRANCH}`,
    'Title=Oblireach Desktop',
    'IsRuntime=false',
    `Url=${base}${REPO_PATH}`,
    `SuggestRemoteName=${suggestedRemoteName(base)}`,
    `Homepage=${base}/download`,
    `RuntimeRepo=${FLATHUB_RUNTIME_REPO}`,
    `GPGKey=${gpgKeyB64}`,
    '',
  ].join('\n');
}

export function buildFlatpakrepo(base: string, gpgKeyB64: string): string {
  return [
    '[Flatpak Repo]',
    `Title=Oblireach Desktop (${publicHost(base)})`,
    `Url=${base}${REPO_PATH}`,
    `Homepage=${base}/download`,
    'Comment=Oblireach Desktop, distributed by this Obliance server',
    `DefaultBranch=${FLATPAK_BRANCH}`,
    `GPGKey=${gpgKeyB64}`,
    '',
  ].join('\n');
}

// ── /version `linux` section ────────────────────────────────────────────────

export interface LinuxDesktopInfo {
  version: string;
  appId: string;
  branch: string;
  /** Relative, like the Windows `downloadUrl`. null: no bundle published. */
  bundleUrl: string | null;
  /** Absolute (public URL): null when this server has no public URL configured. */
  flatpakrefUrl: string | null;
  flatpakrepoUrl: string | null;
  repoUrl: string | null;
  installCommand: string | null;
  releasedAt?: string;
}

/** null = no Linux build on this server (the Windows response is unchanged). */
export async function linuxDesktopInfo(): Promise<LinuxDesktopInfo | null> {
  const [version, key, ready] = await Promise.all([readLinuxVersion(), readPublicKeyBase64(), repoReady()]);
  if (!version || !key || !ready) return null;
  const base = flatpakPublicBase();
  const bundle = await bundleFile(base);
  let releasedAt: string | undefined;
  const summary = await fileStat(path.join(repoDir(), 'summary'));
  if (summary) releasedAt = summary.mtime.toISOString();
  const ref = base ? `${base}${FLATPAKREF_PATH}` : null;
  return {
    version,
    appId: FLATPAK_APP_ID,
    branch: FLATPAK_BRANCH,
    bundleUrl: bundle ? BUNDLE_PATH : null,
    flatpakrefUrl: ref,
    flatpakrepoUrl: base ? `${base}${FLATPAKREPO_PATH}` : null,
    repoUrl: base ? `${base}${REPO_PATH}` : null,
    installCommand: ref ? `flatpak install --user ${ref}` : null,
    releasedAt,
  };
}

// ── Handlers ────────────────────────────────────────────────────────────────

function notAvailable(res: Response, what: string): void {
  res.setHeader('Cache-Control', 'no-store');
  res.status(404).json({ error: `${what} not available: Oblireach Desktop for Linux is not published on this server yet` });
}

async function sendGeneratedFile(res: Response, kind: 'ref' | 'repo'): Promise<void> {
  const [key, ready] = await Promise.all([readPublicKeyBase64(), repoReady()]);
  if (!key || !ready) { notAvailable(res, 'Flatpak repository'); return; }
  const base = flatpakPublicBase();
  if (!base) {
    res.setHeader('Cache-Control', 'no-store');
    res.status(503).json({ error: 'Public URL of this server unknown (set CLIENT_ORIGIN to the public address)' });
    return;
  }
  const body = kind === 'ref' ? buildFlatpakref(base, key) : buildFlatpakrepo(base, key);
  const name = kind === 'ref' ? `${FLATPAK_APP_ID}.flatpakref` : 'oblireach.flatpakrepo';
  // attachment() sets a type from the extension: the real type goes after it.
  res.attachment(name);
  res.type(kind === 'ref' ? 'application/vnd.flatpak.ref' : 'application/vnd.flatpak.repo');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.send(body);
}

export async function flatpakrefHandler(_req: Request, res: Response): Promise<void> {
  await sendGeneratedFile(res, 'ref');
}

export async function flatpakrepoHandler(_req: Request, res: Response): Promise<void> {
  await sendGeneratedFile(res, 'repo');
}

export async function flatpakBundleHandler(_req: Request, res: Response): Promise<void> {
  const [version, ready] = await Promise.all([readLinuxVersion(), repoReady()]);
  const bundle = version && ready ? await bundleFile(flatpakPublicBase()) : null;
  if (!bundle || !version) { notAvailable(res, 'Flatpak bundle'); return; }
  res.attachment(`Oblireach-${version}.flatpak`);
  res.type('application/vnd.flatpak');   // after attachment() (extension lookup)
  res.sendFile(bundle.file, {
    acceptRanges: true,
    cacheControl: false,
    lastModified: true,
    dotfiles: 'deny',
    headers: { 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' },
  }, (err) => sendFileError(res, err, 'bundle'));
}

// ── Static OSTree repository ────────────────────────────────────────────────

// What a Flatpak / OSTree client fetches from an archive repository over HTTP.
// Everything else (state/, tmp/, refs/remotes/, .lock, extensions/…) is never served.
const SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9._+-]{0,254}$/;
const MUTABLE_FILES = new Set(['config', 'summary', 'summary.sig', 'summary.idx', 'summary.idx.sig']);
const TREES: Record<string, 'immutable' | 'long' | 'revalidate'> = {
  objects: 'immutable',        // content-addressed by checksum
  summaries: 'immutable',      // summaries/<checksum>.gz(.sig): content-addressed
  deltas: 'long',              // named by from/to commit checksums
  'delta-indexes': 'revalidate',
  refs: 'revalidate',          // only refs/heads (pull without summary)
};

const CACHE_HEADER = {
  immutable: 'public, max-age=31536000, immutable',
  long: 'public, max-age=86400',
  // summary + summary.sig must never be served out of step: always revalidate.
  revalidate: 'no-cache',
} as const;

/** Validates a repository-relative path. Returns its segments and cache class,
 *  or null (→ 404) for anything outside the published set. */
export function classifyRepoPath(rel: string): { segments: string[]; cache: keyof typeof CACHE_HEADER } | null {
  if (typeof rel !== 'string' || !rel || rel.length > 1024) return null;
  if (rel.includes('\\') || rel.includes('\0') || rel.includes('%')) return null;
  const segments = rel.split('/');
  if (!segments.every((s) => SEGMENT.test(s) && s !== '..' && s !== '.')) return null;
  if (segments.length === 1) {
    return MUTABLE_FILES.has(segments[0]) ? { segments, cache: 'revalidate' } : null;
  }
  const tree = TREES[segments[0]];
  if (!tree) return null;
  if (segments[0] === 'refs' && segments[1] !== 'heads') return null;
  if (segments.length < 2 || segments.length > 16) return null;
  return { segments, cache: tree };
}

export async function flatpakRepoHandler(req: Request, res: Response, _next: NextFunction): Promise<void> {
  const rel = (req.params as Record<string, string>)[0] ?? '';
  const cls = classifyRepoPath(rel);
  if (!cls || !(await repoReady())) {
    res.setHeader('Cache-Control', 'no-store');
    res.status(404).json({ error: 'Not found' });
    return;
  }
  const root = repoDir();
  const file = path.join(root, ...cls.segments);
  // Symlinks or a moved tree must not lead outside the repository.
  try {
    const [realRoot, realFile] = await Promise.all([fs.promises.realpath(root), fs.promises.realpath(file)]);
    const st = await fs.promises.stat(realFile);
    if (!st.isFile() || !(realFile === realRoot || realFile.startsWith(realRoot + path.sep))) throw new Error('outside');
  } catch {
    res.setHeader('Cache-Control', 'no-store');
    res.status(404).json({ error: 'Not found' });
    return;
  }
  // OSTree objects, deltas and signatures are opaque binary for HTTP clients.
  res.type(cls.segments[0] === 'config' ? 'text/plain; charset=utf-8' : 'application/octet-stream');
  res.sendFile(cls.segments.join('/'), {
    root,
    acceptRanges: true,
    cacheControl: false,
    lastModified: true,
    dotfiles: 'deny',
    headers: { 'Cache-Control': CACHE_HEADER[cls.cache], 'X-Content-Type-Options': 'nosniff' },
  }, (err) => sendFileError(res, err, 'repo'));
}

function sendFileError(res: Response, err: unknown, what: string): void {
  if (!err || res.headersSent) return;
  const e = err as Error & { status?: number; headers?: Record<string, string> };
  const status = e.status ?? 500;
  if (status >= 500) logger.warn({ err }, `oblireach-desktop: Linux ${what} download failed`);
  if (e.headers) res.set(e.headers);
  res.removeHeader('Content-Type');
  res.removeHeader('Content-Disposition');
  res.setHeader('Cache-Control', 'no-store');
  res.status(status === 416 ? 416 : status >= 500 ? 500 : 404).json({ error: status === 416 ? 'Range not satisfiable' : 'Not found' });
}
