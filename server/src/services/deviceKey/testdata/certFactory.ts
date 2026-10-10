import crypto, { type KeyObject } from 'node:crypto';

// ── Synthetic Android key attestation chains (TEST ONLY) ───────────────────
//
// The attestation tests need chains
// whose every field can be bent (level, user auth type, root of trust,
// package, signer, challenge, extension placement, validity…). Node's crypto
// cannot WRITE certificates, so this module carries a minimal DER encoder and
// builds X.509 v3 certificates signed with ecdsa-with-SHA256, rooted in a
// FAKE root generated at run time. The production verifier only trusts the
// pinned Google keys (attestationRoots.ts); the tests inject the fake root's
// SPKI hash as the pin. Nothing in production imports this file.
//
// Erasable TypeScript only (node --test strips the types).

// ── DER encoder ─────────────────────────────────────────────────────────────

function lengthBytes(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const out: number[] = [];
  let v = n;
  while (v > 0) { out.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | out.length, ...out]);
}

/** Identifier octets for (class, constructed, tag), high-tag form when >= 31. */
function identifier(cls: number, constructed: boolean, tag: number): Buffer {
  const first = (cls << 6) | (constructed ? 0x20 : 0);
  if (tag < 31) return Buffer.from([first | tag]);
  const parts: number[] = [];
  let v = tag;
  parts.unshift(v & 0x7f);
  v = Math.floor(v / 128);
  while (v > 0) { parts.unshift(0x80 | (v & 0x7f)); v = Math.floor(v / 128); }
  return Buffer.from([first | 0x1f, ...parts]);
}

export function tlv(cls: number, constructed: boolean, tag: number, content: Buffer): Buffer {
  return Buffer.concat([identifier(cls, constructed, tag), lengthBytes(content.length), content]);
}

const U = (tag: number, content: Buffer, constructed = false) => tlv(0, constructed, tag, content);

export const der = {
  seq: (...items: Buffer[]) => U(16, Buffer.concat(items), true),
  set: (...items: Buffer[]) => U(17, Buffer.concat(items), true),
  int(n: number | bigint): Buffer {
    let v = BigInt(n);
    if (v === 0n) return U(2, Buffer.from([0]));
    const bytes: number[] = [];
    if (v > 0n) {
      while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
      if (bytes[0] & 0x80) bytes.unshift(0);
    } else {
      // two's complement, minimal
      let len = 1;
      while (-(1n << BigInt(len * 8 - 1)) > v) len++;
      let t = (1n << BigInt(len * 8)) + v;
      for (let i = 0; i < len; i++) { bytes.unshift(Number(t & 0xffn)); t >>= 8n; }
    }
    return U(2, Buffer.from(bytes));
  },
  enumerated(n: number): Buffer {
    const i = der.int(n);
    i[0] = 0x0a;
    return i;
  },
  bool: (b: boolean) => U(1, Buffer.from([b ? 0xff : 0x00])),
  /** A BOOLEAN with an arbitrary content octet (non-DER, e.g. 0x01). */
  rawBool: (octet: number) => U(1, Buffer.from([octet])),
  nul: () => U(5, Buffer.alloc(0)),
  octet: (b: Buffer | string) => U(4, Buffer.isBuffer(b) ? b : Buffer.from(b, 'utf8')),
  bitString: (b: Buffer, unused = 0) => U(3, Buffer.concat([Buffer.from([unused]), b])),
  utf8: (s: string) => U(12, Buffer.from(s, 'utf8')),
  oid(dotted: string): Buffer {
    const arcs = dotted.split('.').map((x) => BigInt(x));
    const out: number[] = [];
    const push = (v: bigint) => {
      const parts: number[] = [Number(v & 0x7fn)];
      v >>= 7n;
      while (v > 0n) { parts.unshift(0x80 | Number(v & 0x7fn)); v >>= 7n; }
      out.push(...parts);
    };
    push(arcs[0] * 40n + arcs[1]);
    for (const a of arcs.slice(2)) push(a);
    return U(6, Buffer.from(out));
  },
  time(d: Date): Buffer {
    const p = (n: number, w = 2) => String(n).padStart(w, '0');
    const y = d.getUTCFullYear();
    const rest = `${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
    if (y >= 1950 && y < 2050) return U(23, Buffer.from(`${p(y % 100)}${rest}`, 'latin1'));
    return U(24, Buffer.from(`${p(y, 4)}${rest}`, 'latin1'));
  },
  /** [n] EXPLICIT (context, constructed). */
  explicit: (tag: number, inner: Buffer) => tlv(2, true, tag, inner),
};

// ── X.509 ───────────────────────────────────────────────────────────────────

const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_CN = '2.5.4.3';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
export const OID_KEY_DESCRIPTION = '1.3.6.1.4.1.11129.2.1.17';
export const OID_PROVISIONING_INFO = '1.3.6.1.4.1.11129.2.1.30';

export interface Ext { oid: string; critical?: boolean; value: Buffer }

function name(cn: string): Buffer {
  return der.seq(der.set(der.seq(der.oid(OID_CN), der.utf8(cn))));
}

function extension(e: Ext): Buffer {
  return der.seq(der.oid(e.oid), ...(e.critical ? [der.bool(true)] : []), der.octet(e.value));
}

export function basicConstraintsExt(ca: boolean): Ext {
  return { oid: OID_BASIC_CONSTRAINTS, critical: true, value: ca ? der.seq(der.bool(true)) : der.seq() };
}

/** keyUsage: keyCertSign (bit 5) for a CA, digitalSignature (bit 0) otherwise. */
export function keyUsageExt(ca: boolean): Ext {
  return { oid: OID_KEY_USAGE, critical: true, value: ca ? der.bitString(Buffer.from([0x04]), 2) : der.bitString(Buffer.from([0x80]), 7) };
}

export interface CertSpec {
  subject: string;
  issuer: string;
  serial: bigint | number;
  /** SubjectPublicKeyInfo DER of the certified key. */
  spki: Buffer;
  /** Private key of the ISSUER (signs the TBS). */
  signer: KeyObject;
  notBefore?: Date;
  notAfter?: Date;
  extensions?: Ext[];
}

export function makeCert(c: CertSpec): Buffer {
  const alg = der.seq(der.oid(OID_ECDSA_SHA256));
  const exts = c.extensions ?? [];
  const tbs = der.seq(
    der.explicit(0, der.int(2)),
    der.int(BigInt(c.serial)),
    alg,
    name(c.issuer),
    der.seq(der.time(c.notBefore ?? new Date('2020-01-01T00:00:00Z')), der.time(c.notAfter ?? new Date('2045-01-01T00:00:00Z'))),
    name(c.subject),
    c.spki,
    ...(exts.length ? [der.explicit(3, der.seq(...exts.map(extension)))] : []),
  );
  const sig = crypto.sign('sha256', tbs, c.signer); // DER ECDSA for an EC key
  return der.seq(tbs, alg, der.bitString(sig));
}

export function ecKey(curve = 'prime256v1'): { privateKey: KeyObject; publicKey: KeyObject; spki: Buffer } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
  return { privateKey, publicKey, spki: publicKey.export({ type: 'spki', format: 'der' }) as Buffer };
}

// ── KeyDescription (attestation extension) ─────────────────────────────────

/** An AuthorizationList entry: [tag] EXPLICIT inner. */
export type AuthItem = [number, Buffer];

export const TAG = {
  PURPOSE: 1, ALGORITHM: 2, KEY_SIZE: 3, DIGEST: 5, EC_CURVE: 10,
  ROLLBACK_RESISTANCE: 303, USER_SECURE_ID: 502, NO_AUTH_REQUIRED: 503, USER_AUTH_TYPE: 504,
  AUTH_TIMEOUT: 505, UNLOCKED_DEVICE_REQUIRED: 509, ALL_APPLICATIONS: 600, CREATION_DATETIME: 701,
  ORIGIN: 702, ROOT_OF_TRUST: 704, OS_VERSION: 705, OS_PATCH_LEVEL: 706,
  ATTESTATION_APPLICATION_ID: 709, VENDOR_PATCH_LEVEL: 718, BOOT_PATCH_LEVEL: 719,
} as const;

export const TEST_PACKAGE = 'tools.obli.obliance.next';
export const TEST_SIGNER = Buffer.from('8c7e67f860beacde55ab2437a41f50c6e2c8f0777f2faca88876676c6d82ac8d', 'hex');

export function rootOfTrust(o: { locked?: boolean; lockedOctet?: number; state?: number } = {}): Buffer {
  return der.seq(
    der.octet(Buffer.alloc(32, 0x11)),
    o.lockedOctet !== undefined ? der.rawBool(o.lockedOctet) : der.bool(o.locked ?? true),
    der.enumerated(o.state ?? 0),
    der.octet(Buffer.alloc(32, 0x22)),
  );
}

export function applicationId(packages: Array<[string, number]> = [[TEST_PACKAGE, 7]], signers: Buffer[] = [TEST_SIGNER]): Buffer {
  return der.seq(
    der.set(...packages.map(([p, v]) => der.seq(der.octet(p), der.int(v)))),
    der.set(...signers.map((s) => der.octet(s))),
  );
}

/** The hardware list of a key made exactly as the app makes it (API 30+). */
export function goodHardwareList(): AuthItem[] {
  return [
    [TAG.PURPOSE, der.set(der.int(2))],
    [TAG.ALGORITHM, der.int(3)],
    [TAG.KEY_SIZE, der.int(256)],
    [TAG.DIGEST, der.set(der.int(4))],
    [TAG.EC_CURVE, der.int(1)],
    [TAG.USER_AUTH_TYPE, der.int(2)],
    [TAG.UNLOCKED_DEVICE_REQUIRED, der.nul()],
    [TAG.ORIGIN, der.int(0)],
    [TAG.ROOT_OF_TRUST, rootOfTrust()],
    [TAG.OS_VERSION, der.int(150000)],
    [TAG.OS_PATCH_LEVEL, der.int(202609)],
    [TAG.VENDOR_PATCH_LEVEL, der.int(20260905)],
    [TAG.BOOT_PATCH_LEVEL, der.int(20260905)],
  ];
}

export function goodSoftwareList(): AuthItem[] {
  return [
    [TAG.CREATION_DATETIME, der.int(1790000000000)],
    [TAG.ATTESTATION_APPLICATION_ID, der.octet(applicationId())],
  ];
}

export interface KeyDescriptionSpec {
  attestationVersion?: number;
  attestationSecurityLevel?: number;
  keyMintVersion?: number;
  keyMintSecurityLevel?: number;
  challenge: Buffer;
  sw?: AuthItem[];
  hw?: AuthItem[];
}

export function keyDescription(k: KeyDescriptionSpec): Buffer {
  const list = (items: AuthItem[]) => der.seq(...items.map(([t, inner]) => der.explicit(t, inner)));
  return der.seq(
    der.int(k.attestationVersion ?? 200),
    der.enumerated(k.attestationSecurityLevel ?? 1),
    der.int(k.keyMintVersion ?? 200),
    der.enumerated(k.keyMintSecurityLevel ?? 1),
    der.octet(k.challenge),
    der.octet(Buffer.alloc(0)),
    list(k.sw ?? goodSoftwareList()),
    list(k.hw ?? goodHardwareList()),
  );
}

/** Replaces (or removes, with null) the entries of `tag` in a list. */
export function withTag(items: AuthItem[], tag: number, inner: Buffer | null): AuthItem[] {
  const out = items.filter(([t]) => t !== tag);
  if (inner) out.push([tag, inner]);
  return out.sort((a, b) => a[0] - b[0]);
}

// ── Chains ──────────────────────────────────────────────────────────────────

export interface FakeChainSpec {
  nonce: Buffer;
  kd?: Partial<KeyDescriptionSpec>;
  /** Replace the whole KeyDescription extension value. */
  kdValue?: Buffer;
  /** Leaf without the KeyDescription extension. */
  noKd?: boolean;
  /** Also put a KeyDescription in the intermediate. */
  kdInIntermediate?: boolean;
  /** Intermediate certified with CA:FALSE / digitalSignature (factory keyboxes). */
  intermediateNotCa?: boolean;
  /** RKP provisioning-info extension in the intermediate. */
  rkp?: boolean;
  intermediateValidity?: [Date, Date];
  rootValidity?: [Date, Date];
  /** The leaf certifies this SPKI instead of its own. */
  leafSpki?: Buffer;
  /** The leaf is signed by a key other than the intermediate's. */
  breakLeafSignature?: boolean;
  /** Leaf issuer name different from the intermediate subject. */
  wrongLeafIssuer?: boolean;
  /** Reuse an existing root (to share pins between chains). */
  root?: { privateKey: KeyObject; spki: Buffer; subject: string };
}

export interface FakeChain {
  chainB64: string[];
  der: Buffer[];
  leaf: { privateKey: KeyObject; spki: Buffer };
  intermediate: { privateKey: KeyObject; spki: Buffer; subject: string };
  root: { privateKey: KeyObject; spki: Buffer; subject: string };
  rootSpkiSha256: string;
  serials: string[];
}

let serialSeq = 0x1000;

export function makeRoot(subject = 'Fake Attestation Root'): { privateKey: KeyObject; spki: Buffer; subject: string } {
  const k = ecKey();
  return { privateKey: k.privateKey, spki: k.spki, subject };
}

/** leaf → intermediate → root (3 certificates), like a short KeyMint chain. */
export function makeChain(o: FakeChainSpec): FakeChain {
  const root = o.root ?? makeRoot();
  const inter = { ...ecKey(), subject: 'Fake Attestation Intermediate' };
  const leaf = ecKey();
  const s = [serialSeq++, serialSeq++, serialSeq++];
  const rootCert = makeCert({
    subject: root.subject, issuer: root.subject, serial: s[2], spki: root.spki, signer: root.privateKey,
    notBefore: o.rootValidity?.[0], notAfter: o.rootValidity?.[1],
    extensions: [basicConstraintsExt(true), keyUsageExt(true)],
  });
  const kdValue = o.kdValue ?? keyDescription({ challenge: o.nonce, ...o.kd });
  const interExts: Ext[] = o.intermediateNotCa
    ? [basicConstraintsExt(false), keyUsageExt(false)]
    : [basicConstraintsExt(true), keyUsageExt(true)];
  if (o.kdInIntermediate) interExts.push({ oid: OID_KEY_DESCRIPTION, value: kdValue });
  if (o.rkp) interExts.push({ oid: OID_PROVISIONING_INFO, value: der.seq() });
  const interCert = makeCert({
    subject: inter.subject, issuer: root.subject, serial: s[1], spki: inter.spki, signer: root.privateKey,
    notBefore: o.intermediateValidity?.[0], notAfter: o.intermediateValidity?.[1], extensions: interExts,
  });
  const leafExts: Ext[] = [keyUsageExt(false)];
  if (!o.noKd) leafExts.push({ oid: OID_KEY_DESCRIPTION, value: kdValue });
  const leafCert = makeCert({
    subject: 'Android Keystore Key',
    issuer: o.wrongLeafIssuer ? 'Somebody Else' : inter.subject,
    serial: s[0],
    spki: o.leafSpki ?? leaf.spki,
    signer: o.breakLeafSignature ? ecKey().privateKey : inter.privateKey,
    notBefore: new Date('1970-01-01T00:00:00Z'),
    notAfter: new Date('2106-02-07T06:28:15Z'),
    extensions: leafExts,
  });
  const ders = [leafCert, interCert, rootCert];
  return {
    chainB64: ders.map((d) => d.toString('base64')),
    der: ders,
    leaf,
    intermediate: inter,
    root,
    rootSpkiSha256: crypto.createHash('sha256').update(root.spki).digest('hex'),
    serials: s.map((n) => n.toString(16)),
  };
}
