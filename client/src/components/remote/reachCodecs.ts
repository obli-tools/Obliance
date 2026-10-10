/**
 * Video codecs the viewer can offer (ObliReach): the codecs the agent
 * announced in its init (`codecs`: the encoders actually available on the
 * remote — H.265 only with its DLL) AND that this browser decodes
 * (VideoDecoder.isConfigSupported with the codec strings the decoder is
 * configured with). An older agent that announces nothing keeps the full
 * static list.
 */
import { decoderCodecString } from '@/components/remote/reachMosaic';

export interface CodecOption { id: string; label: string }

export const ALL_CODECS: readonly CodecOption[] = [
  { id: 'h264', label: 'H.264' },
  { id: 'h265', label: 'H.265' },
  { id: 'vp9', label: 'VP9' },
  { id: 'av1', label: 'AV1' },
  { id: 'jpeg', label: 'JPEG' },
];

const KNOWN = new Set(ALL_CODECS.map((c) => c.id));

/** init.codecs → known codec ids; null when the agent announces none (older agent). */
export function agentCodecList(codecs: unknown): string[] | null {
  if (!Array.isArray(codecs)) return null;
  return codecs.filter((c): c is string => typeof c === 'string' && KNOWN.has(c));
}

type IsSupported = (cfg: VideoDecoderConfig) => Promise<{ supported?: boolean }>;

let probeCache: Promise<Record<string, boolean>> | null = null;

/**
 * What this browser decodes, probed once per page (the answer does not change
 * while it runs). JPEG is drawn by createImageBitmap: always decodable.
 */
export function probeDecodableCodecs(isSupported?: IsSupported): Promise<Record<string, boolean>> {
  if (probeCache && !isSupported) return probeCache;
  const fn: IsSupported | null = isSupported
    ?? (typeof VideoDecoder !== 'undefined' && typeof VideoDecoder.isConfigSupported === 'function'
      ? (cfg) => VideoDecoder.isConfigSupported(cfg)
      : null);
  const run = (async () => {
    const out: Record<string, boolean> = { jpeg: true };
    await Promise.all(ALL_CODECS.map(async (c) => {
      const codec = decoderCodecString(c.id);
      if (!codec) return;
      if (!fn) { out[c.id] = false; return; }
      try {
        const r = await fn({ codec, codedWidth: 1920, codedHeight: 1080, optimizeForLatency: true });
        out[c.id] = !!r?.supported;
      } catch {
        out[c.id] = false;
      }
    }));
    return out;
  })();
  if (!isSupported) probeCache = run;
  return run;
}

/**
 * The codecs to offer. agent: init.codecs (null: older agent → the static
 * list, unfiltered, as before); decodable: the probe's answer (null while it
 * runs: the agent's list alone). The codec streaming now is always kept, so
 * the control shows it.
 */
export function usableCodecs(agent: string[] | null, decodable: Record<string, boolean> | null, current?: string): CodecOption[] {
  if (!agent) return [...ALL_CODECS];
  return ALL_CODECS.filter((c) => c.id === current || (agent.includes(c.id) && (!decodable || decodable[c.id] !== false)));
}

/** A codec the agent can switch to (older agent: assumed, as before). */
export function codecOffered(id: string, agent: string[] | null, decodable: Record<string, boolean> | null): boolean {
  if (!agent) return true;
  return agent.includes(id) && (!decodable || decodable[id] !== false);
}
