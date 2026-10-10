import './env';

function publicUrlFromEnv(): string {
  const appUrl = (process.env.APP_URL || '').trim();
  if (appUrl) return appUrl.replace(/\/+$/, '');
  const clientOrigin = (process.env.CLIENT_ORIGIN || '').trim();
  try {
    const host = new URL(clientOrigin).hostname;
    if (host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127\./.test(host)) return '';
  } catch {
    return '';
  }
  return clientOrigin.replace(/\/+$/, '');
}

// Only an explicit NODE_ENV=development accepts the local fallbacks below
// (database URL, session secret) and weak secrets. Any other value, unset
// included, is a deployment: see startupConfigErrors(). `nodeEnv` and
// `isDev` (logging, static files, cookie flag) are no such signal: they
// treat an unset NODE_ENV as development.
const explicitDevelopment = process.env.NODE_ENV === 'development';
const DEV_DATABASE_URL = 'postgres://obliance:changeme@localhost:5432/obliance';
const DEV_SESSION_SECRET = 'change-this-secret';

export const config = {
  port: parseInt(process.env.PORT || '3001', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isDev: process.env.NODE_ENV !== 'production',
  /** Empty when DATABASE_URL is unset outside development (refused at start). */
  databaseUrl: process.env.DATABASE_URL || (explicitDevelopment ? DEV_DATABASE_URL : ''),
  /** Empty when SESSION_SECRET is unset outside development (refused at start). */
  sessionSecret: process.env.SESSION_SECRET || (explicitDevelopment ? DEV_SESSION_SECRET : ''),
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  forceHttps: process.env.FORCE_HTTPS === 'true',
  appName: process.env.APP_NAME || 'Obliance',
  appUrl: process.env.APP_URL || '',
  // The public address of this instance: APP_URL, else CLIENT_ORIGIN when the
  // operator set it explicitly (in the Docker deployment both name the same
  // origin: nginx serves the web client and proxies the API). Never the dev
  // default above, never derived from a request header.
  publicUrl: publicUrlFromEnv(),
  // Initial administrator (index.ts:ensureDefaultAdmin), created only while
  // no administrator exists. No default password: when
  // DEFAULT_ADMIN_PASSWORD is empty, a random one is generated and printed
  // once in the startup logs. Outside development, a weak value (under 12
  // characters or a known default) makes the server refuse to start when it
  // would create that account (defaultAdminPasswordError).
  defaultAdminUsername: process.env.DEFAULT_ADMIN_USERNAME || 'admin',
  defaultAdminPassword: process.env.DEFAULT_ADMIN_PASSWORD || '',
  disable2faForce: process.env.DISABLE_2FA_FORCE === 'true',
  minPushInterval: parseInt(process.env.MIN_PUSH_INTERVAL || '10', 10),
  customDir: process.env.CUSTOM_DIR || './custom',
  // Remote access
  remoteTunnelPath: '/api/remote/tunnel',
  // SSH Bastion (ObliJump) — opt-in via .env, like the Oblihub stacks. The
  // ssh2 server only binds when enabled; SSH_BASTION_PORT must NOT be 22 (that
  // stays the host sshd). This port is the one guarded by the IP whitelist,
  // anti-bruteforce and honeypot.
  sshBastion: {
    enabled: process.env.SSH_BASTION_ENABLED === 'true',
    port: parseInt(process.env.SSH_BASTION_PORT || '2222', 10),
  },
  // Device-bound 2FA. Parsed and
  // validated by services/deviceKey/deviceKey.service.ts.
  deviceKeys: {
    /** Emergency switch, overrides the platform settings. */
    disabled: process.env.DEVICE_KEYS_DISABLED === 'true',
    /** Extra enrolment origins (comma-separated), next to APP_URL. */
    origins: process.env.DEVICE_KEY_ORIGINS || '',
    /** Accepted app packages (comma-separated); default tools.obli.obliance.next. */
    appIds: process.env.DEVICE_KEY_APP_IDS || '',
    /** Accepted APK signer SHA-256 digests (comma-separated, ':' ignored);
     *  default: the release signer. A debug signer is added here only on a
     *  development server. */
    appSigners: process.env.DEVICE_KEY_APP_SIGNERS || '',
    /** Secret of the request-binding body key (HMAC, binding v2); empty →
     *  derived from SESSION_SECRET. Never stored in the database. */
    bindingSecret: process.env.DEVICE_KEY_BINDING_SECRET || '',
    /** SSO device-key opt-in (SSO / Obligate accounts): OFF unless exactly 'true'.
     *  While off, Obligate's capabilities are never read and SSO accounts
     *  keep today's behaviour (no phone key, no consuming verify-totp). */
    ssoEnabled: process.env.DEVICE_KEYS_SSO_ENABLED === 'true',
  },
};

// Placeholders shipped at one time or another by the install files
// (changeme, change-this-…, admin123) and their variants: refused outside
// development, whatever the length.
const PLACEHOLDER_RE = /change[-_. ]?(?:me|this)|admin123/i;
const MIN_SESSION_SECRET_LENGTH = 32;
const MIN_ADMIN_PASSWORD_LENGTH = 12;

function isWeakSecret(value: string, minLength: number): boolean {
  return value.length < minLength || PLACEHOLDER_RE.test(value);
}

export const DATABASE_URL_MISSING =
  'DATABASE_URL is not set: point it at the PostgreSQL database (postgres://user:password@host:5432/name). ' +
  'The local development database is only used with NODE_ENV=development.';

/** Under 12 characters or a known default. */
export function isWeakAdminPassword(password: string): boolean {
  return isWeakSecret(password, MIN_ADMIN_PASSWORD_LENGTH);
}

/**
 * Why DEFAULT_ADMIN_PASSWORD may not create the initial administrator, or
 * null (always null in development, or when it is empty: a random password
 * is generated). Checked only when that account is about to be created
 * (index.ts:ensureDefaultAdmin): an existing install whose .env still holds
 * the former default (admin123) keeps starting, the value being unused.
 */
export function defaultAdminPasswordError(): string | null {
  if (explicitDevelopment || !config.defaultAdminPassword) return null;
  if (!isWeakAdminPassword(config.defaultAdminPassword)) return null;
  return 'DEFAULT_ADMIN_PASSWORD is too weak: use at least 12 characters and not a default value, or leave it ' +
    'empty to get a random password printed once in the startup logs.';
}

/** Why the session secret is refused (sessions would be forgeable), or null.
 *  Always null in development. */
export function sessionSecretError(): string | null {
  if (explicitDevelopment) return null;
  if (!config.sessionSecret) {
    return 'SESSION_SECRET is not set: set it to a random value of at least 32 characters ' +
      '(e.g. openssl rand -hex 32). The built-in development secret is only accepted with NODE_ENV=development.';
  }
  if (isWeakSecret(config.sessionSecret, MIN_SESSION_SECRET_LENGTH)) {
    return 'SESSION_SECRET is too weak: use a random value of at least 32 characters, not a placeholder ' +
      '(e.g. openssl rand -hex 32).';
  }
  return null;
}

/**
 * Settings the server refuses to start with, as messages for the operator
 * (empty: none, always in development). Checked by index.ts before anything
 * touches the database. The initial admin password is checked later, only
 * when it would be used (defaultAdminPasswordError).
 */
export function startupConfigErrors(): string[] {
  if (explicitDevelopment) return [];
  const errors: string[] = [];
  if (!config.databaseUrl) errors.push(DATABASE_URL_MISSING);
  const secretError = sessionSecretError();
  if (secretError) errors.push(secretError);
  return errors;
}
