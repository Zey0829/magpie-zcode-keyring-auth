// Turns the local ZCode 3.18 credential store into an auth entry that the
// upstream zcode plugin can consume.
//
// ZCode 3.18 keeps only tokens plus a *location* of the coding-plan API key
// (project-key-location:v1:...) in credentials.json - not the key itself. The
// upstream plugin already knows how to resolve such a location into a real
// key on every request (its `located()` helper), so we emit `loc` + `token`
// instead of baking in a secret. That also means we never copy a key into
// magpie's auth.json.

import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';

// The zcode-sync decryption libraries are vendored in this package so it can
// be published to npm on its own: no sibling repo checkout is required.
// They are CommonJS and use only Node built-ins.
const require = createRequire(import.meta.url);
const paths = require('./lib/paths.cjs');
const credentials = require('./lib/credentials.cjs');
const cryptoLib = require('./lib/crypto.cjs');
const keyring = require('./lib/keyring.cjs');

const SITES = {
  zai: { api: 'https://api.z.ai', families: ['zai', 'zai_cn'] },
  bigmodel: { api: 'https://bigmodel.cn', families: ['bigmodel'] },
};
const LOCATION = 'project-key-location:v1:';

function firstString(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

// Read and decrypt the local credentials file. `options.keyStore` lets tests
// inject a MemoryCredentialStore; in production the OS keyring is used.
export function readLocalPlain(options = {}) {
  const file = paths.resolveCredentialsFile(options);
  const record = credentials.readCredentialsFile(file);
  if (!record) throw new Error('本机没有找到 ZCode 的 credentials.json，请先安装并登录 ZCode');

  const store = options.keyStore || keyring.createCredentialStore();
  const { plain } = cryptoLib.decryptCredentialMap(record.map, {
    credentialsFile: file,
    env: options.env || process.env,
    keyStore: store,
    ...(options.keyringAccount ? { keyringAccount: options.keyringAccount } : {}),
  });
  return { plain, file };
}

function activeFamily(plain) {
  let active = firstString(plain['oauth:active_provider']);
  if (active.startsWith('{')) {
    try {
      active = firstString(JSON.parse(active).provider);
    } catch {
      /* not a JSON value - fall through to the plain string */
    }
  }
  return ['zai', 'zai_cn', 'bigmodel'].includes(active) ? active : 'zai';
}

function parseUserInfo(plain, family) {
  const raw = firstString(plain[`oauth:${family}:user_info`]);
  if (!raw) return {};
  try {
    const info = JSON.parse(raw);
    return info && typeof info === 'object' && !Array.isArray(info) ? info : {};
  } catch {
    return {};
  }
}

function jwtExpiry(jwt) {
  try {
    const part = String(jwt || '').split('.')[1];
    if (!part) return 0;
    const payload = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return Number(payload.exp) > 0 ? Number(payload.exp) * 1000 : 0;
  } catch {
    return 0;
  }
}

// Find the location entry belonging to the active account, mirroring the
// upstream `ownLocation()` rules: personal key (team === null), version 1,
// matching provider family, and matching account id when both are known.
function findLocation(plain, site, account) {
  const families = new Set(SITES[site].families);
  for (const [name, value] of Object.entries(plain)) {
    if (!name.startsWith(LOCATION)) continue;
    let at;
    try {
      at = JSON.parse(decodeURIComponent(name.slice(LOCATION.length)));
    } catch {
      continue;
    }
    if (!Array.isArray(at) || at[3] !== null || String(at[4]) !== '1' || !families.has(at[1])) continue;

    let found;
    try {
      found = JSON.parse(value);
    } catch {
      continue;
    }
    const org = firstString(found?.organizationId);
    const project = firstString(found?.projectId);
    const apiKeyId = firstString(found?.apiKeyId);
    if (!org || !project || !apiKeyId) continue;

    const locationAccount = String(at[2] ?? '');
    if (account && locationAccount && locationAccount !== account) continue;

    let origin = SITES[site].api;
    try {
      const url = new URL(firstString(at[0]));
      const host = url.hostname.toLowerCase();
      const trusted = site === 'zai'
        ? host === 'z.ai' || host.endsWith('.z.ai')
        : host === 'bigmodel.cn' || host.endsWith('.bigmodel.cn');
      if (url.protocol === 'https:' && trusted) origin = url.origin;
    } catch {
      /* keep the site's default API origin */
    }
    return { origin, org, project, apiKeyId };
  }
  return null;
}

function deviceMidOf(plain, options) {
  if (options.deviceMid) return firstString(options.deviceMid);
  const file = options.credentialsFile || paths.resolveCredentialsFile(options);
  const record = paths.readJsonFile(paths.onboardingFile(file));
  return firstString(record?.deviceMid) || randomUUID();
}

// Build the stored auth entry from an already-decrypted credential map.
// Pure with respect to secrets: no network and no writes.
export function buildAuthFromPlain(plain, options = {}) {
  if (!plain || typeof plain !== 'object') throw new Error('凭据为空');

  const family = activeFamily(plain);
  const site = family === 'bigmodel' ? 'bigmodel' : 'zai';
  const token = firstString(plain[`oauth:${family}:access_token`], plain[`oauth:zai:access_token`]);
  const jwt = firstString(plain.zcodejwttoken).replace(/^Bearer\s+/i, '');
  if (!token && !jwt) {
    throw new Error('本机 ZCode 没有可用的登录 token，请先在 ZCode 客户端登录');
  }

  const info = parseUserInfo(plain, family);
  const account = firstString(info.user_id, info.id, info.userId, info.uid);
  const accountId = firstString(info.email, account, info.username, info.displayName, info.name) || 'ZCode';
  const uid = account;

  const loc = findLocation(plain, site, uid);
  const state = {
    source: 'zcode-keyring',
    site,
    device: deviceMidOf(plain, options),
    token,
    jwt,
    ...(loc ? { loc } : {}),
    ...(options.credentialsFile ? { credentialsFile: options.credentialsFile } : {}),
  };

  return {
    type: 'success',
    refresh: JSON.stringify(state),
    // stateOf() uses `access` only when neither key nor jwt is present; we do
    // have a jwt, so this is mainly for consumers that look at `access`.
    access: jwt || token,
    // A coding-plan key resolved from `loc` does not expire. Without a
    // location we can only serve the Start Plan, whose jwt does expire.
    expires: loc ? 0 : jwtExpiry(jwt),
    accountId,
    ...(uid ? { uid } : {}),
  };
}

// Convenience: decrypt the local store and build the auth entry in one call.
export function buildAuth(options = {}) {
  const { plain, file } = readLocalPlain(options);
  return buildAuthFromPlain(plain, { ...options, credentialsFile: file });
}

// Build an auth entry from the plain JSON token file produced by
// `zcode-sync export-json`. That file has the .zcs payload shape:
// { format, createdAt, source: { deviceMid, ... }, summary, credentials }
// A bare credential map is accepted too, for files users assembled by hand.
export function buildAuthFromJson(text, options = {}) {
  let payload;
  try {
    payload = typeof text === 'string' ? JSON.parse(text) : text;
  } catch {
    throw new Error('JSON token 文件不是合法的 JSON');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('JSON token 文件内容无效');
  }

  let plain = payload.credentials;
  if (!plain || typeof plain !== 'object' || Array.isArray(plain)) {
    const bare = Object.values(payload).every((value) => typeof value === 'string');
    if (bare) plain = payload;
    else throw new Error('JSON token 文件缺少 credentials 对象');
  }

  const deviceMid = firstString(payload.source?.deviceMid, options.deviceMid);
  // No credentialsFile is recorded: a machine without ZCode has no local
  // store to follow, so the live-follow wrapper leaves this entry alone.
  return buildAuthFromPlain(plain, deviceMid ? { deviceMid } : {});
}

// A structural fingerprint used by the live-follow wrapper to decide whether
// the stored auth entry needs refreshing. Never includes secret values.
export function authFingerprint(auth) {
  let state = {};
  try {
    state = JSON.parse(auth?.refresh || '{}');
  } catch {
    /* ignore malformed entries */
  }
  return JSON.stringify({
    token: state.token || '',
    jwt: state.jwt || '',
    accountId: auth?.accountId || '',
    loc: state.loc || null,
  });
}

export { SITES, LOCATION };
