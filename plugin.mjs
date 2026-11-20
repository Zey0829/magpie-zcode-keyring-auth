// Wrapper around the upstream zcode plugin. All of its hooks are forwarded
// unchanged; only one thing is added: a login method that reads the local
// ZCode 3.18 credential store.
//
// The new method emits a location-based auth entry (see keyring-state.mjs),
// which the upstream `located()` resolves into a real coding-plan key on each
// request. A thin wrapper around the auth hooks keeps that entry in sync when
// ZCode refreshes its tokens or signs in to another account.

import fs from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { buildAuth, buildAuthFromJson, authFingerprint } from './keyring-state.mjs';

const UPSTREAM_PKG = '@magpie-community/opencode-zcode-auth';
const PROVIDER_ID = 'zcode';
const METHOD_LABEL = 'ZCode: 本机 ZCode 3.18 钥匙串登录';
const JSON_METHOD_LABEL = 'ZCode: 导入 JSON token 文件';
const FOLLOW_CACHE_MS = 30_000;

// ---- upstream loading -----------------------------------------------------

async function upstreamV1Url() {
  if (typeof import.meta.resolve === 'function') return import.meta.resolve(UPSTREAM_PKG);
  // Older runtimes: require.resolve honours the package's exports map too.
  const require = createRequire(import.meta.url);
  return pathToFileURL(require.resolve(UPSTREAM_PKG)).href;
}

async function defaultUpstreamLoader() {
  const entry = await upstreamV1Url();
  // The published package exposes only "." (opencode2.mjs). The v1 plugin
  // function lives one file over, so resolve it relative to the entry URL.
  const mod = await import(new URL('./opencode.mjs', entry).href);
  if (typeof mod.ZCodeAuthPlugin !== 'function') {
    throw new Error('上游 zcode 插件没有导出 ZCodeAuthPlugin；请检查插件版本');
  }
  return mod.ZCodeAuthPlugin;
}

// Tests inject a stub loader so this package can be exercised without the
// upstream dependency installed.
let upstreamLoader = defaultUpstreamLoader;
export function setUpstreamLoader(loader) {
  upstreamLoader = loader;
}

// ---- live follow ----------------------------------------------------------

function makeFollower(client, options) {
  const last = { at: 0, mtime: 0 };

  return async function refreshStoredAuth(getAuth) {
    if (typeof getAuth !== 'function' || typeof client?.auth?.set !== 'function') return;
    let auth;
    try {
      auth = await getAuth();
    } catch {
      return;
    }

    let state;
    try {
      state = JSON.parse(auth?.refresh || '{}');
    } catch {
      return;
    }
    if (state?.source !== 'zcode-keyring') return; // not an entry from our method

    const file = state.credentialsFile;
    if (!file) return;
    let mtime = 0;
    try {
      mtime = fs.statSync(file).mtimeMs;
    } catch {
      return;
    }
    const now = Date.now();
    if (now - last.at < FOLLOW_CACHE_MS && mtime === last.mtime) return;

    let fresh;
    try {
      fresh = buildAuth({
        ...options.keyring,
        credentialsFile: file,
        deviceMid: state.device, // keep the device id stable across refreshes
      });
    } catch {
      return; // transient read failure: keep the stored entry
    }

    let freshState;
    try {
      freshState = JSON.parse(fresh.refresh);
    } catch {
      return;
    }
    freshState.credentialsFile = file;
    freshState.device = state.device || freshState.device;
    fresh.refresh = JSON.stringify(freshState);

    if (authFingerprint(fresh) === authFingerprint(auth)) {
      last.at = now;
      last.mtime = mtime;
      return;
    }

    try {
      // `fresh` is a callback result (type "success"); the stored entry must
      // keep its `oauth` type. Only copy the credential-bearing fields.
      const body = {
        ...auth,
        refresh: fresh.refresh,
        access: fresh.access,
        expires: fresh.expires,
        accountId: fresh.accountId,
        ...(fresh.uid ? { uid: fresh.uid } : {}),
      };
      await client.auth.set({ path: { id: PROVIDER_ID }, body });
      last.at = now;
      last.mtime = mtime;
    } catch {
      // The host may not allow writes from a hook; the stored entry still
      // works until its token expires, so this is not fatal.
    }
  };
}

function withFollow(hook, follow) {
  if (typeof hook !== 'function') return hook;
  return async (...args) => {
    try {
      await follow(args[0]);
    } catch {
      /* following is best-effort; never break the actual hook */
    }
    return hook(...args);
  };
}

// ---- plugin factory -------------------------------------------------------

export async function ZCodeKeyringAuthPlugin(args = {}, options = {}) {
  const UpstreamPlugin = options.upstreamPlugin || (await upstreamLoader());
  const hooks = await UpstreamPlugin(args, options);
  if (!hooks || typeof hooks !== 'object') throw new Error('上游 zcode 插件没有返回 hooks');

  const newMethod = {
    type: 'oauth',
    label: METHOD_LABEL,
    authorize: () => ({
      url: '',
      instructions: '读取本机 ZCode 3.18 客户端的登录凭据，无需浏览器。',
      method: 'auto',
      async callback() {
        try {
          return buildAuth(options.keyring || {});
        } catch (error) {
          return { type: 'failed', error: error?.message || String(error) };
        }
      },
    }),
  };

  const jsonMethod = {
    type: 'oauth',
    label: JSON_METHOD_LABEL,
    prompts: [
      {
        type: 'text',
        key: 'file',
        message: 'JSON token 文件路径（由 zcode-sync export-json 生成）',
        placeholder: 'C:\\path\\to\\zcode-token.json',
      },
    ],
    authorize: (inputs) => ({
      url: '',
      instructions: '读取 JSON token 文件；本机无需安装 ZCode。',
      method: 'auto',
      async callback() {
        try {
          const file = String(inputs?.file || '').trim();
          if (!file) return { type: 'failed', error: '请先填写 JSON token 文件路径' };
          const text = await fs.promises.readFile(file, 'utf8');
          return buildAuthFromJson(text);
        } catch (error) {
          return { type: 'failed', error: error?.message || String(error) };
        }
      },
    }),
  };

  const methods = [...(hooks.auth?.methods || []), newMethod, jsonMethod];
  const follow = makeFollower(args?.client, options);

  return {
    ...hooks,
    auth: {
      ...hooks.auth,
      methods,
      ...(hooks.auth?.loader ? { loader: withFollow(hooks.auth.loader, follow) } : {}),
      ...(hooks.auth?.usage ? { usage: withFollow(hooks.auth.usage, follow) } : {}),
      ...(hooks.auth?.checkin ? { checkin: withFollow(hooks.auth.checkin, follow) } : {}),
    },
  };
}

export { METHOD_LABEL, JSON_METHOD_LABEL, PROVIDER_ID, FOLLOW_CACHE_MS };
