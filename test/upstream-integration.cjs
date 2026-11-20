'use strict';

// Verifies the real upstream import path (import.meta.resolve -> opencode.mjs)
// when the dependency is installed. Skipped in a bare checkout.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('node:url');

async function main() {
  const installed = fs.existsSync(path.join(__dirname, '..', 'node_modules', '@magpie-community', 'opencode-zcode-auth'));
  if (!installed) {
    console.log('SKIP upstream integration (dependency not installed)');
    return;
  }

  const { ZCodeKeyringAuthPlugin, METHOD_LABEL } = await import('../plugin.mjs');
  const hooks = await ZCodeKeyringAuthPlugin({ client: {} });

  assert.strictEqual(hooks.auth.provider, 'zcode');
  assert.ok(Array.isArray(hooks.auth.methods));
  assert.strictEqual(hooks.auth.methods.length, 7, '5 upstream methods + our two new ones');
  assert.strictEqual(hooks.auth.methods.at(-2).label, METHOD_LABEL);
  assert.strictEqual(hooks.auth.methods.at(-1).label, 'ZCode: 导入 JSON token 文件');
  assert.ok(hooks.auth.methods.some((m) => m.label === 'ZCode: Z.ai GLM Coding Plan'));
  assert.ok(hooks.auth.methods.some((m) => m.label === "ZCode: a team's GLM Coding Plan"));
  assert.strictEqual(typeof hooks.auth.loader, 'function');
  assert.strictEqual(typeof hooks.auth.usage, 'function');
  assert.strictEqual(typeof hooks.config, 'function');
  assert.strictEqual(typeof hooks.provider.models, 'function');
  assert.strictEqual(typeof hooks['chat.headers'], 'function');

  const entry = await import('../index.mjs');
  assert.strictEqual(typeof entry.default, 'function');
  assert.strictEqual(entry.default, ZCodeKeyringAuthPlugin, 'the entry must export the plugin function itself');

  // Mirror magpie's plugin-host `servers()` helper exactly: a default object
  // carrying `id`/`tui` but no `server` function would yield zero plugins.
  const servers = (mod) => {
    const d = mod.default;
    if (d && typeof d === 'object' && ('server' in d || 'id' in d || 'tui' in d)) {
      return typeof d.server === 'function' ? [d.server] : [];
    }
    const seen = new Set();
    const out = [];
    for (const v of Object.values(mod)) {
      if (seen.has(v)) continue;
      seen.add(v);
      if (typeof v === 'function') out.push(v);
      else if (v && typeof v === 'object' && typeof v.server === 'function') out.push(v.server);
    }
    return out;
  };
  const found = servers(entry);
  assert.strictEqual(found.length, 1, 'magpie must discover exactly one plugin function');
  assert.strictEqual(found[0], ZCodeKeyringAuthPlugin);
  console.log('PASS magpie plugin-host entry convention');

  // The state our login method emits must be understood by the upstream
  // stateOf(), which is what every request path goes through.
  const { buildAuthFromPlain } = await import('../keyring-state.mjs');
  const locationKey = 'project-key-location:v1:' + encodeURIComponent(
    JSON.stringify(['https://api.z.ai', 'zai', 'user-1', null, 1, {}])
  );
  const auth = buildAuthFromPlain({
    'oauth:active_provider': 'zai',
    'oauth:zai:access_token': 'access-123',
    'oauth:zai:user_info': JSON.stringify({ id: 'user-1', email: 'tester@example.com' }),
    zcodejwttoken: 'h.eyJleHAiOjIwMDAwMDAwMDB9.sig',
    [locationKey]: JSON.stringify({ organizationId: 'org-1', projectId: 'proj-1', apiKeyId: 'key-1' }),
  }, { deviceMid: 'dev-1' });

  const upstreamEntry = require.resolve('@magpie-community/opencode-zcode-auth');
  const { _internal } = await import(new URL('./index.mjs', pathToFileURL(upstreamEntry)).href);
  // Magpie stores a successful callback as an `oauth` entry: the callback's
  // `type: "success"` becomes `type: "oauth"`, keeping refresh/access/etc.
  const storedAuth = {
    type: 'oauth',
    refresh: auth.refresh,
    access: auth.access,
    accountId: auth.accountId,
    uid: auth.uid,
  };
  const state = _internal.stateOf(storedAuth);
  assert.strictEqual(state.site, 'zai');
  assert.strictEqual(state.token, 'access-123');
  assert.strictEqual(state.jwt, 'h.eyJleHAiOjIwMDAwMDAwMDB9.sig');
  assert.strictEqual(state.device, 'dev-1');
  assert.strictEqual(state.base, 'https://api.z.ai/api/anthropic');
  assert.deepStrictEqual(state.loc, {
    origin: 'https://api.z.ai', org: 'org-1', project: 'proj-1', apiKeyId: 'key-1',
  });
  console.log('PASS auth entry is consumable by upstream stateOf()');
  console.log('PASS real upstream composition');
}

main().catch((error) => {
  console.error('upstream integration FAILED:', error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
