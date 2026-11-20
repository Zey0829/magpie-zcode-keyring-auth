'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const credentials = require('../lib/credentials.cjs');
const cryptoLib = require('../lib/crypto.cjs');
const { MemoryCredentialStore } = require('../lib/keyring.cjs');
const paths = require('../lib/paths.cjs');

const LOCATION_KEY = 'project-key-location:v1:' + encodeURIComponent(
  JSON.stringify(['https://api.z.ai', 'zai', 'user-1', null, 1, {}])
);
const LOCATION_VALUE = JSON.stringify({ organizationId: 'org-1', projectId: 'proj-1', apiKeyId: 'key-1' });
const JWT = (exp) => {
  const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  return `${header}.${payload}.sig`;
};
function plainMap(token = 'access-123') {
  return {
    'oauth:active_provider': 'zai',
    'oauth:zai:access_token': token,
    'oauth:zai:user_info': JSON.stringify({ id: 'user-1', email: 'tester@example.com' }),
    zcodejwttoken: JWT(2_000_000_000),
    [LOCATION_KEY]: LOCATION_VALUE,
  };
}

function stubUpstream() {
  const calls = { loader: 0, usage: 0, checkin: 0, config: 0 };
  const hooks = {
    'chat.headers': async () => {},
    config: async () => { calls.config += 1; },
    provider: { id: 'zcode', models: async () => [] },
    auth: {
      provider: 'zcode',
      maxConcurrency: 3,
      methods: [
        { type: 'oauth', label: 'upstream-1' },
        { type: 'oauth', label: 'upstream-2' },
        { type: 'api', label: 'upstream-3' },
      ],
      async loader() { calls.loader += 1; return { baseURL: 'x' }; },
      async usage() { calls.usage += 1; return {}; },
      async checkin() { calls.checkin += 1; return {}; },
    },
  };
  const fn = async () => hooks;
  return { fn, hooks, calls };
}

async function main() {
  const { ZCodeKeyringAuthPlugin, METHOD_LABEL, JSON_METHOD_LABEL } = await import('../plugin.mjs');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-keyring-plugin-'));
  const file = path.join(dir, 'v2', 'credentials.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const key = cryptoLib.randomBytes(32);
  const store = new MemoryCredentialStore({ [paths.pathHash(file)]: key.toString('base64url') });
  const write = (map) => {
    credentials.writeCredentialsFile(file, cryptoLib.encryptCredentialMap(map, { source: 'os', key }));
    credentials.writeCredentialSource(file);
  };
  write(plainMap());

  {
    const upstream = stubUpstream();
    const setCalls = [];
    const client = { auth: { set: async (req) => setCalls.push(req) } };
    const hooks = await ZCodeKeyringAuthPlugin(
      { client },
      { upstreamPlugin: upstream.fn, keyring: { credentialsFile: file, keyStore: store, deviceMid: 'dev-1' } }
    );

    assert.strictEqual(hooks.auth.methods.length, upstream.hooks.auth.methods.length + 2);
    assert.strictEqual(hooks.auth.methods.at(-2).label, METHOD_LABEL);
    assert.strictEqual(hooks.auth.methods.at(-2).type, 'oauth');
    assert.strictEqual(hooks.auth.methods.at(-1).label, JSON_METHOD_LABEL);
    assert.strictEqual(hooks['chat.headers'], upstream.hooks['chat.headers']);
    assert.strictEqual(hooks.config, upstream.hooks.config);
    assert.strictEqual(hooks.provider, upstream.hooks.provider);
    assert.strictEqual(hooks.auth.provider, 'zcode');
    assert.strictEqual(hooks.auth.maxConcurrency, 3);

    const flow = hooks.auth.methods.at(-2).authorize();
    assert.strictEqual(flow.method, 'auto');
    const result = await flow.callback();
    assert.strictEqual(result.type, 'success');
    const state = JSON.parse(result.refresh);
    assert.strictEqual(state.source, 'zcode-keyring');
    assert.strictEqual(state.device, 'dev-1');
    assert.strictEqual(state.token, 'access-123');
    assert.strictEqual(result.expires, 0);
    console.log('PASS wrapper composition + login callback');

    // JSON token login: works from a plain file, no ZCode installation
    // required. Mirrors the payload produced by `zcode-sync export-json`.
    {
      const jsonFile = path.join(dir, 'zcode-token.json');
      fs.writeFileSync(jsonFile, JSON.stringify({
        format: 1,
        createdAt: new Date().toISOString(),
        source: { platform: 'win32', arch: 'x64', deviceMid: 'json-device' },
        summary: {},
        credentials: plainMap(),
      }, null, 2));

      const jsonMethod = hooks.auth.methods.at(-1);
      assert.strictEqual(jsonMethod.prompts[0].key, 'file');
      const result = await jsonMethod.authorize({ file: jsonFile }).callback();
      assert.strictEqual(result.type, 'success');
      const state = JSON.parse(result.refresh);
      assert.strictEqual(state.source, 'zcode-keyring');
      assert.strictEqual(state.device, 'json-device');
      assert.strictEqual(state.token, 'access-123');
      assert.strictEqual(state.credentialsFile, undefined, 'a JSON import has no local store to follow');
      assert.strictEqual(result.expires, 0);

      const failed = await jsonMethod.authorize({ file: path.join(dir, 'missing.json') }).callback();
      assert.strictEqual(failed.type, 'failed');
      assert.ok(/ENOENT|no such file/i.test(failed.error));
      console.log('PASS JSON token login callback');
    }

    // Live follow: a stored entry with an old token must be refreshed from
    // the local store before the upstream loader runs.
    const storedAuth = {
      type: 'oauth',
      refresh: JSON.stringify({ ...state, token: 'old-token' }),
      access: 'old-token',
      accountId: 'tester@example.com',
      uid: 'user-1',
    };
    const getAuth = async () => storedAuth;
    await hooks.auth.loader(getAuth);
    assert.strictEqual(upstream.calls.loader, 1);
    assert.strictEqual(setCalls.length, 1, 'the stale token should be refreshed immediately');
    assert.strictEqual(JSON.parse(setCalls[0].body.refresh).token, 'access-123');
    assert.strictEqual(setCalls[0].body.type, 'oauth', 'the stored entry must keep its oauth type');

    // Write a new token and force another read by advancing the file's mtime.
    write(plainMap('access-999'));
    const future = new Date(Date.now() + 60_000);
    fs.utimesSync(file, future, future);
    await hooks.auth.loader(getAuth);
    assert.strictEqual(upstream.calls.loader, 2);
    assert.strictEqual(setCalls.length, 2, 'a rotated token should update stored auth again');
    const refreshed = JSON.parse(setCalls[1].body.refresh);
    assert.strictEqual(refreshed.token, 'access-999');
    assert.strictEqual(refreshed.device, 'dev-1');
    console.log('PASS live-follow refresh');

    // A foreign entry must not be touched.
    await hooks.auth.loader(async () => ({ type: 'oauth', refresh: JSON.stringify({ source: 'zcode' }) }));
    assert.strictEqual(setCalls.length, 2);
    console.log('PASS live-follow ignores foreign entries');
  }

  console.log('plugin wrapper tests passed');
}

main().catch((error) => {
  console.error('plugin wrapper FAILED:', error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
