'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const credentials = require('../lib/credentials.cjs');
const cryptoLib = require('../lib/crypto.cjs');
const { MemoryCredentialStore } = require('../lib/keyring.cjs');
const paths = require('../lib/paths.cjs');

const JWT = (exp) => {
  const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  return `${header}.${payload}.sig`;
};

function plainMap(overrides = {}) {
  return {
    'oauth:active_provider': 'zai',
    'oauth:zai:access_token': 'access-123',
    'oauth:zai:refresh_token': 'refresh-456',
    'oauth:zai:user_info': JSON.stringify({ id: 'user-1', email: 'tester@example.com', username: 'tester' }),
    zcodejwttoken: JWT(2_000_000_000),
    ...overrides,
  };
}

const LOCATION_KEY = 'project-key-location:v1:' + encodeURIComponent(
  JSON.stringify(['https://api.z.ai', 'zai', 'user-1', null, 1, {}])
);
const LOCATION_VALUE = JSON.stringify({ organizationId: 'org-1', projectId: 'proj-1', apiKeyId: 'key-1' });

async function main() {
  const { buildAuthFromPlain, buildAuth, readLocalPlain, authFingerprint } =
    await import('../keyring-state.mjs');

  {
    const noLoc = buildAuthFromPlain(plainMap());
    const state = JSON.parse(noLoc.refresh);
    assert.strictEqual(state.source, 'zcode-keyring');
    assert.strictEqual(state.site, 'zai');
    assert.strictEqual(state.token, 'access-123');
    assert.strictEqual(state.jwt, JWT(2_000_000_000));
    assert.strictEqual(state.loc, undefined);
    assert.strictEqual(noLoc.expires, 2_000_000_000_000);
    assert.strictEqual(noLoc.accountId, 'tester@example.com');
    assert.strictEqual(noLoc.uid, 'user-1');
    assert.strictEqual(noLoc.access, state.jwt);

    const withLoc = buildAuthFromPlain(plainMap({ [LOCATION_KEY]: LOCATION_VALUE }), {
      credentialsFile: 'C:\\fake\\credentials.json',
      deviceMid: '11111111-2222-3333-4444-555555555555',
    });
    const locState = JSON.parse(withLoc.refresh);
    assert.deepStrictEqual(locState.loc, {
      origin: 'https://api.z.ai', org: 'org-1', project: 'proj-1', apiKeyId: 'key-1',
    });
    assert.strictEqual(withLoc.expires, 0, 'a location means a non-expiring coding-plan key');
    assert.strictEqual(locState.device, '11111111-2222-3333-4444-555555555555');
    assert.strictEqual(locState.credentialsFile, 'C:\\fake\\credentials.json');

    const bigmodel = buildAuthFromPlain(plainMap({
      'oauth:active_provider': 'bigmodel',
      'oauth:bigmodel:access_token': 'big-token',
      'oauth:bigmodel:user_info': JSON.stringify({ id: 'bm-1', email: 'bm@example.com' }),
    }));
    assert.strictEqual(JSON.parse(bigmodel.refresh).site, 'bigmodel');
    assert.strictEqual(JSON.parse(bigmodel.refresh).token, 'big-token');

    assert.throws(() => buildAuthFromPlain({ 'oauth:active_provider': 'zai' }), /没有可用的登录 token/);

    const changed = buildAuthFromPlain(plainMap({ 'oauth:zai:access_token': 'access-999' }));
    assert.notStrictEqual(authFingerprint(changed), authFingerprint(noLoc));
    console.log('PASS buildAuthFromPlain');
  }

  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-keyring-auth-'));
    const file = path.join(dir, 'v2', 'credentials.json');
    fs.mkdirSync(path.dirname(file), { recursive: true });

    const key = cryptoLib.randomBytes(32);
    const store = new MemoryCredentialStore({ [paths.pathHash(file)]: key.toString('base64url') });
    credentials.writeCredentialsFile(file, cryptoLib.encryptCredentialMap(plainMap({
      [LOCATION_KEY]: LOCATION_VALUE,
    }), { source: 'os', key }));
    credentials.writeCredentialSource(file);
    fs.writeFileSync(
      paths.onboardingFile(file),
      JSON.stringify({ version: 2, deviceMid: 'device-from-onboarding' })
    );

    const { plain, file: resolved } = readLocalPlain({ credentialsFile: file, keyStore: store });
    assert.strictEqual(resolved, file);
    assert.strictEqual(plain['oauth:zai:access_token'], 'access-123');

    const auth = buildAuth({ credentialsFile: file, keyStore: store });
    const state = JSON.parse(auth.refresh);
    assert.strictEqual(state.token, 'access-123');
    assert.strictEqual(state.device, 'device-from-onboarding');
    assert.deepStrictEqual(state.loc, {
      origin: 'https://api.z.ai', org: 'org-1', project: 'proj-1', apiKeyId: 'key-1',
    });
    assert.strictEqual(auth.expires, 0);
    console.log('PASS readLocalPlain / buildAuth (synthetic enc:v2:os)');
  }

  console.log('keyring-state tests passed');
}

main().catch((error) => {
  console.error('keyring-state FAILED:', error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
