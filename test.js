// Tests for worker.js. Run: node test.js (Node 18 or later; no packages).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handle } from './worker.js';

const ORIGIN = 'https://pages.example';
const REDIRECT = 'https://pages.example/signoff/auth.html';
const ENV = {
  GITHUB_CLIENT_ID: 'Iv1.testclient',
  GITHUB_CLIENT_SECRET: 'test-secret',
  ALLOWED_ORIGINS: ORIGIN + ' http://localhost:8774',
  ALLOWED_REDIRECTS: REDIRECT,
};
const VERIFIER = 'v'.repeat(43);

function req(path, body, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (opts.origin !== null) headers.Origin = opts.origin || ORIGIN;
  return new Request('https://signoff-auth.example' + path, {
    method: opts.method || 'POST',
    headers,
    body: opts.method === 'OPTIONS' || opts.method === 'GET' ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
  });
}

// A fake GitHub that records what it was asked.
function github(answer) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init, body: init.body instanceof URLSearchParams ? Object.fromEntries(init.body) : init.body });
    return typeof answer === 'function' ? answer(url, init) : answer;
  };
  fn.calls = calls;
  return fn;
}
const json = (status, data) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
const TOKENS = { access_token: 'ghu_abc', expires_in: 28800, refresh_token: 'ghr_def', refresh_token_expires_in: 15897600, token_type: 'bearer', scope: '', extra: 'dropped' };

test('exchange swaps a code for tokens, with the secret and PKCE verifier', async () => {
  const gh = github(json(200, TOKENS));
  const res = await handle(req('/exchange', { code: 'abc123', code_verifier: VERIFIER, redirect_uri: REDIRECT }), ENV, gh);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), ORIGIN);
  assert.equal(res.headers.get('Cache-Control'), 'no-store');
  const out = await res.json();
  assert.equal(out.access_token, 'ghu_abc');
  assert.equal(out.refresh_token, 'ghr_def');
  assert.equal(out.extra, undefined);
  assert.equal(gh.calls.length, 1);
  assert.equal(gh.calls[0].url, 'https://github.com/login/oauth/access_token');
  assert.deepEqual(gh.calls[0].body, { client_id: 'Iv1.testclient', client_secret: 'test-secret', code: 'abc123', code_verifier: VERIFIER, redirect_uri: REDIRECT });
});

test('refresh sends grant_type=refresh_token', async () => {
  const gh = github(json(200, TOKENS));
  const res = await handle(req('/refresh', { refresh_token: 'ghr_old' }), ENV, gh);
  assert.equal(res.status, 200);
  assert.equal(gh.calls[0].body.grant_type, 'refresh_token');
  assert.equal(gh.calls[0].body.refresh_token, 'ghr_old');
});

test("GitHub's 200-with-error comes back as 400 with its error", async () => {
  const gh = github(json(200, { error: 'bad_refresh_token', error_description: 'The refresh token passed is incorrect or expired.' }));
  const res = await handle(req('/refresh', { refresh_token: 'ghr_old' }), ENV, gh);
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'bad_refresh_token');
});

test('revoke calls DELETE /applications/{client_id}/token with basic auth', async () => {
  const gh = github(new Response(null, { status: 204 }));
  const res = await handle(req('/revoke', { access_token: 'ghu_abc' }), ENV, gh);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { revoked: true });
  const call = gh.calls[0];
  assert.equal(call.url, 'https://api.github.com/applications/Iv1.testclient/token');
  assert.equal(call.init.method, 'DELETE');
  assert.equal(call.init.headers.Authorization, 'Basic ' + btoa('Iv1.testclient:test-secret'));
  assert.deepEqual(JSON.parse(call.body), { access_token: 'ghu_abc' });
});

test('revoking an unknown token still counts as signed out', async () => {
  const res = await handle(req('/revoke', { access_token: 'ghu_gone' }), ENV, github(new Response(null, { status: 404 })));
  assert.equal(res.status, 200);
});

test('a foreign origin is refused with no CORS headers, and GitHub is never called', async () => {
  const gh = github(json(200, TOKENS));
  for (const origin of ['https://evil.example', null]) {
    const res = await handle(req('/refresh', { refresh_token: 'ghr_old' }, { origin }), ENV, gh);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get('Access-Control-Allow-Origin'), null);
  }
  assert.equal(gh.calls.length, 0);
});

test('preflight from an allowed origin', async () => {
  const res = await handle(req('/exchange', null, { method: 'OPTIONS', origin: 'http://localhost:8774' }), ENV, github(null));
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), 'http://localhost:8774');
});

test('only the three routes, only POST', async () => {
  const gh = github(json(200, TOKENS));
  assert.equal((await handle(req('/user', { a: 1 }), ENV, gh)).status, 404);
  assert.equal((await handle(req('/login/oauth/access_token', { a: 1 }), ENV, gh)).status, 404);
  assert.equal((await handle(req('/refresh', null, { method: 'GET' }), ENV, gh)).status, 405);
  assert.equal(gh.calls.length, 0);
});

test('bad input is refused before GitHub is called', async () => {
  const gh = github(json(200, TOKENS));
  const cases = [
    req('/exchange', { code: 'abc', code_verifier: VERIFIER, redirect_uri: 'https://evil.example/cb' }),
    req('/exchange', { code: 'abc', code_verifier: 'short', redirect_uri: REDIRECT }),
    req('/exchange', { code: 'a b', code_verifier: VERIFIER, redirect_uri: REDIRECT }),
    req('/exchange', { code_verifier: VERIFIER, redirect_uri: REDIRECT }),
    req('/refresh', { refresh_token: 42 }),
    req('/refresh', 'not json'),
    req('/refresh', [1, 2]),
    req('/refresh', { refresh_token: 'x'.repeat(5000) }),
    req('/revoke', {}),
  ];
  for (const r of cases) assert.equal((await handle(r, ENV, gh)).status, 400);
  assert.equal(gh.calls.length, 0);
});

test('a GitHub outage is a 502, never a crash', async () => {
  const down = async () => { throw new Error('network'); };
  assert.equal((await handle(req('/refresh', { refresh_token: 'ghr_old' }), ENV, down)).status, 502);
  assert.equal((await handle(req('/refresh', { refresh_token: 'ghr_old' }), ENV, github(new Response('<html>', { status: 500 })))).status, 502);
});

test('an unconfigured Worker says so', async () => {
  const res = await handle(req('/refresh', { refresh_token: 'ghr_old' }), { ALLOWED_ORIGINS: ORIGIN }, github(null));
  assert.equal(res.status, 500);
  assert.equal((await res.json()).error, 'not_configured');
});

test('the secret never appears in any answer', async () => {
  const gh = github(json(200, { ...TOKENS, client_secret: 'test-secret' }));
  const res = await handle(req('/exchange', { code: 'abc', code_verifier: VERIFIER, redirect_uri: REDIRECT }), ENV, gh);
  assert.ok(!(await res.text()).includes('test-secret'));
});
