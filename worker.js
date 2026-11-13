// signoff-auth: the token exchange behind the Signoff suite's "Sign in with GitHub".
//
// GitHub's token endpoint needs the GitHub App's client secret and has no CORS, so the suite's static
// pages can't finish a sign-in on their own. This Worker holds the secret and does four things only:
//
//   POST /exchange  {code, code_verifier, redirect_uri}  one-time code → access and refresh tokens
//   POST /refresh   {refresh_token}                       a new token pair (the old refresh token dies)
//   POST /revoke    {access_token}                        sign out: GitHub forgets the authorization
//   POST /invitations {access_token}                      the caller's pending invitations on INVITE_OWNER's
//                                                         private repos, which a sign-in token can't list
//
// It is not a proxy: no other route, no other GitHub call. It stores nothing and logs nothing.
//
// Settings (Cloudflare → the Worker → Settings → Variables and secrets):
//   GITHUB_CLIENT_ID      the app's client id (plain text is fine)
//   GITHUB_CLIENT_SECRET  the app's client secret (type: Secret)
//   ALLOWED_ORIGINS       space-separated page origins, e.g. "https://chrismessick-dpd.github.io"
//   ALLOWED_REDIRECTS     space-separated callback URLs registered on the app, e.g.
//                         "https://chrismessick-dpd.github.io/signoff/auth.html"
//   GITHUB_APP_ID         /invitations only: the app's numeric App ID (not the client id)
//   GITHUB_APP_PRIVATE_KEY  /invitations only: the app's private key, the whole .pem (type: Secret)
//   INVITE_OWNER          /invitations only: the account whose repos are looked through, e.g. "chrismessick-dpd"

const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const GITHUB_API = 'https://api.github.com';
const MAX_BODY = 4096;
const USER_AGENT = 'signoff-auth';

// What a token response may carry back to the page. Anything else GitHub adds is dropped.
const TOKEN_FIELDS = ['access_token', 'expires_in', 'refresh_token', 'refresh_token_expires_in', 'token_type', 'scope'];

// Loose shape checks: enough to refuse junk before it reaches GitHub, without guessing GitHub's formats.
const SHAPES = {
  code: /^[A-Za-z0-9_-]{1,128}$/,
  code_verifier: /^[A-Za-z0-9._~-]{43,128}$/,   // RFC 7636
  refresh_token: /^[A-Za-z0-9_-]{1,512}$/,
  access_token: /^[A-Za-z0-9_-]{1,512}$/,
};

function list(value) {
  return String(value || '').split(/[\s,]+/).filter(Boolean);
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '600',
    'Vary': 'Origin',
  };
}

function reply(status, body, origin) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  };
  if (origin) Object.assign(headers, corsHeaders(origin));
  return new Response(JSON.stringify(body), { status, headers });
}

function fail(status, error, description, origin) {
  return reply(status, { error, error_description: description }, origin);
}

async function readJson(request) {
  const type = request.headers.get('Content-Type') || '';
  if (!/^application\/json\b/i.test(type)) return { error: 'Expected Content-Type: application/json.' };
  const text = await request.text();
  if (text.length > MAX_BODY) return { error: 'Request body too large.' };
  let data;
  try { data = JSON.parse(text); } catch (e) { return { error: 'Request body is not JSON.' }; }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { error: 'Request body must be a JSON object.' };
  return { data };
}

function field(data, name) {
  const v = data[name];
  return typeof v === 'string' && SHAPES[name].test(v) ? v : null;
}

// GitHub answers 200 even for a bad code, with {error, error_description}. Pass those through as 400.
async function tokenCall(env, params, origin, fetchImpl) {
  const body = new URLSearchParams(Object.assign({
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
  }, params));
  let res;
  try {
    res = await fetchImpl(GITHUB_TOKEN_URL, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': USER_AGENT },
      body,
    });
  } catch (e) {
    return fail(502, 'github_unreachable', 'Could not reach GitHub. Try again.', origin);
  }
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok || !data) return fail(502, 'github_error', 'GitHub answered ' + res.status + '.', origin);
  if (data.error) return fail(400, String(data.error), String(data.error_description || data.error), origin);
  if (!data.access_token) return fail(502, 'github_error', 'GitHub sent no token.', origin);
  const out = {};
  TOKEN_FIELDS.forEach((k) => { if (data[k] !== undefined) out[k] = data[k]; });
  return reply(200, out, origin);
}

async function revoke(env, accessToken, origin, fetchImpl) {
  const basic = btoa(env.GITHUB_CLIENT_ID + ':' + env.GITHUB_CLIENT_SECRET);
  let res;
  try {
    res = await fetchImpl(GITHUB_API + '/applications/' + encodeURIComponent(env.GITHUB_CLIENT_ID) + '/token', {
      method: 'DELETE',
      headers: {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Basic ' + basic,
        'Content-Type': 'application/json',
        'User-Agent': USER_AGENT,
        'X-GitHub-Api-Version': '2022-11-28',
      },
      body: JSON.stringify({ access_token: accessToken }),
    });
  } catch (e) {
    return fail(502, 'github_unreachable', 'Could not reach GitHub. Try again.', origin);
  }
  // 204: revoked. 404/422: GitHub doesn't know the token (already revoked or expired). Either way it's gone.
  if (res.status === 204 || res.status === 404 || res.status === 422) return reply(200, { revoked: true }, origin);
  return fail(502, 'github_error', 'GitHub answered ' + res.status + '.', origin);
}

// ── /invitations ──────────────────────────────────────────────────────────────────────────────────
// A sign-in token (ghu_) can accept an invitation to a private repo by its id, but GitHub hides the
// invitation from that token's own list until it's accepted (the app reaches only repos the person can
// already see). So the Worker looks them up as the app: it learns who is asking from their own token
// (GET /user), then lists each private repo's pending invitations with an installation token and
// returns only those addressed to that login. The page accepts them with the person's own token.

const MAX_CALLS = 45;          // Cloudflare's free plan allows 50 outgoing requests per request
const SCAN_BATCH = 6;

function b64url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlText(text) { return b64url(new TextEncoder().encode(text)); }

// DER pieces, to wrap GitHub's PKCS#1 key ("BEGIN RSA PRIVATE KEY") as the PKCS#8 WebCrypto imports.
function derLen(n) {
  if (n < 0x80) return [n];
  const out = [];
  while (n > 0) { out.unshift(n & 0xff); n >>= 8; }
  return [0x80 | out.length].concat(out);
}
function der(tag, body) {
  const head = [tag].concat(derLen(body.length));
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0); out.set(body, head.length);
  return out;
}
function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0), out = new Uint8Array(total);
  let at = 0;
  parts.forEach((p) => { out.set(p, at); at += p.length; });
  return out;
}
export function pemToPkcs8(pem) {
  const text = String(pem || '').replace(/\\n/g, '\n');
  const m = text.match(/-----BEGIN (RSA )?PRIVATE KEY-----([\s\S]*?)-----END (RSA )?PRIVATE KEY-----/);
  if (!m) throw new Error('not a PEM private key');
  const bin = atob(m[2].replace(/\s+/g, ''));
  const body = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) body[i] = bin.charCodeAt(i);
  if (!m[1]) return body;   // already PKCS#8
  const version = new Uint8Array([0x02, 0x01, 0x00]);
  const algorithm = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  return der(0x30, concat([version, algorithm, der(0x04, body)]));
}

export async function appJwt(env, nowSec) {
  const key = await crypto.subtle.importKey('pkcs8', pemToPkcs8(env.GITHUB_APP_PRIVATE_KEY),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const now = nowSec || Math.floor(Date.now() / 1000);
  const head = b64urlText(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const body = b64urlText(JSON.stringify({ iat: now - 60, exp: now + 540, iss: String(env.GITHUB_APP_ID) }));
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(head + '.' + body)));
  return head + '.' + body + '.' + b64url(sig);
}

// An installation token lasts an hour; keep it while this isolate lives (never stored anywhere else).
let installCache = null;
export function _forgetInstallation() { installCache = null; }

function ghHeaders(auth) {
  return {
    'Accept': 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'Authorization': auth,
    'User-Agent': USER_AGENT,
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

async function invitations(env, accessToken, origin, fetchImpl) {
  let calls = 0;
  async function call(url, auth, init) {
    if (calls >= MAX_CALLS) { const e = new Error('budget'); e.budget = true; throw e; }
    calls++;
    return fetchImpl(GITHUB_API + url, Object.assign({ headers: ghHeaders(auth) }, init || {}));
  }
  const owner = String(env.INVITE_OWNER).toLowerCase();
  try {
    // 1. Who is asking, and that the token is this app's (a pasted token lists its own invitations):
    // GitHub's "check a token", with the app's client id and secret. Only their invitations come back.
    const me = await call('/applications/' + encodeURIComponent(env.GITHUB_CLIENT_ID) + '/token',
      'Basic ' + btoa(env.GITHUB_CLIENT_ID + ':' + env.GITHUB_CLIENT_SECRET),
      { method: 'POST', body: JSON.stringify({ access_token: accessToken }) });
    if (me.status === 404 || me.status === 422) return fail(401, 'bad_token', 'That isn’t a live Signoff sign-in.', origin);
    if (!me.ok) return fail(502, 'github_error', 'GitHub answered ' + me.status + '.', origin);
    const login = String(((await me.json()).user || {}).login || '').toLowerCase();
    if (!login) return fail(502, 'github_error', 'GitHub didn’t say who you are.', origin);

    // 2. The app's installation on the owner, and a read-only token for it.
    const key = owner + ':' + env.GITHUB_APP_ID;
    if (!installCache || installCache.key !== key || installCache.expires - Date.now() < 5 * 60000) {
      const jwt = 'Bearer ' + await appJwt(env);
      let inst = await call('/users/' + encodeURIComponent(owner) + '/installation', jwt);
      if (inst.status === 404) inst = await call('/orgs/' + encodeURIComponent(owner) + '/installation', jwt);
      if (!inst.ok) return fail(502, 'github_error', 'The app isn’t installed on ' + owner + ' (GitHub answered ' + inst.status + ').', origin);
      const id = (await inst.json()).id;
      const tok = await call('/app/installations/' + id + '/access_tokens', jwt, {
        method: 'POST',
        body: JSON.stringify({ permissions: { administration: 'read', metadata: 'read' } }),
      });
      if (!tok.ok) return fail(502, 'github_error', 'GitHub refused an installation token (' + tok.status + ').', origin);
      const t = await tok.json();
      installCache = { key, token: t.token, expires: Date.parse(t.expires_at) || Date.now() + 3600000 };
    }
    const inst = 'Bearer ' + installCache.token;

    // 3. The private repos (public ones the person's own token already lists), newest first.
    let repos = [], partial = false;
    for (let page = 1; page <= 10; page++) {
      const r = await call('/installation/repositories?per_page=100&page=' + page, inst);
      if (!r.ok) return fail(502, 'github_error', 'GitHub answered ' + r.status + ' listing repositories.', origin);
      const list = (await r.json()).repositories || [];
      repos = repos.concat(list);
      if (list.length < 100) break;
    }
    repos = repos.filter((r) => r.private && r.owner && String(r.owner.login).toLowerCase() === owner)
      .sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));

    // 4. Each one's pending invitations, keeping the caller's.
    const out = [];
    for (let i = 0; i < repos.length;) {
      const room = MAX_CALLS - calls;
      if (room <= 0) { partial = true; break; }
      const batch = repos.slice(i, i + Math.min(SCAN_BATCH, room));
      i += batch.length;
      const answers = await Promise.all(batch.map((r) => call('/repos/' + r.full_name + '/invitations?per_page=100', inst)
        .then(async (res) => (res.ok ? { r, list: await res.json() } : { r, list: [] }))));
      answers.forEach(({ r, list }) => {
        (Array.isArray(list) ? list : []).forEach((inv) => {
          if (inv && inv.invitee && String(inv.invitee.login).toLowerCase() === login && !inv.expired) {
            out.push({ id: inv.id, repo: r.full_name, created_at: inv.created_at || null });
          }
        });
      });
    }
    return reply(200, { login, invitations: out, partial }, origin);
  } catch (e) {
    if (e && e.budget) return fail(502, 'github_error', 'Too many repositories to check at once.', origin);
    return fail(502, 'github_unreachable', 'Could not reach GitHub. Try again.', origin);
  }
}

export async function handle(request, env, fetchImpl) {
  fetchImpl = fetchImpl || fetch;
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return fail(500, 'not_configured', 'The Worker has no client id or secret.', null);
  }
  const url = new URL(request.url);
  const origin = request.headers.get('Origin') || '';
  const allowed = list(env.ALLOWED_ORIGINS).includes(origin);

  // No CORS headers for a page that isn't ours, so its browser refuses to read any answer.
  if (!allowed) return fail(403, 'origin_not_allowed', 'This origin may not use signoff-auth.', null);

  const route = url.pathname.replace(/\/+$/, '');
  if (!['/exchange', '/refresh', '/revoke', '/invitations'].includes(route)) return fail(404, 'not_found', 'No such route.', origin);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(origin) });
  if (request.method !== 'POST') return fail(405, 'method_not_allowed', 'Use POST.', origin);

  const parsed = await readJson(request);
  if (parsed.error) return fail(400, 'bad_request', parsed.error, origin);
  const data = parsed.data;

  if (route === '/exchange') {
    const code = field(data, 'code');
    const verifier = field(data, 'code_verifier');
    const redirect = typeof data.redirect_uri === 'string' ? data.redirect_uri : '';
    if (!code || !verifier) return fail(400, 'bad_request', 'code and code_verifier are required.', origin);
    if (!list(env.ALLOWED_REDIRECTS).includes(redirect)) return fail(400, 'bad_request', 'redirect_uri is not allowed.', origin);
    return tokenCall(env, { code, code_verifier: verifier, redirect_uri: redirect }, origin, fetchImpl);
  }
  if (route === '/refresh') {
    const refresh = field(data, 'refresh_token');
    if (!refresh) return fail(400, 'bad_request', 'refresh_token is required.', origin);
    return tokenCall(env, { grant_type: 'refresh_token', refresh_token: refresh }, origin, fetchImpl);
  }
  const token = field(data, 'access_token');
  if (!token) return fail(400, 'bad_request', 'access_token is required.', origin);
  if (route === '/invitations') {
    if (!env.GITHUB_APP_ID || !env.GITHUB_APP_PRIVATE_KEY || !env.INVITE_OWNER) {
      return fail(501, 'not_configured', 'This Worker doesn’t look up invitations (no app id, private key, or owner).', origin);
    }
    return invitations(env, token, origin, fetchImpl);
  }
  return revoke(env, token, origin, fetchImpl);
}

export default {
  fetch(request, env) { return handle(request, env); },
};
