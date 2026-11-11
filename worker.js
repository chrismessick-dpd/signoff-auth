// signoff-auth: the token exchange behind the Signoff suite's "Sign in with GitHub".
//
// GitHub's token endpoint needs the GitHub App's client secret and has no CORS, so the suite's static
// pages can't finish a sign-in on their own. This Worker holds the secret and does three things only:
//
//   POST /exchange  {code, code_verifier, redirect_uri}  one-time code → access and refresh tokens
//   POST /refresh   {refresh_token}                       a new token pair (the old refresh token dies)
//   POST /revoke    {access_token}                        sign out: GitHub forgets the authorization
//
// It is not a proxy: no other route, no other GitHub call. It stores nothing and logs nothing.
//
// Settings (Cloudflare → the Worker → Settings → Variables and secrets):
//   GITHUB_CLIENT_ID      the app's client id (plain text is fine)
//   GITHUB_CLIENT_SECRET  the app's client secret (type: Secret)
//   ALLOWED_ORIGINS       space-separated page origins, e.g. "https://chrismessick-dpd.github.io"
//   ALLOWED_REDIRECTS     space-separated callback URLs registered on the app, e.g.
//                         "https://chrismessick-dpd.github.io/signoff/auth.html"

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
  if (!['/exchange', '/refresh', '/revoke'].includes(route)) return fail(404, 'not_found', 'No such route.', origin);
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
  return revoke(env, token, origin, fetchImpl);
}

export default {
  fetch(request, env) { return handle(request, env); },
};
