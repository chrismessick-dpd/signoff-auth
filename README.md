# signoff-auth

The token exchange behind the Signoff suite's **Sign in with GitHub**, as a Cloudflare Worker.

The suite's tools are static pages on GitHub Pages. Signing in with a GitHub App gives the page a
one-time code, and swapping that code for a token needs the app's client secret at GitHub's token
endpoint, which browsers can't call (no CORS). This Worker holds the secret and makes that swap. It
does nothing else.

The design is in the hub's `docs/sign-in.md`.

## Routes

Every route is `POST` with a JSON body, and answers JSON with `Cache-Control: no-store`. Requests
from an origin not in `ALLOWED_ORIGINS` get 403 with no CORS headers, so the browser can't read any
answer.

| Route | Body | Answer |
| --- | --- | --- |
| `/exchange` | `{code, code_verifier, redirect_uri}` | `{access_token, expires_in, refresh_token, refresh_token_expires_in, token_type, scope}` |
| `/refresh` | `{refresh_token}` | the same, a new pair (the old refresh token stops working) |
| `/revoke` | `{access_token}` | `{revoked: true}`, also when GitHub no longer knows the token |
| `/invitations` | `{access_token}` | `{login, invitations: [{id, repo, created_at}], partial}` |

`/invitations` (2026-11-12): a Sign in with GitHub token can accept an invitation to a private repo by
its id, but GitHub leaves it out of that token's own list until it's accepted. So the Worker checks the token
with GitHub's *check a token* (`POST /applications/{client_id}/token`, the client id and secret): it must
be a live token of this app (a pasted token lists its own invitations), and GitHub says whose it is. Then, as the app (a JWT from the private key, then a read-only
installation token, kept for its hour), lists the pending invitations of each private repo of
`INVITE_OWNER`, newest repo first, and returns only the caller's. The page accepts them with its own
token. It stays under Cloudflare's 50 outgoing requests per request (free plan) and says `partial: true`
when it had to stop early. Newest repos go first, so past about 40 private repos the oldest (the data
repos) are the ones left out; an organization (planned) makes this moot for FTEs. Without the three settings below it answers 501 and the other routes work as
before. 401 means GitHub refused the caller's token.

Errors are `{error, error_description}`:
- 400: bad input, or GitHub refused the request (for example `bad_verification_code` or `bad_refresh_token`).
- 403: the origin isn't allowed.
- 404 and 405: an unknown route or method.
- 502: GitHub was unreachable or gave an unexpected answer.
- 500: the Worker isn't configured.

`redirect_uri` must be one of `ALLOWED_REDIRECTS`, and `code_verifier` is required, so every sign-in
uses PKCE.

## Settings

Set these under Cloudflare → Workers & Pages → `signoff-auth` → Settings → Variables and secrets:

| Name | Type | Value |
| --- | --- | --- |
| `GITHUB_CLIENT_ID` | Text | the GitHub App's client id |
| `GITHUB_CLIENT_SECRET` | **Secret** | the GitHub App's client secret |
| `ALLOWED_ORIGINS` | Text | page origins, space-separated |
| `ALLOWED_REDIRECTS` | Text | callback URLs registered on the app, space-separated |
| `GITHUB_APP_ID` | Text | the app's **App ID** (a number, on the app's General page; not the client id) |
| `GITHUB_APP_PRIVATE_KEY` | **Secret** | the app's private key: the whole `.pem` file, BEGIN and END lines included |
| `INVITE_OWNER` | Text | `chrismessick-dpd` (the account the app is installed on) |

Production: `ALLOWED_ORIGINS` = `https://chrismessick-dpd.github.io`, and `ALLOWED_REDIRECTS` =
`https://chrismessick-dpd.github.io/signoff/auth.html`.

The dev Worker, `signoff-auth-dev`, uses the dev GitHub App, with `http://localhost:8774
http://localhost:8771` and the matching `/signoff/auth.html` callbacks. The production Worker never
lists localhost.

## Deploy

From the dashboard, with no tools to install:
1. Go to Workers & Pages → Create → Create Worker, name it `signoff-auth` (or `signoff-auth-dev`), and Deploy.
2. Click Edit code, replace everything with `worker.js`, and Deploy.
3. Add the four settings above, then Deploy again.

Or with Wrangler: `npx wrangler deploy` (or `--env dev`), then
`npx wrangler secret put GITHUB_CLIENT_SECRET`.

The Worker's address is `https://signoff-auth.<your-subdomain>.workers.dev`. The hub's `auth.html` names it.

## Rotating the client secret

GitHub allows two client secrets at once, so nobody gets signed out:
1. In the GitHub App's settings, click Generate a new client secret.
2. Set it as `GITHUB_CLIENT_SECRET` in the Worker.
3. Sign in once to check that it works.
4. Delete the old secret on GitHub.

## Tests

```bash
node test.js
```

The tests use Node 18 or later and need no packages. They check the three routes, the origin and
input checks, GitHub errors and outages, and that the secret never comes back in an answer. The
`/invitations` tests make a throwaway RSA key at run time and check the JWT's signature with it.

## What it never does

It stores nothing, logs no request or token, has no other route, and makes no other GitHub call.
Review data never passes through it.
