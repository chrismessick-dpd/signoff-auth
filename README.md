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
input checks, GitHub errors and outages, and that the secret never comes back in an answer.

## What it never does

It stores nothing, logs no request or token, has no other route, and makes no other GitHub call.
Review data never passes through it.
