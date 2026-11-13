# signoff-auth: notes for Claude

The Cloudflare Worker behind the Signoff suite's Sign in with GitHub. It does four things: code to
tokens, refresh, revoke, and invitations (`worker.js`). When the suite folder is checked out, read `../CLAUDE.md`
first. The plan is in `../signoff/docs/sign-in.md`. This repo is public.

**Serial comma** (Chris, 2026-11-08): use the Oxford comma in every list of three or more, in UI text, docs, demo data, checklists, and commit messages: "A, B, and C". Never change check ids or data keys to fit it.

## Rules

- **No secrets here, ever.** The client secret lives only in the Worker's settings (type Secret).
  Never put it in `wrangler.toml`, a test, a commit, or chat. Tests use made-up values.
- **No other routes, and no proxying.** Every route added is attack surface for every signed-in user.
  `/invitations` (2026-11-12, Chris: "start building it") is the one exception so far: it answers only
  the caller's own invitations, proven by their own token, with a read-only installation token.
- **The app's private key** (for `/invitations`) lives only in the Worker's settings (type Secret), like
  the client secret. Never on disk in a repo, in a test, or in chat.
- **Never log** request bodies, tokens, or GitHub's answers.
- **Chris deploys.** He owns the Cloudflare account; Claude has no access to it. The dashboard steps
  are in the README.
- **Tests:** `node test.js` (19, 2026-11-12). Node is at `C:\Program Files\nodejs\node.exe` for shells
  that don't have it on PATH. Files are LF.

## State (2026-11-12)

Deployed by Chris (dev and production, 2026-11-10). `/invitations` written and tested locally (2026-11-12), not deployed: it needs GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, and INVITE_OWNER in each Worker.
