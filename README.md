# Personal Website + Privacy-Aware First-Party Analytics — Cloudflare Workers + D1

Fast, mobile-first personal homepage with anonymous-visitor analytics, a private
dashboard, and a controlled request-inspection experiment system — deployed fully
on Cloudflare (Workers + Static Assets + D1). No external backend.

## Architecture
- **Worker** (`src/worker.js`) — Workers-native router: same routes and behavior
  as the original Express server (homepage tracking, beacon, clicks, admin APIs).
- **Static Assets** (`public/`) — HTML/CSS/JS served by the same Worker deployment
  via the `ASSETS` binding (modern Workers Static Assets, `run_worker_first` for
  `/`, `/api/*`, `/admin*`).
- **D1** (`migrations/`) — persistent SQLite at the edge: `visitors`, `sessions`,
  `events`, `request_logs` (same schema as before).
- **Secrets** — `ADMIN_TOKEN` (+ optional `IP_HASH_SALT`) via `wrangler secret`.
  Never in source code. `.dev.vars` holds local-only test values.

## Routes
`/` (tracked homepage) · `/privacy` · `/robots.txt` · `/api/site` · `/api/beacon` ·
`/api/click` · `/admin/login` · `/admin` (guarded dashboard) ·
`/admin/api/{summary,events,requests,visitors}.json` (guarded)

## Quick start (local)
```bash
npm install
npm run db:migrate:local      # apply D1 migrations to the local dev DB
npm run dev                   # http://localhost:8787  (uses .dev.vars secrets)
```
Local secrets live in `.dev.vars` (create it from the example values; git-ignored).

## Deploy (production, ~5 commands)
```bash
npm install
npx wrangler login
npx wrangler d1 create personal-site-analytics
#   -> copy the printed database_id into wrangler.jsonc (replace REPLACE_WITH_YOUR_D1_DATABASE_ID)
npx wrangler d1 migrations apply personal-site-analytics --remote
npx wrangler secret put ADMIN_TOKEN          # choose a long secret
npx wrangler secret put IP_HASH_SALT         # optional (falls back to ADMIN_TOKEN)
npm run deploy
#   -> your permanent URL: https://personal-site.<your-subdomain>.workers.dev
```
Put that URL in your Instagram bio. You can attach a custom domain later in the
Cloudflare dashboard (Workers → your worker → Domains & Routes).

## Inspect / manage D1
```bash
npm run db:shell:local "SELECT COUNT(*) FROM events"      # local
npm run db:shell:remote "SELECT COUNT(*) FROM visitors"   # production
npx wrangler d1 migrations list personal-site-analytics --remote
```

## Updating later
- Site content (name/links): edit the `/api/site` handler in `src/worker.js`, or
  move it to a D1 table later.
- New pages: drop `.html` into `public/` (auto-served at its pretty URL, e.g.
  `privacy.html` → `/privacy`).
- Schema changes: `npx wrangler d1 migrations create personal-site-analytics <name>`,
  edit the generated SQL, then `--local` test → `--remote` apply.
- Redeploy: `npm run deploy`.

## Privacy model (unchanged from v1)
Anonymous crypto-random visitor ID in a first-party cookie (`avid`, SameSite=Lax,
Secure on HTTPS). No PII, no IPs (HMAC-SHA256 keyed hash of `CF-Connecting-IP`
only — the Workers-native equivalent of the old salted hash), no fingerprinting.
Dashboard labels: DETERMINISTIC (own cookie ID) / PROBABILISTIC / UNKNOWN.
See `RESEARCH.md` for the identity model and experiment protocol.
