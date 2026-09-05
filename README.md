# ALUCARD — wep-site

موقع شخصي على Cloudflare Workers + D1: ألعاب، برمجة، وتجارب AI.
مع نظام تحليلات طرف أول يحترم الخصوصية، ولوحة تحكم خاصة.

هوية الموقع: dark luxury — أسود كربوني، ذهبي معدني، وأحمر دم خفيف. بدون توهج نيون مبتذل.

## البنية
- **Worker** (`src/worker.js`) — توجيه أصلي: تتبع الزيارات، البيكون، النقرات، حماية الأدمن، APIs التحليلات.
- **Static Assets** (`public/`) — الموقع، الأغلفة (`public/covers/`)، اللوحة، صفحة الخصوصية.
- **D1** (`migrations/`) — قاعدة دائمة: `visitors`, `sessions`, `events`, `request_logs`.
- **أسرار** — `ADMIN_TOKEN` و `IP_HASH_SALT` عبر `wrangler secret` فقط. أبدًا ليست في الكود.

## المسارات
`/` الموقع · `/privacy` · `/robots.txt` · `/api/beacon` · `/api/click` ·
`/admin/login` · `/admin` (محمية بالتوكن) ·
`/admin/api/{summary,events,visitors,sessions,requests}.json`

## محليًا
```bash
npm install
npx wrangler d1 migrations apply personal-site-analytics --local
npx wrangler dev            # http://localhost:8787
```
الأسرار المحلية في `.dev.vars` (git-ignored، مش موجودة في الريبو).

## نشر (الريموتر جاهز بالفعل)
```bash
npx wrangler d1 migrations apply personal-site-analytics --remote   # أول مرة فقط
npx wrangler secret put ADMIN_TOKEN     # لو لسه
npx wrangler secret put IP_HASH_SALT
npx wrangler deploy
```
الريبو مربوط بـ Cloudflare: أي push لـ main بيشغّل النشر تلقائيًا.

## فحص قاعدة D1
```bash
npx wrangler d1 execute personal-site-analytics --remote --command "SELECT COUNT(*) FROM visitors"
```

## الخصوصية (نفس نموذج v1)
معرّف مجهول عشوائي في كوكي أولي. لا PII، لا IP (hash مُمليح اتجاه واحد)، لا fingerprinting،
لا تتبع خارجي. اللوحة تفرّق بوضوح: DETERMINISTIC / PROBABILISTIC / UNKNOWN.
شوف `RESEARCH.md` لتجربة إنستغرام webview الموثقة.
