// Cloudflare Worker — personal website + privacy-aware first-party analytics.
// Workers-native port of the original Express server (same routes, same behavior):
//   GET  /                     homepage (tracks first_visit / returning_visit)
//   POST /api/beacon           client environment beacon
//   POST /api/click            outbound link click events
//   GET  /api/site             site name + links
//   GET  /robots.txt           robots
//   GET  /admin/login           login page (static)
//   POST /admin/login           token -> admin session cookie
//   GET  /admin                dashboard (static, guarded)
//   GET  /admin/api/*.json     analytics JSON APIs (guarded)
//   *    ->                    static assets via ASSETS binding
//
// Storage: Cloudflare D1 (SQLite at the edge) — same schema as before
// (migrations/0001_init.sql). Anonymous visitor ID is still a crypto-random
// 128-bit value in a first-party cookie; it never represents a real identity.
// IP is stored only as an HMAC-SHA256 keyed hash (salt from Worker secrets).

import { extractRequestObservations } from '../lib/detect.js';

const AVID = 'avid';   // anonymous visitor id cookie
const ADM = 'adm';     // admin session cookie

/* ---------------- small helpers ---------------- */

function randomHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(b => b.toString(16).padStart(2, '0')).join('');
}

function nowIso() { return new Date().toISOString(); }

function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)));
  return hex(d);
}

// Keyed, non-reversible IP hash — same privacy idea as the original salted hash.
async function hmacIp(ip, salt) {
  if (!ip) return null;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(salt), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(String(ip)));
  return hex(sig).slice(0, 24);
}

// Constant-time string compare (avoid timing leaks on token checks).
function ctEq(a, b) {
  a = String(a || ''); b = String(b || '');
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function getCookie(request, name) {
  const m = String(request.headers.get('cookie') || '').match(
    new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}

function isHttps(request) { return new URL(request.url).protocol === 'https:'; }

function jsonResponse(obj, status = 200, setCookies = []) {
  const h = { 'Content-Type': 'application/json; charset=utf-8' };
  const headers = new Headers(h);
  for (const c of setCookies) headers.append('set-cookie', c);
  return new Response(JSON.stringify(obj), { status, headers });
}

function textResponse(text, type = 'text/plain; charset=utf-8', status = 200) {
  return new Response(text, { status, headers: { 'Content-Type': type } });
}

/* ---------------- request observation ---------------- */

function buildReqLike(request) {
  // Standard request data only — exactly what reaches the Worker.
  // NOTE: request.headers is a Headers instance, NOT a plain object — spreading
  // it ({...request.headers}) yields an empty object. Iterate entries instead.
  const u = new URL(request.url);
  const query = {};
  for (const [k, v] of u.searchParams) query[k] = v;
  const headers = {};
  for (const [k, v] of request.headers) headers[k] = v;
  return { method: request.method, path: u.pathname, query, headers };
}

function clientIp(request) {
  // Cloudflare-proxied requests carry the true client IP in CF-Connecting-IP.
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf;
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return null; // e.g. plain `wrangler dev` local traffic — store nothing
}

/* ---------------- visit tracking (same semantics as the Node version) ---------------- */

async function trackVisit(request, env, db) {
  let vid = getCookie(request, AVID);
  if (vid && !/^[a-f0-9]{32}$/.test(vid)) vid = null;

  const obs = extractRequestObservations(buildReqLike(request));
  const ts = nowIso();
  const ipH = await hmacIp(clientIp(request), env.IP_HASH_SALT || env.ADMIN_TOKEN);

  let identityMode = 'deterministic';
  let eventType;

  const existing = vid
    ? await db.prepare('SELECT id FROM visitors WHERE id = ?').bind(vid).first()
    : null;

  if (vid && existing) {
    eventType = 'returning_visit';
  } else {
    if (vid) identityMode = 'unknown'; // cookie present but unknown to DB — treat as new
    vid = randomHex(16);
    eventType = 'first_visit';
  }

  const sessionId = randomHex(12);

  await db.prepare(`
    INSERT INTO visitors (id, first_seen, last_seen, visit_count, created_ip_h)
    VALUES (?, ?, ?, 1, ?)
    ON CONFLICT(id) DO UPDATE SET last_seen = ?, visit_count = visit_count + 1
  `).bind(vid, ts, ts, ipH, ts).run();

  await db.prepare(`
    INSERT INTO sessions (id, visitor_id, started_at) VALUES (?, ?, ?)
    ON CONFLICT(id) DO NOTHING
  `).bind(sessionId, vid, ts).run();

  const envJson = JSON.stringify({
    device: obs.device, os: obs.os, browser: obs.browser,
    in_app_app: obs.in_app_app, is_webview: obs.is_webview,
    x_requested_with: obs.x_requested_with,
  });

  await db.prepare(`
    INSERT INTO events (visitor_id, session_id, ts, type, path, referrer, referrer_source,
                        is_ig_inapp, identity_mode, env, query_params, extra)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(vid, sessionId, ts, eventType, obs.path, obs.referrer, obs.referrer_source,
          obs.is_ig_inapp ? 1 : 0, identityMode, envJson, JSON.stringify(obs.query),
          JSON.stringify({ session: sessionId, server_observed: true })).run();

  // raw request inspector row (minimized headers only — see extractRequestObservations)
  await db.prepare(`
    INSERT INTO request_logs (ts, visitor_id, method, path, query_json, headers_json, ua,
                              is_ig_inapp, referrer, ip_h)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(ts, vid, obs.method, obs.path, JSON.stringify(obs.query),
          JSON.stringify(obs.headers), obs.ua, obs.is_ig_inapp ? 1 : 0, obs.referrer, ipH).run();

  const cookie = `${AVID}=${vid}; Max-Age=31536000; Path=/; SameSite=Lax${isHttps(request) ? '; Secure' : ''}`;
  return { cookie, eventType };
}

/* ---------------- auth ---------------- */

async function adminTokenHash(env) {
  return sha256hex(String(env.ADMIN_TOKEN || ''));
}

async function isAdmin(request, env) {
  const c = getCookie(request, ADM);
  if (!c || !/^[a-f0-9]{64}$/.test(c)) return false;
  return ctEq(c, await adminTokenHash(env));
}

/* ---------------- main worker ---------------- */

export default {
  async fetch(request, env) {
    const db = env.DB;
    const url = new URL(request.url);
    const p = url.pathname;

    try {
      /* ---------- homepage ---------- */
      if (p === '/' && request.method === 'GET') {
        const { cookie } = await trackVisit(request, env, db);
        const asset = await env.ASSETS.fetch(request);
        const headers = new Headers(asset.headers);
        headers.append('set-cookie', cookie);
        return new Response(asset.body, { status: asset.status, headers });
      }

      /* ---------- robots ---------- */
      if (p === '/robots.txt') {
        return textResponse('User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\n');
      }

      if (p === '/api/beacon' && request.method === 'POST') {
        const vid = getCookie(request, AVID);
        if (!vid || !/^[a-f0-9]{32}$/.test(vid)) return jsonResponse({ ok: false }, 404);
        if (parseInt(request.headers.get('content-length') || '0', 10) > 32768)
          return jsonResponse({ ok: false }, 413);
        let body = {};
        try { body = await request.json(); } catch { body = {}; }
        const pl = body || {};
        // Visitor must exist (registered on first page view) before events can be logged.
        // A well-formed but fabricated cookie id would otherwise trip the FK constraint.
        const known = await db.prepare(`SELECT 1 FROM visitors WHERE id = ?`).bind(vid).first();
        if (!known) return jsonResponse({ ok: false }, 404);
        const envJson = JSON.stringify(pl.env || {});
        await db.prepare(`
          INSERT INTO events (visitor_id, session_id, ts, type, path, referrer, referrer_source,
                              is_ig_inapp, identity_mode, env, query_params, extra)
          VALUES (?, ?, ?, 'beacon_env', ?, ?, NULL, ?, 'deterministic', ?, ?, ?)
        `).bind(
          vid, pl.session || null, nowIso(), pl.path || '/', pl.referrer || null,
          (pl.env && pl.env.in_app_app === 'Instagram') ? 1 : 0,
          envJson, JSON.stringify(pl.query || {}),
          JSON.stringify({
            languages: (pl.env && pl.env.languages) || undefined,
            timezone: (pl.env && pl.env.timezone) || undefined,
            screen_bucket: (pl.env && pl.env.screen_bucket) || undefined,
            connection: (pl.env && pl.env.connection) || undefined,
          })
        ).run();
        return jsonResponse({ ok: true });
      }

      if (p === '/api/click' && request.method === 'POST') {
        const vid = getCookie(request, AVID);
        if (!vid || !/^[a-f0-9]{32}$/.test(vid)) return jsonResponse({ ok: false }, 404);
        let pl = {};
        try { pl = await request.json(); } catch { pl = {}; }
        const known = await db.prepare(`SELECT 1 FROM visitors WHERE id = ?`).bind(vid).first();
        if (!known) return jsonResponse({ ok: false }, 404);
        await db.prepare(`
          INSERT INTO events (visitor_id, session_id, ts, type, path, referrer, referrer_source,
                              is_ig_inapp, identity_mode, env, query_params, extra)
          VALUES (?, NULL, ?, 'link_click', '/', NULL, NULL, 0, 'deterministic', NULL, NULL, ?)
        `).bind(vid, nowIso(),
          JSON.stringify({
            href: String(pl.href || '').slice(0, 300),
            label: String(pl.label || '').slice(0, 100),
          })).run();
        return jsonResponse({ ok: true });
      }

      /* ---------- admin ---------- */
      if (p === '/admin/login' && request.method === 'POST') {
        let body = {};
        try { body = await request.json(); } catch { body = {}; }
        const token = body && body.token;
        if (!token || !ctEq(String(token), String(env.ADMIN_TOKEN || '')))
          return jsonResponse({ ok: false }, 401);
        const h = await adminTokenHash(env);
        const cookie = `${ADM}=${h}; Max-Age=43200; Path=/; HttpOnly; SameSite=Lax${isHttps(request) ? '; Secure' : ''}`;
        return jsonResponse({ ok: true }, 200, [cookie]);
      }

      // Login page must be reachable WITHOUT auth (otherwise redirect loop).
      // Serve via its pretty URL "/login" ("login.html" would 307-redirect).
      if (p === '/admin/login' && request.method === 'GET') {
        return env.ASSETS.fetch(new Request(new URL('/login', request.url), request));
      }

      if (p.startsWith('/admin')) {
        if (!(await isAdmin(request, env))) {
          if (p.endsWith('.json')) return jsonResponse({ ok: false }, 401);
          return Response.redirect(new URL('/admin/login', request.url), 302);
        }

        if (p === '/admin' && request.method === 'GET') {
          // Serve via pretty URL "/dashboard" ("dashboard.html" would 307-redirect).
          return env.ASSETS.fetch(new Request(new URL('/dashboard', request.url), request));
        }

        if (p === '/admin/api/summary.json') {
          const totals = await db.prepare(`SELECT
              (SELECT COUNT(*) FROM visitors) visitors,
              (SELECT COUNT(*) FROM visitors WHERE visit_count > 1) returning_visitors,
              (SELECT COUNT(*) FROM sessions) sessions,
              (SELECT COUNT(*) FROM events) events,
              (SELECT COUNT(*) FROM events WHERE is_ig_inapp = 1) ig_events,
              (SELECT COUNT(*) FROM events WHERE type = 'link_click') link_clicks,
              (SELECT COUNT(*) FROM request_logs) requests`).first();
          const bySource = (await db.prepare(
            `SELECT referrer_source, COUNT(*) n FROM events GROUP BY referrer_source ORDER BY n DESC LIMIT 15`
          ).all()).results;
          const byDevice = (await db.prepare(
            `SELECT json_extract(env,'$.device') d, COUNT(*) n FROM events WHERE env IS NOT NULL GROUP BY d ORDER BY n DESC`
          ).all()).results;
          return jsonResponse({ totals, bySource, byDevice });
        }

        if (p === '/admin/api/events.json') {
          const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 500);
          const rows = (await db.prepare(`SELECT visitor_id, session_id, ts, type, path, referrer,
              referrer_source, is_ig_inapp, identity_mode, env, query_params
              FROM events ORDER BY id DESC LIMIT ?`).bind(limit).all()).results;
          return jsonResponse(rows);
        }

        if (p === '/admin/api/requests.json') {
          const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 500);
          const rows = (await db.prepare(`SELECT ts, visitor_id, method, path, query_json,
              headers_json, ua, is_ig_inapp, referrer
              FROM request_logs ORDER BY id DESC LIMIT ?`).bind(limit).all()).results;
          return jsonResponse(rows);
        }

        if (p === '/admin/api/visitors.json') {
          const rows = (await db.prepare(
            `SELECT id, first_seen, last_seen, visit_count FROM visitors ORDER BY last_seen DESC LIMIT 500`
          ).all()).results;
          return jsonResponse(rows);
        }

        if (p === '/admin/api/sessions.json') {
          const rows = (await db.prepare(
            `SELECT id, visitor_id, started_at FROM sessions ORDER BY started_at DESC LIMIT 500`
          ).all()).results;
          return jsonResponse(rows);
        }
      }

      /* ---------- everything else: static assets ---------- */
      return env.ASSETS.fetch(request);

    } catch (err) {
      console.error('worker error:', err);
      return jsonResponse({ ok: false, error: String(err && err.message || err) }, 500);
    }
  },
};
