// Cloudflare Worker — ALUCARD personal site + privacy-aware first-party analytics.
// ═══════════════════════════════════════════════════════════════════════════
// ANALYTICS MODEL (v2 — Umami/Plausible-inspired):
//   visitor  = persistent anonymous identity  (cookie `avid`, 32-hex)
//   session  = continuous visit window         (cookie `asid`, stitched, 30-min gap)
//   pageview = page load inside a session     (event type 'pageview'; refreshes tracked)
//   event    = interaction evidence           (beacon_env / link_click / visit markers)
//
// Every session gets a probabilistic multi-signal classification:
//   human_likely | unknown | bot | social_preview | internal | suspicious
// with a confidence score and human-readable reasons (lib/classify.js).
// Nothing here is PII: IP only as keyed HMAC hash; no usernames; no accounts.
//
// Preserved from v1: ADMIN_TOKEN auth (sha256 cookie, constant-time compare),
// D1 binding `DB`, ASSETS binding, export API, wrangler deploy flow.

import { extractRequestObservations, detectInApp } from '../lib/detect.js';
import { parseUAFull } from '../lib/ua.js';
import { classifySession, isBotUA, isPreviewUA } from '../lib/classify.js';

const AVID = 'avid';   // anonymous visitor cookie (32-hex)
const ASID = 'asid';   // anonymous session cookie   (24-hex)
const ADM  = 'adm';    // admin session cookie      (64-hex = sha256(ADMIN_TOKEN))
const TEST = 'alucard_test'; // internal/test-mode cookie

const SESSION_GAP_S   = 30 * 60;  // inactivity window that ends a session (configurable)
const REFRESH_WINDOW_S = 60;      // same-path reload within this window = refresh, not new pageview
const LIVE_WINDOW_S    = 5 * 60;  // "live now" = activity in the last 5 minutes

/* ───────────────────────── helpers ───────────────────────── */

function randomHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(b => b.toString(16).padStart(2, '0')).join('');
}
const nowIso = () => new Date().toISOString();
function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)));
  return hex(d);
}
async function hmacIp(ip, salt) {
  if (!ip) return null;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(salt), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(String(ip)))).slice(0, 24);
}
function ctEq(a, b) {
  a = String(a || ''); b = String(b || '');
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function getCookie(request, name) {
  const m = String(request.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}
const isHttps = r => new URL(r.url).protocol === 'https:';
const secure = r => isHttps(r) ? '; Secure' : '';

function jsonResponse(obj, status = 200, setCookies = []) {
  const h = new Headers({ 'Content-Type': 'application/json; charset=utf-8' });
  for (const c of setCookies) h.append('set-cookie', c);
  return new Response(JSON.stringify(obj), { status, headers: h });
}
const textResponse = (t, type = 'text/plain; charset=utf-8', status = 200) =>
  new Response(t, { status, headers: { 'Content-Type': type } });

function buildReqLike(request) {
  const u = new URL(request.url), query = {}, headers = {};
  for (const [k, v] of u.searchParams) query[k] = v;
  for (const [k, v] of request.headers) headers[k] = v;
  return { method: request.method, path: u.pathname, query, headers };
}
function clientIp(request) {
  return request.headers.get('cf-connecting-ip')
    || (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() || null;
}

/* ───────────────────────── admin auth (unchanged model) ───────────────────────── */

async function adminTokenHash(env) { return sha256hex(String(env.ADMIN_TOKEN || '')); }
async function isAdmin(request, env) {
  const c = getCookie(request, ADM);
  if (!c || !/^[a-f0-9]{64}$/.test(c)) return false;
  return ctEq(c, await adminTokenHash(env));
}
async function guardAdmin(request, env) {
  if (await isAdmin(request, env)) return null;
  const p = new URL(request.url).pathname;
  if (p.endsWith('.json')) return jsonResponse({ ok: false }, 401);
  return Response.redirect(new URL('/admin/login', request.url), 302);
}

/* ───────────────────────── schema migrations (idempotent) ───────────────────────── */

const MIGRATION_COLS = [
  ['sessions', 'last_activity_at', 'TEXT'],
  ['sessions', 'ended_at', 'TEXT'],
  ['sessions', 'duration_s', 'REAL'],
  ['sessions', 'active_duration_s', 'REAL'],
  ['sessions', 'pageviews', 'INTEGER NOT NULL DEFAULT 1'],
  ['sessions', 'event_count', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'refresh_count', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'source', 'TEXT'],
  ['sessions', 'referrer', 'TEXT'],
  ['sessions', 'is_ig_inapp', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'is_inapp', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'in_app_app', 'TEXT'],
  ['sessions', 'device_type', 'TEXT'],
  ['sessions', 'device_vendor', 'TEXT'],
  ['sessions', 'device_model', 'TEXT'],
  ['sessions', 'os', 'TEXT'],
  ['sessions', 'os_version', 'TEXT'],
  ['sessions', 'browser', 'TEXT'],
  ['sessions', 'browser_version', 'TEXT'],
  ['sessions', 'classification', 'TEXT'],
  ['sessions', 'confidence', 'INTEGER'],
  ['sessions', 'classification_reasons', 'TEXT'],
  ['sessions', 'is_internal', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'internal_override', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'ua', 'TEXT'],
  ['sessions', 'js_beacons', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'heartbeats', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'interactions', 'INTEGER NOT NULL DEFAULT 0'],
  ['sessions', 'distinct_paths', 'INTEGER NOT NULL DEFAULT 1'],
  ['visitors', 'classification_summary', 'TEXT'],
];
const MIGRATION_IDX = [
  'CREATE INDEX IF NOT EXISTS idx_sessions_visitor ON sessions(visitor_id)',
  'CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at)',
  'CREATE INDEX IF NOT EXISTS idx_sessions_last_act ON sessions(last_activity_at)',
  'CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)',
  'CREATE INDEX IF NOT EXISTS idx_events_session_type ON events(session_id, type)',
];

async function runMigrations(db) {
  for (const [tbl, col, def] of MIGRATION_COLS) {
    try { await db.prepare(`ALTER TABLE ${tbl} ADD COLUMN ${col} ${def}`).run(); }
    catch (e) { /* already exists — expected */ }
  }
  for (const sql of MIGRATION_IDX) {
    try { await db.prepare(sql).run(); } catch (e) { /* index exists */ }
  }
  await backfillLegacy(db);
}

/* One-time backfill: give legacy (pre-v2) sessions honest classifications by
   reconstructing their counters from the events log. Runs as a no-op (one
   cheap COUNT) once every legacy row is classified. */
async function backfillLegacy(db) {
  const nulls = (await db.prepare(
    `SELECT COUNT(*) n FROM sessions WHERE classification IS NULL`).first() || {}).n || 0;
  if (!nulls) return;
  await db.prepare(`UPDATE sessions SET js_beacons = (
      SELECT COUNT(*) FROM events e WHERE e.session_id = sessions.id AND e.type = 'beacon_env')
    WHERE classification IS NULL AND js_beacons = 0`).run();
  await db.prepare(`UPDATE sessions SET interactions = (
      SELECT COUNT(*) FROM events e WHERE e.session_id = sessions.id AND e.type = 'link_click')
    WHERE classification IS NULL AND interactions = 0`).run();
  await db.prepare(`UPDATE sessions SET pageviews = MAX(1, (
      SELECT COUNT(*) FROM events e WHERE e.session_id = sessions.id
        AND e.type IN ('pageview','first_visit','returning_visit')))
    WHERE classification IS NULL`).run();
  await db.prepare(`UPDATE sessions SET last_activity_at = (
      SELECT MAX(e.ts) FROM events e WHERE e.session_id = sessions.id)
    WHERE classification IS NULL AND last_activity_at IS NULL`).run();
  await db.prepare(`UPDATE sessions SET duration_s = MAX(0, CAST(
      (julianday(COALESCE(last_activity_at, started_at)) - julianday(started_at)) * 86400 AS REAL))
    WHERE classification IS NULL AND duration_s IS NULL AND last_activity_at IS NOT NULL`).run();
  const rows = (await db.prepare(
    `SELECT * FROM sessions WHERE classification IS NULL`).all()).results;
  for (const s of rows) await classifyAndStore(db, s);
}

/* ───────────────────────── session model ───────────────────────── */

function secBetween(aIso, bIso) {
  try { return Math.max(0, (Date.parse(bIso) - Date.parse(aIso)) / 1000); }
  catch { return 0; }
}

// Map referrer to a source, collapsing self-referrals (worker host) to 'self'.
function sourceOf(referrerSource, url) {
  if (!referrerSource) return 'direct';
  if (referrerSource.startsWith('website:')) {
    const host = referrerSource.slice(8).toLowerCase();
    try { if (host === new URL(url).hostname.toLowerCase()) return 'self'; } catch {}
    return 'website:' + host;
  }
  return referrerSource;
}

/* Look up (or stitch) the session for this visitor. */
async function getOrStitchSession(db, request, vid, obs) {
  const ts = nowIso();
  let sid = getCookie(request, ASID);
  let sess = null;

  if (sid && /^[a-f0-9]{24}$/.test(sid)) {
    const row = await db.prepare('SELECT * FROM sessions WHERE id = ? AND visitor_id = ?')
      .bind(sid, vid).first();
    if (row) {
      const last = row.last_activity_at || row.started_at;
      if (secBetween(last, ts) <= SESSION_GAP_S) sess = row;   // ← stitching
    }
  }

  const isInternal = !!getCookie(request, TEST);

  if (!sess) {
    sid = randomHex(12);
    const dev = parseUAFull(obs.ua, obs.headers);
    await db.prepare(`
      INSERT INTO sessions (id, visitor_id, started_at, last_activity_at, source, referrer,
        is_ig_inapp, is_inapp, in_app_app, device_type, device_vendor, device_model,
        os, os_version, browser, browser_version, is_internal, pageviews, distinct_paths, ua)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,?)`)
      .bind(sid, vid, ts, ts, sourceOf(obs.referrer_source, request.url), obs.referrer,
        obs.is_ig_inapp ? 1 : 0, obs.is_webview ? 1 : 0, obs.in_app_app || null,
        dev.device_type, dev.device_vendor, dev.device_model,
        dev.os, dev.os_version, dev.browser, dev.browser_version,
        isInternal ? 1 : 0, obs.ua).run();
    sess = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(sid).first();
  } else if (isInternal && !sess.is_internal) {
    await db.prepare('UPDATE sessions SET is_internal = 1 WHERE id = ?').bind(sid).run();
    sess.is_internal = 1;
  }
  return { sess, sid, ts };
}

/* Re-run the multi-signal classifier and persist classification on the session. */
async function classifyAndStore(db, sess) {
  // Manual admin overrides are STICKY — signal re-classification never
  // overwrites a decision the admin made explicitly.
  if (sess.internal_override) {
    let kept = [];
    try { kept = JSON.parse(sess.classification_reasons || '[]'); } catch (e) {}
    return { classification: sess.classification, confidence: sess.confidence, reasons: kept };
  }
  const burst = (await db.prepare(`
    SELECT COUNT(*) n FROM sessions
    WHERE visitor_id = ? AND started_at >= ?
  `).bind(sess.visitor_id, new Date(Date.now() - 3600 * 1000).toISOString()).first()).n;

  const facts = {
    ua: sess.ua || '',
    known_bot: isBotUA(sess.ua || ''),
    js_beacon_count: sess.js_beacons || 0,
    heartbeat_count: sess.heartbeats || 0,
    interaction_count: sess.interactions || 0,
    pageviews: sess.pageviews || 1,
    distinct_paths: sess.distinct_paths || 1,
    refresh_count: sess.refresh_count || 0,
    active_duration_s: sess.active_duration_s || sess.duration_s || 0,
    in_app_app: sess.in_app_app || null,
    is_internal: !!sess.is_internal || !!sess.internal_override,
    visitor_burst_sessions: burst,
  };
  const r = classifySession(facts);
  await db.prepare(`
    UPDATE sessions SET classification = ?, confidence = ?, classification_reasons = ?
    WHERE id = ?`)
    .bind(r.classification, r.confidence, JSON.stringify(r.reasons), sess.id).run();
  return r;
}

/* Update session activity bookkeeping. kind: 'pageview' | 'event' | 'heartbeat' */
async function touchSession(db, sid, kind, opts = {}) {
  const sets = ['last_activity_at = ?', 'event_count = event_count + 1'];
  const vals = [opts.ts || nowIso()];
  if (kind === 'pageview') {
    sets.push('pageviews = pageviews + 1');
    if (opts.isRefresh) sets.push('refresh_count = refresh_count + 1');
    if (opts.newPath) sets.push('distinct_paths = distinct_paths + 1');
  }
  if (kind === 'beacon')  sets.push('js_beacons = js_beacons + 1');
  if (kind === 'click')   sets.push('interactions = interactions + 1');
  if (kind === 'heartbeat') sets.push('heartbeats = heartbeats + 1');
  // Client-verified gesture evidence is idempotent (MAX, not +1): repeated
  // pings carrying the same gesture count must not inflate the signal.
  if (opts.gestureN != null && opts.gestureN > 0)
    sets.push('interactions = MAX(interactions, ?)'), vals.push(opts.gestureN);
  if (opts.activeS != null) sets.push('active_duration_s = MAX(COALESCE(active_duration_s,0), ?)'), vals.push(opts.activeS);
  const dur = opts.wallS != null ? opts.wallS : null;
  if (dur != null) sets.push('duration_s = ?'), vals.push(dur);
  vals.push(sid);
  await db.prepare(`UPDATE sessions SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
}

/* ───────────────────────── filter builder ───────────────────────── */

const FILTERS = ['from','to','source','device_type','os','browser','classification',
                 'in_app','returning','min_duration','max_duration','visitor_id',
                 'session_id','path','exclude_internal'];
function buildWhere(f) {
  // Base 1=1 keeps "${where} AND …" valid even when no filter is set.
  const w = ['1=1'], v = [];
  if (f.from) w.push("s.started_at >= ?"), v.push(f.from);
  if (f.to)   w.push("s.started_at <= ?"), v.push(f.to + (f.to.length === 10 ? 'T23:59:59.999Z' : ''));
  if (f.source) w.push('s.source = ?'), v.push(f.source);
  if (f.device_type) w.push('s.device_type = ?'), v.push(f.device_type);
  if (f.os) w.push('s.os = ?'), v.push(f.os);
  if (f.browser) w.push('s.browser = ?'), v.push(f.browser);
  if (f.classification) w.push('s.classification = ?'), v.push(f.classification);
  if (f.in_app === '1') w.push('s.is_inapp = 1');
  if (f.in_app === '0') w.push('s.is_inapp = 0');
  if (f.returning === '1') w.push('(SELECT visit_count FROM visitors WHERE id = s.visitor_id) > 1');
  if (f.returning === '0') w.push('(SELECT visit_count FROM visitors WHERE id = s.visitor_id) = 1');
  if (f.min_duration) w.push('COALESCE(s.duration_s,0) >= ?'), v.push(+f.min_duration);
  if (f.max_duration) w.push('COALESCE(s.duration_s,0) <= ?'), v.push(+f.max_duration);
  if (f.visitor_id) w.push('s.visitor_id = ?'), v.push(f.visitor_id);
  if (f.session_id) w.push('s.id = ?'), v.push(f.session_id);
  // When the admin is inspecting a SPECIFIC visitor/session id, never hide
  // internal rows from them — they asked for that identity explicitly.
  const explicitLookup = !!(f.visitor_id || f.session_id);
  if (f.exclude_internal === '1') w.push('COALESCE(s.is_internal,0) = 1');
  else if (f.exclude_internal !== '0' && !explicitLookup) w.push('COALESCE(s.is_internal,0) = 0');
  if (f.path) w.push(`EXISTS (SELECT 1 FROM events e WHERE e.session_id = s.id AND e.path = ?)`), v.push(f.path);
  return { where: w.length ? 'WHERE ' + w.join(' AND ') : '', vals: v };
}

/* ═══════════════════════════ MAIN WORKER ═══════════════════════════ */

export default {
  async fetch(request, env) {
    const db = env.DB;
    const url = new URL(request.url);
    const p = url.pathname;
    const sp = url.searchParams;

    try {
      await runMigrations(db);

      /* ─────────── public: homepage (tracked pageview) ─────────── */
      if (p === '/' && request.method === 'GET') {
        const obs = extractRequestObservations(buildReqLike(request));
        const uaBot = isBotUA(obs.ua), uaPreview = isPreviewUA(obs.ua);

        // Serve page to everyone (never break crawlers/previews), but only
        // track sessions for browser-like requests. Bots & previews still
        // get logged into request_logs + a classified session row.
        let avidCookie = null, asidCookie = null;

        if (!uaBot) {                       // previews get a session (social_preview class)
          let vid = getCookie(request, AVID);
          if (vid && !/^[a-f0-9]{32}$/.test(vid)) vid = null;
          const ts = nowIso();
          const existing = vid ? await db.prepare('SELECT id FROM visitors WHERE id = ?').bind(vid).first() : null;
          const eventType = (vid && existing) ? 'returning_visit' : 'first_visit';
          if (!existing) vid = randomHex(16);
          const identityMode = eventType === 'returning_visit' ? 'deterministic' : 'deterministic';

          const ipH = await hmacIp(clientIp(request), env.IP_HASH_SALT || env.ADMIN_TOKEN || 'fallback');

          await db.prepare(`
            INSERT INTO visitors (id, first_seen, last_seen, visit_count, created_ip_h)
            VALUES (?,?,?,1,?)
            ON CONFLICT(id) DO UPDATE SET last_seen = ?, visit_count = visit_count + 1`)
            .bind(vid, ts, ts, ipH, ts).run();

          const { sess, sid, ts: sts } = await getOrStitchSession(db, request, vid, obs);

          // refresh detection: same session, same path, recent pageview
          const lastPv = await db.prepare(`
            SELECT ts, path FROM events
            WHERE session_id = ? AND type = 'pageview' ORDER BY id DESC LIMIT 1`)
            .bind(sid).first();
          const isRefresh = !!(lastPv && lastPv.path === obs.path
            && secBetween(lastPv.ts, sts) <= REFRESH_WINDOW_S);
          const newPath = !(lastPv && lastPv.path === obs.path);

          await db.prepare(`
            INSERT INTO events (visitor_id, session_id, ts, type, path, referrer, referrer_source,
              is_ig_inapp, identity_mode, env, query_params, extra)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
            .bind(vid, sid, sts, 'pageview', obs.path, obs.referrer, obs.referrer_source,
              obs.is_ig_inapp ? 1 : 0, identityMode,
              JSON.stringify({ device: obs.device, os: obs.os, browser: obs.browser,
                in_app_app: obs.in_app_app, is_webview: obs.is_webview }),
              JSON.stringify(obs.query),
              JSON.stringify({ refresh: isRefresh })).run();
          await db.prepare(`
            INSERT INTO events (visitor_id, session_id, ts, type, path, referrer, referrer_source,
              is_ig_inapp, identity_mode, env, query_params, extra)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
            .bind(vid, sid, sts, eventType, obs.path, obs.referrer, obs.referrer_source,
              obs.is_ig_inapp ? 1 : 0, identityMode, null,
              JSON.stringify(obs.query),
              JSON.stringify({ session_start: true })).run();

          const wall = secBetween(sess.started_at, sts);
          await touchSession(db, sid, 'pageview', { ts: sts, isRefresh, newPath, wallS: wall });
          const fresh = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(sid).first();
          await classifyAndStore(db, fresh);

          await db.prepare(`
            INSERT INTO request_logs (ts, visitor_id, method, path, query_json, headers_json,
              ua, is_ig_inapp, referrer, ip_h)
            VALUES (?,?,?,?,?,?,?,?,?,?)`)
            .bind(sts, vid, obs.method, obs.path, JSON.stringify(obs.query),
              JSON.stringify(obs.headers), obs.ua, obs.is_ig_inapp ? 1 : 0, obs.referrer, ipH).run();

          const s = secure(request);
          avidCookie = `${AVID}=${vid}; Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax${s}`;
          asidCookie = `${ASID}=${sid}; Max-Age=${SESSION_GAP_S}; Path=/; HttpOnly; SameSite=Lax${s}`;
        } else {
          // bot / preview: log request only (no cookies, no visitor rows)
          const ipH = await hmacIp(clientIp(request), env.IP_HASH_SALT || env.ADMIN_TOKEN || 'fallback');
          await db.prepare(`
            INSERT INTO request_logs (ts, visitor_id, method, path, query_json, headers_json,
              ua, is_ig_inapp, referrer, ip_h)
            VALUES (?,?,?,?,?,?,?,?,?,?)`)
            .bind(nowIso(), null, obs.method, obs.path, JSON.stringify(obs.query),
              JSON.stringify(obs.headers), obs.ua, obs.is_ig_inapp ? 1 : 0, obs.referrer, ipH).run();
          if (uaPreview || uaBot) {
            // Automated traffic (social preview / known bot) still gets a session
            // row so the dashboard can account for EVERY request type —
            // bots get no cookies, so each hit is its own anonymous session.
            const sid = randomHex(12), vid = randomHex(16), ts = nowIso();
            const dev = parseUAFull(obs.ua, obs.headers);
            const cls = uaPreview ? 'social_preview' : 'bot';
            const reason = uaPreview
              ? 'UA معروف لتوليد معاينات الروابط (Social preview)'
              : 'UA معروف لبوت/كراولر';
            await db.prepare(`INSERT INTO visitors (id, first_seen, last_seen, visit_count)
              VALUES (?,?,?,1) ON CONFLICT(id) DO NOTHING`).bind(vid, ts, ts).run();
            await db.prepare(`
              INSERT INTO sessions (id, visitor_id, started_at, last_activity_at, source, referrer,
                is_ig_inapp, is_inapp, in_app_app, device_type, os, browser, pageviews,
                classification, confidence, classification_reasons)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)`)
              .bind(sid, vid, ts, ts, sourceOf(obs.referrer_source, request.url), obs.referrer,
                obs.is_ig_inapp ? 1 : 0, 0, null, dev.device_type, dev.os, dev.browser,
                cls, 95, JSON.stringify([{ kind: 'bot', w: 95, text: reason }])).run();
          }
        }

        const asset = await env.ASSETS.fetch(request);
        if (!avidCookie) return asset;
        const headers = new Headers(asset.headers);
        headers.append('set-cookie', avidCookie);
        headers.append('set-cookie', asidCookie);
        return new Response(asset.body, { status: asset.status, headers });
      }

      /* ─────────── robots ─────────── */
      if (p === '/robots.txt')
        return textResponse('User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\n');

      /* ─────────── beacon (JS executed = key human signal) ─────────── */
      if (p === '/api/beacon' && request.method === 'POST') {
        const vid = getCookie(request, AVID);
        if (!vid || !/^[a-f0-9]{32}$/.test(vid)) return jsonResponse({ ok: false }, 404);
        if (parseInt(request.headers.get('content-length') || '0', 10) > 32768)
          return jsonResponse({ ok: false }, 413);
        let pl = {}; try { pl = await request.json() || {}; } catch {}
        const known = await db.prepare('SELECT id FROM visitors WHERE id = ?').bind(vid).first();
        if (!known) return jsonResponse({ ok: false }, 404);
        let sid = getCookie(request, ASID);
        if (!sid || !/^[a-f0-9]{24}$/.test(sid)) return jsonResponse({ ok: false }, 404);
        const sess = await db.prepare('SELECT * FROM sessions WHERE id = ? AND visitor_id = ?').bind(sid, vid).first();
        if (!sess) return jsonResponse({ ok: false }, 404);

        const ts = nowIso();
        const envJ = JSON.stringify(pl.env || {});
        await db.prepare(`
          INSERT INTO events (visitor_id, session_id, ts, type, path, referrer, referrer_source,
            is_ig_inapp, identity_mode, env, query_params, extra)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
          .bind(vid, sid, ts, 'beacon_env', pl.path || '/', pl.referrer || null, null,
            (pl.env && pl.env.in_app_app === 'Instagram') ? 1 : 0, 'deterministic',
            envJ, JSON.stringify(pl.query || {}),
            JSON.stringify({
              languages: pl.env?.languages, timezone: pl.env?.timezone,
              screen_bucket: pl.env?.screen_bucket, connection: pl.env?.connection,
              standalone: pl.env?.standalone, in_app_app: pl.env?.in_app_app,
              pcm_injected: pl.env?.pcm_injected })) .run();
        const wall = secBetween(sess.started_at, ts);
        await touchSession(db, sid, 'beacon', { ts, wallS: wall });
        await classifyAndStore(db, await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(sid).first());
        return jsonResponse({ ok: true });
      }

      /* ─────────── click ─────────── */
      if (p === '/api/click' && request.method === 'POST') {
        const vid = getCookie(request, AVID), sid = getCookie(request, ASID);
        if (!vid || !/^[a-f0-9]{32}$/.test(vid) || !sid || !/^[a-f0-9]{24}$/.test(sid))
          return jsonResponse({ ok: false }, 404);
        let pl = {}; try { pl = await request.json() || {}; } catch {}
        const sess = await db.prepare('SELECT * FROM sessions WHERE id = ? AND visitor_id = ?').bind(sid, vid).first();
        if (!sess) return jsonResponse({ ok: false }, 404);
        const ts = nowIso();
        await db.prepare(`
          INSERT INTO events (visitor_id, session_id, ts, type, path, extra)
          VALUES (?,?,?,?,?,?)`)
          .bind(vid, sid, ts, 'link_click', pl.path || '/',
            JSON.stringify({ href: String(pl.href || '').slice(0, 300),
                             label: String(pl.label || '').slice(0, 100) })).run();
        await touchSession(db, sid, 'click', { ts, wallS: secBetween(sess.started_at, ts) });
        await classifyAndStore(db, await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(sid).first());
        return jsonResponse({ ok: true });
      }

      /* ─────────── ping (heartbeat: duration + activity evidence) ─────────── */
      if (p === '/api/ping' && request.method === 'POST') {
        const vid = getCookie(request, AVID), sid = getCookie(request, ASID);
        if (!vid || !/^[a-f0-9]{32}$/.test(vid) || !sid || !/^[a-f0-9]{24}$/.test(sid))
          return jsonResponse({ ok: false }, 404);
        let pl = {}; try { pl = await request.json() || {}; } catch {}
        const sess = await db.prepare('SELECT * FROM sessions WHERE id = ? AND visitor_id = ?').bind(sid, vid).first();
        if (!sess) return jsonResponse({ ok: false }, 404);

        const ts = nowIso();
        const activeS = Math.max(0, Math.min(parseInt(pl.active_s || 0, 10) || 0, 7200));
        const gestureN = Math.max(0, Math.min(parseInt(pl.gestures || 0, 10) || 0, 5));
        await touchSession(db, sid, 'heartbeat', {
          ts, activeS: activeS || null, wallS: secBetween(sess.started_at, ts), gestureN });
        // record visibility transitions as evidence events (sparse, not every ping)
        if (pl.visibility_event) {
          await db.prepare(`INSERT INTO events (visitor_id, session_id, ts, type, path, extra)
            VALUES (?,?,?,?,?,?)`)
            .bind(vid, sid, ts, 'visibility', pl.path || '/',
              JSON.stringify({ state: pl.visibility_event })).run();
        }
        const s = secure(request);
        const h = new Headers({ 'Content-Type': 'application/json; charset=utf-8' });
        h.append('set-cookie', `${ASID}=${sid}; Max-Age=${SESSION_GAP_S}; Path=/; HttpOnly; SameSite=Lax${s}`);
        return new Response('{"ok":true}', { status: 200, headers: h });
      }

      /* ─────────── internal/test-mode toggle (requires ADMIN_TOKEN) ─────────── */
      if (p === '/internal/toggle' && request.method === 'POST') {
        let body = {}; try { body = await request.json() || {}; } catch {}
        if (!body.token || !ctEq(String(body.token), String(env.ADMIN_TOKEN || '')))
          return jsonResponse({ ok: false, error: 'unauthorized' }, 401);
        const on = body.on !== false;
        const s = secure(request);
        const cookie = on
          ? `${TEST}=1; Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax${s}`
          : `${TEST}=deleted; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${s}`;
        return jsonResponse({ ok: true, internal: on }, 200, [cookie]);
      }

      /* ═══════════ admin auth (unchanged) ═══════════ */
      if (p === '/admin/login' && request.method === 'POST') {
        let body = {}; try { body = await request.json() || {}; } catch {}
        if (!body.token || !ctEq(String(body.token), String(env.ADMIN_TOKEN || '')))
          return jsonResponse({ ok: false }, 401);
        const s = secure(request);
        return jsonResponse({ ok: true }, 200,
          [`${ADM}=${await adminTokenHash(env)}; Max-Age=43200; Path=/; HttpOnly; SameSite=Strict${s}`]);
      }
      if (p === '/admin/login' && request.method === 'GET')
        return env.ASSETS.fetch(new Request(new URL('/login.html', request.url), request));
      if (p === '/admin/logout' && request.method === 'POST') {
        const s = secure(request);
        return jsonResponse({ ok: true }, 200, [`${ADM}=deleted; Max-Age=0; Path=/; HttpOnly; SameSite=Strict${s}`]);
      }

      /* dashboard aliases — guarded */
      if (p === '/dashboard' || p === '/dashboard.html') {
        const redir = await guardAdmin(request, env);
        if (redir) return redir;
        return env.ASSETS.fetch(new Request(new URL('/dashboard.html', request.url), request));
      }

      /* ═══════════ admin APIs ═══════════ */
      if (p.startsWith('/admin')) {
        const redir = await guardAdmin(request, env);
        if (redir) return redir;

        if (p === '/admin' && request.method === 'GET')
          return env.ASSETS.fetch(new Request(new URL('/dashboard.html', request.url), request));

        /* filters shared by every analytics endpoint */
        const f = {};
        for (const k of FILTERS) if (sp.get(k)) f[k] = sp.get(k);
        const { where, vals } = buildWhere(f);
        // A second WHERE that skips the internal-exclusion — used to count
        // internal/test traffic TRUTHFULLY even while it's excluded from KPIs.
        // '0' explicitly disables the internal-exclusion (unlike deleting an
        // absent key, which leaves the default-exclusion clause in place).
        const fIncl = { ...f, exclude_internal: '0' };
        const { where: whereIncl } = buildWhere(fIncl);

        /* ── KPI summary ── */
        if (p === '/admin/api/summary.json') {
          const t = (await db.prepare(`
            SELECT
              (SELECT COUNT(DISTINCT visitor_id) FROM sessions
                 WHERE COALESCE(classification,'unknown') NOT IN ('bot','social_preview')
                   AND COALESCE(classification,'unknown') != 'internal') visitors_total,
              (SELECT COUNT(DISTINCT s.visitor_id) FROM sessions s
                 ${where}) visitors,
              (SELECT COUNT(*) FROM sessions s ${where}) sessions,
              (SELECT COUNT(*) FROM sessions s ${where} AND s.classification = 'human_likely') human_sessions,
              (SELECT COUNT(*) FROM sessions s ${where} AND s.classification = 'bot') bot_sessions,
              (SELECT COUNT(*) FROM sessions s ${where} AND s.classification = 'unknown') unknown_sessions,
              (SELECT COUNT(*) FROM sessions s ${where} AND s.classification = 'suspicious') suspicious_sessions,
              (SELECT COUNT(*) FROM sessions s ${where} AND s.classification = 'social_preview') preview_sessions,
              (SELECT COUNT(*) FROM sessions s ${whereIncl} AND s.classification = 'internal') internal_sessions,
              (SELECT COUNT(DISTINCT s.visitor_id) FROM sessions s
                 ${where} AND s.classification = 'human_likely') human_visitors,
              (SELECT COUNT(DISTINCT s.visitor_id) FROM sessions s
                 JOIN visitors v ON v.id = s.visitor_id ${where} AND v.visit_count > 1) returning_visitors,
              (SELECT COUNT(*) FROM sessions s ${where}
                 AND s.pageviews = 1 AND s.interactions = 0
                 AND s.classification IS NOT NULL) bounce_sessions
          `).bind(...vals, ...vals, ...vals, ...vals, ...vals, ...vals, ...vals, ...vals, ...vals, ...vals, ...vals).first());

          // Pageviews from the denormalized session counter — legacy sessions
          // default to 1 (they predate per-pageview events), which keeps the
          // invariant pageviews >= sessions always true.
          const pv = (await db.prepare(`
            SELECT SUM(COALESCE(s.pageviews,1)) n FROM sessions s ${where}`)
            .bind(...vals).first()).n || 0;

          const dur = (await db.prepare(`
            SELECT COUNT(*) n, AVG(s.duration_s) avg_s,
              SUM(CASE WHEN s.duration_s >= 5 AND s.duration_s < 3600 THEN 1 ELSE 0 END) valid_n,
              AVG(CASE WHEN s.duration_s >= 5 AND s.duration_s < 3600 THEN s.duration_s END) valid_avg
            FROM sessions s ${where}`).bind(...vals).first());
          const act = (await db.prepare(`
            SELECT AVG(CASE WHEN s.active_duration_s >= 5 THEN s.active_duration_s END) avg_active
            FROM sessions s ${where}`).bind(...vals).first());

          // median + p90 (small dataset — fine to compute over rows)
          const durs = (await db.prepare(`
            SELECT s.duration_s d FROM sessions s
            ${where} AND s.duration_s IS NOT NULL AND s.duration_s >= 5 AND s.duration_s < 3600
            ORDER BY s.duration_s`).bind(...vals).all()).results.map(r => r.d);
          const med = durs.length ? durs[Math.floor(durs.length / 2)] : null;
          const p90 = durs.length ? durs[Math.floor(durs.length * 0.9)] : null;

          const live = (await db.prepare(`
            SELECT COUNT(*) n FROM sessions s
            WHERE s.last_activity_at >= ?
              AND COALESCE(s.is_internal,0) = 0`)
            .bind(new Date(Date.now() - LIVE_WINDOW_S * 1000).toISOString()).first()).n;

          return jsonResponse({
            totals: {
              visitors_total: t.visitors_total,
              visitors: t.visitors,
              returning_visitors: t.returning_visitors,
              sessions: t.sessions,
              human_sessions: t.human_sessions,
              human_visitors: t.human_visitors,
              bot_sessions: t.bot_sessions,
              unknown_sessions: t.unknown_sessions,
              suspicious_sessions: t.suspicious_sessions,
              preview_sessions: t.preview_sessions,
              internal_sessions: t.internal_sessions,
              bounce_sessions: t.bounce_sessions,
              pageviews: pv,
              avg_duration_s: dur.valid_n >= 3 ? Math.round(dur.valid_avg) : null,
              median_duration_s: durs.length >= 3 ? Math.round(med) : null,
              p90_duration_s: durs.length >= 3 ? Math.round(p90) : null,
              avg_active_s: act.avg_active ? Math.round(act.avg_active) : null,
              duration_sample_n: dur.valid_n || 0,
              live_now: live,
            },
            model: { session_gap_s: SESSION_GAP_S, refresh_window_s: REFRESH_WINDOW_S },
          });
        }

        /* ── chart data (sources, devices, os, browsers, classification, over-time) ── */
        if (p === '/admin/api/overview.json') {
          const group = async (col) =>
            (await db.prepare(`SELECT s.${col} k, COUNT(*) n,
                SUM(CASE WHEN s.classification='human_likely' THEN 1 ELSE 0 END) human
              FROM sessions s ${where} GROUP BY s.${col} ORDER BY n DESC`)
              .bind(...vals).all()).results;

          const overTime = (await db.prepare(`
            SELECT substr(s.started_at, 1, 13) hour, COUNT(*) sessions,
              SUM(CASE WHEN s.classification='human_likely' THEN 1 ELSE 0 END) human
            FROM sessions s ${where}
            GROUP BY hour ORDER BY hour`).bind(...vals).all()).results;

          const sources = (await db.prepare(`
            SELECT s.source k, COUNT(*) n,
              SUM(CASE WHEN s.classification='human_likely' THEN 1 ELSE 0 END) human,
              AVG(CASE WHEN s.duration_s >= 5 AND s.duration_s < 3600 THEN s.duration_s END) avg_dur,
              AVG(s.pageviews) avg_pv
            FROM sessions s ${where} GROUP BY s.source ORDER BY n DESC`).bind(...vals).all()).results;

          const inapp = (await db.prepare(`
            SELECT s.in_app_app k, COUNT(*) n FROM sessions s
            ${where} AND s.is_inapp = 1 GROUP BY s.in_app_app`).bind(...vals).all()).results;

          return jsonResponse({
            bySource: sources,
            byDevice: await group('device_type'),
            byOs: await group('os'),
            byBrowser: await group('browser'),
            byVendor: await group('device_vendor'),
            byClassification: await group('classification'),
            byInApp: inapp,
            overTime,
          });
        }

        /* ── sessions table ── */
        if (p === '/admin/api/sessions.json') {
          const limit = Math.min(parseInt(sp.get('limit') || '200', 10) || 200, 500);
          const rows = (await db.prepare(`
            SELECT s.id, s.visitor_id, s.started_at, s.last_activity_at, s.ended_at,
              s.duration_s, s.active_duration_s, s.pageviews, s.event_count,
              s.refresh_count, s.source, s.referrer, s.is_ig_inapp, s.is_inapp,
              s.in_app_app, s.device_type, s.device_vendor, s.device_model, s.os,
              s.browser, s.browser_version, s.classification, s.confidence,
              s.is_internal, v.visit_count
            FROM sessions s JOIN visitors v ON v.id = s.visitor_id
            ${where} ORDER BY s.last_activity_at DESC LIMIT ?`)
            .bind(...vals, limit).all()).results;
          return jsonResponse(rows);
        }

        /* ── session detail (timeline) ── */
        if (p === '/admin/api/session.json') {
          const id = sp.get('id') || '';
          if (!/^[a-f0-9]{24}$/.test(id)) return jsonResponse({ ok: false }, 400);
          const sess = await db.prepare(`
            SELECT s.*, v.visit_count, v.first_seen visitor_first_seen
            FROM sessions s JOIN visitors v ON v.id = s.visitor_id
            WHERE s.id = ?`).bind(id).first();
          if (!sess) return jsonResponse({ ok: false }, 404);
          const timeline = (await db.prepare(`
            SELECT ts, type, path, extra FROM events WHERE session_id = ?
            ORDER BY id ASC`).bind(id).all()).results;
          return jsonResponse({ session: sess, timeline });
        }

        /* ── visitor profile ── */
        if (p === '/admin/api/visitor.json') {
          const id = sp.get('id') || '';
          if (!/^[a-f0-9]{32}$/.test(id)) return jsonResponse({ ok: false }, 400);
          const v = await db.prepare('SELECT * FROM visitors WHERE id = ?').bind(id).first();
          if (!v) return jsonResponse({ ok: false }, 404);
          const sess = (await db.prepare(`
            SELECT id, started_at, last_activity_at, duration_s, pageviews,
              refresh_count, source, classification, confidence, is_internal,
              device_type, device_vendor, browser, in_app_app
            FROM sessions WHERE visitor_id = ? ORDER BY started_at ASC`)
            .bind(id).all()).results;
          const sources = {}, devices = {}, browsers = {};
          for (const s of sess) {
            sources[s.source || 'direct'] = (sources[s.source || 'direct'] || 0) + 1;
            devices[s.device_type || 'unknown'] = (devices[s.device_type || 'unknown'] || 0) + 1;
            browsers[s.browser || 'unknown'] = (browsers[s.browser || 'unknown'] || 0) + 1;
          }
          return jsonResponse({ visitor: v, sessions: sess,
            source_history: sources, device_history: devices, browser_history: browsers });
        }

        /* ── live now ── */
        if (p === '/admin/api/live.json') {
          const rows = (await db.prepare(`
            SELECT s.id, s.visitor_id, s.last_activity_at, s.started_at,
              s.duration_s, s.active_duration_s, s.source, s.device_type,
              s.device_vendor, s.browser, s.classification, s.confidence,
              s.is_inapp, s.in_app_app, s.pageviews,
              (SELECT e.path FROM events e WHERE e.session_id = s.id
                 AND e.type = 'pageview' ORDER BY e.id DESC LIMIT 1) current_path
            FROM sessions s
            WHERE s.last_activity_at >= ?
              AND COALESCE(s.is_internal,0) = 0
            ORDER BY s.last_activity_at DESC LIMIT 50`)
            .bind(new Date(Date.now() - LIVE_WINDOW_S * 1000).toISOString()).all()).results;
          return jsonResponse(rows);
        }

        /* ── manual classification override (mark internal etc.) ── */
        if (p === '/admin/api/override.json' && request.method === 'POST') {
          let body = {}; try { body = await request.json() || {}; } catch {}
          const id = String(body.session_id || '');
          const cls = String(body.classification || '');
          if (!/^[a-f0-9]{24}$/.test(id)) return jsonResponse({ ok: false }, 400);
          if (!['internal', 'human_likely', 'bot', 'unknown', 'suspicious'].includes(cls))
            return jsonResponse({ ok: false }, 400);
          await db.prepare(`
            UPDATE sessions SET internal_override = 1, classification = ?, confidence = 100,
              is_internal = CASE WHEN ? = 'internal' THEN 1 ELSE is_internal END,
              classification_reasons = ?
            WHERE id = ?`)
            .bind(cls, cls,
              JSON.stringify([{ kind: 'admin', w: 100, text: 'تصنيف يدوي من الأدمن' }]), id).run();
          return jsonResponse({ ok: true });
        }

        /* ── legacy endpoints kept for compatibility ── */
        if (p === '/admin/api/events.json') {
          const limit = Math.min(parseInt(sp.get('limit') || '100', 10) || 100, 500);
          const rows = (await db.prepare(`
            SELECT visitor_id, session_id, ts, type, path, referrer, referrer_source,
              is_ig_inapp, identity_mode, env, query_params
            FROM events ORDER BY id DESC LIMIT ?`).bind(limit).all()).results;
          return jsonResponse(rows);
        }
        if (p === '/admin/api/requests.json') {
          const limit = Math.min(parseInt(sp.get('limit') || '100', 10) || 100, 500);
          const rows = (await db.prepare(`
            SELECT ts, visitor_id, method, path, query_json, headers_json, ua, is_ig_inapp, referrer
            FROM request_logs ORDER BY id DESC LIMIT ?`).bind(limit).all()).results;
          return jsonResponse(rows);
        }
        if (p === '/admin/api/visitors.json') {
          const rows = (await db.prepare(`
            SELECT id, first_seen, last_seen, visit_count FROM visitors
            ORDER BY last_seen DESC LIMIT 500`).all()).results;
          return jsonResponse(rows);
        }

        /* ── enriched export ── */
        if (p === '/admin/api/export.json') {
          const [summaryRes, sess, vis, evts] = await Promise.all([
            db.prepare(`SELECT
              (SELECT COUNT(*) FROM visitors) visitors,
              (SELECT COUNT(*) FROM sessions) sessions,
              (SELECT COUNT(*) FROM sessions WHERE classification = 'human_likely') human_sessions,
              (SELECT COUNT(*) FROM sessions WHERE classification = 'bot') bot_sessions,
              (SELECT COUNT(*) FROM sessions WHERE classification = 'unknown') unknown_sessions,
              (SELECT COUNT(*) FROM sessions WHERE classification = 'suspicious') suspicious_sessions,
              (SELECT COUNT(*) FROM sessions WHERE classification = 'social_preview') preview_sessions,
              (SELECT COUNT(*) FROM sessions WHERE classification = 'internal') internal_sessions,
              (SELECT COUNT(*) FROM events WHERE type = 'pageview') pageviews,
              (SELECT ROUND(AVG(CASE WHEN duration_s >= 5 AND duration_s < 3600 THEN duration_s END))
                 FROM sessions) avg_duration_s
            `).first(),
            db.prepare(`SELECT s.*, v.visit_count FROM sessions s
              JOIN visitors v ON v.id = s.visitor_id ORDER BY s.started_at DESC LIMIT 2000`).all(),
            db.prepare(`SELECT id, first_seen, last_seen, visit_count FROM visitors
              ORDER BY last_seen DESC LIMIT 1000`).all(),
            db.prepare(`SELECT visitor_id, session_id, ts, type, path, referrer, referrer_source,
              is_ig_inapp, identity_mode FROM events ORDER BY id DESC LIMIT 5000`).all(),
          ]);
          const data = {
            exported_at: nowIso(),
            model_version: 2,
            classification_legend: ['human_likely','unknown','bot','social_preview','internal','suspicious'],
            summary: summaryRes,
            visitors: vis.results,
            sessions: sess.results,   // includes classification, confidence, reasons, device/browser/OS
            events: evts.results,
          };
          return new Response(JSON.stringify(data, null, 2), {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Content-Disposition': `attachment; filename="alucard-analytics-v2-${nowIso().slice(0, 10)}.json"`,
            },
          });
        }
      } // /admin

      /* ─────────── static assets ─────────── */
      return env.ASSETS.fetch(request);

    } catch (err) {
      console.error('worker error:', err);
      return jsonResponse({ ok: false, error: String(err && err.message || err) }, 500);
    }
  },
};
