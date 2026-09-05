-- Migration 0001: initial schema for privacy-aware first-party analytics (Cloudflare D1).
-- Ported 1:1 from the original better-sqlite3 schema (lib/db.js).
-- No PII: no IP addresses, no names, no emails.
-- IP is stored ONLY as a keyed hash (HMAC-SHA256 of CF-Connecting-IP with a secret salt),
-- never reversible without the salt, which lives in Worker secrets, never in the DB.

CREATE TABLE IF NOT EXISTS visitors (
  id            TEXT PRIMARY KEY,          -- anonymous_visitor_id: 32 hex chars, crypto random
  first_seen    TEXT NOT NULL,
  last_seen     TEXT NOT NULL,
  visit_count   INTEGER NOT NULL DEFAULT 1,
  created_ip_h  TEXT                      -- keyed hash of first-seen IP (not reversible)
);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  visitor_id  TEXT NOT NULL REFERENCES visitors(id),
  started_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  visitor_id    TEXT NOT NULL REFERENCES visitors(id),
  session_id    TEXT,
  ts            TEXT NOT NULL,
  type          TEXT NOT NULL,             -- first_visit | returning_visit | pageview | link_click | beacon_env | custom
  path          TEXT,
  referrer      TEXT,
  referrer_source TEXT,                    -- instagram | direct | search | social | other-website | unknown
  is_ig_inapp   INTEGER NOT NULL DEFAULT 0,
  identity_mode TEXT NOT NULL DEFAULT 'deterministic-first-party-id', -- deterministic | probabilistic | unknown
  env           TEXT,                      -- JSON: device/os/browser/app detection (coarse)
  query_params  TEXT,                      -- JSON of URL query params (the experiment's raw material)
  extra         TEXT                       -- JSON: misc payload (client env, flags)
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_visitor ON events(visitor_id);

CREATE TABLE IF NOT EXISTS request_logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  visitor_id   TEXT,
  method      TEXT,
  path        TEXT,
  query_json  TEXT,                        -- full query string parsed
  headers_json TEXT,                       -- minimized subset of headers
  ua          TEXT,
  is_ig_inapp INTEGER NOT NULL DEFAULT 0,
  referrer    TEXT,
  ip_h        TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON request_logs(ts);
