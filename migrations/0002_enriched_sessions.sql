-- Migration 0002: enriched session model for the upgraded analytics dashboard.
-- ADDITIVE ONLY — no existing column is dropped or renamed, so historical data
-- (including the A/B test traffic) survives untouched.
--
-- Data model after this migration:
--   visitor  = persistent anonymous identity (cookie `avid`)
--   session  = continuous visit window (cookie `asid`, stitched; 30-min default gap)
--   pageview = page load inside a session (event type 'pageview', refreshes counted)
--   event    = any interaction (beacon_env / link_click / heartbeat signals …)

-- Session stitching & activity
ALTER TABLE sessions ADD COLUMN last_activity_at TEXT;
ALTER TABLE sessions ADD COLUMN ended_at         TEXT;
ALTER TABLE sessions ADD COLUMN duration_s        REAL;   -- wall-clock: last_activity − started_at (server-computed)
ALTER TABLE sessions ADD COLUMN active_duration_s REAL;   -- client-verified active time (visibility-aware)

-- Counters (denormalized for fast dashboard reads; events remain source of truth)
ALTER TABLE sessions ADD COLUMN pageviews    INTEGER NOT NULL DEFAULT 1;
ALTER TABLE sessions ADD COLUMN event_count  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN refresh_count INTEGER NOT NULL DEFAULT 0;

-- Traffic context (captured once at session start)
ALTER TABLE sessions ADD COLUMN source       TEXT;   -- direct | instagram | facebook | search | website:<host> …
ALTER TABLE sessions ADD COLUMN referrer    TEXT;
ALTER TABLE sessions ADD COLUMN is_ig_inapp  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN is_inapp     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN in_app_app  TEXT;   -- Instagram | Facebook | TikTok | … (browser context, NOT identity)

-- Raw UA kept on the session row for classification (never shown publicly)
ALTER TABLE sessions ADD COLUMN ua             TEXT;

-- Enriched device/OS/browser (from lib/ua.js — UA + client hints, never fabricated)
ALTER TABLE sessions ADD COLUMN device_type    TEXT;
ALTER TABLE sessions ADD COLUMN device_vendor  TEXT;
ALTER TABLE sessions ADD COLUMN device_model   TEXT;
ALTER TABLE sessions ADD COLUMN os             TEXT;
ALTER TABLE sessions ADD COLUMN os_version     TEXT;
ALTER TABLE sessions ADD COLUMN browser       TEXT;
ALTER TABLE sessions ADD COLUMN browser_version TEXT;

-- Classification (multi-signal, probabilistic)
ALTER TABLE sessions ADD COLUMN classification        TEXT;   -- human_likely|unknown|bot|social_preview|internal|suspicious
ALTER TABLE sessions ADD COLUMN confidence           INTEGER;
ALTER TABLE sessions ADD COLUMN classification_reasons TEXT;  -- JSON [{kind,w,text}]
ALTER TABLE sessions ADD COLUMN is_internal          INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN internal_override    INTEGER NOT NULL DEFAULT 0; -- manual admin override

-- Classifier evidence counters (updated on every beacon/click/heartbeat)
ALTER TABLE sessions ADD COLUMN js_beacons     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN heartbeats    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN interactions  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN distinct_paths INTEGER NOT NULL DEFAULT 1;

-- Visitors: per-visitor classification summary (JSON) for the profile view
ALTER TABLE visitors ADD COLUMN classification_summary TEXT;

-- Legacy columns from the interim runtime migration, kept for compatibility.
-- (Safe no-ops if they already exist in your local DB.)

CREATE INDEX IF NOT EXISTS idx_sessions_visitor    ON sessions(visitor_id);
CREATE INDEX IF NOT EXISTS idx_sessions_started    ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_act   ON sessions(last_activity_at);
CREATE INDEX IF NOT EXISTS idx_events_session      ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_session_type  ON events(session_id, type);
