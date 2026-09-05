-- Migration 0003: add webdriver to sessions table

ALTER TABLE sessions ADD COLUMN webdriver INTEGER NOT NULL DEFAULT 0;
