CREATE TABLE IF NOT EXISTS docs (sub TEXT PRIMARY KEY, rev INTEGER NOT NULL DEFAULT 0, doc TEXT NOT NULL, updated INTEGER);
CREATE TABLE IF NOT EXISTS logins (state TEXT PRIMARY KEY, session TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS accounts (sub TEXT PRIMARY KEY, ver INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, invite_hash TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS members (team TEXT NOT NULL, sub TEXT NOT NULL, mid TEXT NOT NULL, role TEXT NOT NULL, joined INTEGER NOT NULL, PRIMARY KEY (team, sub));
CREATE INDEX IF NOT EXISTS members_by_sub ON members (sub);
CREATE INDEX IF NOT EXISTS members_by_mid ON members (team, mid);
CREATE TABLE IF NOT EXISTS snaps (team TEXT NOT NULL, sub TEXT NOT NULL, doc TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (team, sub));
-- Push notifications (the worker also creates these on first use, so no manual step is needed)
CREATE TABLE IF NOT EXISTS push (id TEXT PRIMARY KEY, sub TEXT NOT NULL, box TEXT NOT NULL, next_at INTEGER, updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS push_next ON push (next_at);
CREATE INDEX IF NOT EXISTS push_by_sub ON push (sub);
CREATE TABLE IF NOT EXISTS conf (k TEXT PRIMARY KEY, v TEXT NOT NULL);
-- Ella smart conversation: only a per-day message count per account (created on first use too)
CREATE TABLE IF NOT EXISTS ella_use (sub TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (sub, day));
-- Leader nudges: per-day count per member, so a lead can nudge someone at most twice a day (created on first use too)
CREATE TABLE IF NOT EXISTS nudge_use (team TEXT NOT NULL, sub TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (team, sub, day));
-- Accountability partners (one way): sealed names and shared copy per invite link (created on first use too)
CREATE TABLE IF NOT EXISTS partners (id TEXT PRIMARY KEY, owner TEXT NOT NULL, viewer TEXT, invite_hash TEXT, names TEXT, doc TEXT, updated INTEGER, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS partners_by_owner ON partners (owner);
CREATE INDEX IF NOT EXISTS partners_by_viewer ON partners (viewer);
