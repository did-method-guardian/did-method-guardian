-- Post-recovery login secret reissue (user-decided design, 2026-11-23):
-- a guardian-approved recovery issues a fresh login secret the guardian
-- never chose and the ward never saw being set -- the account dashboard
-- needs to know, at the ward's very next login, that this one should be
-- replaced with something only the ward knows. 0/1 (SQLite has no real
-- boolean), defaulting to 0 so every existing row (every secret anyone
-- already knowingly set or was handed through the existing self-service
-- paths) is unaffected.
ALTER TABLE held_keys ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
