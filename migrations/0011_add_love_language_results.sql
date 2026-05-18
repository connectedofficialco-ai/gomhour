CREATE TABLE IF NOT EXISTS love_language_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  couple_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  top1 TEXT NOT NULL,
  top2 TEXT NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_love_language_results_couple_user
  ON love_language_results (couple_id, user_id);

CREATE INDEX IF NOT EXISTS idx_love_language_results_couple
  ON love_language_results (couple_id);
