CREATE TABLE IF NOT EXISTS love_quote_draws (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  couple_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  quote_text TEXT NOT NULL,
  quote_index INTEGER NOT NULL,
  draw_date TEXT NOT NULL,
  saved INTEGER DEFAULT 0,
  saved_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_love_quote_draws_couple_date
ON love_quote_draws (couple_id, draw_date);

CREATE INDEX IF NOT EXISTS idx_love_quote_draws_couple_saved
ON love_quote_draws (couple_id, saved, draw_date);
