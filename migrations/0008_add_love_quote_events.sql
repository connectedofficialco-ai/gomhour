CREATE TABLE IF NOT EXISTS love_quote_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  couple_id INTEGER NOT NULL,
  spinner_user_id INTEGER NOT NULL,
  quote_text TEXT NOT NULL,
  spin_date TEXT NOT NULL,
  saved INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_love_quote_events_couple_date ON love_quote_events (couple_id, spin_date);
CREATE INDEX IF NOT EXISTS idx_love_quote_events_couple_id ON love_quote_events (couple_id);
