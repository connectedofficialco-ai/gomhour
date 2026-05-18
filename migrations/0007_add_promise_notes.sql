-- 커플 약속 메모
CREATE TABLE IF NOT EXISTS promise_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  couple_id INTEGER NOT NULL,
  author_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  note_date TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_promise_notes_couple_id
  ON promise_notes (couple_id);

CREATE INDEX IF NOT EXISTS idx_promise_notes_note_date
  ON promise_notes (note_date);
