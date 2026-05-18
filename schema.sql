-- D1 schema for 곰아워
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kakao_id TEXT UNIQUE,
  apple_id TEXT UNIQUE,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  picture TEXT,
  gender TEXT,
  couple_id INTEGER,
  couple_linked_at TEXT,
  met_date TEXT,
  notification_time TEXT DEFAULT '20:00',
  password TEXT,
  pin TEXT,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS couples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  couple_code TEXT UNIQUE NOT NULL,
  met_date TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  couple_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  message_date TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  platform TEXT DEFAULT 'ios',
  last_notified_date TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS message_reads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message_id INTEGER NOT NULL,
  read_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS promise_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  couple_id INTEGER NOT NULL,
  author_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 3,
  note_date TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS love_quote_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  couple_id INTEGER NOT NULL,
  spinner_user_id INTEGER NOT NULL,
  quote_text TEXT NOT NULL,
  spin_date TEXT NOT NULL,
  saved INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

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

CREATE INDEX IF NOT EXISTS idx_users_couple_id ON users (couple_id);
CREATE INDEX IF NOT EXISTS idx_messages_couple_id ON messages (couple_id);
CREATE INDEX IF NOT EXISTS idx_messages_user_date ON messages (user_id, message_date);
CREATE INDEX IF NOT EXISTS idx_device_tokens_user_id ON device_tokens (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_message_reads_user_message ON message_reads (user_id, message_id);
CREATE INDEX IF NOT EXISTS idx_message_reads_user_id ON message_reads (user_id);
CREATE INDEX IF NOT EXISTS idx_message_reads_message_id ON message_reads (message_id);
CREATE INDEX IF NOT EXISTS idx_promise_notes_couple_id ON promise_notes (couple_id);
CREATE INDEX IF NOT EXISTS idx_promise_notes_note_date ON promise_notes (note_date);
CREATE INDEX IF NOT EXISTS idx_promise_notes_priority ON promise_notes (priority);
CREATE UNIQUE INDEX IF NOT EXISTS idx_love_quote_events_couple_date ON love_quote_events (couple_id, spin_date);
CREATE INDEX IF NOT EXISTS idx_love_quote_events_couple_id ON love_quote_events (couple_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_love_quote_draws_couple_date ON love_quote_draws (couple_id, draw_date);
CREATE INDEX IF NOT EXISTS idx_love_quote_draws_couple_saved ON love_quote_draws (couple_id, saved, draw_date);
