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
  notification_time TEXT DEFAULT '20:00',
  password TEXT,
  pin TEXT,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS couples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  couple_code TEXT UNIQUE NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_users_couple_id ON users (couple_id);
CREATE INDEX IF NOT EXISTS idx_messages_couple_id ON messages (couple_id);
CREATE INDEX IF NOT EXISTS idx_messages_user_date ON messages (user_id, message_date);
CREATE INDEX IF NOT EXISTS idx_device_tokens_user_id ON device_tokens (user_id);
