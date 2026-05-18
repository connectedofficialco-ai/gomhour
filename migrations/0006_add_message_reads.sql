-- 메시지 읽음 상태 저장 (사용자별)
CREATE TABLE IF NOT EXISTS message_reads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message_id INTEGER NOT NULL,
  read_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_message_reads_user_message
  ON message_reads (user_id, message_id);

CREATE INDEX IF NOT EXISTS idx_message_reads_user_id
  ON message_reads (user_id);

CREATE INDEX IF NOT EXISTS idx_message_reads_message_id
  ON message_reads (message_id);
