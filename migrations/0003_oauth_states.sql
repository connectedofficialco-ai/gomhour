-- Apple OAuth state 저장 (WebView/Safari 간 쿠키 미공유 시 대비)
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);
