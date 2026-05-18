-- 연동 시 상대방 앱에서 우리의 약속 표시용
ALTER TABLE users ADD COLUMN promise_pending INTEGER DEFAULT 0;
