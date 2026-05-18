-- 계약 알림 모달(전날 상대 미작성)은 사용자당 최초 1회만 표시
ALTER TABLE users ADD COLUMN contract_no_msg_reminder_shown INTEGER DEFAULT 0;
