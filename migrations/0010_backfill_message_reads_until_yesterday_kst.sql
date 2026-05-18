-- 일회성: 어제(KST 기준)까지 작성된 모든 메시지를, 같은 커플의 상대방 사용자 기준으로 읽음 처리
-- (기존에 두 번째 탭 등에서 읽음 API가 호출되지 않아 쌓인 미읽음 정리용)
-- message_date는 YYYY-MM-DD 문자열로 저장된다고 가정
INSERT OR IGNORE INTO message_reads (user_id, message_id, read_at)
SELECT u.id, m.id, CURRENT_TIMESTAMP
FROM messages m
JOIN users u
  ON u.couple_id = m.couple_id
 AND u.id != m.user_id
WHERE m.couple_id IS NOT NULL
  AND m.message_date <= date(datetime('now', '+9 hours', '-1 day'));
