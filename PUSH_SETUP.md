# 푸시 알림 설정 가이드

푸시가 안 될 때 아래를 순서대로 확인하세요.

---

## 1. Sandbox vs Production (가장 흔한 원인)

Apple APNs는 **sandbox**와 **production**이 완전히 분리되어 있습니다.

| 빌드 종류 | aps-environment | APNs 서버 | APNS_USE_SANDBOX |
|-----------|-----------------|-----------|------------------|
| Debug, TestFlight | development | api.sandbox.push.apple.com | **"true"** |
| App Store 출시 | production | api.push.apple.com | **"false"** |

**문제:** TestFlight 빌드 → sandbox 토큰 발급 → 백엔드가 production APNs로 전송 → 푸시 조용히 실패

**해결:** 테스트 중이면 `APNS_USE_SANDBOX = "true"` 로 설정 후 재배포.

---

## 2. wrangler-legacy.toml 설정

```toml
# 푸시 테스트(debug/TestFlight): "true"
# 앱스토어 출시 빌드: "false"
APNS_USE_SANDBOX = "true"
```

- **지금 테스트 중** → `"true"` 유지, 배포 후 푸시 재확인
- **앱스토어에 출시할 때** → `"false"` 로 변경 후 배포

---

## 3. APNS_PRIVATE_KEY 시크릿

Legacy Worker에 APNs용 시크릿이 있어야 합니다:

```bash
npx wrangler secret put APNS_PRIVATE_KEY -c wrangler-legacy.toml
```

Apple Developer에서 생성한 `.p8` 키 파일 내용을 붙여넣습니다.

---

## 4. 푸시 등록 흐름

**중요:** 토큰은 **앱(Flutter)**에서만 등록됩니다. 브라우저에서 gom-hr.com을 열어도 토큰은 등록되지 않습니다.

1. **앱**에서 `/dashboard` 또는 `/settings` 진입
2. Flutter → MethodChannel("apns") → `requestToken`
3. iOS 네이티브 → APNs 등록 → 토큰 수신
4. WebView에 JS 주입 → `fetch('/api/push/register', { token })`
5. 백엔드가 D1 `device_tokens` 테이블에 저장

**tokenCount: 0** 이면 → 앱을 켜고 설정 화면에 들어온 뒤 알림 허용이 필요합니다.

---

## 5. 체크리스트

- [ ] `APNS_USE_SANDBOX`: 테스트면 `"true"`, 출시면 `"false"`
- [ ] `npx wrangler deploy -c wrangler-legacy.toml` 실행
- [ ] `APNS_PRIVATE_KEY` 시크릿 설정됨
- [ ] 앱에서 설정 화면 진입 후 알림 권한 허용
- [ ] 마이페이지에서 "테스트 푸시 보내기"로 동작 확인
