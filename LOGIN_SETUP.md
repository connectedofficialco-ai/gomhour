# 로그인 설정 점검 가이드

Apple·카카오 로그인이 안 될 때 아래를 순서대로 확인하세요.

---

## 1. 카카오 로그인

### 카카오 개발자 콘솔
**경로:** [developers.kakao.com](https://developers.kakao.com) → 내 애플리케이션 → 앱 선택

1. **플랫폼**
   - **Web** 플랫폼 추가
   - 사이트 도메인: `gom-hr.com`

2. **카카오 로그인** → **활성화 ON**

3. **Redirect URI** (필수)
   - 아래 URI를 **정확히** 등록:
   ```
   https://gom-hr.com/auth/kakao/callback
   ```
   - `http` 아님, 끝에 `/` 없음

4. **동의항목**
   - 프로필 정보(닉네임, 프로필 이미지): 선택 동의
   - 카카오계정(이메일): 선택 동의

5. **REST API 키**
   - `wrangler.toml`의 `KAKAO_CLIENT_ID`와 동일한지 확인

6. **Client Secret** (선택, 보안 강화 시)
   - 제품 설정 → 카카오 로그인 → Client Secret 발급
   - 있으면 `wrangler secret put KAKAO_CLIENT_SECRET`으로 설정

---

## 2. Apple 로그인

### Apple Developer
**경로:** [developer.apple.com](https://developer.apple.com) → Certificates, Identifiers & Profiles

1. **Identifiers** → **Services IDs**
   - `com.gomhour.gomawo.web` 선택 (없으면 생성)

2. **Sign in with Apple** → Configure
   - **Domains and Subdomains:** `gom-hr.com`
   - **Return URLs:**
   ```
   https://gom-hr.com/auth/apple/callback
   ```
   - 저장

3. **Keys** (Sign in with Apple용)
   - Key ID, Team ID, Client ID, Private Key가 `wrangler secret`에 설정되어 있는지 확인:
   ```bash
   wrangler secret list
   ```
   - 필요한 시크릿: `APPLE_PRIVATE_KEY` (나머지는 wrangler.toml vars에 있음)

---

## 3. Cloudflare 시크릿 확인

다음 명령으로 시크릿 존재 여부 확인:
```bash
npx wrangler secret list
```

Apple 로그인에 필요한 시크릿:
- `APPLE_PRIVATE_KEY` (필수)

카카오 Client Secret 사용 시:
- `KAKAO_CLIENT_SECRET`

---

## 4. 앱에서 확인할 점

- 앱은 `https://gom-hr.com/app` 으로 진입해야 함
- 로그인 실패 시 화면에 표시되는 **에러 메시지** 확인
- 에러 예:
  - `카카오 로그인이 취소되었습니다` → 사용자가 취소
  - `토큰 교환 실패` → Redirect URI 불일치 또는 Client Secret
  - `Apple 로그인 설정이 필요합니다` → APPLE_* 시크릿/환경변수 누락

---

## 5. 요약

| 서비스 | 확인 항목 |
|--------|-----------|
| 카카오 | Redirect URI `https://gom-hr.com/auth/kakao/callback` 등록 |
| Apple  | Return URL `https://gom-hr.com/auth/apple/callback` 등록, APPLE_PRIVATE_KEY 시크릿 |
| 앱     | `gom-hr.com/app` 진입 후 로그인 |
