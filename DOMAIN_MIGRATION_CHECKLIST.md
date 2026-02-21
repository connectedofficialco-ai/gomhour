# gom-hr.com 도메인 전환 체크리스트

도메인이 gom-hr.com으로 바뀌었을 때 확인할 사항입니다.

---

## ✅ 이미 완료된 것 (코드 기준)

- [x] wrangler.toml - KAKAO_REDIRECT_URI, APPLE_REDIRECT_URI → gom-hr.com
- [x] Flutter config.dart - baseUrl → https://gom-hr.com
- [x] 홈페이지, 로그인, 고객지원 모두 gom-hr.com에서 제공

---

## 🔧 해야 할 것

### 1. 배포

```bash
cd /Users/yeonjikim/Projects/곰아워
npx wrangler deploy
```

배포 후 https://gom-hr.com, https://gom-hr.com/support 에 접속해 동작 확인.

---

### 2. 카카오 개발자 콘솔

- [developers.kakao.com](https://developers.kakao.com) → 앱 선택
- **플랫폼** → **Web**
- Redirect URI에 추가/수정:
  ```
  https://gom-hr.com/auth/kakao/callback
  ```
- 예전 `workers.dev` URI가 있으면 삭제

---

### 3. Apple Developer

- [developer.apple.com](https://developer.apple.com) → Certificates, Identifiers & Profiles
- **Identifiers** → `com.gomhour.gomawo.web` (Sign In with Apple용)
- **Sign In with Apple** → **Configure**
- Return URLs에 추가/수정:
  ```
  https://gom-hr.com/auth/apple/callback
  ```
- 예전 `workers.dev` URI가 있으면 삭제

---

### 4. App Store Connect

- [appstoreconnect.apple.com](https://appstoreconnect.apple.com) → 앱 선택
- **앱 정보** (App Information) → **지원 URL**:
  ```
  https://gom-hr.com/support
  ```
- **개인정보처리방침 URL**:
  ```
  https://gom-hr.com/privacy.html
  ```
- (선택) **마케팅 URL**:
  ```
  https://gom-hr.com
  ```

---

### 5. Flutter 앱 새 버전 출시

- config.dart는 이미 gom-hr.com 사용 중
- iOS 앱 빌드 후 App Store Connect에 새 버전 제출
- 기존 사용자는 업데이트 후 gom-hr.com 기반 서비스 사용

---

## 📋 URL 정리

| 용도 | URL |
|------|-----|
| 홈페이지 | https://gom-hr.com |
| 로그인 | https://gom-hr.com/login |
| 고객지원 | https://gom-hr.com/support |
| 회원가입 | https://gom-hr.com/signup |
| 개인정보처리방침 | https://gom-hr.com/privacy.html |
| 카카오 콜백 | https://gom-hr.com/auth/kakao/callback |
| Apple 콜백 | https://gom-hr.com/auth/apple/callback |

---

## ⚠️ 참고

- 고객지원 사이트는 별도가 아니라 **gom-hr.com/support** 에 포함됩니다.
- 배포만 하면 홈, 로그인, 고객지원이 모두 gom-hr.com에서 동작합니다.
