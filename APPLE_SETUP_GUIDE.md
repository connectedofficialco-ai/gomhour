# Apple Developer & App Store Connect 설정 가이드

gom-hr.com 도메인으로 변경 시 필요한 설정 방법입니다.

---

## 1. Apple Developer – Return URL (Sign in with Apple)

**경로:** developer.apple.com → Certificates, Identifiers & Profiles

1. 왼쪽 메뉴에서 **Identifiers** 클릭
2. 상단 **+** 버튼 클릭 → **Services IDs** 선택 (오른쪽 상단 팝업에서)
3. 기존 **com.gomhour.gomawo.web** 선택
   - 없다면 Services ID 생성 후 아래 진행
4. **Sign in with Apple** 체크 → **Configure** 클릭
5. **Primary App ID** 선택 (앱과 연결할 App ID)
6. **Website URLs** 항목에 아래 입력 (쉼표로 구분 가능):
   ```
   https://gom-hr.com/auth/apple/callback
   ```
7. **Done** 클릭
8. **Continue** → **Save** 클릭

> 💡 예전 `workers.dev` URL이 있으면 삭제하고 위 URL만 남기세요.

---

## 2. App Store Connect – Support URL

**경로:** appstoreconnect.apple.com → 내 앱 → 곰아워

1. 앱 선택 후 왼쪽 메뉴에서 **앱** (App) 클릭
2. **iOS** (또는 해당 플랫폼) 아래 **버전** 선택 (예: 1.0)
3. 스크롤하여 **지원 URL** (Support URL) 필드 찾기
   - 설명, 키워드, 마케팅 URL 근처에 있음
4. **지원 URL** 필드에 입력:
   ```
   https://gom-hr.com/support
   ```

> ⚠️ Support URL은 **버전별**로 설정됩니다. 새 버전을 제출할 때 확인하세요.

---

## 3. App Store Connect – Privacy Policy URL

**경로:** appstoreconnect.apple.com

1. **앱** (Apps) 메뉴 클릭
2. **곰아워** 앱 선택
3. 왼쪽 사이드바에서 **일반** (General) 섹션 펼치기
4. **일반** 아래에 있는 **앱 정보** (App Information) 클릭
   - 앱 이름, 번들 ID, SKU 등이 있는 페이지로 이동
5. 페이지를 스크롤하여 **개인정보처리방침 URL** (Privacy Policy URL) 필드 찾기
6. 아래 URL 입력:
   ```
   https://gom-hr.com/privacy.html
   ```
7. 우측 상단 **저장** (Save) 클릭

> 💡 **찾기 어렵다면:** 앱 선택 → 왼쪽 사이드바 맨 아래쪽 **일반** → **앱 정보** 순서로 확인하세요.

---

## 요약

| 항목 | 위치 | URL |
|------|------|-----|
| Return URL | Apple Developer → Identifiers → Services ID → Sign in with Apple → Configure | https://gom-hr.com/auth/apple/callback |
| Support URL | App Store Connect → 앱 → iOS 버전 → 앱 정보 | https://gom-hr.com/support |
| Privacy URL | App Store Connect → 앱 정보 (App Information) | https://gom-hr.com/privacy.html |
