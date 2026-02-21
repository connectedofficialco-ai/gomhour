# gom-hr.com 도메인 설정 가이드

GoDaddy에서 구매한 gom-hr.com을 Cloudflare Workers에 연결하는 방법입니다.

---

## 1단계: Cloudflare에 도메인 추가

1. [Cloudflare 대시보드](https://dash.cloudflare.com) 로그인
2. **"웹사이트 추가"** 또는 **"Add a site"** 클릭
3. `gom-hr.com` 입력 후 **"사이트 추가"** 클릭
4. 요금제 선택 → **Free 플랜** 선택
5. Cloudflare가 DNS 레코드를 스캔함 → **"계속"** 클릭
6. **네임서버 정보 확인** – 예:
   ```
   예시:
   ns1.cloudflare.com
   ns2.cloudflare.com
   ```
   이 네임서버 주소를 메모해 두세요 (다음 단계에서 사용)

---

## 2단계: GoDaddy 네임서버 변경

1. [GoDaddy](https://www.godaddy.com) 로그인
2. **내 제품** → **gom-hr.com** → **관리** 클릭
3. **도메인** 섹션에서 **"네임서버 관리"** 또는 **"Nameservers"** 클릭
4. **"변경"** 선택
5. **"사용자 정의"** 또는 **"Custom"** 선택
6. Cloudflare에서 받은 네임서버 2개 입력:
   - `ns1.cloudflare.com`
   - `ns2.cloudflare.com`
7. **저장** 클릭
8. **전파 대기** – 보통 5분~48시간 (보통 1–2시간 이내)

> 💡 전파 확인: [https://dnschecker.org](https://dnschecker.org) 에서 gom-hr.com 검색

---

## 3단계: Cloudflare에서 도메인 활성화 확인

1. Cloudflare 대시보드로 돌아가기
2. gom-hr.com이 **"활성"** 상태가 될 때까지 대기 (초록색 체크)
3. 상태가 활성이면 4단계로 진행

---

## 4단계: Worker에 커스텀 도메인 연결

> ⚠️ **반드시 1~3단계 완료 후** 진행하세요. (gom-hr.com이 Cloudflare에 "활성" 상태여야 함)

**방법 A: Cloudflare 대시보드에서**

1. Cloudflare → **Workers & Pages** → **gomhour** Worker 선택
2. **Settings** → **Domains & Routes**
3. **Add** → **Custom Domain**
4. `gom-hr.com` 입력 후 추가
5. (선택) `www.gom-hr.com`도 추가

**방법 B: wrangler.toml 사용** (권장, 이미 설정됨)

- 프로젝트의 `wrangler.toml`에 routes가 이미 추가되어 있음
- 5단계에서 `npx wrangler deploy` 실행 시 자동 적용

---

## 5단계: 프로젝트 설정 업데이트 후 배포

1. **카카오 개발자 콘솔** 업데이트
   - [developers.kakao.com](https://developers.kakao.com) → 앱 선택
   - **플랫폼** → **Web** → Redirect URI에 추가:
     ```
     https://gom-hr.com/auth/kakao/callback
     ```

2. **Apple Developer** 업데이트
   - [developer.apple.com](https://developer.apple.com) → Certificates, Identifiers & Profiles
   - **Identifiers** → `com.gomhour.gomawo.web` 선택
   - **Sign In with Apple** → **Configure** → Return URLs에 추가:
     ```
     https://gom-hr.com/auth/apple/callback
     ```

3. **배포 실행**
   ```bash
   cd /Users/yeonjikim/Projects/곰아워
   npx wrangler deploy
   ```

4. **Flutter 앱 빌드 & App Store 제출**
   - config.dart가 이미 gom-hr.com으로 업데이트됨
   - 앱을 다시 빌드하고 App Store Connect에 새 버전 제출

5. **App Store Connect** 업데이트
   - Support URL: `https://gom-hr.com/support`
   - Privacy Policy URL: `https://gom-hr.com/privacy.html`

---

## 완료 확인

- https://gom-hr.com → 로그인 페이지 표시
- https://gom-hr.com/support → 고객지원 페이지 표시
- 카카오/애플 로그인 동작 확인

---

## 문제 해결

**"사이트에 연결할 수 없음"**
- 네임서버 전파 대기 (최대 48시간)
- Cloudflare에서 도메인 상태가 "활성"인지 확인

**OAuth 로그인 실패**
- 카카오/Apple 개발자 콘솔에 새 Redirect URI가 등록되었는지 확인
- wrangler.toml의 KAKAO_REDIRECT_URI, APPLE_REDIRECT_URI 확인
