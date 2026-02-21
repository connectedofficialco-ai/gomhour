# 곰아워 앱 컨텍스트

> AI에게 앱 구조를 전달할 때 이 파일을 `@CONTEXT.md` 로 첨부하세요.

## 프로젝트 개요

- **앱 이름**: 곰아워 (커플 관계 관리 앱)
- **배포**: App Store 심사 제출 완료 (Xcode로 빌드)
- **구성**: Flutter WebView 앱 + Cloudflare Workers 백엔드

## 구조

```
곰아워/
├── flutter_app/          # iOS 앱 (WebView 래퍼)
│   ├── lib/
│   │   ├── main.dart
│   │   ├── config.dart       # baseUrl: https://gom-hr.com/app
│   │   ├── screens/web_app_screen.dart  # WebView + APNS 푸시 등록
│   │   └── widgets/loading_overlay.dart
│   └── ios/                  # Xcode 프로젝트
├── index.tsx             # Hono 라우트, 홈/앱/API
├── renderer.tsx          # HTML 렌더링
├── routes/kakao.ts       # 카카오 로그인
├── public/privacy.html   # 개인정보처리방침
└── wrangler.toml         # Cloudflare 설정
```

## 주요 URL

| 경로 | 설명 |
|------|------|
| `gom-hr.com`, `www.gom-hr.com` | 홈페이지 (서비스 소개) |
| `gom-hr.com/app` | 앱 진입점 (로그인 후 대시보드) |
| `gom-hr.com/privacy` | 개인정보처리방침 |
| `gom-hr.com/support` | 고객지원 |
| `gom-hr.com/auth/kakao/callback` | 카카오 로그인 콜백 |
| `gom-hr.com/auth/apple/callback` | Apple 로그인 콜백 |

## 로그인

- **카카오**: Redirect URI `https://gom-hr.com/auth/kakao/callback`
- **Apple**: Return URL `https://gom-hr.com/auth/apple/callback`, `domain: gom-hr.com` (apex·www 공유)
- 쿠키 `domain: 'gom-hr.com'` 으로 apex·www 공유

## Flutter 앱 (iOS)

- WebView로 `https://gom-hr.com/app` 로드
- APNS 토큰을 `/api/push/register` 로 전송 (대시보드/설정 등 진입 시)
- MethodChannel `apns` 로 네이티브 푸시 토큰 요청

## 참고 문서

- `LOGIN_SETUP.md` - 로그인 설정 점검
- `APPLE_SETUP_GUIDE.md` - Apple 로그인 설정
- `flutter_app/README.md` - Flutter 실행 방법
