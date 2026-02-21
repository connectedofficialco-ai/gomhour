# 곰아워 Flutter 앱

이 프로젝트는 기존 Hono/Cloudflare 웹앱을 iOS 시뮬레이터에서 바로 실행할 수 있도록 **WebView 래퍼**로 구성했습니다.

## 실행 절차 (iOS 시뮬레이터)

1) Flutter SDK 설치 및 환경 설정
2) 이 디렉터리에서 플랫폼 파일 생성

```
flutter create .
```

3) 의존성 설치

```
flutter pub get
```

4) iOS 실행

```
flutter run -d "iPhone 15"
```

## 로컬 서버 주소

기본 주소는 `http://127.0.0.1:8787` 입니다.  
다른 주소로 실행하려면 아래처럼 `--dart-define`으로 설정하세요.

```
flutter run -d "iPhone 15" --dart-define=BASE_URL=http://127.0.0.1:8787
```
