# 앱 Legacy 분리 설정 가이드

gom-hr.com 웹사이트는 그대로 두고, **앱(/app)** 만 별도 Worker(gomhour-legacy)에서 서빙하도록 구성했습니다.

## 구조

| Worker | 담당 경로 | 설명 |
|--------|-----------|------|
| **gomhour** (Main) | `/`, `/support`, `/privacy` | 홈페이지, 고객지원, 개인정보처리방침 |
| **gomhour-legacy** | `/app*`, `/dashboard`, `/setup`, `/history`, `/settings`, `/auth*`, `/api*`, `/signup`, `/logout` | 앱 전용 (2.11 버전용) |

## 배포 방법

### 1. Legacy Worker 배포

```bash
cd /Users/yeonjikim/Projects/곰아워
npx wrangler deploy -c wrangler-legacy.toml
```

### 2. Main Worker 배포 (변경 없음)

```bash
npx wrangler deploy
```

## 2.11 버전 코드로 교체하기

현재 Legacy Worker는 **Main과 동일한 코드**를 사용합니다. 2.11 버전으로 되돌리려면:

1. **Time Machine**으로 프로젝트 폴더를 2월 11일 시점으로 복원
2. 복원된 `index.tsx`를 `index-legacy.tsx`로 복사
3. `wrangler-legacy.toml`에서 `main = "index-legacy.tsx"` 로 변경
4. `npx wrangler deploy -c wrangler-legacy.toml` 실행

또는 2.11 시점의 `index.tsx`만 복구했다면:

```toml
# wrangler-legacy.toml
main = "index-legacy.tsx"  # 2.11 버전 코드
```

## Cloudflare 라우팅

- `wrangler-legacy.toml`에 `zone_name = "gom-hr.com"` 사용
- gom-hr.com이 Cloudflare에 등록된 zone이어야 함
- 더 구체적인 경로(`/app*` 등)가 Main Worker의 custom domain보다 우선 적용됨

## 시크릿 공유

Legacy Worker는 Main과 **같은 D1 DB, 같은 시크릿**을 사용합니다.  
Main에 설정한 `APPLE_PRIVATE_KEY`, `APNS_PRIVATE_KEY` 등은 **별도 설정 없이** Legacy에서도 사용됩니다.  
(Wrangler는 같은 계정의 시크릿을 Worker 이름별로 관리)

**주의:** Legacy Worker를 처음 배포할 때, Main에 설정된 시크릿이 Legacy에도 필요하면:

```bash
npx wrangler secret list  # Main 시크릿 확인
# Legacy용으로 동일 시크릿 설정 (같은 값 사용)
npx wrangler secret put APPLE_PRIVATE_KEY -c wrangler-legacy.toml
npx wrangler secret put APNS_PRIVATE_KEY -c wrangler-legacy.toml
```
