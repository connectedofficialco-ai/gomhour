# 곰아워 프로젝트 Git 사용법

## 1. 처음 한 번만: Git 초기화

```bash
cd /Users/yeonjikim/Projects/곰아워
git init
git add .
git commit -m "초기 커밋 - 2.11 버전 복구 상태"
```

---

## 2. 평소에: 변경 후 커밋하기

**수정할 때마다** 아래를 실행하세요:

```bash
cd /Users/yeonjikim/Projects/곰아워

# 변경된 파일 확인
git status

# 모든 변경사항 스테이징
git add .

# 커밋 (메시지는 수정 내용으로)
git commit -m "홈페이지 문구 수정"
```

---

## 3. 예전 버전으로 되돌리기

```bash
# 커밋 히스토리 보기
git log --oneline

# 특정 버전으로 되돌리기 (예: abc1234 커밋)
git checkout abc1234 -- index.tsx
```

---

## 4. GitHub에 백업하기 (선택)

1. [GitHub](https://github.com)에서 새 저장소 생성
2. 아래 명령 실행:

```bash
cd /Users/yeonjikim/Projects/곰아워
git remote add origin https://github.com/내아이디/곰아워.git
git branch -M main
git push -u origin main
```

---

## 5. 요약

| 상황 | 명령 |
|------|------|
| 수정 후 저장 | `git add .` → `git commit -m "메시지"` |
| 히스토리 보기 | `git log --oneline` |
| 예전 파일 복구 | `git checkout 커밋ID -- 파일명` |

**커밋을 자주 하면** 나중에 언제든 되돌릴 수 있습니다.
