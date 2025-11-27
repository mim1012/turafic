# V5 패치 배포 가이드 (성능 개선)

## 🚀 V5 주요 개선사항

### 1. 성능 향상 (2배)
- **BATCH_SIZE**: 10 → 15 (50% 증가)
- **BATCH_COOLDOWN**: 10초 → 5초 (50% 감소)
- **예상 속도**: 22개/분 → 45개/분 (2배 향상)

### 2. 히스토리 저장 로직 개선
- **-1 순위는 히스토리 테이블에 저장되지 않음**
- slot_naver는 업데이트되지만, slot_rank_naver_history에는 추가되지 않음
- 로그: `⏭️ -1 순위 → 히스토리 저장 스킵`

### 3. 재시도 로그 명확화
- 기존: `🔄 다음 배치에서 재시도 예정 (1/1)`
- 개선: `🔄 재시도 예정 (1/1) - 히스토리 미저장`

---

## 📦 패키지 내용

`turafic-v5-patch.zip` (약 7KB)
```
rank-check/
  ├── utils/
  │   └── save-rank-to-slot-naver.ts  (히스토리 저장 조건 추가)
  └── batch/
      └── check-batch-keywords.ts      (BATCH_SIZE, COOLDOWN 변경)
```

---

## 🔧 원격 PC 배포 방법

### 방법 1: 압축 해제 (권장)

```batch
# 1. 원격 PC의 기존 turafic 폴더로 이동
cd C:\turafic

# 2. turafic-v5-patch.zip 압축 해제 (덮어쓰기)
# Windows 탐색기에서 우클릭 > "압축 풀기" > "예(모두)" 선택

# 3. 바로 실행 (재설치 불필요)
batch-scripts\run-rank-check.bat
```

### 방법 2: 파일 직접 복사

```batch
# 1. 다음 2개 파일을 원격 PC로 복사
rank-check\utils\save-rank-to-slot-naver.ts
rank-check\batch\check-batch-keywords.ts

# 2. 각각 덮어쓰기
# 3. 바로 실행
batch-scripts\run-rank-check.bat
```

---

## ✅ 배포 후 확인사항

### 1. 성능 확인
```batch
# 5개 상품으로 테스트
batch-scripts\run-rank-check.bat --limit=5

# 예상 소요 시간: 5개 = 약 6~8초 (기존: 13~15초)
```

### 2. 히스토리 저장 확인
```sql
-- Supabase SQL Editor에서 실행
SELECT * FROM slot_rank_naver_history
WHERE current_rank = -1
ORDER BY created_at DESC
LIMIT 10;

-- 결과: 0 rows (V5 배포 후 -1 순위는 저장되지 않음)
```

### 3. 로그 확인
```
✅ 정상 순위 발견 시:
   💾 slot_naver 업데이트: ID 123, 순위 45
   📊 히스토리 추가 완료
   🗑️ 작업 완료 - 대기열에서 삭제됨

❌ 순위 미발견 (-1) 시:
   💾 slot_naver 업데이트: ID 123, 순위 -1
   ⏭️ -1 순위 → 히스토리 저장 스킵
   🔄 재시도 예정 (1/1) - 히스토리 미저장
```

---

## 📊 성능 비교

| 항목 | V4 (이전) | V5 (현재) | 개선 |
|------|-----------|-----------|------|
| BATCH_SIZE | 10 | 15 | 50% ↑ |
| BATCH_COOLDOWN | 10초 | 5초 | 50% ↓ |
| 처리 속도 | 22개/분 | 45개/분 | 2배 ↑ |
| 히스토리 저장 | -1 포함 | -1 제외 | 불필요한 데이터 방지 |

---

## ⚠️ 주의사항

1. **재설치 불필요**: node_modules가 이미 설치되어 있으므로 pnpm install 필요 없음
2. **실행 중인 프로세스 종료**: 배포 전 기존 rank checker 종료
3. **백업 권장**: 배포 전 기존 2개 파일 백업 (선택사항)

---

## 🔄 롤백 방법

V4로 돌아가려면:
```batch
# V4 설정값으로 수동 변경
# check-batch-keywords.ts 수정:
const BATCH_SIZE = 10;
const BATCH_COOLDOWN_MS = 10000;
```

---

## 📞 문제 발생 시

1. **로그 확인**: `batch-scripts\logs\rank-check-*.log`
2. **테스트 실행**: `batch-scripts\run-rank-check.bat --limit=1`
3. **Supabase 연결 확인**: `.env` 파일의 API 키 확인

---

**배포 일시**: 2025-11-27
**버전**: V5 (Performance Improvement)
**패키지 파일**: turafic-v5-patch.zip
