# 순위 체크 시스템 사용 가이드

## 📋 개요

순위 체크 시스템이 완전히 구현되었습니다. 이제 **Mock 데이터가 아닌 실제 네이버 쇼핑 순위**를 측정할 수 있습니다.

---

## 🚀 설치 및 실행

### 1. 의존성 설치

```bash
pip install -r requirements.txt
```

주요 추가 패키지:
- `apscheduler>=3.10.4` - 백그라운드 스케줄링

### 2. 데이터베이스 마이그레이션

```bash
# SQLite (개발용)
python -c "from server.core.database import init_db; import asyncio; asyncio.run(init_db())"

# PostgreSQL (운영용)
psql -U turafic_user -d turafic -f server/migrations/add_ranking_tables.sql
```

생성되는 테이블:
- `ranking_checks` - 순위 측정 기록
- `ranking_changes` - 순위 변동 분석
- `batch_executions` - 배치 실행 이력

### 3. 서버 실행

```bash
cd D:\Project\Navertrafic
python server/main.py
```

또는 Uvicorn으로:

```bash
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 📡 API 사용 방법

### 1. 순위 체크 요청 (서버가 직접 측정)

**엔드포인트**: `POST /api/v1/ranking/request_check`

**요청**:
```json
{
  "bot_id": "bot-uuid-1234",
  "campaign_id": "campaign-uuid-5678",
  "keyword": "프로틴 쉐이크",
  "max_pages": 10
}
```

**응답**:
```json
{
  "check_id": "check-uuid-abcd",
  "campaign_id": "campaign-uuid-5678",
  "keyword": "프로틴 쉐이크",
  "rank_position": 28,
  "page_number": 2,
  "measured_at": "2025-11-01T12:00:00",
  "message": "순위 측정 완료: 28위"
}
```

**cURL 예시**:
```bash
curl -X POST "http://localhost:8000/api/v1/ranking/request_check" \
  -H "Content-Type: application/json" \
  -d '{
    "bot_id": "bot-001",
    "campaign_id": "camp-001",
    "keyword": "무선 이어폰"
  }'
```

---

### 2. 순위 보고 (봇이 직접 측정하여 보고)

**엔드포인트**: `POST /api/v1/ranking/report`

**요청**:
```json
{
  "bot_id": "bot-uuid-1234",
  "campaign_id": "campaign-uuid-5678",
  "keyword": "프로틴 쉐이크",
  "rank_position": 28,
  "page_number": 2,
  "position_in_page": 8,
  "product_id": "12345678",
  "product_name": "프로틴 쉐이크 초코맛",
  "product_url": "https://shopping.naver.com/...",
  "check_type": "batch_1"
}
```

**응답**:
```json
{
  "check_id": "check-uuid-abcd",
  "campaign_id": "campaign-uuid-5678",
  "keyword": "프로틴 쉐이크",
  "rank_position": 28,
  "page_number": 2,
  "measured_at": "2025-11-01T12:00:00",
  "message": "순위 보고 완료"
}
```

---

### 3. 순위 이력 조회

**엔드포인트**: `GET /api/v1/ranking/campaigns/{campaign_id}/history`

**응답**:
```json
{
  "campaign_id": "campaign-uuid-5678",
  "keyword": "프로틴 쉐이크",
  "baseline_rank": 52,
  "checkpoints": [
    {
      "iteration": 1,
      "check_type": "baseline",
      "rank": 52,
      "page": 3,
      "position": 12,
      "timestamp": "2025-11-01T00:00:00",
      "change": 0,
      "improved": null
    },
    {
      "iteration": 2,
      "check_type": "batch_1",
      "rank": 28,
      "page": 2,
      "position": 8,
      "timestamp": "2025-11-01T12:00:00",
      "change": -24,
      "improved": true
    }
  ],
  "statistics": {
    "total_checks": 2,
    "best_rank": 28,
    "worst_rank": 52,
    "average_rank": 40.0,
    "total_change": -24,
    "improvements": 1,
    "declines": 0
  }
}
```

**cURL 예시**:
```bash
curl "http://localhost:8000/api/v1/ranking/campaigns/camp-001/history"
```

---

### 4. 현재 순위 조회

**엔드포인트**: `GET /api/v1/ranking/campaigns/{campaign_id}/current`

**응답**:
```json
{
  "campaign_id": "campaign-uuid-5678",
  "keyword": "프로틴 쉐이크",
  "current_rank": 28,
  "page": 2,
  "position": 8,
  "last_checked_at": "2025-11-01T12:00:00",
  "measured_by": "bot-001"
}
```

---

### 5. 전체 캠페인 순위 현황

**엔드포인트**: `GET /api/v1/ranking/dashboard/overview`

**응답**:
```json
{
  "campaigns": [
    {
      "campaign_id": "campaign-001",
      "campaign_name": "프로틴 테스트",
      "keyword": "프로틴 쉐이크",
      "baseline_rank": 52,
      "current_rank": 28,
      "change": -24,
      "last_checked": "2025-11-01T12:00:00"
    },
    {
      "campaign_id": "campaign-002",
      "campaign_name": "이어폰 테스트",
      "keyword": "무선 이어폰",
      "baseline_rank": 35,
      "current_rank": 20,
      "change": -15,
      "last_checked": "2025-11-01T11:30:00"
    }
  ]
}
```

---

### 6. ANOVA 분석 (테스트 케이스별 효과)

**엔드포인트**: `GET /api/v1/ranking/analyze`

**응답**:
```json
{
  "total_test_cases": 27,
  "total_samples": 243,
  "test_case_effects": {
    "TC#001": {
      "average_change": -15.3,
      "sample_size": 9,
      "interpretation": "상승"
    },
    "TC#002": {
      "average_change": -8.7,
      "sample_size": 9,
      "interpretation": "상승"
    }
  },
  "best_case": {
    "test_case_id": "TC#217",
    "average_change": -42.0,
    "sample_size": 9
  },
  "worst_case": {
    "test_case_id": "TC#005",
    "average_change": 3.2,
    "sample_size": 9
  }
}
```

---

## 🕐 백그라운드 스케줄링

### APScheduler 사용

서버가 시작되면 자동으로 APScheduler가 실행됩니다.

**수동으로 순위 체크 작업 추가**:

```python
from server.core.background_tasks import add_ranking_check_job

# 12시간마다 순위 체크
add_ranking_check_job(
    job_id="rank_check_protein",
    keyword="프로틴 쉐이크",
    interval_hours=12,
    campaign_id="campaign-001"
)
```

**작업 제거**:

```python
from server.core.background_tasks import remove_ranking_check_job

remove_ranking_check_job("rank_check_protein")
```

**모든 작업 조회**:

```python
from server.core.background_tasks import list_all_jobs

jobs = list_all_jobs()
print(jobs)
```

---

## 🧪 테스트 시나리오

### 시나리오 1: 즉시 순위 체크

```bash
# 1. 서버 시작
python server/main.py

# 2. 순위 체크 요청
curl -X POST "http://localhost:8000/api/v1/ranking/request_check" \
  -H "Content-Type: application/json" \
  -d '{
    "bot_id": "test-bot-001",
    "campaign_id": "test-campaign-001",
    "keyword": "무선 이어폰",
    "max_pages": 5
  }'

# 3. 결과 확인
curl "http://localhost:8000/api/v1/ranking/campaigns/test-campaign-001/current"
```

### 시나리오 2: 순위 변동 추적

```bash
# 1. Baseline 순위 측정
curl -X POST "http://localhost:8000/api/v1/ranking/report" \
  -H "Content-Type: application/json" \
  -d '{
    "bot_id": "bot-001",
    "campaign_id": "campaign-001",
    "keyword": "프로틴 쉐이크",
    "rank_position": 52,
    "page_number": 3,
    "position_in_page": 12,
    "check_type": "baseline"
  }'

# 2. 12시간 후 재측정
curl -X POST "http://localhost:8000/api/v1/ranking/report" \
  -H "Content-Type: application/json" \
  -d '{
    "bot_id": "bot-001",
    "campaign_id": "campaign-001",
    "keyword": "프로틴 쉐이크",
    "rank_position": 28,
    "page_number": 2,
    "position_in_page": 8,
    "check_type": "batch_1"
  }'

# 3. 순위 변동 확인
curl "http://localhost:8000/api/v1/ranking/campaigns/campaign-001/history"
```

---

## 📊 데이터베이스 쿼리 예시

### 순위 이력 조회

```sql
SELECT
    check_type,
    rank_position,
    page_number,
    position_in_page,
    measured_at
FROM ranking_checks
WHERE campaign_id = 'campaign-001'
ORDER BY measured_at;
```

### 순위 변동 분석

```sql
SELECT
    test_case_id,
    AVG(rank_change) AS avg_change,
    COUNT(*) AS sample_size
FROM ranking_changes
WHERE campaign_id = 'campaign-001'
GROUP BY test_case_id
ORDER BY avg_change ASC;
```

### 최고 순위 케이스 찾기

```sql
SELECT
    test_case_id,
    MIN(after_rank) AS best_rank
FROM ranking_changes
GROUP BY test_case_id
ORDER BY best_rank ASC
LIMIT 10;
```

---

## 🛠️ 문제 해결

### 1. 순위를 찾지 못함

**증상**: `상품을 N페이지 내에서 찾지 못했습니다.`

**해결**:
- `max_pages` 값을 늘리기 (최대 10페이지 = 200위)
- `product_id`를 함께 제공하여 정확도 향상
- 키워드가 정확한지 확인

### 2. 광고가 순위에 포함됨

**증상**: 순위가 예상보다 높게 측정됨

**해결**:
- `RankChecker._is_advertisement()` 함수가 8가지 패턴으로 광고 감지
- 네이버 쇼핑 HTML 구조 변경 시 패턴 업데이트 필요

### 3. DB 저장 실패

**증상**: 순위는 측정되지만 DB에 저장 안됨

**해결**:
```bash
# 마이그레이션 재실행
psql -U turafic_user -d turafic -f server/migrations/add_ranking_tables.sql

# 테이블 확인
psql -U turafic_user -d turafic -c "\dt"
```

---

## 🎯 다음 단계

1. **봇 에이전트 연동**: Android APK에서 순위 체크 명령 수신 및 보고
2. **실시간 대시보드**: 웹 UI에서 순위 그래프 표시
3. **알림 시스템**: 순위 급상승/급하락 시 알림
4. **고급 ANOVA**: scipy를 사용한 통계적 유의성 검증

---

## 📚 참고 자료

- **API 문서**: http://localhost:8000/docs
- **데이터베이스 스키마**: `server/migrations/add_ranking_tables.sql`
- **순위 체크 로직**: `src/ranking/checker.py`
- **스케줄러 로직**: `server/core/ranking_scheduler.py`

---

**생성일**: 2025-11-01
**버전**: 1.0.0
**상태**: ✅ 완성
