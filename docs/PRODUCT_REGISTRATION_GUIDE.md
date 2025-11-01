# Product Registration Guide

## 목차

1. [개요](#개요)
2. [빠른 시작](#빠른-시작)
3. [API 상세 가이드](#api-상세-가이드)
4. [워크플로우 예시](#워크플로우-예시)
5. [Best Practices](#best-practices)
6. [트러블슈팅](#트러블슈팅)

---

## 개요

### 목적

Turafic Product Management System을 통해 네이버 쇼핑의 임의 상품을 시스템에 등록하고, 해당 상품을 대상으로:
- 트래픽 생성 (봇 작업)
- 순위 추적 (Rank Checker)
- 캠페인 연동 (Campaign Management)

을 수행할 수 있습니다.

### 핵심 5가지 파라미터

| 파라미터 | 설명 | 예시 |
|---------|------|------|
| **keyword** | 검색 키워드 | "프로틴 쉐이크 초코" |
| **naver_product_id** | 네이버 상품 고유 ID | "1234567890" |
| **product_name** | 상품 표시명 | "머슬밀 단백질 쉐이크 초코맛 20팩" |
| **product_url** | 상품 전체 URL | "https://smartstore.naver.com/musclemeal/products/1234567890" |
| **campaign_id** | 연동할 캠페인 ID (선택) | "camp-uuid-5678" |

---

## 빠른 시작

### 1. 상품 등록 (최소 정보)

```bash
curl -X POST http://localhost:8000/api/v1/products \
  -H "Content-Type: application/json" \
  -d '{
    "keyword": "프로틴 쉐이크 초코",
    "naver_product_id": "1234567890",
    "product_name": "머슬밀 단백질 쉐이크 초코맛 20팩",
    "product_url": "https://smartstore.naver.com/musclemeal/products/1234567890"
  }'
```

**응답 예시**:
```json
{
  "product_id": "prod-abc-123",
  "message": "Product created successfully",
  "next_steps": [
    "Create campaign: POST /api/v1/campaigns (with product_id=prod-abc-123)",
    "Check rank: POST /api/v1/products/prod-abc-123/rank",
    "View product: GET /api/v1/products/prod-abc-123"
  ]
}
```

### 2. 캠페인 생성 및 상품 연동

```bash
curl -X POST http://localhost:8000/api/v1/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "프로틴 쉐이크 100회 트래픽",
    "target_keyword": "프로틴 쉐이크 초코",
    "target_traffic": 100,
    "product_id": "prod-abc-123"
  }'
```

**응답 예시**:
```json
{
  "campaign_id": "camp-uuid-5678",
  "name": "프로틴 쉐이크 100회 트래픽",
  "target_keyword": "프로틴 쉐이크 초코",
  "target_traffic": 100,
  "current_traffic_count": 0,
  "status": "active",
  "product_id": "prod-abc-123",
  "product_name": "머슬밀 단백질 쉐이크 초코맛 20팩",
  "created_at": "2025-11-02T10:30:00"
}
```

### 3. 순위 업데이트

```bash
curl -X POST http://localhost:8000/api/v1/products/prod-abc-123/rank \
  -H "Content-Type: application/json" \
  -d '{
    "rank": 45,
    "page": 3,
    "position": 5,
    "checked_by": "bot-rank-checker-001",
    "campaign_id": "camp-uuid-5678"
  }'
```

**응답 예시**:
```json
{
  "message": "Rank updated successfully",
  "current_rank": 45,
  "initial_rank": 45,
  "rank_improvement": 0,
  "best_rank": 45,
  "worst_rank": 45
}
```

---

## API 상세 가이드

### 1. 상품 등록 (POST /api/v1/products)

#### 요청 본문

```json
{
  // 필수 필드
  "keyword": "검색 키워드",
  "naver_product_id": "네이버 상품 ID (고유)",
  "product_name": "상품명",
  "product_url": "전체 URL",

  // 선택 필드 (메타데이터)
  "category": "건강식품",
  "brand": "머슬밀",
  "price": 35000,
  "original_price": 50000,
  "discount_rate": 30,
  "notes": "Phase 1 테스트용 상품"
}
```

#### 응답 (201 Created)

```json
{
  "product_id": "uuid-generated",
  "message": "Product created successfully",
  "next_steps": [
    "Create campaign: POST /api/v1/campaigns (with product_id=...)",
    "Check rank: POST /api/v1/products/{product_id}/rank",
    "View product: GET /api/v1/products/{product_id}"
  ]
}
```

#### 에러 응답 (400 Bad Request)

```json
{
  "detail": "Product with naver_product_id '1234567890' already exists"
}
```

---

### 2. 상품 조회 (GET /api/v1/products/{product_id})

#### 요청 예시

```bash
curl http://localhost:8000/api/v1/products/prod-abc-123
```

#### 응답 예시

```json
{
  "product_id": "prod-abc-123",
  "keyword": "프로틴 쉐이크 초코",
  "naver_product_id": "1234567890",
  "product_name": "머슬밀 단백질 쉐이크 초코맛 20팩",
  "product_url": "https://smartstore.naver.com/musclemeal/products/1234567890",
  "category": "건강식품",
  "brand": "머슬밀",
  "price": 35000,
  "current_rank": 45,
  "initial_rank": 52,
  "rank_improvement": -7,
  "status": "active",
  "is_target": true,
  "total_traffic_count": 250,
  "total_rank_checks": 12,
  "created_at": "2025-11-01T10:00:00",
  "updated_at": "2025-11-02T14:30:00",
  "last_rank_check_at": "2025-11-02T14:30:00",
  "notes": "Phase 1 테스트용 상품"
}
```

---

### 3. 상품 목록 조회 (GET /api/v1/products)

#### 쿼리 파라미터

| 파라미터 | 타입 | 설명 | 기본값 |
|---------|------|------|--------|
| `status` | string | 상태 필터 (active, inactive, testing, completed) | 없음 |
| `keyword` | string | 키워드 부분 매칭 | 없음 |
| `is_target` | boolean | 타겟 상품 여부 | 없음 |
| `limit` | int | 페이지 크기 (1-200) | 50 |
| `offset` | int | 오프셋 | 0 |

#### 요청 예시

```bash
# 활성 상품만 조회
curl "http://localhost:8000/api/v1/products?status=active&limit=10"

# 키워드로 검색
curl "http://localhost:8000/api/v1/products?keyword=프로틴"

# 타겟 상품만 조회
curl "http://localhost:8000/api/v1/products?is_target=true"
```

#### 응답 예시

```json
{
  "total": 15,
  "limit": 10,
  "offset": 0,
  "products": [
    {
      "product_id": "prod-abc-123",
      "keyword": "프로틴 쉐이크 초코",
      "naver_product_id": "1234567890",
      "product_name": "머슬밀 단백질 쉐이크 초코맛 20팩",
      "product_url": "https://smartstore.naver.com/musclemeal/products/1234567890",
      "category": "건강식품",
      "brand": "머슬밀",
      "price": 35000,
      "current_rank": 45,
      "initial_rank": 52,
      "rank_improvement": -7,
      "status": "active",
      "is_target": true,
      "total_traffic_count": 250,
      "total_rank_checks": 12,
      "created_at": "2025-11-01T10:00:00"
    }
    // ... 9 more products
  ]
}
```

---

### 4. 상품 정보 수정 (PATCH /api/v1/products/{product_id})

#### 요청 본문 (모든 필드 선택)

```json
{
  "keyword": "새 키워드",
  "product_name": "변경된 상품명",
  "product_url": "새 URL",
  "category": "새 카테고리",
  "brand": "새 브랜드",
  "price": 40000,
  "status": "testing",
  "is_target": false,
  "notes": "업데이트된 메모"
}
```

#### 요청 예시

```bash
curl -X PATCH http://localhost:8000/api/v1/products/prod-abc-123 \
  -H "Content-Type: application/json" \
  -d '{
    "price": 32000,
    "notes": "할인 이벤트 진행 중"
  }'
```

#### 응답 (200 OK)

```json
{
  "message": "Product updated successfully"
}
```

---

### 5. 상품 삭제 (소프트 삭제) (DELETE /api/v1/products/{product_id})

**주의**: 실제로 데이터를 삭제하지 않고 `status`를 `inactive`로 변경합니다.

#### 요청 예시

```bash
curl -X DELETE http://localhost:8000/api/v1/products/prod-abc-123
```

#### 응답 (200 OK)

```json
{
  "message": "Product deactivated successfully"
}
```

---

### 6. 순위 업데이트 (POST /api/v1/products/{product_id}/rank)

#### 순위 계산 공식

```
전체 순위 = (페이지 - 1) × 20 + 페이지 내 위치

예시:
- 3페이지 5번째 → (3-1) × 20 + 5 = 45위
- 1페이지 1번째 → (1-1) × 20 + 1 = 1위
```

#### 요청 본문

```json
{
  "rank": 45,
  "page": 3,
  "position": 5,
  "checked_by": "bot-rank-checker-001",  // 선택
  "campaign_id": "camp-uuid-5678"        // 선택
}
```

#### 요청 예시

```bash
curl -X POST http://localhost:8000/api/v1/products/prod-abc-123/rank \
  -H "Content-Type: application/json" \
  -d '{
    "rank": 28,
    "page": 2,
    "position": 8,
    "checked_by": "bot-rank-checker-002"
  }'
```

#### 응답 예시

```json
{
  "message": "Rank updated successfully",
  "current_rank": 28,
  "initial_rank": 52,
  "rank_improvement": -24,
  "best_rank": 28,
  "worst_rank": 52
}
```

**주의**: `rank_improvement`는 음수가 순위 상승을 의미합니다.

---

### 7. 순위 히스토리 조회 (GET /api/v1/products/{product_id}/rank/history)

#### 쿼리 파라미터

| 파라미터 | 타입 | 설명 | 기본값 |
|---------|------|------|--------|
| `days` | int | 조회 기간 (1-90) | 7 |

#### 요청 예시

```bash
# 최근 7일 히스토리
curl "http://localhost:8000/api/v1/products/prod-abc-123/rank/history"

# 최근 30일 히스토리
curl "http://localhost:8000/api/v1/products/prod-abc-123/rank/history?days=30"
```

#### 응답 예시

```json
{
  "product_id": "prod-abc-123",
  "trend": [
    {
      "check_date": "2025-11-02",
      "avg_rank": 28.5,
      "min_rank": 25,
      "max_rank": 32,
      "check_count": 4
    },
    {
      "check_date": "2025-11-01",
      "avg_rank": 45.2,
      "min_rank": 42,
      "max_rank": 48,
      "check_count": 5
    }
  ],
  "history": [
    {
      "id": 123,
      "product_id": "prod-abc-123",
      "rank": 28,
      "page": 2,
      "position": 8,
      "keyword": "프로틴 쉐이크 초코",
      "checked_by": "bot-rank-checker-002",
      "campaign_id": "camp-uuid-5678",
      "checked_at": "2025-11-02T14:30:00"
    }
    // ... more history records
  ]
}
```

---

### 8. 상품 통계 조회 (GET /api/v1/products/{product_id}/stats)

#### 요청 예시

```bash
curl http://localhost:8000/api/v1/products/prod-abc-123/stats
```

#### 응답 예시

```json
{
  "product_id": "prod-abc-123",
  "product_name": "머슬밀 단백질 쉐이크 초코맛 20팩",
  "keyword": "프로틴 쉐이크 초코",
  "current_rank": 28,
  "initial_rank": 52,
  "rank_improvement": -24,
  "status": "active",
  "total_campaigns": 3,
  "active_campaigns": 2,
  "total_traffic_generated": 450,
  "successful_tasks": 432,
  "total_rank_checks": 18,
  "best_rank_ever": 25,
  "worst_rank_ever": 52,
  "last_rank_check_at": "2025-11-02T14:30:00"
}
```

---

### 9. 전체 상품 요약 통계 (GET /api/v1/products/stats/summary)

#### 요청 예시

```bash
curl http://localhost:8000/api/v1/products/stats/summary
```

#### 응답 예시

```json
{
  "total_products": 25,
  "active_products": 20,
  "target_products": 15,
  "total_traffic": 12500,
  "total_rank_checks": 450,
  "avg_current_rank": 38.5,
  "products_improved": 18
}
```

---

## 워크플로우 예시

### 시나리오 1: 신규 상품 등록 → 캠페인 생성 → 트래픽 발생 → 순위 추적

#### Step 1: 상품 등록

```bash
curl -X POST http://localhost:8000/api/v1/products \
  -H "Content-Type: application/json" \
  -d '{
    "keyword": "무선 이어폰",
    "naver_product_id": "9876543210",
    "product_name": "갤럭시 버즈2 프로 블랙",
    "product_url": "https://smartstore.naver.com/samsung/products/9876543210",
    "category": "이어폰",
    "brand": "삼성",
    "price": 189000
  }'
```

**응답**: `product_id = "prod-xyz-789"`

#### Step 2: 초기 순위 측정

```bash
curl -X POST http://localhost:8000/api/v1/products/prod-xyz-789/rank \
  -H "Content-Type: application/json" \
  -d '{
    "rank": 82,
    "page": 5,
    "position": 2,
    "checked_by": "bot-rank-checker-001"
  }'
```

**응답**:
```json
{
  "current_rank": 82,
  "initial_rank": 82,
  "rank_improvement": 0
}
```

#### Step 3: 캠페인 생성 (상품 연동)

```bash
curl -X POST http://localhost:8000/api/v1/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "갤럭시 버즈2 트래픽 테스트",
    "target_keyword": "무선 이어폰",
    "target_traffic": 100,
    "product_id": "prod-xyz-789"
  }'
```

**응답**: `campaign_id = "camp-def-456"`

#### Step 4: 봇 작업 대기 (자동)

봇들이 `/api/v1/tasks/get_task`를 호출하여 작업을 받아 실행합니다.

#### Step 5: 12시간 후 순위 재측정

```bash
curl -X POST http://localhost:8000/api/v1/products/prod-xyz-789/rank \
  -H "Content-Type: application/json" \
  -d '{
    "rank": 55,
    "page": 3,
    "position": 15,
    "checked_by": "bot-rank-checker-001",
    "campaign_id": "camp-def-456"
  }'
```

**응답**:
```json
{
  "current_rank": 55,
  "initial_rank": 82,
  "rank_improvement": -27,
  "best_rank": 55,
  "worst_rank": 82
}
```

**결과**: 82위 → 55위 (27위 상승!)

#### Step 6: 순위 히스토리 확인

```bash
curl "http://localhost:8000/api/v1/products/prod-xyz-789/rank/history?days=1"
```

---

### 시나리오 2: 여러 상품에 대한 A/B 테스트

#### Step 1: 3개 상품 등록

```bash
# 상품 A
curl -X POST http://localhost:8000/api/v1/products \
  -H "Content-Type: application/json" \
  -d '{
    "keyword": "노트북 가방",
    "naver_product_id": "5555555555",
    "product_name": "맥북 15인치 파우치 가방",
    "product_url": "https://smartstore.naver.com/bags/products/5555555555"
  }'
# → product_id = "prod-aaa-111"

# 상품 B
curl -X POST http://localhost:8000/api/v1/products \
  -H "Content-Type: application/json" \
  -d '{
    "keyword": "노트북 가방",
    "naver_product_id": "6666666666",
    "product_name": "LG그램 17인치 노트북 가방",
    "product_url": "https://smartstore.naver.com/bags/products/6666666666"
  }'
# → product_id = "prod-bbb-222"

# 상품 C (대조군 - 트래픽 없음)
curl -X POST http://localhost:8000/api/v1/products \
  -H "Content-Type: application/json" \
  -d '{
    "keyword": "노트북 가방",
    "naver_product_id": "7777777777",
    "product_name": "삼성 갤럭시북 가방",
    "product_url": "https://smartstore.naver.com/bags/products/7777777777",
    "is_target": false
  }'
# → product_id = "prod-ccc-333"
```

#### Step 2: 초기 순위 측정 (3개 모두)

```bash
# 상품 A: 120위
curl -X POST http://localhost:8000/api/v1/products/prod-aaa-111/rank \
  -d '{"rank": 120, "page": 6, "position": 20}'

# 상품 B: 115위
curl -X POST http://localhost:8000/api/v1/products/prod-bbb-222/rank \
  -d '{"rank": 115, "page": 6, "position": 15}'

# 상품 C (대조군): 118위
curl -X POST http://localhost:8000/api/v1/products/prod-ccc-333/rank \
  -d '{"rank": 118, "page": 6, "position": 18}'
```

#### Step 3: 캠페인 생성 (A, B만)

```bash
# 캠페인 A - 트래픽 200회
curl -X POST http://localhost:8000/api/v1/campaigns \
  -d '{
    "name": "노트북 가방 A - 200회",
    "target_keyword": "노트북 가방",
    "target_traffic": 200,
    "product_id": "prod-aaa-111"
  }'

# 캠페인 B - 트래픽 100회
curl -X POST http://localhost:8000/api/v1/campaigns \
  -d '{
    "name": "노트북 가방 B - 100회",
    "target_keyword": "노트북 가방",
    "target_traffic": 100,
    "product_id": "prod-bbb-222"
  }'
```

#### Step 4: 24시간 후 결과 비교

```bash
# 전체 상품 목록 조회
curl "http://localhost:8000/api/v1/products?keyword=노트북 가방"
```

**예상 결과**:
```json
{
  "total": 3,
  "products": [
    {
      "product_id": "prod-aaa-111",
      "product_name": "맥북 15인치 파우치 가방",
      "initial_rank": 120,
      "current_rank": 65,
      "rank_improvement": -55,
      "total_traffic_count": 200
    },
    {
      "product_id": "prod-bbb-222",
      "product_name": "LG그램 17인치 노트북 가방",
      "initial_rank": 115,
      "current_rank": 82,
      "rank_improvement": -33,
      "total_traffic_count": 100
    },
    {
      "product_id": "prod-ccc-333",
      "product_name": "삼성 갤럭시북 가방",
      "initial_rank": 118,
      "current_rank": 119,
      "rank_improvement": 1,
      "total_traffic_count": 0
    }
  ]
}
```

**분석**:
- 상품 A (200회 트래픽): **55위 상승** ✅
- 상품 B (100회 트래픽): **33위 상승** ✅
- 상품 C (대조군): **1위 하락** (자연 변동)

**결론**: 트래픽이 많을수록 순위 상승 효과가 큽니다.

---

## Best Practices

### 1. 상품 등록 시

✅ **권장**:
- `naver_product_id`는 네이버 쇼핑 URL에서 추출 (고유값)
- `keyword`는 실제 사용자가 검색할 키워드 사용
- 메타데이터 (`category`, `brand`, `price`) 가능한 한 입력 (나중에 필터링 용이)

❌ **피해야 할 것**:
- 동일한 `naver_product_id` 중복 등록 (에러 발생)
- 너무 긴 `product_name` (300자 제한)
- 유효하지 않은 URL

### 2. 캠페인-상품 연동 시

✅ **권장**:
- 캠페인 생성 전 상품 먼저 등록
- `product_id`와 `target_keyword` 일치 확인
- 초기 순위 측정 후 캠페인 시작

❌ **피해야 할 것**:
- 존재하지 않는 `product_id` 사용 (404 에러)
- inactive 상태 상품에 캠페인 연결
- 순위 측정 없이 캠페인 시작 (비교 기준 없음)

### 3. 순위 측정 시

✅ **권장**:
- 측정 주기: 12시간 (네이버 알고리즘 반영 시간)
- `checked_by` 필드로 어떤 봇이 체크했는지 기록
- `campaign_id` 연결로 어떤 캠페인 영향인지 추적

❌ **피해야 할 것**:
- 너무 짧은 간격으로 측정 (5분마다 등) → 의미 없음
- 순위 계산 오류 (`rank ≠ (page-1)×20 + position`)

### 4. 데이터 분석 시

✅ **권장**:
- `/products/{id}/rank/history`로 트렌드 파악
- `/products/{id}/stats`로 전체 효과 측정
- 대조군 상품 설정 (`is_target=false`)으로 자연 변동 분리

❌ **피해야 할 것**:
- 단일 측정값으로 결론 도출 (최소 7일 데이터)
- 외부 변수 무시 (경쟁사 트래픽, 네이버 알고리즘 변경)

---

## 트러블슈팅

### 문제 1: 상품 등록 시 "naver_product_id already exists" 에러

**원인**: 동일한 네이버 상품 ID가 이미 등록되어 있음

**해결**:
```bash
# 기존 상품 조회
curl "http://localhost:8000/api/v1/products?naver_product_id=1234567890"

# 기존 상품 수정 또는 삭제
curl -X PATCH http://localhost:8000/api/v1/products/{existing_product_id} \
  -d '{"status": "inactive"}'
```

---

### 문제 2: 캠페인 생성 시 "Product not found or inactive" 에러

**원인**:
- `product_id`가 존재하지 않음
- 상품 `status`가 `inactive`

**해결**:
```bash
# 상품 상태 확인
curl http://localhost:8000/api/v1/products/{product_id}

# 상품 활성화
curl -X PATCH http://localhost:8000/api/v1/products/{product_id} \
  -d '{"status": "active"}'
```

---

### 문제 3: 순위가 업데이트되지 않음

**원인**:
- 순위 측정 API 호출 안 됨
- Rank Checker 봇 미작동

**해결**:
```bash
# 수동으로 순위 업데이트
curl -X POST http://localhost:8000/api/v1/products/{product_id}/rank \
  -d '{
    "rank": 50,
    "page": 3,
    "position": 10
  }'

# 봇 상태 확인
curl http://localhost:8000/api/v1/admin/dashboard
```

---

### 문제 4: 순위 변동이 없음 (rank_improvement = 0)

**가능한 원인**:
1. 트래픽이 아직 반영 안 됨 (12시간 대기 필요)
2. 트래픽 양이 부족
3. 네이버 알고리즘이 봇 트래픽 감지

**해결**:
```bash
# 1. 충분한 시간 대기 (최소 12시간)
# 2. 트래픽 증가
curl -X PATCH http://localhost:8000/api/v1/campaigns/{campaign_id} \
  -d '{"target_traffic": 500}'

# 3. 안티 탐지 시스템 강화 확인
```

---

### 문제 5: 순위 히스토리가 비어있음

**원인**: 순위 업데이트를 한 번도 호출하지 않음

**해결**:
```bash
# 순위 업데이트 호출
curl -X POST http://localhost:8000/api/v1/products/{product_id}/rank \
  -d '{"rank": 45, "page": 3, "position": 5}'

# 히스토리 확인
curl http://localhost:8000/api/v1/products/{product_id}/rank/history
```

---

## 부록: Python SDK 예시

### 상품 관리 클래스

```python
import requests
from typing import Optional, Dict, List

class ProductManager:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.api_base = f"{base_url}/api/v1"

    def create_product(
        self,
        keyword: str,
        naver_product_id: str,
        product_name: str,
        product_url: str,
        **kwargs
    ) -> Dict:
        """상품 등록"""
        payload = {
            "keyword": keyword,
            "naver_product_id": naver_product_id,
            "product_name": product_name,
            "product_url": product_url,
            **kwargs
        }
        response = requests.post(f"{self.api_base}/products", json=payload)
        response.raise_for_status()
        return response.json()

    def get_product(self, product_id: str) -> Dict:
        """상품 조회"""
        response = requests.get(f"{self.api_base}/products/{product_id}")
        response.raise_for_status()
        return response.json()

    def list_products(
        self,
        status: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 50
    ) -> Dict:
        """상품 목록 조회"""
        params = {"limit": limit}
        if status:
            params["status"] = status
        if keyword:
            params["keyword"] = keyword

        response = requests.get(f"{self.api_base}/products", params=params)
        response.raise_for_status()
        return response.json()

    def update_rank(
        self,
        product_id: str,
        rank: int,
        page: int,
        position: int,
        checked_by: Optional[str] = None,
        campaign_id: Optional[str] = None
    ) -> Dict:
        """순위 업데이트"""
        payload = {
            "rank": rank,
            "page": page,
            "position": position
        }
        if checked_by:
            payload["checked_by"] = checked_by
        if campaign_id:
            payload["campaign_id"] = campaign_id

        response = requests.post(
            f"{self.api_base}/products/{product_id}/rank",
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_rank_history(self, product_id: str, days: int = 7) -> Dict:
        """순위 히스토리 조회"""
        response = requests.get(
            f"{self.api_base}/products/{product_id}/rank/history",
            params={"days": days}
        )
        response.raise_for_status()
        return response.json()

# 사용 예시
if __name__ == "__main__":
    pm = ProductManager()

    # 상품 등록
    product = pm.create_product(
        keyword="프로틴 쉐이크 초코",
        naver_product_id="1234567890",
        product_name="머슬밀 단백질 쉐이크 초코맛 20팩",
        product_url="https://smartstore.naver.com/musclemeal/products/1234567890",
        category="건강식품",
        brand="머슬밀",
        price=35000
    )

    product_id = product["product_id"]
    print(f"상품 등록 완료: {product_id}")

    # 초기 순위 측정
    rank_result = pm.update_rank(
        product_id=product_id,
        rank=52,
        page=3,
        position=12,
        checked_by="bot-rank-checker-001"
    )
    print(f"초기 순위: {rank_result['current_rank']}위")

    # 7일 후 순위 히스토리 조회
    history = pm.get_rank_history(product_id, days=7)
    print(f"총 {len(history['history'])}회 순위 체크")
```

---

## 마무리

이 가이드를 통해 Turafic Product Management System의 모든 기능을 활용할 수 있습니다.

추가 질문이나 문제 발생 시:
- GitHub Issues: https://github.com/mim1012/turafic/issues
- 관리자 대시보드: http://localhost:8000/api/v1/admin/dashboard
- API 문서: http://localhost:8000/docs

**Good luck with your testing!** 🚀
