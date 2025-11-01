# 작업 할당 모델: "1봇 = 1캠페인 전담" 방식

## 개요

Turafic 시스템의 작업 할당 모델은 **"1봇 = 1캠페인 전담"** 방식을 채택합니다. 이는 각 봇이 하나의 캠페인(테스트 케이스)에만 전담으로 할당되어, 해당 테스트 케이스를 100회 반복 실행하는 구조입니다.

## 기존 모델 vs 새로운 모델

### ❌ 기존 모델 (잘못된 이해)
- **공유 방식**: 여러 봇이 하나의 캠페인을 공유
- **선착순 분배**: `SELECT FOR UPDATE`를 사용하여 동시성 제어
- **문제점**: 
  - 봇 간 경쟁 조건 발생
  - 테스트 케이스별 순수한 결과 측정 불가
  - 봇이 여러 테스트 케이스를 섞어서 실행할 가능성

### ✅ 새로운 모델 (올바른 이해)
- **전담 방식**: 1봇 = 1캠페인 = 100회 전담 실행
- **고정 할당**: 봇이 처음 작업 요청 시 캠페인 할당, 완료 시까지 유지
- **장점**:
  - 테스트 케이스별 순수한 결과 측정 가능
  - 봇 간 경쟁 조건 없음
  - 병렬 실행으로 전체 테스트 시간 단축

## 데이터베이스 스키마 변경

### Campaign 테이블
```sql
ALTER TABLE campaigns ADD COLUMN assigned_bot_id VARCHAR(36);
CREATE INDEX idx_campaigns_assigned_bot ON campaigns(assigned_bot_id);
```

- `assigned_bot_id`: 이 캠페인에 할당된 봇의 ID (NULL = 미할당)

### Bot 테이블
```sql
ALTER TABLE bots ADD COLUMN assigned_campaign_id VARCHAR(36);
CREATE INDEX idx_bots_assigned_campaign ON bots(assigned_campaign_id);
```

- `assigned_campaign_id`: 이 봇에 할당된 캠페인 ID (NULL = 미할당)

## 작업 할당 로직

### 1. 봇이 작업 요청 (`/get_task`)

```python
# 1. 이 봇에게 이미 할당된 캠페인이 있는지 확인
campaign = await session.execute(
    select(Campaign)
    .where(Campaign.assigned_bot_id == bot_id)
    .where(Campaign.status == "active")
)

# 2. 할당된 캠페인이 없으면, 미할당 캠페인 중 하나를 할당
if not campaign:
    campaign = await session.execute(
        select(Campaign)
        .where(Campaign.status == "active")
        .where(Campaign.assigned_bot_id.is_(None))
        .order_by(Campaign.created_at.asc())
        .limit(1)
    )
    
    if campaign:
        # 이 봇에게 캠페인 할당
        campaign.assigned_bot_id = bot_id
        bot.assigned_campaign_id = campaign.campaign_id
        await session.commit()
```

### 2. 캠페인 완료 처리

```python
# 목표 트래픽 수 달성 시
if campaign.current_traffic_count >= campaign.target_traffic:
    campaign.status = "completed"
    campaign.completed_at = datetime.utcnow()
    campaign.assigned_bot_id = None  # 봇 할당 해제
    bot.assigned_campaign_id = None  # 봇의 캠페인 할당도 해제
    await session.commit()
    
    # 봇은 10초 대기 후 새로운 캠페인 요청 가능
    return TaskResponse(
        task_id="wait",
        pattern=[{"action": "wait", "duration": 10000}]
    )
```

## 실행 시나리오

### 시나리오 1: 9개 봇 + 18개 테스트 케이스

1. **초기 상태**:
   - 봇 9대 (Bot-1 ~ Bot-9)
   - 캠페인 18개 (TC#1 ~ TC#18), 각 100회 실행 목표

2. **1차 할당** (봇 9대가 동시 작업 요청):
   - Bot-1 → TC#1 할당 (100회 전담)
   - Bot-2 → TC#2 할당 (100회 전담)
   - ...
   - Bot-9 → TC#9 할당 (100회 전담)

3. **1차 완료** (각 봇이 100회 완료):
   - Bot-1: TC#1 완료 → 10초 대기 → TC#10 요청
   - Bot-2: TC#2 완료 → 10초 대기 → TC#11 요청
   - ...

4. **2차 할당**:
   - Bot-1 → TC#10 할당
   - Bot-2 → TC#11 할당
   - ...
   - Bot-9 → TC#18 할당

5. **최종 완료**:
   - 모든 18개 테스트 케이스 완료
   - 총 실행 횟수: 18 × 100 = 1,800회

### 시나리오 2: 27개 봇 + 18개 테스트 케이스

1. **1차 할당** (봇 27대가 동시 작업 요청):
   - Bot-1 ~ Bot-18 → TC#1 ~ TC#18 할당
   - Bot-19 ~ Bot-27 → 대기 (미할당 캠페인 없음)

2. **1차 완료** (18개 봇이 완료):
   - 모든 테스트 케이스 완료
   - Bot-19 ~ Bot-27은 계속 대기 상태

## 캠페인 정의

하나의 **캠페인(Campaign)**은 다음을 의미합니다:

- **1개 상품** (target_keyword)
- **1개 테스트 케이스** (L18 매트릭스의 특정 행)
- **정확히 100회 실행** (target_traffic = 100)
- **1개 봇 전담** (assigned_bot_id)

## 구현 파일

- **데이터베이스 모델**: `/home/ubuntu/turafic/server/core/database.py`
- **작업 할당 API**: `/home/ubuntu/turafic/server/api/task_assignment.py`
- **마이그레이션 스크립트**: `/home/ubuntu/turafic/server/migrations/add_bot_campaign_assignment.sql`

## 참고 문서

- `ARCHITECTURE.md`: 전체 시스템 아키텍처
- `CC_SERVER_ARCHITECTURE.md`: C&C 서버 상세 설계
- `final_test_matrix_design.md`: L18 테스트 매트릭스 설계
