# 배포 및 테스트 가이드 (개발자용)

## 📋 개요

대장-쫄병 순위 체크 시스템을 배포하고 단계별로 테스트하는 완전한 가이드입니다.

---

## 🚀 Phase 1: 로컬 환경 배포 및 테스트

### 1-1. 환경 준비

#### Python 가상환경 설정

```bash
cd D:\Project\Navertrafic

# 가상환경 생성
python -m venv venv

# 가상환경 활성화 (Windows)
.\venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt
```

#### 추가 의존성 설치

```bash
# APScheduler (백그라운드 작업용)
pip install apscheduler>=3.10.4

# 전체 의존성 확인
pip list | grep -E "(fastapi|sqlalchemy|apscheduler|asyncpg|aiosqlite)"
```

---

### 1-2. 데이터베이스 설정

#### Option A: SQLite (개발/테스트용)

```bash
# .env 파일 생성
cat > .env << EOF
DATABASE_URL=sqlite+aiosqlite:///./turafic.db
REDIS_URL=redis://localhost:6379/0
LOG_LEVEL=DEBUG
EOF

# SQLite는 자동으로 생성되므로 추가 설정 불필요
```

#### Option B: PostgreSQL (운영용)

```bash
# PostgreSQL 설치 (Windows)
# https://www.postgresql.org/download/windows/

# 데이터베이스 생성
psql -U postgres
CREATE DATABASE turafic;
CREATE USER turafic_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE turafic TO turafic_user;
\q

# .env 파일 생성
cat > .env << EOF
DATABASE_URL=postgresql+asyncpg://turafic_user:your_password@localhost/turafic
REDIS_URL=redis://localhost:6379/0
LOG_LEVEL=DEBUG
EOF
```

#### Redis 설치 (선택사항)

```bash
# Windows: https://github.com/microsoftarchive/redis/releases
# 또는 Docker 사용:
docker run -d -p 6379:6379 redis:7-alpine
```

---

### 1-3. 데이터베이스 마이그레이션

#### 방법 1: Python으로 자동 생성 (SQLite)

```bash
# 서버를 한 번 실행하면 자동으로 테이블 생성됨
python server/main.py

# 출력 확인:
# ✅ Database tables created
```

#### 방법 2: SQL 파일 직접 실행 (PostgreSQL)

```bash
# 기본 테이블 생성
psql -U turafic_user -d turafic -f server/migrations/add_ranking_tables.sql

# 대장-쫄병 시스템 테이블 추가
psql -U turafic_user -d turafic -f server/migrations/add_dynamic_ranking_groups.sql

# 성공 메시지 확인:
# ========================================
# 대장-쫄병 시스템 DB 마이그레이션 완료!
# ========================================
```

#### 테이블 생성 확인

```bash
# SQLite
sqlite3 turafic.db ".tables"

# PostgreSQL
psql -U turafic_user -d turafic -c "\dt"

# 예상 출력:
# bots
# campaigns
# tasks
# ranking_groups
# ip_change_history
# task_completion_signals
# ranking_checks
# ranking_changes
# batch_executions
# ui_coordinate_maps
```

---

### 1-4. 서버 실행

```bash
# 개발 모드 (자동 재시작)
python server/main.py

# 또는 Uvicorn 직접 실행
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

# 출력 확인:
# 🚀 Turafic C&C Server Starting...
# ✅ Database and Cache initialized
# ✅ APScheduler initialized with automated tasks
# INFO:     Uvicorn running on http://0.0.0.0:8000
```

#### 서버 상태 확인

```bash
# 브라우저에서 열기
http://localhost:8000

# 또는 curl로 확인
curl http://localhost:8000

# 예상 응답:
{
    "service": "Turafic C&C Server",
    "status": "running",
    "version": "1.0.0",
    "endpoints": { ... }
}
```

#### API 문서 확인

```bash
# Swagger UI
http://localhost:8000/docs

# ReDoc
http://localhost:8000/redoc
```

---

## 🧪 Phase 2: API 단위 테스트

### 2-1. Bot Management API 테스트

#### 봇 등록

```bash
# 테스트 봇 #1 등록 (대장 봇)
curl -X POST "http://localhost:8000/api/v1/bots/register" \
  -H "Content-Type: application/json" \
  -d '{
    "android_id": "test-android-001",
    "device_model": "SM-G998N",
    "android_version": "13",
    "screen_resolution": "1440x3200"
  }'

# 예상 응답:
{
    "bot_id": "uuid-bot-001",
    "group": 1,
    "status": "active",
    "registered_at": "2025-11-02T10:00:00"
}

# bot_id를 저장해두기
export BOT_ID_1="uuid-bot-001"
```

#### 추가 봇 등록 (쫄병 봇 7개)

```bash
# 스크립트로 일괄 등록
for i in {2..8}; do
  curl -X POST "http://localhost:8000/api/v1/bots/register" \
    -H "Content-Type: application/json" \
    -d "{
      \"android_id\": \"test-android-00$i\",
      \"device_model\": \"SM-G998N\",
      \"android_version\": \"13\",
      \"screen_resolution\": \"1440x3200\"
    }"
  echo ""
done
```

#### 봇 목록 조회

```bash
curl "http://localhost:8000/api/v1/bots/list"

# 예상 응답:
{
    "bots": [
        {
            "bot_id": "uuid-bot-001",
            "device_model": "SM-G998N",
            "status": "active",
            "is_leader": false,
            "ranking_group_id": null
        },
        ...
    ]
}
```

---

### 2-2. Ranking Group API 테스트

#### 그룹 생성

```bash
# Traffic Group 1 생성
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/create" \
  -H "Content-Type: application/json" \
  -d '{
    "group_name": "Traffic Group 1",
    "group_type": "traffic",
    "leader_bot_id": "uuid-bot-001",
    "initial_minion_count": 7
  }'

# 예상 응답:
{
    "success": true,
    "group_id": "uuid-group-001",
    "group_name": "Traffic Group 1"
}

# group_id 저장
export GROUP_ID="uuid-group-001"
```

#### 쫄병 할당

```bash
# 봇 #2를 쫄병으로 할당
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/minions/assign" \
  -H "Content-Type: application/json" \
  -d '{
    "bot_id": "uuid-bot-002"
  }'

# 예상 응답:
{
    "success": true,
    "bot_id": "uuid-bot-002",
    "group_id": "uuid-group-001"
}

# 나머지 쫄병 6개도 할당 (봇 #3~#8)
for i in {3..8}; do
  curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/minions/assign" \
    -H "Content-Type: application/json" \
    -d "{\"bot_id\": \"uuid-bot-00$i\"}"
  echo ""
done
```

#### 그룹 상태 조회

```bash
curl "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/status" | jq

# 예상 응답:
{
    "group_id": "uuid-group-001",
    "group_name": "Traffic Group 1",
    "group_type": "traffic",
    "status": "active",
    "leader": {
        "bot_id": "uuid-bot-001",
        "battery_level": 100,
        "device_temperature": 25.0,
        "health_score": 100.0,
        "current_ip": null
    },
    "minions": [
        {
            "bot_id": "uuid-bot-002",
            "connection_status": "disconnected",
            "task_status": "idle"
        },
        ...
    ],
    "health_summary": {
        "current_minion_count": 7,
        "target_minion_count": 7,
        "connected_minions": 0
    }
}
```

---

### 2-3. Health Score 테스트

#### 대장 봇 헬스 정보 업데이트

```bash
# 정상 상태 (7 minions 유지)
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/leader/health" \
  -H "Content-Type: application/json" \
  -d '{
    "battery_level": 80,
    "memory_available_mb": 2000,
    "hotspot_stability_score": 95.0,
    "network_latency_ms": 50,
    "device_temperature": 35.0
  }'

# 예상 응답:
{
    "success": true,
    "health_score": 89.5,
    "recommended_minion_count": 7,
    "reason": "정상 상태",
    "level": "normal"
}
```

#### 경고 상태 테스트 (6 minions로 감소)

```bash
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/leader/health" \
  -H "Content-Type: application/json" \
  -d '{
    "battery_level": 25,
    "memory_available_mb": 1500,
    "hotspot_stability_score": 85.0,
    "network_latency_ms": 80,
    "device_temperature": 42.0
  }'

# 예상 응답:
{
    "success": true,
    "health_score": 65.3,
    "recommended_minion_count": 6,
    "reason": "배터리 25% / 온도 42° (경고)",
    "level": "warning"
}
```

#### 위험 상태 테스트 (5 minions로 감소)

```bash
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/leader/health" \
  -H "Content-Type: application/json" \
  -d '{
    "battery_level": 10,
    "memory_available_mb": 800,
    "hotspot_stability_score": 70.0,
    "network_latency_ms": 120,
    "device_temperature": 48.0
  }'

# 예상 응답:
{
    "success": true,
    "health_score": 42.8,
    "recommended_minion_count": 5,
    "reason": "배터리 10% / 온도 48° (위험)",
    "level": "critical"
}
```

---

### 2-4. 쫄병 수 자동 조정 테스트

```bash
# 수동 조정 트리거
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/adjust?force=true"

# 예상 응답 (위험 상태에서):
{
    "adjusted": true,
    "old_count": 7,
    "new_count": 5,
    "reason": "배터리 10% / 온도 48° (위험)",
    "level": "critical"
}

# 그룹 상태 재확인
curl "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/status" | jq '.health_summary'

# 예상 출력:
{
    "current_minion_count": 5,
    "target_minion_count": 5,
    "connected_minions": 0
}
```

---

### 2-5. IP 로테이션 테스트

#### 작업 완료 신호 전송

```bash
# 쫄병 #2 작업 완료
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/tasks/complete" \
  -H "Content-Type: application/json" \
  -d '{
    "bot_id": "uuid-bot-002",
    "task_id": "task-uuid-001"
  }'

# 예상 응답:
{
    "success": true,
    "all_completed": false,
    "message": "작업 완료 신호 수신."
}

# 나머지 쫄병들도 완료 신호 전송 (봇 #3~#6, 총 5개)
for i in {3..6}; do
  curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/tasks/complete" \
    -H "Content-Type: application/json" \
    -d "{\"bot_id\": \"uuid-bot-00$i\", \"task_id\": \"task-uuid-00$i\"}"
  echo ""
done

# 마지막 쫄병 완료 시
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/tasks/complete" \
  -H "Content-Type: application/json" \
  -d '{
    "bot_id": "uuid-bot-006",
    "task_id": "task-uuid-006"
  }'

# 예상 응답:
{
    "success": true,
    "all_completed": true,
    "message": "모든 쫄병이 작업 완료. IP 변경 준비됨."
}
```

#### IP 변경 시점 체크

```bash
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/ip/check"

# 예상 응답:
{
    "should_change": true,
    "reason": "all_completed",
    "wait_duration": 85,
    "completed_minions": 5,
    "total_minions": 5
}
```

#### IP 변경 실행

```bash
curl -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/ip/execute"

# 예상 응답:
{
    "success": true,
    "old_ip": "192.168.1.100",
    "new_ip": "192.168.2.50",
    "leader_bot_id": "uuid-bot-001"
}
```

#### IP 변경 이력 조회

```bash
# PostgreSQL
psql -U turafic_user -d turafic -c "
SELECT
    group_id,
    old_ip,
    new_ip,
    change_reason,
    wait_duration_sec,
    changed_at
FROM ip_change_history
ORDER BY changed_at DESC
LIMIT 5;"

# SQLite
sqlite3 turafic.db "
SELECT
    group_id,
    old_ip,
    new_ip,
    change_reason,
    wait_duration_sec,
    changed_at
FROM ip_change_history
ORDER BY changed_at DESC
LIMIT 5;"
```

---

### 2-6. Campaign & Task API 테스트

#### 캠페인 생성

```bash
curl -X POST "http://localhost:8000/api/v1/campaigns/create" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "프로틴 쉐이크 테스트",
    "target_keyword": "프로틴 쉐이크",
    "target_traffic": 100,
    "test_case": "TC#001",
    "execution_mode": "appium",
    "identity_profile_group": "samsung_mobile_default",
    "assigned_bot_id": "uuid-bot-002"
  }'

# 예상 응답:
{
    "campaign_id": "uuid-campaign-001",
    "name": "프로틴 쉐이크 테스트",
    "status": "active"
}

export CAMPAIGN_ID="uuid-campaign-001"
```

#### 작업 요청 (봇 시뮬레이션)

```bash
curl "http://localhost:8000/api/v1/tasks/get_task?bot_id=uuid-bot-002"

# 예상 응답:
{
    "task_id": "uuid-task-001",
    "campaign_id": "uuid-campaign-001",
    "pattern": [
        {
            "action": "kill",
            "target": "com.sec.android.app.sbrowser",
            "description": "삼성 브라우저 강제 종료"
        },
        {
            "action": "wait",
            "duration": 2000
        },
        {
            "action": "start",
            "target": "com.sec.android.app.sbrowser"
        },
        {
            "action": "tap",
            "x": 540,
            "y": 200,
            "description": "검색창 터치"
        },
        {
            "action": "text",
            "value": "프로틴 쉐이크"
        },
        {
            "action": "wait",
            "duration": 65000,
            "description": "상품 페이지 체류 (65초)"
        }
    ]
}
```

#### 작업 결과 보고

```bash
curl -X POST "http://localhost:8000/api/v1/tasks/report_result" \
  -H "Content-Type: application/json" \
  -d '{
    "task_id": "uuid-task-001",
    "bot_id": "uuid-bot-002",
    "status": "success",
    "log": "작업 완료: 프로틴 쉐이크 검색 → 상품 페이지 65초 체류",
    "screenshot_url": null
  }'

# 예상 응답:
{
    "success": true,
    "message": "작업 결과 저장 완료"
}
```

---

## 🤖 Phase 3: 백그라운드 작업 테스트

### 3-1. APScheduler 동작 확인

#### 서버 로그 모니터링

```bash
# 서버 실행 중 로그 확인
tail -f logs/turafic.log

# 예상 로그 (30초마다):
# [2025-11-02 10:00:30] ✅ [IP 로테이션] Traffic Group 1: 192.168.1.100 → 192.168.2.50 (이유: all_completed, 대기: 285초)

# 예상 로그 (5분마다):
# [2025-11-02 10:05:00] ✅ [쫄병 수 조정] Traffic Group 1: 7 → 6 (이유: 배터리 28% / 온도 39° (경고), 레벨: warning)
```

#### 스케줄된 작업 목록 확인

```python
# Python 셸에서 실행
python

>>> from server.core.background_tasks import list_all_jobs
>>> jobs = list_all_jobs()
>>> for job in jobs:
...     print(f"{job['id']}: {job['name']} - Next: {job['next_run']}")

# 예상 출력:
# ip_rotation_check: IP 로테이션 자동 체크 - Next: 2025-11-02T10:00:30
# health_check_adjust: 그룹 헬스 체크 및 쫄병 수 조정 - Next: 2025-11-02T10:05:00
```

---

### 3-2. 자동 IP 로테이션 테스트

```bash
# 1. 그룹 상태를 'active'로 설정
psql -U turafic_user -d turafic -c "
UPDATE ranking_groups
SET status = 'active',
    last_ip_change_at = NOW() - INTERVAL '6 minutes'
WHERE group_id = '$GROUP_ID';"

# 2. 모든 쫄병을 'completed' 상태로 변경
psql -U turafic_user -d turafic -c "
UPDATE bots
SET task_status = 'completed'
WHERE ranking_group_id = '$GROUP_ID' AND is_leader = FALSE;"

# 3. 30초 대기 (다음 스케줄 실행 시까지)
sleep 30

# 4. 로그 확인
tail -n 20 logs/turafic.log | grep "IP 로테이션"

# 예상 출력:
# ✅ [IP 로테이션] Traffic Group 1: 192.168.1.100 → 192.168.2.50 (이유: all_completed, 대기: 360초)
```

---

### 3-3. 자동 쫄병 수 조정 테스트

```bash
# 1. 대장 봇 배터리를 낮게 설정
psql -U turafic_user -d turafic -c "
UPDATE bots
SET battery_level = 20,
    device_temperature = 43.0,
    health_score = 60.0
WHERE bot_id = 'uuid-bot-001';"

# 2. 5분 대기 (다음 헬스 체크 실행 시까지)
sleep 300

# 3. 로그 확인
tail -n 20 logs/turafic.log | grep "쫄병 수 조정"

# 예상 출력:
# ✅ [쫄병 수 조정] Traffic Group 1: 7 → 6 (이유: 배터리 20% / 온도 43° (경고), 레벨: warning)

# 4. 그룹 상태 확인
curl "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/status" | jq '.health_summary.current_minion_count'

# 예상 출력:
# 6
```

---

## 📊 Phase 4: 통합 테스트 시나리오

### 4-1. 전체 워크플로우 시뮬레이션

```bash
# 테스트 스크립트 생성
cat > test_full_workflow.sh << 'EOF'
#!/bin/bash

echo "=== 전체 워크플로우 테스트 시작 ==="

# 1. 봇 8대 등록
echo "[1/7] 봇 등록 중..."
for i in {1..8}; do
  curl -s -X POST "http://localhost:8000/api/v1/bots/register" \
    -H "Content-Type: application/json" \
    -d "{\"android_id\": \"test-bot-$(printf %03d $i)\", \"device_model\": \"SM-G998N\", \"android_version\": \"13\", \"screen_resolution\": \"1440x3200\"}" \
    | jq -r '.bot_id' > bot_$i.txt
done

BOT_1=$(cat bot_1.txt)
echo "대장 봇: $BOT_1"

# 2. 그룹 생성
echo "[2/7] 그룹 생성 중..."
GROUP_ID=$(curl -s -X POST "http://localhost:8000/api/v1/ranking-groups/groups/create" \
  -H "Content-Type: application/json" \
  -d "{\"group_name\": \"Test Group\", \"group_type\": \"traffic\", \"leader_bot_id\": \"$BOT_1\", \"initial_minion_count\": 7}" \
  | jq -r '.group_id')
echo "그룹 ID: $GROUP_ID"

# 3. 쫄병 할당
echo "[3/7] 쫄병 할당 중..."
for i in {2..8}; do
  BOT=$(cat bot_$i.txt)
  curl -s -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/minions/assign" \
    -H "Content-Type: application/json" \
    -d "{\"bot_id\": \"$BOT\"}" > /dev/null
  echo "  - 쫄병 $i 할당 완료"
done

# 4. 대장 헬스 업데이트
echo "[4/7] 대장 헬스 업데이트 중..."
curl -s -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/leader/health" \
  -H "Content-Type: application/json" \
  -d '{"battery_level": 80, "memory_available_mb": 2000, "hotspot_stability_score": 95.0, "network_latency_ms": 50, "device_temperature": 35.0}' \
  | jq '.health_score'

# 5. 캠페인 생성
echo "[5/7] 캠페인 생성 중..."
BOT_2=$(cat bot_2.txt)
CAMPAIGN_ID=$(curl -s -X POST "http://localhost:8000/api/v1/campaigns/create" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"테스트 캠페인\", \"target_keyword\": \"프로틴 쉐이크\", \"target_traffic\": 10, \"test_case\": \"TC#001\", \"execution_mode\": \"appium\", \"assigned_bot_id\": \"$BOT_2\"}" \
  | jq -r '.campaign_id')
echo "캠페인 ID: $CAMPAIGN_ID"

# 6. 작업 요청 및 완료 (쫄병 7개)
echo "[6/7] 작업 실행 시뮬레이션 중..."
for i in {2..8}; do
  BOT=$(cat bot_$i.txt)

  # 작업 요청
  TASK_ID=$(curl -s "http://localhost:8000/api/v1/tasks/get_task?bot_id=$BOT" | jq -r '.task_id')
  echo "  - 쫄병 $i: 작업 $TASK_ID 시작"

  # 2초 대기 (작업 실행 시뮬레이션)
  sleep 2

  # 작업 완료 보고
  curl -s -X POST "http://localhost:8000/api/v1/tasks/report_result" \
    -H "Content-Type: application/json" \
    -d "{\"task_id\": \"$TASK_ID\", \"bot_id\": \"$BOT\", \"status\": \"success\"}" > /dev/null

  # 완료 신호 전송
  curl -s -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/tasks/complete" \
    -H "Content-Type: application/json" \
    -d "{\"bot_id\": \"$BOT\", \"task_id\": \"$TASK_ID\"}" \
    | jq -r '.message'
done

# 7. IP 변경 실행
echo "[7/7] IP 변경 실행 중..."
curl -s -X POST "http://localhost:8000/api/v1/ranking-groups/groups/$GROUP_ID/ip/execute" \
  | jq '{success, old_ip, new_ip}'

echo ""
echo "=== 전체 워크플로우 테스트 완료 ==="
echo "그룹 ID: $GROUP_ID"
echo "캠페인 ID: $CAMPAIGN_ID"

# 정리
rm -f bot_*.txt

EOF

chmod +x test_full_workflow.sh
./test_full_workflow.sh
```

---

### 4-2. 부하 테스트

```bash
# Apache Bench로 부하 테스트
apt-get install apache2-utils  # Ubuntu
# 또는
brew install apache2  # macOS

# 100개 동시 요청, 총 1000개
ab -n 1000 -c 100 http://localhost:8000/

# 예상 출력:
# Requests per second: 250.5 [#/sec] (mean)
# Time per request: 399.2 [ms] (mean)
# Transfer rate: 80.5 [Kbytes/sec] received
```

---

## 🐛 Phase 5: 디버깅 및 모니터링

### 5-1. 로그 레벨 설정

```python
# server/main.py 또는 .env
LOG_LEVEL=DEBUG  # DEBUG, INFO, WARNING, ERROR
```

### 5-2. 주요 로그 확인 포인트

```bash
# 봇 등록 로그
grep "봇 등록" logs/turafic.log

# IP 변경 로그
grep "IP 로테이션" logs/turafic.log

# 쫄병 수 조정 로그
grep "쫄병 수 조정" logs/turafic.log

# 에러 로그
grep "ERROR" logs/turafic.log
```

### 5-3. 데이터베이스 쿼리

```sql
-- 그룹 현황
SELECT
    group_name,
    group_type,
    current_minion_count,
    target_minion_count,
    status,
    current_ip
FROM ranking_groups;

-- 봇 상태
SELECT
    bot_id,
    is_leader,
    battery_level,
    device_temperature,
    health_score,
    task_status,
    ranking_group_id
FROM bots
WHERE ranking_group_id IS NOT NULL;

-- IP 변경 통계
SELECT
    change_reason,
    COUNT(*) as count,
    AVG(wait_duration_sec) as avg_wait,
    AVG(minions_completed::float / minions_total * 100) as completion_rate
FROM ip_change_history
GROUP BY change_reason;

-- 작업 성공률
SELECT
    status,
    COUNT(*) as count,
    ROUND(COUNT(*)::numeric / SUM(COUNT(*)) OVER () * 100, 2) as percentage
FROM tasks
GROUP BY status;
```

---

## 🚀 Phase 6: 프로덕션 배포

### 6-1. Oracle Cloud 설정

```bash
# SSH 접속
ssh -i your-key.pem ubuntu@your-server-ip

# 시스템 업데이트
sudo apt update && sudo apt upgrade -y

# Python 3.10+ 설치
sudo apt install python3.10 python3-pip python3-venv

# PostgreSQL 설치
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Redis 설치
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis

# Nginx 설치 (리버스 프록시)
sudo apt install nginx
```

### 6-2. 프로젝트 배포

```bash
# Git 클론
cd /home/ubuntu
git clone https://github.com/mim1012/turafic.git
cd turafic

# 가상환경 생성
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# .env 파일 생성 (프로덕션)
cat > .env << EOF
DATABASE_URL=postgresql+asyncpg://turafic_user:your_password@localhost/turafic
REDIS_URL=redis://localhost:6379/0
LOG_LEVEL=INFO
SECRET_KEY=your-secret-key-here
EOF

# DB 마이그레이션
psql -U turafic_user -d turafic -f server/migrations/add_ranking_tables.sql
psql -U turafic_user -d turafic -f server/migrations/add_dynamic_ranking_groups.sql
```

### 6-3. Systemd 서비스 등록

```bash
# systemd 서비스 파일 생성
sudo cat > /etc/systemd/system/turafic.service << 'EOF'
[Unit]
Description=Turafic C&C Server
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/turafic
Environment="PATH=/home/ubuntu/turafic/venv/bin"
ExecStart=/home/ubuntu/turafic/venv/bin/uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 서비스 활성화
sudo systemctl daemon-reload
sudo systemctl enable turafic
sudo systemctl start turafic
sudo systemctl status turafic
```

### 6-4. Nginx 리버스 프록시 설정

```bash
sudo cat > /etc/nginx/sites-available/turafic << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/turafic /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 📱 Phase 7: Android APK 통합 테스트

### 7-1. APK 설정

```java
// config.properties
server_url=http://your-server-ip:8000
api_key=your-api-key

// 대장 봇 설정
bot_role=leader
hotspot_ssid=Traffic-G1
hotspot_password=12345678
health_report_interval=300000  // 5분

// 쫄병 봇 설정
bot_role=minion
leader_hotspot_ssid=Traffic-G1
leader_hotspot_password=12345678
task_poll_interval=5000  // 5초
```

### 7-2. 봇 연동 테스트

```bash
# 1. 서버 로그 모니터링
tail -f logs/turafic.log

# 2. Android APK 실행 (대장 봇)
# - 앱이 자동으로 봇 등록 API 호출
# - 핫스팟 활성화
# - 헬스 정보 5분마다 전송

# 3. Android APK 실행 (쫄병 봇 7개)
# - 앱이 자동으로 봇 등록 API 호출
# - 대장 핫스팟 자동 연결
# - 작업 요청 5초마다 폴링

# 4. 로그 확인
# 예상 로그:
# [2025-11-02 10:00:00] 봇 등록: android-id-001 (대장)
# [2025-11-02 10:00:05] 봇 등록: android-id-002 (쫄병)
# [2025-11-02 10:00:10] 작업 할당: bot-002 → campaign-001
# [2025-11-02 10:01:15] 작업 완료: bot-002 (65초 소요)
# [2025-11-02 10:05:00] 헬스 업데이트: bot-001 (Health: 87.5)
```

---

## 🎯 테스트 체크리스트

### ✅ 기본 기능

- [ ] 서버 실행 및 상태 확인
- [ ] API 문서 접근 (/docs)
- [ ] 봇 등록 (8대)
- [ ] 그룹 생성
- [ ] 쫄병 할당
- [ ] 그룹 상태 조회

### ✅ Health Score

- [ ] 정상 상태 (7 minions)
- [ ] 경고 상태 (6 minions)
- [ ] 위험 상태 (5 minions)
- [ ] 자동 조정 동작

### ✅ IP 로테이션

- [ ] 작업 완료 신호 전송
- [ ] IP 변경 시점 체크
- [ ] IP 변경 실행
- [ ] IP 변경 이력 저장

### ✅ 백그라운드 작업

- [ ] APScheduler 초기화
- [ ] IP 로테이션 자동 체크 (30초)
- [ ] 헬스 체크 자동 조정 (5분)

### ✅ 작업 할당

- [ ] 캠페인 생성
- [ ] 작업 요청
- [ ] 작업 패턴 생성
- [ ] 작업 결과 보고

### ✅ 성능

- [ ] 100 req/s 처리 가능
- [ ] API 응답 시간 < 100ms
- [ ] DB 쿼리 최적화

### ✅ 프로덕션

- [ ] Systemd 서비스 등록
- [ ] Nginx 리버스 프록시
- [ ] HTTPS 설정 (Let's Encrypt)
- [ ] 로그 로테이션 설정

---

## 🐛 문제 해결

### 문제 1: 서버 시작 실패

```bash
# 로그 확인
tail -n 50 logs/turafic.log

# 포트 충돌 확인
netstat -ano | grep 8000

# 프로세스 종료
kill -9 <PID>
```

### 문제 2: DB 연결 실패

```bash
# PostgreSQL 상태 확인
sudo systemctl status postgresql

# 연결 테스트
psql -U turafic_user -d turafic -c "SELECT 1;"

# 권한 확인
psql -U postgres -c "\du"
```

### 문제 3: APScheduler 동작 안함

```python
# Python 셸에서 확인
from server.core.background_tasks import scheduler

print(scheduler)  # None이면 초기화 실패
print(scheduler.running)  # False면 시작 안됨
```

---

**작성일**: 2025-11-02
**버전**: 1.0.0
**상태**: ✅ 완성
