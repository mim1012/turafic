# 대장-쫄병 순위 체크 시스템 가이드

## 📋 개요

네이버 쇼핑 순위 체크를 위한 **대장-쫄병 (Leader-Minion) 시스템**을 구현합니다. 대장 봇이 핫스팟을 제공하고, 쫄병들이 연결하여 동일한 IP를 공유하며 순위를 체크합니다.

---

## 🎯 시스템 구조

### 그룹 구성

```
┌─────────────────────────────────────────────┐
│          Ranking Group (그룹)               │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │  대장 봇 (Leader)                    │  │
│  │  - 핫스팟 제공                        │  │
│  │  - IP 관리 (비행기 모드 토글)         │  │
│  │  - Health Score 모니터링             │  │
│  │  - 배터리: 75%, 온도: 35°           │  │
│  └──────────────────────────────────────┘  │
│              │                              │
│    ┌─────────┴─────────┐                   │
│    ▼         ▼         ▼                   │
│  ┌────┐  ┌────┐  ┌────┐                   │
│  │쫄병│  │쫄병│  │쫄병│  ...  (5~7개)     │
│  │#1  │  │#2  │  │#3  │                   │
│  └────┘  └────┘  └────┘                   │
│                                             │
│  현재 IP: 192.168.1.100                    │
│  쫄병 수: 7개 (목표) / 7개 (현재)          │
│  상태: active                               │
└─────────────────────────────────────────────┘
```

### 봇 역할

| 역할 | 책임 | 개수 |
|------|------|------|
| **대장 (Leader)** | 핫스팟 제공, IP 변경, Health 관리 | 1개/그룹 |
| **쫄병 (Minion)** | 순위 체크 작업 실행, 대장 IP 공유 | 5~7개/그룹 |

### 그룹 타입

- **Traffic Group**: 트래픽 생성용 (3개 그룹 × 8봇 = 24봇)
- **Rank Checker Group**: 순위 체크 전용 (1개 그룹 × 8봇 = 8봇)

---

## 🔧 쫄병 수 자동 조정 시스템

### Health Score 계산

대장 봇의 건강 상태를 0~100 점수로 평가:

```python
Health Score = (
    배터리 × 30% +
    메모리 × 25% +
    핫스팟 안정성 × 25% +
    네트워크 지연 × 15% +
    온도 × 5%
)
```

### 쫄병 수 결정 정책

**보수적 접근**: 기본 7개, 필요 시에만 감소

| 조건 | 배터리 | 온도 | 쫄병 수 | 레벨 |
|------|--------|------|---------|------|
| **정상** | ≥30% | ≤40° | 7개 | normal |
| **경고** | <30% | >40° | 6개 | warning |
| **위험** | <15% | >45° | 5개 | critical |

**예시**:

```python
# 정상 상태
battery: 75%, temp: 35° → 7 minions

# 경고 상태
battery: 25%, temp: 38° → 6 minions

# 위험 상태
battery: 10%, temp: 46° → 5 minions
```

### 자동 조정 프로세스

```
[5분 주기 헬스 체크]
  ↓
[Health Score 계산]
  ↓
[쫄병 수 결정]
  ↓
[현재 수와 비교]
  ↓
├─ 동일 → 변경 없음
└─ 다름 → 자동 조정
      ├─ 증가 → 미할당 봇 추가
      └─ 감소 → idle 봇부터 제거
```

---

## 📡 API 사용 가이드

### 1. 그룹 생성

**엔드포인트**: `POST /api/v1/ranking-groups/groups/create`

**요청**:
```json
{
    "group_name": "Traffic Group 1",
    "group_type": "traffic",
    "leader_bot_id": "bot-uuid-1234",
    "initial_minion_count": 7
}
```

**응답**:
```json
{
    "success": true,
    "group_id": "group-uuid-5678",
    "group_name": "Traffic Group 1"
}
```

---

### 2. 쫄병 할당

**엔드포인트**: `POST /api/v1/ranking-groups/groups/{group_id}/minions/assign`

**요청**:
```json
{
    "bot_id": "bot-uuid-9999"
}
```

**응답**:
```json
{
    "success": true,
    "bot_id": "bot-uuid-9999",
    "group_id": "group-uuid-5678"
}
```

---

### 3. 대장 헬스 업데이트

**엔드포인트**: `POST /api/v1/ranking-groups/groups/{group_id}/leader/health`

**요청**:
```json
{
    "battery_level": 75,
    "memory_available_mb": 1500,
    "hotspot_stability_score": 95.0,
    "network_latency_ms": 50,
    "device_temperature": 35.0
}
```

**응답**:
```json
{
    "success": true,
    "health_score": 87.5,
    "recommended_minion_count": 7,
    "reason": "정상 상태",
    "level": "normal"
}
```

---

### 4. 쫄병 수 자동 조정

**엔드포인트**: `POST /api/v1/ranking-groups/groups/{group_id}/adjust?force=false`

**응답**:
```json
{
    "adjusted": true,
    "old_count": 7,
    "new_count": 6,
    "reason": "배터리 25% / 온도 38° (경고)",
    "level": "warning"
}
```

---

### 5. 그룹 상태 조회

**엔드포인트**: `GET /api/v1/ranking-groups/groups/{group_id}/status`

**응답**:
```json
{
    "group_id": "group-uuid-5678",
    "group_name": "Traffic Group 1",
    "group_type": "traffic",
    "status": "active",
    "leader": {
        "bot_id": "bot-uuid-1234",
        "battery_level": 75,
        "device_temperature": 35.0,
        "health_score": 87.5,
        "current_ip": "192.168.1.100"
    },
    "minions": [
        {
            "bot_id": "bot-uuid-2222",
            "connection_status": "connected",
            "task_status": "working"
        },
        {
            "bot_id": "bot-uuid-3333",
            "connection_status": "connected",
            "task_status": "completed"
        }
    ],
    "health_summary": {
        "leader_health_score": 87.5,
        "leader_battery": 75,
        "leader_temperature": 35.0,
        "current_minion_count": 7,
        "target_minion_count": 7,
        "connected_minions": 6
    }
}
```

---

### 6. 전체 그룹 목록 조회

**엔드포인트**: `GET /api/v1/ranking-groups/groups/list?group_type=traffic`

**응답**:
```json
{
    "groups": [
        {
            "group_id": "group-uuid-1",
            "group_name": "Traffic Group 1",
            "group_type": "traffic",
            "status": "active",
            "current_minion_count": 7,
            "target_minion_count": 7,
            "current_ip": "192.168.1.100",
            "last_ip_change_at": "2025-11-02T10:00:00"
        },
        {
            "group_id": "group-uuid-2",
            "group_name": "Rank Checker Group",
            "group_type": "rank_checker",
            "status": "active",
            "current_minion_count": 6,
            "target_minion_count": 7,
            "current_ip": "192.168.2.50",
            "last_ip_change_at": "2025-11-02T10:05:00"
        }
    ]
}
```

---

## 🔄 워크플로우 예시

### 시나리오 1: 그룹 초기 설정

```bash
# 1. 대장 봇을 지정하여 그룹 생성
POST /api/v1/ranking-groups/groups/create
{
    "group_name": "Traffic Group 1",
    "group_type": "traffic",
    "leader_bot_id": "leader-001",
    "initial_minion_count": 7
}

# 2. 쫄병 7개 할당
POST /api/v1/ranking-groups/groups/{group_id}/minions/assign
{"bot_id": "minion-001"}

POST /api/v1/ranking-groups/groups/{group_id}/minions/assign
{"bot_id": "minion-002"}

... (총 7번 반복)

# 3. 그룹 상태 확인
GET /api/v1/ranking-groups/groups/{group_id}/status
```

---

### 시나리오 2: 헬스 기반 자동 조정

```bash
# 1. 대장 봇이 5분마다 헬스 정보 전송
POST /api/v1/ranking-groups/groups/{group_id}/leader/health
{
    "battery_level": 25,  # 경고 수준
    "memory_available_mb": 1200,
    "hotspot_stability_score": 90.0,
    "network_latency_ms": 60,
    "device_temperature": 38.0  # 경고 수준
}

# 응답:
{
    "health_score": 72.5,
    "recommended_minion_count": 6,  # 7 → 6으로 감소 권장
    "reason": "배터리 25% / 온도 38° (경고)",
    "level": "warning"
}

# 2. 백그라운드 작업이 자동으로 쫄병 수 조정
# (5분 주기 자동 실행)

# 3. 조정 결과 로그
✅ [쫄병 수 조정] Traffic Group 1: 7 → 6
   (이유: 배터리 25% / 온도 38° (경고), 레벨: warning)
```

---

### 시나리오 3: IP 로테이션과 연동

```bash
# 1. 쫄병들이 작업 완료 신호 전송
POST /api/v1/ranking-groups/groups/{group_id}/tasks/complete
{"bot_id": "minion-001", "task_id": "task-001"}

POST /api/v1/ranking-groups/groups/{group_id}/tasks/complete
{"bot_id": "minion-002", "task_id": "task-002"}

... (모든 쫄병이 완료 신호 전송)

# 2. IP 변경 시점 체크
GET /api/v1/ranking-groups/groups/{group_id}/ip/check

# 응답:
{
    "should_change": true,
    "reason": "all_completed",
    "wait_duration": 285,
    "completed_minions": 6,
    "total_minions": 6
}

# 3. IP 변경 실행 (자동 or 수동)
POST /api/v1/ranking-groups/groups/{group_id}/ip/execute

# 응답:
{
    "success": true,
    "old_ip": "192.168.1.100",
    "new_ip": "192.168.2.50",
    "leader_bot_id": "leader-001"
}
```

---

## 🤖 백그라운드 자동화

### APScheduler 통합

시스템은 다음 작업을 자동으로 실행합니다:

#### 1. IP 로테이션 자동 체크 (30초 주기)

```python
# 30초마다 모든 그룹의 IP 변경 시점 체크
scheduler.add_job(
    func=ip_rotation_check_job,
    trigger=IntervalTrigger(seconds=30),
    id="ip_rotation_check"
)
```

#### 2. 헬스 체크 및 쫄병 수 조정 (5분 주기)

```python
# 5분마다 대장 봇 Health Score 확인 및 쫄병 수 자동 조정
scheduler.add_job(
    func=health_check_and_adjust_job,
    trigger=IntervalTrigger(minutes=5),
    id="health_check_adjust"
)
```

---

## 📊 모니터링 및 통계

### 데이터베이스 뷰

**그룹 상태 요약 뷰**:
```sql
CREATE VIEW ranking_group_status AS
SELECT
    g.group_id,
    g.group_name,
    g.target_minion_count,
    g.current_minion_count,
    g.status,
    g.current_ip,

    -- 대장 봇 정보
    b.battery_level AS leader_battery,
    b.device_temperature AS leader_temp,
    b.health_score AS leader_health,

    -- 작업 중인 쫄병 수
    COUNT(*) FILTER (WHERE bots.task_status = 'working') AS working_minions,

    -- 완료한 쫄병 수
    COUNT(*) FILTER (WHERE bots.task_status = 'completed') AS completed_minions,

    -- IP 변경 가능 여부
    CASE WHEN working_minions = 0 THEN TRUE ELSE FALSE END AS can_change_ip

FROM ranking_groups g
LEFT JOIN bots b ON g.leader_bot_id = b.bot_id
LEFT JOIN bots ON bots.ranking_group_id = g.group_id;
```

### 통계 쿼리

**쫄병 수 조정 이력**:
```sql
SELECT
    group_name,
    last_resize_at,
    resize_reason,
    current_minion_count
FROM ranking_groups
WHERE last_resize_at IS NOT NULL
ORDER BY last_resize_at DESC
LIMIT 10;
```

**IP 변경 이력**:
```sql
SELECT
    group_id,
    old_ip,
    new_ip,
    change_reason,
    minions_completed,
    minions_total,
    wait_duration_sec,
    changed_at
FROM ip_change_history
WHERE changed_at >= NOW() - INTERVAL '7 days'
ORDER BY changed_at DESC;
```

---

## 🚀 실전 배포 가이드

### 1단계: 데이터베이스 마이그레이션

```bash
# PostgreSQL
psql -U turafic_user -d turafic -f server/migrations/add_dynamic_ranking_groups.sql

# 성공 메시지 확인:
# ========================================
# 대장-쫄병 시스템 DB 마이그레이션 완료!
# ========================================
```

### 2단계: 서버 시작

```bash
cd D:\Project\Navertrafic
python server/main.py

# 또는 Uvicorn
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3단계: 그룹 초기화

```python
# 스크립트: init_groups.py
import requests

# 트래픽 그룹 3개 생성
for i in range(1, 4):
    response = requests.post(
        "http://localhost:8000/api/v1/ranking-groups/groups/create",
        json={
            "group_name": f"Traffic Group {i}",
            "group_type": "traffic",
            "leader_bot_id": f"leader-{i:03d}",
            "initial_minion_count": 7
        }
    )
    print(f"그룹 {i} 생성: {response.json()}")

# 순위 체크 그룹 1개 생성
response = requests.post(
    "http://localhost:8000/api/v1/ranking-groups/groups/create",
    json={
        "group_name": "Rank Checker Group",
        "group_type": "rank_checker",
        "leader_bot_id": "leader-rank-001",
        "initial_minion_count": 7
    }
)
print(f"순위 체크 그룹 생성: {response.json()}")
```

### 4단계: Android APK 설정

**대장 봇 APK 설정**:
```java
// config.properties
bot_role=leader
hotspot_enabled=true
ip_rotation_enabled=true
health_report_interval=300000  // 5분
```

**쫄병 봇 APK 설정**:
```java
// config.properties
bot_role=minion
leader_bot_id=leader-001
auto_connect_hotspot=true
task_completion_report=true
```

---

## 🎯 성능 지표

### 목표 KPI

| 지표 | 목표값 | 측정 방법 |
|------|--------|-----------|
| **대장 Health Score** | ≥80 | 5분 주기 모니터링 |
| **쫄병 연결 성공률** | ≥95% | 연결 시도 대비 성공 횟수 |
| **IP 변경 간격** | 5~6분 | last_ip_change_at 차이 |
| **작업 중단률** | <5% | IP 변경 시 working_minions / total_minions |
| **쫄병 수 안정성** | 90% 시간 동안 목표치 유지 | 조정 빈도 추적 |

### 대시보드 지표

```javascript
// 실시간 모니터링 대시보드
{
    "total_groups": 4,
    "active_groups": 4,
    "total_bots": 32,
    "active_leaders": 4,
    "active_minions": 28,
    "average_health_score": 85.3,
    "average_minion_count": 7.0,
    "ip_changes_today": 120,
    "minion_adjustments_today": 8
}
```

---

## 🛠️ 문제 해결

### 문제 1: 쫄병이 대장 핫스팟에 연결 안됨

**증상**:
```json
{
    "connection_status": "disconnected",
    "connection_retry_count": 10
}
```

**해결**:
1. 대장 봇 핫스팟 활성화 확인
2. 쫄병의 WiFi 설정 확인 (저장된 SSID)
3. IP 대역 충돌 확인 (192.168.43.x)

---

### 문제 2: Health Score가 계속 낮음

**증상**:
```json
{
    "health_score": 45.0,
    "battery_level": 8,
    "device_temperature": 48
}
```

**해결**:
1. 대장 폰 충전 (배터리 ≥30%)
2. 냉각 대기 (온도 ≤40°)
3. 임시로 다른 대장으로 교체

---

### 문제 3: 쫄병 수가 자주 변경됨

**증상**:
```
✅ [쫄병 수 조정] Group 1: 7 → 6 (배터리 28%)
✅ [쫄병 수 조정] Group 1: 6 → 7 (배터리 32%)
✅ [쫄병 수 조정] Group 1: 7 → 6 (배터리 29%)
```

**해결**:
1. 배터리 임계값 조정 (30% → 25%)
2. Health Score 버퍼 추가 (±5% 여유)
3. 조정 주기 연장 (5분 → 10분)

---

## 📚 관련 문서

- [IP_ROTATION_STRATEGY.md](./IP_ROTATION_STRATEGY.md) - IP 로테이션 타이밍 충돌 해결
- [RANKING_SYSTEM_GUIDE.md](./RANKING_SYSTEM_GUIDE.md) - 순위 체크 시스템 전체 가이드
- [CLAUDE.md](../CLAUDE.md) - 프로젝트 전체 아키텍처

---

**생성일**: 2025-11-02
**버전**: 1.0.0
**상태**: ✅ 구현 완료
