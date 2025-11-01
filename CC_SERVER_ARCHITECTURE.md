# C&C 서버 아키텍처: 4계층 모듈형 구조

## 개요

수천 대의 봇 네트워크를 효율적으로 제어하기 위한 **Command & Control(C&C) 서버**의 완전한 구현입니다.

### 설계 원칙
- **모듈 분리**: 각 계층은 독립적으로 개발/배포 가능
- **확장성**: 수평 확장을 통해 수만 대의 봇 지원
- **안정성**: 장애 복구 및 실시간 모니터링
- **보안**: 인증/인가 및 속도 제한

---

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                      봇 네트워크 (수천 대)                       │
│  봇 #1 ↔ 봇 #2 ↔ ... ↔ 봇 #N                                 │
└────────────────┬────────────────────────────────────────────┘
                 ↓ REST API (HTTPS)
┌─────────────────────────────────────────────────────────────┐
│                    1️⃣ API 게이트웨이                          │
│  - 인증/인가 (API Key, bot_id 검증)                           │
│  - 요청 라우팅 (Load Balancer)                               │
│  - 속도 제한 (Rate Limiting: 10 req/sec per bot)             │
│  - 로깅 및 모니터링                                           │
└────────────────┬────────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────────┐
│                  2️⃣ 작업 할당 엔진 (두뇌)                      │
│  - 캠페인 관리 (Campaign Manager)                            │
│  - 그룹 관리 (A/B Test Group Allocator)                      │
│  - 작업 패턴 생성 (Task Pattern Generator)                   │
│  - 봇 상태 추적 (Bot State Tracker)                          │
│  - 자가 치유 트리거 (Failure Detection)                       │
└────────────┬───────────────────┬────────────────────────────┘
             ↓                   ↓
┌────────────────────────┐  ┌───────────────────────────────┐
│   3️⃣ 데이터 저장소      │  │  4️⃣ 관리자 대시보드            │
│                        │  │                               │
│  📊 PostgreSQL         │  │  📈 실시간 모니터링             │
│    - bots 테이블       │  │    - 활성 봇 수                │
│    - tasks 테이블      │  │    - 작업 처리량               │
│    - results 테이블    │  │    - 성공/실패율               │
│    - campaigns 테이블  │  │                               │
│                        │  │  🎯 캠페인 관리                │
│  🚀 Redis (Cache)      │  │    - 신규 캠페인 생성          │
│    - UI 좌표 맵        │  │    - A/B 테스트 설계           │
│    - 봇 상태 캐시      │  │    - 실시간 수정/중지          │
│                        │  │                               │
│  📁 파일 시스템/S3     │  │  🤖 봇 관리                    │
│    - 테스트 매트릭스   │  │    - 봇 목록/상세 조회         │
│    - 스크린샷 저장     │  │    - 개별 봇 제어              │
│    - 결과 보고서       │  │    - 로그 분석                │
└────────────────────────┘  └───────────────────────────────┘
```

---

## 1️⃣ API 게이트웨이 (API Gateway)

### 역할
봇 네트워크와 서버 내부 로직 간의 **유일한 통로**

### 핵심 기능

#### 1.1 인증 및 인가

```python
# src/cc_server/gateway/auth.py

from functools import wraps
from flask import request, jsonify
import hashlib
import hmac
import time

class AuthManager:
    """API 인증 관리자"""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.valid_api_keys = set()  # 유효한 API 키 세트

    def generate_api_key(self, bot_id: str) -> str:
        """봇 ID로 API 키 생성"""
        timestamp = str(int(time.time()))
        payload = f"{bot_id}:{timestamp}"
        signature = hmac.new(
            self.secret_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        api_key = f"{bot_id}.{timestamp}.{signature}"
        self.valid_api_keys.add(api_key)
        return api_key

    def verify_api_key(self, api_key: str) -> tuple[bool, str]:
        """
        API 키 검증

        Returns:
            (유효 여부, bot_id)
        """
        try:
            parts = api_key.split('.')
            if len(parts) != 3:
                return False, ""

            bot_id, timestamp, signature = parts

            # 타임스탬프 검증 (24시간 유효)
            if int(time.time()) - int(timestamp) > 86400:
                return False, ""

            # 서명 검증
            payload = f"{bot_id}:{timestamp}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()

            if signature == expected_signature:
                return True, bot_id

        except Exception as e:
            print(f"⚠️ API 키 검증 오류: {e}")

        return False, ""


def require_auth(f):
    """인증 필수 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Authorization 헤더 확인
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        api_key = auth_header[7:]  # "Bearer " 제거

        # API 키 검증
        from src.cc_server.gateway.app import auth_manager
        valid, bot_id = auth_manager.verify_api_key(api_key)

        if not valid:
            return jsonify({"error": "Invalid API key"}), 403

        # bot_id를 request context에 저장
        request.bot_id = bot_id

        return f(*args, **kwargs)

    return decorated_function
```

#### 1.2 속도 제한 (Rate Limiting)

```python
# src/cc_server/gateway/rate_limiter.py

from collections import defaultdict
from datetime import datetime, timedelta
from flask import request, jsonify
from functools import wraps

class RateLimiter:
    """속도 제한기"""

    def __init__(self, max_requests: int = 10, window_seconds: int = 1):
        """
        Args:
            max_requests: 허용할 최대 요청 수
            window_seconds: 시간 윈도우 (초)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)  # bot_id → [timestamp1, timestamp2, ...]

    def is_allowed(self, bot_id: str) -> bool:
        """요청 허용 여부 확인"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # 오래된 요청 제거
        self.requests[bot_id] = [
            ts for ts in self.requests[bot_id]
            if ts > cutoff
        ]

        # 제한 확인
        if len(self.requests[bot_id]) >= self.max_requests:
            return False

        # 현재 요청 기록
        self.requests[bot_id].append(now)
        return True

    def cleanup(self):
        """메모리 정리 (오래된 기록 삭제)"""
        cutoff = datetime.now() - timedelta(minutes=10)

        for bot_id in list(self.requests.keys()):
            self.requests[bot_id] = [
                ts for ts in self.requests[bot_id]
                if ts > cutoff
            ]

            if not self.requests[bot_id]:
                del self.requests[bot_id]


def rate_limit(limiter: RateLimiter):
    """속도 제한 데코레이터"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            bot_id = getattr(request, 'bot_id', None)

            if not bot_id:
                return jsonify({"error": "Bot ID not found"}), 400

            if not limiter.is_allowed(bot_id):
                return jsonify({
                    "error": "Rate limit exceeded",
                    "retry_after": limiter.window_seconds
                }), 429

            return f(*args, **kwargs)

        return decorated_function
    return decorator
```

#### 1.3 Flask API 게이트웨이 서버

```python
# src/cc_server/gateway/app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
from src.cc_server.gateway.auth import AuthManager, require_auth
from src.cc_server.gateway.rate_limiter import RateLimiter, rate_limit
import logging

# Flask 앱 생성
app = Flask(__name__)
CORS(app)

# 인증 및 속도 제한 초기화
auth_manager = AuthManager(secret_key="your-secret-key-here")
rate_limiter = RateLimiter(max_requests=10, window_seconds=1)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/health', methods=['GET'])
def health_check():
    """헬스 체크"""
    return jsonify({"status": "healthy"}), 200


@app.route('/register', methods=['POST'])
def register_bot():
    """
    봇 등록 엔드포인트

    POST /register
    Body: {
        "device_id": "abc123...",
        "manufacturer": "Samsung",
        "model": "SM-G991N",
        ...
    }

    Response: {
        "bot_id": "uuid...",
        "api_key": "bot_id.timestamp.signature",
        "status": "registered"
    }
    """
    data = request.json
    device_id = data.get("device_id")

    if not device_id:
        return jsonify({"error": "device_id is required"}), 400

    # 작업 할당 엔진에 전달
    from src.cc_server.engine.task_engine import task_engine
    bot_id = task_engine.register_bot(device_id, data)

    # API 키 생성
    api_key = auth_manager.generate_api_key(bot_id)

    logger.info(f"✅ 봇 등록: {bot_id}")

    return jsonify({
        "bot_id": bot_id,
        "api_key": api_key,
        "status": "registered"
    }), 200


@app.route('/get_task', methods=['GET'])
@require_auth
@rate_limit(rate_limiter)
def get_task():
    """
    작업 요청 엔드포인트

    GET /get_task
    Headers: Authorization: Bearer {api_key}

    Response: {
        "task_id": "...",
        "test_case": "IT-001",
        ...
    }
    """
    bot_id = request.bot_id

    # 작업 할당 엔진에서 작업 가져오기
    from src.cc_server.engine.task_engine import task_engine
    task = task_engine.get_next_task(bot_id)

    if task:
        logger.info(f"📤 작업 할당: {task['task_id']} → 봇 {bot_id}")
        return jsonify(task), 200
    else:
        return jsonify({"task": None, "message": "No tasks available"}), 200


@app.route('/report_result', methods=['POST'])
@require_auth
@rate_limit(rate_limiter)
def report_result():
    """
    작업 결과 보고

    POST /report_result
    Headers: Authorization: Bearer {api_key}
    Body: {
        "task_id": "...",
        "success": true,
        "duration": 45.3,
        "result": {...}
    }
    """
    bot_id = request.bot_id
    data = request.json

    task_id = data.get("task_id")
    success = data.get("success", False)
    duration = data.get("duration", 0)
    result_data = data.get("result", {})

    # 작업 할당 엔진에 결과 전달
    from src.cc_server.engine.task_engine import task_engine
    task_engine.report_result(bot_id, task_id, success, duration, result_data)

    logger.info(f"✅ 결과 보고: {task_id} (봇 {bot_id}) - {'성공' if success else '실패'}")

    return jsonify({"status": "success"}), 200


@app.route('/feedback/error', methods=['POST'])
@require_auth
def report_error():
    """
    자가 치유를 위한 오류 보고

    POST /feedback/error
    Headers: Authorization: Bearer {api_key}
    Body: {
        "task_id": "...",
        "error_type": "ui_not_found",
        "element_name": "search_bar",
        "screenshot": "base64_encoded_image"
    }
    """
    bot_id = request.bot_id
    data = request.json

    # 자가 치유 시스템에 전달
    from src.cc_server.engine.self_healing import self_healing_system
    self_healing_system.handle_error_report(bot_id, data)

    logger.warning(f"⚠️ 오류 보고: 봇 {bot_id} - {data.get('error_type')}")

    return jsonify({"status": "received"}), 200


@app.route('/heartbeat', methods=['POST'])
@require_auth
def heartbeat():
    """
    생존 신호

    POST /heartbeat
    Headers: Authorization: Bearer {api_key}
    Body: {
        "battery_level": 75,
        "ip": "192.168.1.100"
    }
    """
    bot_id = request.bot_id
    data = request.json

    # 작업 할당 엔진에 전달
    from src.cc_server.engine.task_engine import task_engine
    task_engine.update_bot_heartbeat(bot_id, data)

    return jsonify({"status": "alive"}), 200


if __name__ == '__main__':
    logger.info("\n" + "="*80)
    logger.info("🚀 C&C 서버 API 게이트웨이 시작")
    logger.info("="*80)

    app.run(host='0.0.0.0', port=5000, debug=False)
```

---

## 2️⃣ 작업 할당 엔진 (Task Assignment Engine)

### 역할
서버의 **두뇌**: 어떤 봇에게 어떤 작업을 할당할지 결정

### 핵심 컴포넌트

#### 2.1 캠페인 관리자

```python
# src/cc_server/engine/campaign_manager.py

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum
import json

class CampaignStatus(Enum):
    """캠페인 상태"""
    DRAFT = "draft"           # 초안
    RUNNING = "running"       # 실행 중
    PAUSED = "paused"         # 일시 정지
    COMPLETED = "completed"   # 완료
    CANCELLED = "cancelled"   # 취소


@dataclass
class Campaign:
    """캠페인 정의"""
    campaign_id: str
    name: str
    description: str
    target_product: Dict          # 목표 상품 정보
    test_matrix: List[Dict]       # 테스트 매트릭스
    total_iterations: int         # 총 반복 횟수
    status: CampaignStatus = CampaignStatus.DRAFT
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # 통계
    assigned_bots: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "status": self.status.value,
            "target_product": self.target_product,
            "total_iterations": self.total_iterations,
            "assigned_bots": self.assigned_bots,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "progress": self.completed_tasks / (self.total_iterations * len(self.test_matrix)) if self.total_iterations > 0 else 0,
        }


class CampaignManager:
    """캠페인 관리자"""

    def __init__(self):
        self.campaigns: Dict[str, Campaign] = {}
        self.active_campaign: Optional[str] = None

    def create_campaign(
        self,
        name: str,
        description: str,
        target_product: Dict,
        test_matrix_path: str,
        total_iterations: int = 100
    ) -> Campaign:
        """새 캠페인 생성"""
        import uuid

        campaign_id = str(uuid.uuid4())

        # 테스트 매트릭스 로드
        with open(test_matrix_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        test_matrix = data.get("test_cases", [])

        campaign = Campaign(
            campaign_id=campaign_id,
            name=name,
            description=description,
            target_product=target_product,
            test_matrix=test_matrix,
            total_iterations=total_iterations,
        )

        self.campaigns[campaign_id] = campaign

        print(f"✅ 캠페인 생성: {campaign_id} - {name}")
        print(f"   테스트 케이스: {len(test_matrix)}개")
        print(f"   총 작업: {len(test_matrix) * total_iterations}개")

        return campaign

    def start_campaign(self, campaign_id: str) -> bool:
        """캠페인 시작"""
        campaign = self.campaigns.get(campaign_id)

        if not campaign:
            return False

        campaign.status = CampaignStatus.RUNNING
        campaign.started_at = datetime.now()
        self.active_campaign = campaign_id

        print(f"🚀 캠페인 시작: {campaign.name}")

        return True

    def pause_campaign(self, campaign_id: str) -> bool:
        """캠페인 일시 정지"""
        campaign = self.campaigns.get(campaign_id)

        if not campaign:
            return False

        campaign.status = CampaignStatus.PAUSED
        print(f"⏸️ 캠페인 일시 정지: {campaign.name}")

        return True

    def get_active_campaign(self) -> Optional[Campaign]:
        """현재 활성 캠페인 반환"""
        if self.active_campaign:
            return self.campaigns.get(self.active_campaign)
        return None

    def update_progress(self, campaign_id: str, success: bool):
        """캠페인 진행 상황 업데이트"""
        campaign = self.campaigns.get(campaign_id)

        if not campaign:
            return

        if success:
            campaign.completed_tasks += 1
        else:
            campaign.failed_tasks += 1

        # 완료 확인
        total_tasks = len(campaign.test_matrix) * campaign.total_iterations
        if campaign.completed_tasks + campaign.failed_tasks >= total_tasks:
            campaign.status = CampaignStatus.COMPLETED
            campaign.completed_at = datetime.now()
            print(f"🎉 캠페인 완료: {campaign.name}")
```

#### 2.2 작업 할당 엔진 (메인)

```python
# src/cc_server/engine/task_engine.py

from typing import Dict, Optional
from src.cc_server.engine.campaign_manager import CampaignManager
from src.distributed.bot_registry import BotRegistry, BotStatus
from src.distributed.models import Task
import uuid

class TaskEngine:
    """작업 할당 엔진"""

    def __init__(self):
        self.campaign_manager = CampaignManager()
        self.bot_registry = BotRegistry()
        self.task_queue: Dict[str, list] = {}  # group_name → [task1, task2, ...]

    def register_bot(self, device_id: str, device_info: dict) -> str:
        """봇 등록"""
        bot_id = self.bot_registry.register_bot(device_id, device_info)
        return bot_id

    def load_campaign_tasks(self, campaign_id: str):
        """캠페인의 작업들을 큐에 로드"""
        campaign = self.campaign_manager.campaigns.get(campaign_id)

        if not campaign:
            return

        # 각 테스트 케이스별로 작업 생성
        for tc in campaign.test_matrix:
            tc_id = tc["tc"]
            self.task_queue[tc_id] = []

            for i in range(campaign.total_iterations):
                task = Task(
                    task_id=f"{tc_id}-{i+1:03d}",
                    test_case=tc_id,
                    profile=tc["profile"],
                    behavior=tc["behavior"],
                    target_url=campaign.target_product.get("product_url", ""),
                    search_keyword=campaign.target_product.get("search_keyword", ""),
                    actions=tc.get("actions", []),
                )
                self.task_queue[tc_id].append(task)

        print(f"✅ 캠페인 {campaign.name} 작업 로드 완료")

    def assign_bots_to_groups(self):
        """봇들을 그룹에 균등 분배"""
        campaign = self.campaign_manager.get_active_campaign()

        if not campaign:
            return

        idle_bots = self.bot_registry.get_idle_bots()
        groups = list(self.task_queue.keys())

        for i, bot in enumerate(idle_bots):
            group_name = groups[i % len(groups)]
            self.bot_registry.assign_group(bot.bot_id, group_name)

        campaign.assigned_bots = len(idle_bots)

    def get_next_task(self, bot_id: str) -> Optional[Dict]:
        """봇에게 다음 작업 할당"""
        bot = self.bot_registry.get_bot(bot_id)

        if not bot or not bot.assigned_group:
            return None

        # 해당 그룹의 작업 큐
        group_tasks = self.task_queue.get(bot.assigned_group, [])

        if not group_tasks:
            return None

        # 첫 번째 작업 할당
        task = group_tasks.pop(0)
        bot.current_task = task.task_id
        self.bot_registry.update_bot_status(bot_id, BotStatus.WORKING)

        return task.to_dict()

    def report_result(self, bot_id: str, task_id: str, success: bool,
                     duration: float, result_data: dict):
        """작업 결과 처리"""
        # 봇 상태 업데이트
        self.bot_registry.record_task_completion(bot_id, success, duration)

        bot = self.bot_registry.get_bot(bot_id)
        if bot:
            bot.current_task = None
            self.bot_registry.update_bot_status(bot_id, BotStatus.IDLE)

        # 캠페인 진행률 업데이트
        campaign = self.campaign_manager.get_active_campaign()
        if campaign:
            self.campaign_manager.update_progress(campaign.campaign_id, success)

        # 결과 저장
        self._save_result(bot_id, task_id, success, duration, result_data)

    def update_bot_heartbeat(self, bot_id: str, data: dict):
        """봇 생존 신호 처리"""
        bot = self.bot_registry.get_bot(bot_id)
        if bot:
            bot.last_seen = datetime.now()
            bot.battery_level = data.get("battery_level")
            if data.get("ip"):
                self.bot_registry.update_bot_ip(bot_id, data["ip"])

    def _save_result(self, bot_id: str, task_id: str, success: bool,
                     duration: float, result_data: dict):
        """결과 저장 (파일 또는 DB)"""
        from pathlib import Path
        import json
        from datetime import datetime

        result_dir = Path("data/distributed_results")
        result_dir.mkdir(parents=True, exist_ok=True)

        result_file = result_dir / f"{task_id}.json"

        result = {
            "bot_id": bot_id,
            "task_id": task_id,
            "success": success,
            "duration": duration,
            "timestamp": datetime.now().isoformat(),
            "data": result_data,
        }

        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)


# 전역 인스턴스
task_engine = TaskEngine()
```

---

## 3️⃣ 데이터 저장소 (Data Store)

### PostgreSQL 스키마

```sql
-- src/cc_server/database/schema.sql

-- 봇 테이블
CREATE TABLE bots (
    bot_id VARCHAR(36) PRIMARY KEY,
    device_id VARCHAR(64) UNIQUE NOT NULL,
    manufacturer VARCHAR(64),
    model VARCHAR(64),
    android_version VARCHAR(16),
    screen_resolution VARCHAR(16),
    current_ip VARCHAR(45),
    last_ip_change TIMESTAMP,
    status VARCHAR(16) DEFAULT 'offline',
    last_seen TIMESTAMP,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_group VARCHAR(32),
    current_task VARCHAR(64),
    completed_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0,
    avg_task_duration FLOAT DEFAULT 0.0,
    success_rate FLOAT DEFAULT 1.0,
    battery_level INTEGER,
    INDEX idx_status (status),
    INDEX idx_assigned_group (assigned_group),
    INDEX idx_last_seen (last_seen)
);

-- 캠페인 테이블
CREATE TABLE campaigns (
    campaign_id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    target_product JSON,
    test_matrix JSON,
    total_iterations INTEGER DEFAULT 100,
    status VARCHAR(16) DEFAULT 'draft',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    assigned_bots INTEGER DEFAULT 0,
    completed_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0,
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

-- 작업 테이블
CREATE TABLE tasks (
    task_id VARCHAR(64) PRIMARY KEY,
    campaign_id VARCHAR(36) REFERENCES campaigns(campaign_id),
    bot_id VARCHAR(36) REFERENCES bots(bot_id),
    test_case VARCHAR(32),
    profile VARCHAR(8),
    behavior VARCHAR(32),
    status VARCHAR(16) DEFAULT 'pending',
    assigned_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration FLOAT,
    success BOOLEAN,
    INDEX idx_campaign (campaign_id),
    INDEX idx_bot (bot_id),
    INDEX idx_status (status)
);

-- 결과 테이블
CREATE TABLE results (
    result_id SERIAL PRIMARY KEY,
    task_id VARCHAR(64) REFERENCES tasks(task_id),
    bot_id VARCHAR(36) REFERENCES bots(bot_id),
    before_rank INTEGER,
    after_rank INTEGER,
    rank_change INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    error_log TEXT,
    screenshot_path VARCHAR(256),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_task (task_id),
    INDEX idx_created_at (created_at)
);

-- UI 좌표 맵 캐시 (Redis 대신 PostgreSQL 사용 가능)
CREATE TABLE ui_coordinate_maps (
    map_id SERIAL PRIMARY KEY,
    app_name VARCHAR(64),
    app_version VARCHAR(16),
    resolution VARCHAR(16),
    element_name VARCHAR(64),
    x INTEGER,
    y INTEGER,
    width INTEGER,
    height INTEGER,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_name, app_version, resolution, element_name),
    INDEX idx_app_resolution (app_name, resolution)
);
```

---

## 4️⃣ 관리자 대시보드 (Admin Dashboard)

### Flask + React 구조

```python
# src/cc_server/dashboard/app.py

from flask import Flask, render_template, jsonify
from src.cc_server.engine.task_engine import task_engine

dashboard_app = Flask(__name__)


@dashboard_app.route('/')
def index():
    """대시보드 메인 페이지"""
    return render_template('dashboard.html')


@dashboard_app.route('/api/statistics')
def get_statistics():
    """실시간 통계 API"""
    stats = task_engine.bot_registry.get_statistics()

    campaign = task_engine.campaign_manager.get_active_campaign()
    if campaign:
        stats["campaign"] = campaign.to_dict()

    return jsonify(stats)


@dashboard_app.route('/api/bots')
def get_bots():
    """봇 목록 API"""
    bots = [
        bot.to_dict()
        for bot in task_engine.bot_registry._bots.values()
    ]
    return jsonify({"bots": bots, "total": len(bots)})


@dashboard_app.route('/api/campaigns')
def get_campaigns():
    """캠페인 목록 API"""
    campaigns = [
        campaign.to_dict()
        for campaign in task_engine.campaign_manager.campaigns.values()
    ]
    return jsonify({"campaigns": campaigns, "total": len(campaigns)})


@dashboard_app.route('/api/campaigns/<campaign_id>/start', methods=['POST'])
def start_campaign(campaign_id):
    """캠페인 시작"""
    success = task_engine.campaign_manager.start_campaign(campaign_id)

    if success:
        # 작업 로드 및 봇 할당
        task_engine.load_campaign_tasks(campaign_id)
        task_engine.assign_bots_to_groups()
        return jsonify({"status": "started"}), 200
    else:
        return jsonify({"error": "Campaign not found"}), 404


if __name__ == '__main__':
    dashboard_app.run(host='0.0.0.0', port=8080, debug=True)
```

### React 대시보드 UI (간략)

```jsx
// src/cc_server/dashboard/static/Dashboard.jsx

import React, { useState, useEffect } from 'react';

function Dashboard() {
  const [stats, setStats] = useState({});
  const [bots, setBots] = useState([]);

  useEffect(() => {
    // 1초마다 통계 갱신
    const interval = setInterval(async () => {
      const response = await fetch('/api/statistics');
      const data = await response.json();
      setStats(data);
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard">
      <h1>🎮 C&C 서버 대시보드</h1>

      <div className="stats">
        <div className="card">
          <h3>활성 봇</h3>
          <p className="number">{stats.online_bots || 0}</p>
        </div>

        <div className="card">
          <h3>작업 중</h3>
          <p className="number">{stats.working_bots || 0}</p>
        </div>

        <div className="card">
          <h3>성공률</h3>
          <p className="number">
            {stats.campaign?.completed_tasks /
              (stats.campaign?.completed_tasks + stats.campaign?.failed_tasks) * 100 || 0}%
          </p>
        </div>
      </div>

      {/* 실시간 차트, 봇 목록 등 추가 */}
    </div>
  );
}

export default Dashboard;
```

---

## 실행 예시

### 1. 서버 시작

```bash
# API 게이트웨이
python src/cc_server/gateway/app.py

# 관리자 대시보드 (다른 터미널)
python src/cc_server/dashboard/app.py
```

### 2. 캠페인 생성 및 시작

```python
# 관리자 스크립트
from src.cc_server.engine.task_engine import task_engine

# 캠페인 생성
campaign = task_engine.campaign_manager.create_campaign(
    name="단백질쉐이크 순위 상승 테스트",
    description="12개 조합 × 100회 반복",
    target_product={
        "product_url": "https://shopping.naver.com/...",
        "search_keyword": "단백질쉐이크"
    },
    test_matrix_path="config/test_matrix.json",
    total_iterations=100
)

# 캠페인 시작
task_engine.campaign_manager.start_campaign(campaign.campaign_id)
task_engine.load_campaign_tasks(campaign.campaign_id)
task_engine.assign_bots_to_groups()

print("✅ 캠페인 시작 완료!")
```

### 3. 봇 클라이언트 실행

```bash
python src/distributed/bot_client.py
```

---

## 결론

이 4계층 C&C 서버 아키텍처는:

- ✅ **확장성**: 수평 확장으로 수만 대 봇 지원
- ✅ **안정성**: 장애 복구 및 실시간 모니터링
- ✅ **보안**: 인증/인가 및 속도 제한
- ✅ **유지보수성**: 모듈 분리로 독립 개발/배포
- ✅ **실시간 제어**: 관리자 대시보드로 즉시 제어

모든 혁신 아이디어(하이브리드 제어, 자가 치유, 분산 테스팅)의 기반이 됩니다.
