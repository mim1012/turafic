# 봇 ID 기반 상태 저장(Stateful) 아키텍처

## 핵심 원칙

> **IP는 봇의 "임시 주소"이고, 봇 ID는 봇의 "주민등록번호"입니다.**

모든 봇은 고유한 `bot_id`로 식별되며, 서버는 각 봇의 상태를 추적합니다.

---

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                   중앙 제어 서버                           │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  📊 봇 레지스트리 (Bot Registry)                           │
│     - bot_id → Bot 정보 매핑                              │
│     - 상태 추적 (연결, 작업 중, 유휴)                       │
│     - 작업 이력 (누적 통계)                                │
│                                                           │
│  🎯 작업 할당기 (Task Allocator)                          │
│     - 그룹별 작업 할당                                     │
│     - 봇 능력 기반 매칭                                    │
│     - 부하 분산                                           │
│                                                           │
│  📡 실시간 통신 (WebSocket/MQTT)                          │
│     - 봇 등록/해제                                        │
│     - 명령 전달                                           │
│     - 결과 수집                                           │
│                                                           │
└─────────────────────────────────────────────────────────┘
                         ↕️  (bot_id 기반 통신)
        ┌────────────────┴────────────────┐
        ↓                                  ↓
┌─────────────────┐              ┌─────────────────┐
│  봇 #1           │              │  봇 #N           │
│  ID: a1b2c3d4   │              │  ID: x9y8z7w6   │
├─────────────────┤              ├─────────────────┤
│ IP: 변동 (비행기모드)│          │ IP: 변동 (비행기모드)│
│ 상태: 캐시됨      │              │ 상태: 캐시됨      │
└─────────────────┘              └─────────────────┘
```

---

## 데이터 모델

### 1. 봇 정보 (Bot Info)

```python
# src/distributed/models.py

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
from enum import Enum

class BotStatus(Enum):
    """봇 상태"""
    OFFLINE = "offline"          # 연결 끊김
    IDLE = "idle"               # 대기 중
    WORKING = "working"         # 작업 중
    ERROR = "error"             # 오류 발생
    MAINTENANCE = "maintenance"  # 유지보수 중

@dataclass
class BotInfo:
    """봇 정보 데이터 클래스"""

    # 고유 식별자
    bot_id: str                          # UUID4 (예: "a1b2c3d4-e5f6-...")

    # 기기 정보
    device_id: str                       # Android ID 또는 IMEI
    manufacturer: str                    # 제조사 (예: "Samsung")
    model: str                          # 모델명 (예: "SM-G991N")
    android_version: str                # Android 버전 (예: "12")
    screen_resolution: str              # 화면 해상도 (예: "1080x2400")

    # 네트워크 정보
    current_ip: Optional[str] = None    # 현재 IP (변동)
    last_ip_change: Optional[datetime] = None  # 마지막 IP 변경 시간
    carrier: Optional[str] = None       # 통신사 (예: "SKT")

    # 상태 정보
    status: BotStatus = BotStatus.OFFLINE
    last_seen: Optional[datetime] = None
    registered_at: datetime = field(default_factory=datetime.now)

    # 작업 정보
    assigned_group: Optional[str] = None    # 할당된 그룹 (예: "TC-001")
    current_task: Optional[str] = None      # 현재 작업 ID
    completed_tasks: int = 0                # 완료한 작업 수
    failed_tasks: int = 0                   # 실패한 작업 수

    # 성능 정보
    avg_task_duration: float = 0.0         # 평균 작업 시간 (초)
    success_rate: float = 1.0              # 성공률 (0.0~1.0)
    battery_level: Optional[int] = None    # 배터리 잔량 (%)

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            "bot_id": self.bot_id,
            "device_id": self.device_id,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "android_version": self.android_version,
            "screen_resolution": self.screen_resolution,
            "current_ip": self.current_ip,
            "status": self.status.value,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "registered_at": self.registered_at.isoformat(),
            "assigned_group": self.assigned_group,
            "current_task": self.current_task,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "success_rate": self.success_rate,
            "battery_level": self.battery_level,
        }
```

### 2. 작업 정의 (Task Definition)

```python
@dataclass
class Task:
    """작업 정의"""

    task_id: str                        # 작업 고유 ID
    test_case: str                      # 테스트 케이스 (예: "IT-001")
    profile: str                        # 브라우저 지문 프로필 ("A", "B", "C")
    behavior: str                       # 행동 패턴 ("빠른이탈", "일반둘러보기" ...)

    # 작업 상세
    target_url: str                     # 목표 URL
    search_keyword: str                 # 검색 키워드
    actions: List[dict]                 # 수행할 액션 리스트

    # 메타데이터
    created_at: datetime = field(default_factory=datetime.now)
    timeout: int = 300                  # 타임아웃 (초)
    priority: int = 5                   # 우선순위 (1~10)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "test_case": self.test_case,
            "profile": self.profile,
            "behavior": self.behavior,
            "target_url": self.target_url,
            "search_keyword": self.search_keyword,
            "actions": self.actions,
            "timeout": self.timeout,
            "priority": self.priority,
        }
```

---

## 서버 구현 (Flask)

### 1. 봇 레지스트리 관리자

```python
# src/distributed/bot_registry.py

from typing import Dict, List, Optional
from datetime import datetime, timedelta
import uuid
from src.distributed.models import BotInfo, BotStatus

class BotRegistry:
    """봇 레지스트리: 모든 봇의 상태를 추적"""

    def __init__(self):
        self._bots: Dict[str, BotInfo] = {}  # bot_id → BotInfo
        self._device_to_bot: Dict[str, str] = {}  # device_id → bot_id

    def register_bot(self, device_id: str, device_info: dict) -> str:
        """
        봇 등록 또는 재등록

        Args:
            device_id: 기기 고유 ID (Android ID)
            device_info: 기기 정보 딕셔너리

        Returns:
            bot_id: 발급된 봇 ID
        """
        # 이미 등록된 기기인지 확인
        if device_id in self._device_to_bot:
            bot_id = self._device_to_bot[device_id]
            bot = self._bots[bot_id]

            # 상태 업데이트
            bot.status = BotStatus.IDLE
            bot.last_seen = datetime.now()
            bot.current_ip = device_info.get("ip")
            bot.battery_level = device_info.get("battery_level")

            print(f"✅ 봇 재연결: {bot_id} (기기: {device_id})")
            return bot_id

        # 새 봇 등록
        bot_id = str(uuid.uuid4())

        bot = BotInfo(
            bot_id=bot_id,
            device_id=device_id,
            manufacturer=device_info.get("manufacturer", "Unknown"),
            model=device_info.get("model", "Unknown"),
            android_version=device_info.get("android_version", "Unknown"),
            screen_resolution=device_info.get("screen_resolution", "1080x1920"),
            current_ip=device_info.get("ip"),
            status=BotStatus.IDLE,
            last_seen=datetime.now(),
            battery_level=device_info.get("battery_level"),
        )

        self._bots[bot_id] = bot
        self._device_to_bot[device_id] = bot_id

        print(f"🆕 신규 봇 등록: {bot_id}")
        print(f"   기기: {bot.manufacturer} {bot.model}")
        print(f"   해상도: {bot.screen_resolution}")

        return bot_id

    def get_bot(self, bot_id: str) -> Optional[BotInfo]:
        """봇 정보 조회"""
        return self._bots.get(bot_id)

    def update_bot_status(self, bot_id: str, status: BotStatus):
        """봇 상태 업데이트"""
        bot = self._bots.get(bot_id)
        if bot:
            bot.status = status
            bot.last_seen = datetime.now()

    def update_bot_ip(self, bot_id: str, new_ip: str):
        """봇 IP 업데이트 (비행기모드 토글 후)"""
        bot = self._bots.get(bot_id)
        if bot:
            if bot.current_ip != new_ip:
                bot.current_ip = new_ip
                bot.last_ip_change = datetime.now()
                print(f"🔄 봇 {bot_id} IP 변경: {new_ip}")

    def assign_group(self, bot_id: str, group_name: str):
        """봇을 특정 그룹에 할당"""
        bot = self._bots.get(bot_id)
        if bot:
            bot.assigned_group = group_name
            print(f"📋 봇 {bot_id} → 그룹 {group_name} 할당")

    def record_task_completion(self, bot_id: str, success: bool, duration: float):
        """작업 완료 기록"""
        bot = self._bots.get(bot_id)
        if bot:
            if success:
                bot.completed_tasks += 1
            else:
                bot.failed_tasks += 1

            # 평균 작업 시간 업데이트 (이동 평균)
            total_tasks = bot.completed_tasks + bot.failed_tasks
            bot.avg_task_duration = (
                (bot.avg_task_duration * (total_tasks - 1) + duration) / total_tasks
            )

            # 성공률 업데이트
            bot.success_rate = bot.completed_tasks / total_tasks if total_tasks > 0 else 1.0

    def get_idle_bots(self, count: int = None) -> List[BotInfo]:
        """대기 중인 봇 목록"""
        idle_bots = [
            bot for bot in self._bots.values()
            if bot.status == BotStatus.IDLE
        ]

        # 성공률 높은 순으로 정렬
        idle_bots.sort(key=lambda b: b.success_rate, reverse=True)

        if count:
            return idle_bots[:count]
        return idle_bots

    def get_bots_by_group(self, group_name: str) -> List[BotInfo]:
        """특정 그룹에 속한 봇들"""
        return [
            bot for bot in self._bots.values()
            if bot.assigned_group == group_name
        ]

    def cleanup_offline_bots(self, timeout_minutes: int = 10):
        """일정 시간 이상 응답 없는 봇을 오프라인 처리"""
        now = datetime.now()
        threshold = now - timedelta(minutes=timeout_minutes)

        for bot in self._bots.values():
            if bot.last_seen and bot.last_seen < threshold:
                if bot.status != BotStatus.OFFLINE:
                    print(f"⚠️ 봇 {bot.bot_id} 타임아웃 → OFFLINE")
                    bot.status = BotStatus.OFFLINE

    def get_statistics(self) -> dict:
        """전체 통계"""
        total = len(self._bots)
        online = sum(1 for b in self._bots.values() if b.status != BotStatus.OFFLINE)
        idle = sum(1 for b in self._bots.values() if b.status == BotStatus.IDLE)
        working = sum(1 for b in self._bots.values() if b.status == BotStatus.WORKING)

        return {
            "total_bots": total,
            "online_bots": online,
            "idle_bots": idle,
            "working_bots": working,
            "offline_bots": total - online,
        }
```

### 2. 작업 할당기

```python
# src/distributed/task_allocator.py

from typing import Dict, List, Optional
import json
from src.distributed.models import Task, BotInfo
from src.distributed.bot_registry import BotRegistry

class TaskAllocator:
    """작업 할당기: 봇에게 작업을 할당하는 전략"""

    def __init__(self, registry: BotRegistry):
        self.registry = registry
        self.task_queue: Dict[str, List[Task]] = {}  # group_name → task_list

    def load_test_matrix(self, matrix_path: str):
        """테스트 매트릭스 로드"""
        with open(matrix_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        test_cases = data.get("test_cases", [])

        for tc in test_cases:
            tc_id = tc["tc"]
            self.task_queue[tc_id] = []

            # 각 테스트 케이스당 100개 작업 생성
            for i in range(100):
                task = Task(
                    task_id=f"{tc_id}-{i+1:03d}",
                    test_case=tc_id,
                    profile=tc["profile"],
                    behavior=tc["behavior"],
                    target_url=tc.get("target_url", ""),
                    search_keyword=tc.get("search_keyword", ""),
                    actions=tc.get("actions", []),
                )
                self.task_queue[tc_id].append(task)

        print(f"✅ 테스트 매트릭스 로드 완료: {len(test_cases)}개 그룹, "
              f"{sum(len(tasks) for tasks in self.task_queue.values())}개 작업")

    def assign_bots_to_groups(self, bots_per_group: int = 100):
        """봇들을 그룹에 균등 분배"""
        idle_bots = self.registry.get_idle_bots()
        groups = list(self.task_queue.keys())

        if not groups:
            print("⚠️ 할당할 그룹이 없습니다.")
            return

        for i, bot in enumerate(idle_bots):
            group_name = groups[i % len(groups)]
            self.registry.assign_group(bot.bot_id, group_name)

        # 통계 출력
        for group in groups:
            assigned = len(self.registry.get_bots_by_group(group))
            print(f"📊 {group}: {assigned}개 봇 할당됨")

    def get_next_task(self, bot_id: str) -> Optional[Task]:
        """봇에게 다음 작업 할당"""
        bot = self.registry.get_bot(bot_id)

        if not bot or not bot.assigned_group:
            return None

        # 해당 그룹의 작업 큐에서 꺼내기
        group_tasks = self.task_queue.get(bot.assigned_group, [])

        if not group_tasks:
            print(f"✅ 봇 {bot_id}: 그룹 {bot.assigned_group} 작업 모두 완료")
            return None

        # 첫 번째 작업 할당
        task = group_tasks.pop(0)
        bot.current_task = task.task_id
        self.registry.update_bot_status(bot_id, BotStatus.WORKING)

        print(f"📤 봇 {bot_id}: 작업 {task.task_id} 할당 "
              f"(남은 작업: {len(group_tasks)}개)")

        return task

    def report_task_result(self, bot_id: str, task_id: str, success: bool,
                          duration: float, result_data: dict):
        """작업 결과 보고"""
        bot = self.registry.get_bot(bot_id)

        if not bot:
            return

        # 통계 업데이트
        self.registry.record_task_completion(bot_id, success, duration)

        # 상태 복원
        bot.current_task = None
        self.registry.update_bot_status(bot_id, BotStatus.IDLE)

        status_emoji = "✅" if success else "❌"
        print(f"{status_emoji} 봇 {bot_id}: 작업 {task_id} 완료 "
              f"({duration:.1f}초, 성공률: {bot.success_rate*100:.1f}%)")

        # 결과 저장 (파일 또는 DB)
        self._save_result(bot_id, task_id, success, duration, result_data)

    def _save_result(self, bot_id: str, task_id: str, success: bool,
                     duration: float, result_data: dict):
        """결과를 파일에 저장"""
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
```

### 3. Flask API 서버

```python
# src/distributed/server.py

from flask import Flask, request, jsonify
from flask_cors import CORS
from src.distributed.bot_registry import BotRegistry, BotStatus
from src.distributed.task_allocator import TaskAllocator
import threading
import time

app = Flask(__name__)
CORS(app)

# 전역 인스턴스
registry = BotRegistry()
allocator = TaskAllocator(registry)

# 테스트 매트릭스 로드
allocator.load_test_matrix("config/test_matrix.json")


@app.route('/register', methods=['POST'])
def register_bot():
    """
    봇 등록 엔드포인트

    POST /register
    Body: {
        "device_id": "abc123...",
        "manufacturer": "Samsung",
        "model": "SM-G991N",
        "android_version": "12",
        "screen_resolution": "1080x2400",
        "ip": "192.168.1.100",
        "battery_level": 85
    }

    Response: {
        "bot_id": "a1b2c3d4-e5f6-...",
        "status": "registered"
    }
    """
    data = request.json
    device_id = data.get("device_id")

    if not device_id:
        return jsonify({"error": "device_id is required"}), 400

    bot_id = registry.register_bot(device_id, data)

    return jsonify({
        "bot_id": bot_id,
        "status": "registered",
        "message": "Bot registered successfully"
    }), 200


@app.route('/get_task', methods=['GET'])
def get_task():
    """
    작업 요청 엔드포인트

    GET /get_task?bot_id=a1b2c3d4-e5f6-...

    Response: {
        "task_id": "IT-001-042",
        "test_case": "IT-001",
        "profile": "A",
        "behavior": "빠른이탈",
        "target_url": "https://shopping.naver.com/...",
        "search_keyword": "무선 이어폰",
        "actions": [...],
        "timeout": 300
    }

    또는 작업 없음:
    {
        "task": null,
        "message": "No tasks available"
    }
    """
    bot_id = request.args.get('bot_id')

    if not bot_id:
        return jsonify({"error": "bot_id is required"}), 400

    bot = registry.get_bot(bot_id)
    if not bot:
        return jsonify({"error": "Bot not found"}), 404

    # 봇의 현재 IP 업데이트
    client_ip = request.remote_addr
    registry.update_bot_ip(bot_id, client_ip)

    # 다음 작업 할당
    task = allocator.get_next_task(bot_id)

    if task:
        return jsonify(task.to_dict()), 200
    else:
        return jsonify({
            "task": None,
            "message": "No tasks available for your group"
        }), 200


@app.route('/report_result', methods=['POST'])
def report_result():
    """
    작업 결과 보고 엔드포인트

    POST /report_result
    Body: {
        "bot_id": "a1b2c3d4-e5f6-...",
        "task_id": "IT-001-042",
        "success": true,
        "duration": 45.3,
        "result": {
            "before_rank": 52,
            "after_rank": 48,
            "rank_change": -4
        }
    }

    Response: {
        "status": "success",
        "next_action": "poll_next_task"
    }
    """
    data = request.json
    bot_id = data.get("bot_id")
    task_id = data.get("task_id")
    success = data.get("success", False)
    duration = data.get("duration", 0)
    result_data = data.get("result", {})

    if not bot_id or not task_id:
        return jsonify({"error": "bot_id and task_id are required"}), 400

    allocator.report_task_result(bot_id, task_id, success, duration, result_data)

    return jsonify({
        "status": "success",
        "next_action": "poll_next_task",
        "message": "Result recorded successfully"
    }), 200


@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    """
    봇 생존 신호 엔드포인트

    POST /heartbeat
    Body: {
        "bot_id": "a1b2c3d4-e5f6-...",
        "battery_level": 75,
        "ip": "192.168.1.101"
    }

    Response: {
        "status": "alive"
    }
    """
    data = request.json
    bot_id = data.get("bot_id")

    if not bot_id:
        return jsonify({"error": "bot_id is required"}), 400

    bot = registry.get_bot(bot_id)
    if not bot:
        return jsonify({"error": "Bot not found"}), 404

    # 상태 업데이트
    bot.last_seen = datetime.now()
    bot.battery_level = data.get("battery_level")

    if data.get("ip"):
        registry.update_bot_ip(bot_id, data["ip"])

    return jsonify({"status": "alive"}), 200


@app.route('/statistics', methods=['GET'])
def get_statistics():
    """
    전체 통계 조회

    GET /statistics

    Response: {
        "total_bots": 1200,
        "online_bots": 1150,
        "idle_bots": 50,
        "working_bots": 1100,
        "offline_bots": 50,
        "groups": {
            "IT-001": {"assigned": 100, "completed": 95, "remaining": 5},
            ...
        }
    }
    """
    stats = registry.get_statistics()

    # 그룹별 통계
    group_stats = {}
    for group_name, tasks in allocator.task_queue.items():
        bots = registry.get_bots_by_group(group_name)
        completed = sum(b.completed_tasks for b in bots)

        group_stats[group_name] = {
            "assigned_bots": len(bots),
            "completed_tasks": completed,
            "remaining_tasks": len(tasks),
        }

    stats["groups"] = group_stats

    return jsonify(stats), 200


@app.route('/assign_groups', methods=['POST'])
def assign_groups():
    """
    봇들을 그룹에 할당 (관리자 명령)

    POST /assign_groups
    Body: {
        "bots_per_group": 100
    }

    Response: {
        "status": "success",
        "assignments": {
            "IT-001": 100,
            "IT-002": 100,
            ...
        }
    }
    """
    data = request.json
    bots_per_group = data.get("bots_per_group", 100)

    allocator.assign_bots_to_groups(bots_per_group)

    # 할당 결과
    assignments = {}
    for group in allocator.task_queue.keys():
        assignments[group] = len(registry.get_bots_by_group(group))

    return jsonify({
        "status": "success",
        "assignments": assignments
    }), 200


# 백그라운드 작업: 오프라인 봇 정리
def cleanup_worker():
    """5분마다 오프라인 봇 정리"""
    while True:
        time.sleep(300)  # 5분
        registry.cleanup_offline_bots(timeout_minutes=10)


# 서버 시작 시 백그라운드 워커 실행
cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
cleanup_thread.start()


if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 분산 봇 제어 서버 시작")
    print("="*80)
    print(f"\n📡 엔드포인트:")
    print(f"  - POST /register          : 봇 등록")
    print(f"  - GET  /get_task          : 작업 요청")
    print(f"  - POST /report_result     : 결과 보고")
    print(f"  - POST /heartbeat         : 생존 신호")
    print(f"  - GET  /statistics        : 통계 조회")
    print(f"  - POST /assign_groups     : 그룹 할당\n")

    app.run(host='0.0.0.0', port=5000, debug=True)
```

---

## 봇 클라이언트 구현 (Android/Python)

### Python 봇 클라이언트 (테스트용)

```python
# src/distributed/bot_client.py

import requests
import time
import uuid
import random
from typing import Optional, Dict
from src.automation.mobile import ADBController

class BotClient:
    """봇 클라이언트: 서버와 통신하며 작업 수행"""

    def __init__(self, server_url: str = "http://localhost:5000"):
        self.server_url = server_url
        self.bot_id: Optional[str] = None
        self.device_id = self._get_device_id()
        self.adb = ADBController()

    def _get_device_id(self) -> str:
        """기기 고유 ID 생성 (실제로는 Android ID 사용)"""
        # 테스트용: 임의 생성
        return str(uuid.uuid4())

    def register(self) -> bool:
        """서버에 봇 등록"""
        device_info = self.adb.get_device_info()

        payload = {
            "device_id": self.device_id,
            "manufacturer": device_info.get("manufacturer", "Unknown"),
            "model": device_info.get("model", "Unknown"),
            "android_version": device_info.get("android_version", "Unknown"),
            "screen_resolution": f"{device_info.get('screen_width', 1080)}x{device_info.get('screen_height', 1920)}",
            "ip": self.adb.get_ip_address(),
            "battery_level": device_info.get("battery_level", 100),
        }

        try:
            response = requests.post(
                f"{self.server_url}/register",
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.bot_id = data["bot_id"]
                print(f"✅ 봇 등록 성공: {self.bot_id}")
                return True
            else:
                print(f"❌ 봇 등록 실패: {response.status_code}")
                return False

        except Exception as e:
            print(f"⚠️ 서버 연결 실패: {e}")
            return False

    def get_task(self) -> Optional[Dict]:
        """서버로부터 작업 요청"""
        if not self.bot_id:
            print("⚠️ 봇 ID 없음. 먼저 register()를 호출하세요.")
            return None

        try:
            response = requests.get(
                f"{self.server_url}/get_task",
                params={"bot_id": self.bot_id},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("task"):
                    return None  # 작업 없음

                return data  # 작업 반환
            else:
                print(f"❌ 작업 요청 실패: {response.status_code}")
                return None

        except Exception as e:
            print(f"⚠️ 작업 요청 오류: {e}")
            return None

    def execute_task(self, task: Dict) -> tuple[bool, float, Dict]:
        """
        작업 실행

        Returns:
            (성공 여부, 소요 시간, 결과 데이터)
        """
        task_id = task["task_id"]
        print(f"\n{'='*60}")
        print(f"🚀 작업 시작: {task_id}")
        print(f"   테스트 케이스: {task['test_case']}")
        print(f"   프로필: {task['profile']}, 행동: {task['behavior']}")
        print(f"{'='*60}\n")

        start_time = time.time()

        try:
            # 실제 작업 수행 (시뮬레이션)
            # TODO: 실제 트래픽 생성 로직 통합

            # 순위 체크 (Before)
            before_rank = random.randint(40, 60)

            # 트래픽 생성
            time.sleep(random.uniform(30, 60))  # 시뮬레이션

            # IP 변경 (비행기모드 토글)
            self.adb.toggle_airplane_mode(duration=3)
            self.adb.wait_for_network(timeout=30)

            # 순위 체크 (After)
            after_rank = before_rank + random.randint(-5, 2)

            duration = time.time() - start_time

            result_data = {
                "before_rank": before_rank,
                "after_rank": after_rank,
                "rank_change": after_rank - before_rank,
            }

            print(f"✅ 작업 완료: {task_id} ({duration:.1f}초)")
            print(f"   순위 변화: {before_rank}위 → {after_rank}위")

            return True, duration, result_data

        except Exception as e:
            duration = time.time() - start_time
            print(f"❌ 작업 실패: {task_id} - {e}")
            return False, duration, {"error": str(e)}

    def report_result(self, task_id: str, success: bool,
                     duration: float, result_data: Dict) -> bool:
        """작업 결과 보고"""
        payload = {
            "bot_id": self.bot_id,
            "task_id": task_id,
            "success": success,
            "duration": duration,
            "result": result_data,
        }

        try:
            response = requests.post(
                f"{self.server_url}/report_result",
                json=payload,
                timeout=10
            )

            return response.status_code == 200

        except Exception as e:
            print(f"⚠️ 결과 보고 실패: {e}")
            return False

    def run_forever(self, poll_interval: int = 5):
        """무한 루프: 작업 요청 → 실행 → 보고"""
        # 최초 등록
        if not self.register():
            print("❌ 봇 등록 실패. 종료합니다.")
            return

        print(f"\n🤖 봇 {self.bot_id} 작업 시작...\n")

        while True:
            # 작업 요청
            task = self.get_task()

            if task:
                # 작업 실행
                success, duration, result_data = self.execute_task(task)

                # 결과 보고
                self.report_result(task["task_id"], success, duration, result_data)
            else:
                print(f"⏳ 대기 중... (작업 없음)")

            # 다음 폴링까지 대기
            time.sleep(poll_interval)


# 실행
if __name__ == "__main__":
    client = BotClient(server_url="http://localhost:5000")
    client.run_forever()
```

---

## 실행 예시

### 1. 서버 시작

```bash
python src/distributed/server.py
```

### 2. 봇 클라이언트 실행 (여러 터미널)

```bash
# 터미널 1
python src/distributed/bot_client.py

# 터미널 2
python src/distributed/bot_client.py

# 터미널 3
python src/distributed/bot_client.py
```

### 3. 그룹 할당

```bash
curl -X POST http://localhost:5000/assign_groups \
  -H "Content-Type: application/json" \
  -d '{"bots_per_group": 100}'
```

### 4. 통계 조회

```bash
curl http://localhost:5000/statistics
```

---

## 결론

이 아키텍처는 **봇 ID 기반의 상태 저장(Stateful) 통신**을 통해:

1. ✅ **IP 변경에 무관**: 비행기모드로 IP가 바뀌어도 봇은 bot_id로 식별
2. ✅ **개별 제어**: 특정 봇에게 명령 전달 가능
3. ✅ **상태 추적**: 각 봇의 작업 이력, 성능, 현재 상태 추적
4. ✅ **확장 가능**: 수천 대의 봇 동시 관리 가능
5. ✅ **그룹 관리**: 테스트 케이스별로 봇 그룹 분배

이제 분산 A/B 테스팅, 자가 치유, 하이브리드 제어 등 모든 혁신 아이디어가 구현 가능합니다.
