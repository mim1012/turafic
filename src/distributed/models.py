"""
분산 시스템 데이터 모델
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
from enum import Enum


class BotStatus(Enum):
    """봇 상태"""
    OFFLINE = "offline"
    IDLE = "idle"
    WORKING = "working"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class BotInfo:
    """봇 정보"""
    bot_id: str
    device_id: str
    manufacturer: str
    model: str
    android_version: str
    screen_resolution: str
    current_ip: Optional[str] = None
    last_ip_change: Optional[datetime] = None
    carrier: Optional[str] = None
    status: BotStatus = BotStatus.OFFLINE
    last_seen: Optional[datetime] = None
    registered_at: datetime = field(default_factory=datetime.now)
    assigned_group: Optional[str] = None
    current_task: Optional[str] = None
    completed_tasks: int = 0
    failed_tasks: int = 0
    avg_task_duration: float = 0.0
    success_rate: float = 1.0
    battery_level: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "bot_id": self.bot_id,
            "device_id": self.device_id,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "status": self.status.value,
            "assigned_group": self.assigned_group,
            "completed_tasks": self.completed_tasks,
            "success_rate": self.success_rate,
        }


@dataclass
class Task:
    """작업 정의"""
    task_id: str
    test_case: str
    profile: str
    behavior: str
    target_url: str
    search_keyword: str
    actions: List[dict]
    created_at: datetime = field(default_factory=datetime.now)
    timeout: int = 300
    priority: int = 5

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
        }
