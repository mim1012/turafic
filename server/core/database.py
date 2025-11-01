"""
Database Connection and Models
PostgreSQL 연결 및 SQLAlchemy 모델 정의
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Boolean, Text, ForeignKey
from datetime import datetime
import os

# 데이터베이스 URL (환경 변수에서 로드, 없으면 SQLite 사용)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./turafic.db"  # 개발용 SQLite
    # 실제 배포 시: "postgresql+asyncpg://user:password@localhost/turafic"
)

# SQLAlchemy 엔진 및 세션
engine = None
async_session_maker = None
Base = declarative_base()

# ==================== 데이터베이스 모델 ====================

class Bot(Base):
    """봇 정보 테이블"""
    __tablename__ = "bots"

    bot_id = Column(String(36), primary_key=True)  # UUID
    android_id = Column(String(64), unique=True, nullable=False)
    device_model = Column(String(50), nullable=False)
    android_version = Column(String(20), nullable=False)
    screen_resolution = Column(String(20), nullable=False)

    # A/B 테스트 그룹 (1~9)
    group = Column(Integer, nullable=True)

    # 할당된 캠페인 (조회 편의성)
    assigned_campaign_id = Column(String(36), nullable=True)

    # 봇 타입 및 역할 (대장-쫄병 시스템)
    bot_type = Column(String(20), default="traffic")  # 'traffic' or 'rank_checker'
    is_leader = Column(Boolean, default=False)
    leader_bot_id = Column(String(36), nullable=True)  # 쫄병인 경우 대장 봇 ID
    ranking_group_id = Column(String(36), ForeignKey("ranking_groups.group_id"), nullable=True)

    # 대장 봇 상태 (대장만 사용)
    max_minion_capacity = Column(Integer, default=7)
    current_minion_count = Column(Integer, default=0)
    health_score = Column(Float, default=100.0)
    battery_level = Column(Integer, default=100)
    memory_available_mb = Column(Integer, default=0)
    hotspot_stability_score = Column(Float, default=100.0)
    network_latency_ms = Column(Integer, default=0)
    device_temperature = Column(Float, default=25.0)
    last_health_check_at = Column(DateTime, nullable=True)

    # IP 변경 관련
    current_ip = Column(String(50), nullable=True)
    last_ip_change_at = Column(DateTime, nullable=True)
    ip_change_count = Column(Integer, default=0)

    # 쫄병 봇 상태 (쫄병만 사용)
    connection_status = Column(String(20), default="disconnected")  # disconnected, connecting, connected, reconnecting
    last_connected_at = Column(DateTime, nullable=True)
    connection_retry_count = Column(Integer, default=0)

    # 작업 완료 상태 (IP 변경 타이밍 조율용)
    task_status = Column(String(20), default="idle")  # idle, working, completed
    task_started_at = Column(DateTime, nullable=True)
    task_completed_at = Column(DateTime, nullable=True)

    # 상태 관리
    status = Column(String(20), default="active")  # active, inactive, error
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_task_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)

    # 통계
    success_count = Column(Integer, default=0)
    fail_count = Column(Integer, default=0)
    total_traffic_generated = Column(Integer, default=0)


class Task(Base):
    """작업 정보 테이블"""
    __tablename__ = "tasks"
    
    task_id = Column(String(36), primary_key=True)  # UUID
    bot_id = Column(String(36), nullable=False)
    campaign_id = Column(String(36), nullable=True)
    
    # 작업 내용
    group = Column(Integer, nullable=False)  # 테스트 그룹
    pattern = Column(JSON, nullable=False)  # JSON 작업 패턴
    
    # 상태 관리
    status = Column(String(20), default="assigned")  # assigned, running, success, failed
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # 결과
    log = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    screenshot_url = Column(String(255), nullable=True)


class Campaign(Base):
    """캠페인 정보 테이블"""
    __tablename__ = "campaigns"
    
    campaign_id = Column(String(36), primary_key=True)  # UUID
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    
    # 캠페인 설정
    target_keyword = Column(String(100), nullable=False)
    target_traffic = Column(Integer, nullable=False)  # 목표 트래픽 수
    test_matrix_path = Column(String(255), nullable=True)  # 테스트 매트릭스 파일 경로
    
    # 실행 모드 및 신원 프로필
    execution_mode = Column(String(20), default="appium")  # 'appium' or 'http'
    identity_profile_group = Column(String(50), default="samsung_mobile_default")
    
    # 상태 관리
    status = Column(String(20), default="active")  # active, paused, completed
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # 통계
    total_tasks = Column(Integer, default=0)
    current_traffic_count = Column(Integer, default=0)  # 현재까지 완료된 트래픽 수
    assigned_bot_id = Column(String(36), nullable=True)  # 특정 봇에게만 할당 (1봇 = 1캠페인)
    success_tasks = Column(Integer, default=0)
    fail_tasks = Column(Integer, default=0)


class UICoordinateMap(Base):
    """UI 좌표 맵 테이블 (캐시 백업용)"""
    __tablename__ = "ui_coordinate_maps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    resolution = Column(String(20), unique=True, nullable=False)  # 예: "1080x2340"
    coordinates = Column(JSON, nullable=False)  # JSON 형태의 좌표 맵
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RankingGroup(Base):
    """대장-쫄병 그룹 테이블"""
    __tablename__ = "ranking_groups"

    group_id = Column(String(36), primary_key=True)
    group_name = Column(String(100), nullable=False)
    group_type = Column(String(20), nullable=False)  # 'traffic' or 'rank_checker'
    leader_bot_id = Column(String(36), ForeignKey("bots.bot_id", ondelete="CASCADE"), nullable=False)

    # 쫄병 수 설정
    min_minions = Column(Integer, default=5)
    max_minions = Column(Integer, default=7)
    target_minion_count = Column(Integer, default=7)  # 기본값 7개
    current_minion_count = Column(Integer, default=0)

    # IP 변경 전략
    ip_change_strategy = Column(String(30), default="wait_for_completion")
    # 'wait_for_completion': 작업 완료 후 IP 변경 (하이브리드)
    # 'fixed_interval': 고정 주기 (5분)
    # 'manual': 수동

    ip_change_interval_sec = Column(Integer, default=300)  # 5분 (300초)
    max_wait_time_sec = Column(Integer, default=180)  # 최대 대기 3분

    # 현재 IP 정보
    current_ip = Column(String(50), nullable=True)
    last_ip_change_at = Column(DateTime, nullable=True)

    # 할당된 작업
    assigned_products = Column(Text, nullable=True)  # JSON 배열: ["product_1", "product_2", ...]
    assigned_test_cases = Column(Text, nullable=True)  # JSON 배열: ["TC#001", "TC#002", ...]
    total_products = Column(Integer, default=0)
    total_test_cases = Column(Integer, default=0)

    # 상태 관리
    status = Column(String(20), default="active")  # active, resizing, paused, waiting_for_tasks
    created_at = Column(DateTime, default=datetime.utcnow)
    last_resize_at = Column(DateTime, nullable=True)
    resize_reason = Column(Text, nullable=True)

    # 통계
    total_rank_checks = Column(Integer, default=0)
    total_traffic_tasks = Column(Integer, default=0)
    avg_task_duration_sec = Column(Float, default=0.0)
    total_ip_changes = Column(Integer, default=0)


class IPChangeHistory(Base):
    """IP 변경 이력 테이블"""
    __tablename__ = "ip_change_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    group_id = Column(String(36), ForeignKey("ranking_groups.group_id", ondelete="CASCADE"), nullable=False)
    leader_bot_id = Column(String(36), nullable=False)
    old_ip = Column(String(50), nullable=True)
    new_ip = Column(String(50), nullable=True)
    change_reason = Column(String(50), nullable=True)  # 'scheduled', 'manual', 'emergency'
    minions_completed = Column(Integer, default=0)
    minions_total = Column(Integer, default=0)
    wait_duration_sec = Column(Integer, default=0)
    changed_at = Column(DateTime, default=datetime.utcnow)


class TaskCompletionSignal(Base):
    """작업 완료 신호 테이블 (IP 타이밍 조율용)"""
    __tablename__ = "task_completion_signals"

    signal_id = Column(String(36), primary_key=True)
    group_id = Column(String(36), ForeignKey("ranking_groups.group_id", ondelete="CASCADE"), nullable=False)
    bot_id = Column(String(36), ForeignKey("bots.bot_id", ondelete="CASCADE"), nullable=False)
    task_id = Column(String(36), nullable=True)
    completed_at = Column(DateTime, default=datetime.utcnow)
    reported_at = Column(DateTime, default=datetime.utcnow)


# ==================== 데이터베이스 초기화 ====================

async def init_db():
    """데이터베이스 초기화 및 테이블 생성"""
    global engine, async_session_maker
    
    engine = create_async_engine(
        DATABASE_URL,
        echo=True,  # SQL 쿼리 로깅 (개발 모드)
        future=True
    )
    
    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    # 테이블 생성
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    print("✅ Database tables created")


async def close_db():
    """데이터베이스 연결 종료"""
    global engine
    if engine:
        await engine.dispose()
        print("✅ Database connection closed")


async def get_session() -> AsyncSession:
    """데이터베이스 세션 생성 (의존성 주입용)"""
    async with async_session_maker() as session:
        yield session
