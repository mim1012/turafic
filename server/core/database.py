"""
Database Connection and Models
PostgreSQL 연결 및 SQLAlchemy 모델 정의
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Boolean, Text
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
    success_tasks = Column(Integer, default=0)
    fail_tasks = Column(Integer, default=0)


class UICoordinateMap(Base):
    """UI 좌표 맵 테이블 (캐시 백업용)"""
    __tablename__ = "ui_coordinate_maps"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    resolution = Column(String(20), unique=True, nullable=False)  # 예: "1080x2340"
    coordinates = Column(JSON, nullable=False)  # JSON 형태의 좌표 맵
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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
