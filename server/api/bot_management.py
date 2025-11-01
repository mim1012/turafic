"""
Bot Management API
봇 등록, 조회, 상태 업데이트 API
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime
import uuid

from server.core.database import get_session, Bot
from server.core.task_engine import assign_group

router = APIRouter()

# ==================== 요청/응답 모델 ====================

class BotRegisterRequest(BaseModel):
    device_model: str  # 예: "SM-G996N"
    android_version: str  # 예: "12"
    screen_resolution: str  # 예: "1080x2340"
    android_id: str  # 기기 고유 식별자
    role: str = "follower"  # "leader", "follower", "rank_checker"
    is_leader: bool = False  # True if role is "leader"
    config_json: dict = {}  # Role-specific configuration


class BotRegisterResponse(BaseModel):
    bot_id: str
    group: int
    role: str
    is_leader: bool
    ranking_group_id: str = None
    message: str


class BotStatusUpdate(BaseModel):
    status: str  # "active", "inactive", "error"


# ==================== API 엔드포인트 ====================

@router.post("/register", response_model=BotRegisterResponse)
async def register_bot(
    request: BotRegisterRequest,
    session: AsyncSession = Depends(get_session)
):
    """
    신규 봇 등록 (역할 포함)

    - 기존 봇인지 확인 (android_id 기준)
    - 신규 봇이면 UUID 발급 및 그룹 할당
    - 역할별 기본 설정 자동 생성
    - 기존 봇이면 기존 bot_id 반환
    """
    # Validate role
    if request.role not in ["leader", "follower", "rank_checker"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'leader', 'follower', or 'rank_checker'")

    # Validate leader flag
    if request.role == "leader" and not request.is_leader:
        raise HTTPException(status_code=400, detail="Leader role must have is_leader=True")

    # 기존 봇 확인
    result = await session.execute(
        select(Bot).where(Bot.android_id == request.android_id)
    )
    existing_bot = result.scalar_one_or_none()

    if existing_bot:
        # 기존 봇 - last_seen_at 업데이트
        existing_bot.last_seen_at = datetime.utcnow()

        # 역할이 변경되었다면 업데이트
        if existing_bot.role != request.role:
            existing_bot.role = request.role
            existing_bot.is_leader = request.is_leader
            existing_bot.role_last_changed_at = datetime.utcnow()

        await session.commit()

        return BotRegisterResponse(
            bot_id=existing_bot.bot_id,
            group=existing_bot.group,
            role=existing_bot.role,
            is_leader=existing_bot.is_leader,
            ranking_group_id=existing_bot.ranking_group_id,
            message="Already registered"
        )

    # 신규 봇 - 등록
    bot_id = str(uuid.uuid4())

    # 현재 등록된 봇 수 조회 (그룹 할당용)
    bot_count_result = await session.execute(select(func.count(Bot.bot_id)))
    bot_count = bot_count_result.scalar()

    # 그룹 할당 (1~9)
    group = assign_group(bot_count)

    # 역할별 기본 설정 생성
    default_config = {}
    if request.role == "leader":
        default_config = {
            "hotspot_ssid": f"Turafic-Leader-{bot_id[:8]}",
            "hotspot_password": "turafic2025",
            "ip_rotation_strategy": "wait_for_completion",
            "max_wait_time": 180000  # 3분
        }
    elif request.role == "follower":
        default_config = {
            "leader_hotspot_ssid": "",
            "leader_hotspot_password": ""
        }
    elif request.role == "rank_checker":
        default_config = {
            "check_interval": 3600,  # 60분
            "target_keywords": [],
            "target_products": []
        }

    # 사용자 제공 설정과 병합
    final_config = {**default_config, **request.config_json}

    # 데이터베이스에 저장
    new_bot = Bot(
        bot_id=bot_id,
        android_id=request.android_id,
        device_model=request.device_model,
        android_version=request.android_version,
        screen_resolution=request.screen_resolution,
        group=group,
        role=request.role,
        is_leader=request.is_leader,
        config_json=final_config,
        status="active",
        registered_at=datetime.utcnow(),
        last_seen_at=datetime.utcnow()
    )

    session.add(new_bot)
    await session.commit()

    return BotRegisterResponse(
        bot_id=bot_id,
        group=group,
        role=request.role,
        is_leader=request.is_leader,
        ranking_group_id=None,
        message="Registration successful"
    )


@router.get("/{bot_id}")
async def get_bot_info(
    bot_id: str,
    session: AsyncSession = Depends(get_session)
):
    """봇 정보 조회 (역할 포함)"""
    result = await session.execute(
        select(Bot).where(Bot.bot_id == bot_id)
    )
    bot = result.scalar_one_or_none()

    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")

    return {
        "bot_id": bot.bot_id,
        "device_model": bot.device_model,
        "android_version": bot.android_version,
        "screen_resolution": bot.screen_resolution,
        "group": bot.group,
        "role": bot.role,
        "is_leader": bot.is_leader,
        "config_json": bot.config_json,
        "ranking_group_id": bot.ranking_group_id,
        "status": bot.status,
        "registered_at": bot.registered_at.isoformat(),
        "last_task_at": bot.last_task_at.isoformat() if bot.last_task_at else None,
        "success_count": bot.success_count,
        "fail_count": bot.fail_count,
        "total_traffic_generated": bot.total_traffic_generated
    }


@router.patch("/{bot_id}/status")
async def update_bot_status(
    bot_id: str,
    status_update: BotStatusUpdate,
    session: AsyncSession = Depends(get_session)
):
    """봇 상태 업데이트"""
    result = await session.execute(
        select(Bot).where(Bot.bot_id == bot_id)
    )
    bot = result.scalar_one_or_none()
    
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    bot.status = status_update.status
    await session.commit()
    
    return {"message": f"Bot status updated to {status_update.status}"}


@router.get("/")
async def list_bots(
    status: str = None,
    group: int = None,
    role: str = None,
    session: AsyncSession = Depends(get_session)
):
    """봇 목록 조회 (필터링 가능 - status, group, role)"""
    query = select(Bot)

    if status:
        query = query.where(Bot.status == status)
    if group:
        query = query.where(Bot.group == group)
    if role:
        query = query.where(Bot.role == role)

    result = await session.execute(query)
    bots = result.scalars().all()

    return {
        "total": len(bots),
        "bots": [
            {
                "bot_id": bot.bot_id,
                "device_model": bot.device_model,
                "group": bot.group,
                "role": bot.role,
                "is_leader": bot.is_leader,
                "status": bot.status,
                "success_count": bot.success_count,
                "fail_count": bot.fail_count
            }
            for bot in bots
        ]
    }
