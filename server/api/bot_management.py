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


class BotRegisterResponse(BaseModel):
    bot_id: str
    group: int
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
    신규 봇 등록
    
    - 기존 봇인지 확인 (android_id 기준)
    - 신규 봇이면 UUID 발급 및 그룹 할당
    - 기존 봇이면 기존 bot_id 반환
    """
    # 기존 봇 확인
    result = await session.execute(
        select(Bot).where(Bot.android_id == request.android_id)
    )
    existing_bot = result.scalar_one_or_none()
    
    if existing_bot:
        # 기존 봇 - last_seen_at 업데이트
        existing_bot.last_seen_at = datetime.utcnow()
        await session.commit()
        
        return BotRegisterResponse(
            bot_id=existing_bot.bot_id,
            group=existing_bot.group,
            message="Already registered"
        )
    
    # 신규 봇 - 등록
    bot_id = str(uuid.uuid4())
    
    # 현재 등록된 봇 수 조회 (그룹 할당용)
    bot_count_result = await session.execute(select(func.count(Bot.bot_id)))
    bot_count = bot_count_result.scalar()
    
    # 그룹 할당 (1~9)
    group = assign_group(bot_count)
    
    # 데이터베이스에 저장
    new_bot = Bot(
        bot_id=bot_id,
        android_id=request.android_id,
        device_model=request.device_model,
        android_version=request.android_version,
        screen_resolution=request.screen_resolution,
        group=group,
        status="active",
        registered_at=datetime.utcnow(),
        last_seen_at=datetime.utcnow()
    )
    
    session.add(new_bot)
    await session.commit()
    
    return BotRegisterResponse(
        bot_id=bot_id,
        group=group,
        message="Registration successful"
    )


@router.get("/{bot_id}")
async def get_bot_info(
    bot_id: str,
    session: AsyncSession = Depends(get_session)
):
    """봇 정보 조회"""
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
    session: AsyncSession = Depends(get_session)
):
    """봇 목록 조회 (필터링 가능)"""
    query = select(Bot)
    
    if status:
        query = query.where(Bot.status == status)
    if group:
        query = query.where(Bot.group == group)
    
    result = await session.execute(query)
    bots = result.scalars().all()
    
    return {
        "total": len(bots),
        "bots": [
            {
                "bot_id": bot.bot_id,
                "device_model": bot.device_model,
                "group": bot.group,
                "status": bot.status,
                "success_count": bot.success_count,
                "fail_count": bot.fail_count
            }
            for bot in bots
        ]
    }
