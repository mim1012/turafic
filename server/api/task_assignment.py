"""
Task Assignment API
작업 요청 및 결과 보고 API
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from datetime import datetime
from typing import Optional, List, Dict
import uuid

from server.core.database import get_session, Bot, Task, Campaign
from server.core.cache import get_ui_coordinates
from server.core.task_engine import load_test_matrix, generate_task_pattern, add_randomness_to_pattern
from server.core.identity_profiles import IdentityProfile, create_default_samsung_profiles
from server.core.http_pattern_generator import generate_http_pattern, generate_appium_pattern
from server.core.role_based_task_engine import generate_leader_task, generate_follower_task
import random

router = APIRouter()

# ==================== 요청/응답 모델 ====================

class TaskRequest(BaseModel):
    bot_id: str


class TaskResponse(BaseModel):
    task_id: str
    pattern: List[Dict]


class TaskResultReport(BaseModel):
    bot_id: str
    task_id: str
    status: str  # "success" or "failed"
    log: Optional[str] = None


# ==================== API 엔드포인트 ====================

@router.get("/get_task", response_model=TaskResponse)
async def get_task(
    bot_id: str,
    session: AsyncSession = Depends(get_session)
):
    """
    작업 요청 - 캠페인 기반 분산 작업 할당
    
    1. 봇 존재 여부 확인
    2. 실행 중인 캠페인 조회
    3. 캠페인 목표 달성 여부 확인
    4. 봇의 그룹에 맞는 테스트 케이스 로드
    5. 봇의 해상도에 맞는 UI 좌표 조회
    6. 작업 패턴 생성 (무작위성 추가)
    7. 작업 ID 생성 및 저장, 캠페인 카운트 증가
    """
    # 봇 존재 여부 확인
    result = await session.execute(
        select(Bot).where(Bot.bot_id == bot_id)
    )
    bot = result.scalar_one_or_none()
    
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    # 봇 상태 확인
    if bot.status != "active":
        raise HTTPException(status_code=403, detail=f"Bot is {bot.status}, not active")
    
    # 이 봇에게 이미 할당된 캠페인이 있는지 확인
    assigned_campaign_result = await session.execute(
        select(Campaign)
        .where(Campaign.assigned_bot_id == bot_id)
        .where(Campaign.status == "active")
    )
    campaign = assigned_campaign_result.scalar_one_or_none()
    
    # 할당된 캠페인이 없으면, 미할당 캠페인 중 하나를 할당
    if not campaign:
        unassigned_campaign_result = await session.execute(
            select(Campaign)
            .where(Campaign.status == "active")
            .where(Campaign.assigned_bot_id.is_(None))
            .order_by(Campaign.created_at.asc())
            .limit(1)
        )
        campaign = unassigned_campaign_result.scalar_one_or_none()
        
        if campaign:
            # 이 봇에게 캠페인 할당
            campaign.assigned_bot_id = bot_id
            bot.assigned_campaign_id = campaign.campaign_id
            await session.commit()
    
    if not campaign:
        # 실행 중인 캠페인이 없으면 대기 명령 반환
        return TaskResponse(
            task_id="wait",
            pattern=[{"action": "wait", "duration": 300000, "description": "대기 (5분)"}]
        )
    
    # 캠페인 목표 달성 여부 확인 (SELECT ... FOR UPDATE로 동시성 문제 해결)
    campaign_lock_result = await session.execute(
        select(Campaign)
        .where(Campaign.campaign_id == campaign.campaign_id)
        .with_for_update()  # 행 락 획듍
    )
    campaign_locked = campaign_lock_result.scalar_one()
    
    if campaign_locked.current_traffic_count >= campaign_locked.target_traffic:
        # 목표 달성 시 캠페인 종료
        campaign_locked.status = "completed"
        campaign_locked.completed_at = datetime.utcnow()
        campaign_locked.assigned_bot_id = None  # 봇 할당 해제
        bot.assigned_campaign_id = None  # 봇의 캠페인 할당도 해제
        await session.commit()
        
        # 이 봇에게 새로운 캠페인 할당 가능하도록 대기 명령 반환
        return TaskResponse(
            task_id="wait",
            pattern=[{"action": "wait", "duration": 10000, "description": "캠페인 완료, 다음 캠페인 대기 (10초)"}]
        )
    
    # 그룹 확인
    group = bot.group
    if group is None:
        raise HTTPException(status_code=400, detail="Bot group not assigned")
    
    # 테스트 매트릭스 로드
    test_matrix = load_test_matrix()
    if group < 1 or group > len(test_matrix):
        raise HTTPException(status_code=400, detail=f"Invalid group number: {group}")
    
    task_config = test_matrix[group - 1]  # 그룹 1 -> 인덱스 0

    # 상품 정보 조회 (naver_product_id)
    product_result = await session.execute(
        text("SELECT naver_product_id FROM products WHERE product_id = :pid"),
        {"pid": campaign_locked.product_id}
    )
    product = product_result.mappings().one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    naver_product_id = product["naver_product_id"]

    # 신원 프로필 선택
    identity_profiles_result = await session.execute(
        select(IdentityProfile).where(
            IdentityProfile.group_name == campaign_locked.identity_profile_group
        )
    )
    identity_profiles = identity_profiles_result.scalars().all()
    
    if not identity_profiles:
        # 기본 프로필 생성 (첫 실행 시)
        default_profiles = create_default_samsung_profiles()
        session.add_all(default_profiles)
        await session.commit()
        identity_profiles = default_profiles
    
    # 무작위로 프로필 선택
    selected_profile = random.choice(identity_profiles)
    
    # 사용 횟수 증가
    selected_profile.usage_count += 1
    
    identity_dict = {
        "user_agent": selected_profile.user_agent,
        "cookies": selected_profile.cookies,
        "headers": selected_profile.headers,
        "fingerprint": selected_profile.fingerprint
    }
    
    # UI 좌표 맵 조회 (Appium 모드용)
    coordinates = await get_ui_coordinates(bot.screen_resolution)

    # 봇 역할에 따른 작업 패턴 생성
    if bot.role == "leader":
        # Leader: 캠페인 실행 + IP 관리
        pattern = generate_leader_task(
            task_config=task_config,
            coordinates=coordinates,
            keyword=campaign_locked.target_keyword,
            naver_product_id=naver_product_id,  # 특정 상품 클릭
            ranking_group_id=bot.ranking_group_id
        )
    elif bot.role == "follower":
        # Follower: 캠페인 실행만
        pattern = generate_follower_task(
            task_config=task_config,
            coordinates=coordinates,
            keyword=campaign_locked.target_keyword,
            naver_product_id=naver_product_id,  # 특정 상품 클릭
            ranking_group_id=bot.ranking_group_id
        )
    else:
        # 기본 패턴 (role 없는 경우 - 하위 호환성)
        pattern = generate_task_pattern(
            task_config=task_config,
            coordinates=coordinates,
            keyword=campaign_locked.target_keyword,
            naver_product_id=naver_product_id  # 특정 상품 클릭
        )
        pattern = add_randomness_to_pattern(pattern)
    
    # 작업 ID 생성 및 저장
    task_id = str(uuid.uuid4())
    new_task = Task(
        task_id=task_id,
        bot_id=bot_id,
        group=group,
        pattern=pattern,
        status="assigned",
        created_at=datetime.utcnow()
    )
    
    session.add(new_task)
    
    # 캠페인 카운트 증가 (원자적 연산)
    campaign_locked.current_traffic_count += 1
    campaign_locked.total_tasks += 1
    
    # 봇 정보 업데이트
    bot.last_task_at = datetime.utcnow()
    bot.last_seen_at = datetime.utcnow()
    
    await session.commit()
    
    return TaskResponse(
        task_id=task_id,
        pattern=pattern
    )


@router.post("/report_result")
async def report_result(
    report: TaskResultReport,
    session: AsyncSession = Depends(get_session)
):
    """
    작업 결과 보고
    
    1. 봇 및 작업 존재 여부 확인
    2. 작업 상태 업데이트
    3. 봇 통계 업데이트
    """
    # 봇 확인
    bot_result = await session.execute(
        select(Bot).where(Bot.bot_id == report.bot_id)
    )
    bot = bot_result.scalar_one_or_none()
    
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    # 작업 확인
    task_result = await session.execute(
        select(Task).where(Task.task_id == report.task_id)
    )
    task = task_result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # 작업 상태 업데이트
    task.status = report.status
    task.completed_at = datetime.utcnow()
    task.log = report.log
    
    # 봇 통계 업데이트
    if report.status == "success":
        bot.success_count += 1
        bot.total_traffic_generated += 1
    else:
        bot.fail_count += 1
    
    bot.last_seen_at = datetime.utcnow()
    
    await session.commit()
    
    return {
        "message": "Result recorded",
        "task_id": report.task_id,
        "status": report.status
    }


@router.post("/feedback/error")
async def feedback_error(
    bot_id: str,
    screenshot: UploadFile = File(...),
    session: AsyncSession = Depends(get_session)
):
    """
    자가 치유를 위한 오류 피드백 (스크린샷 포함)
    
    TODO: AI 비전 분석 및 UI 좌표 맵 자동 업데이트
    """
    # 봇 확인
    result = await session.execute(
        select(Bot).where(Bot.bot_id == bot_id)
    )
    bot = result.scalar_one_or_none()
    
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    # 스크린샷 저장
    screenshot_path = f"/tmp/error_{bot_id}_{datetime.now().timestamp()}.png"
    with open(screenshot_path, "wb") as f:
        f.write(await screenshot.read())
    
    # TODO: AI 비전 분석 (GPT-4 Vision API 호출)
    # TODO: UI 좌표 맵 자동 업데이트
    
    return {
        "message": "Error feedback received",
        "screenshot_path": screenshot_path,
        "note": "AI vision analysis not implemented yet"
    }


@router.get("/tasks/{task_id}")
async def get_task_info(
    task_id: str,
    session: AsyncSession = Depends(get_session)
):
    """작업 정보 조회"""
    result = await session.execute(
        select(Task).where(Task.task_id == task_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return {
        "task_id": task.task_id,
        "bot_id": task.bot_id,
        "group": task.group,
        "status": task.status,
        "created_at": task.created_at.isoformat(),
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
        "pattern": task.pattern,
        "log": task.log
    }
