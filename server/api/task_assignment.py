"""
Task Assignment API
작업 요청 및 결과 보고 API
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
from typing import Optional, List, Dict
import uuid

from server.core.database import get_session, Bot, Task
from server.core.cache import get_ui_coordinates
from server.core.task_engine import load_test_matrix, generate_task_pattern, add_randomness_to_pattern

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
    작업 요청 - 봇 ID 기반 작업 할당
    
    1. 봇 존재 여부 확인
    2. 봇의 그룹 확인
    3. 그룹에 맞는 테스트 케이스 로드
    4. 봇의 해상도에 맞는 UI 좌표 조회
    5. 작업 패턴 생성 (무작위성 추가)
    6. 작업 ID 생성 및 저장
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
    
    # 그룹 확인
    group = bot.group
    if group is None:
        raise HTTPException(status_code=400, detail="Bot group not assigned")
    
    # 테스트 매트릭스 로드
    test_matrix = load_test_matrix()
    if group < 1 or group > len(test_matrix):
        raise HTTPException(status_code=400, detail=f"Invalid group number: {group}")
    
    task_config = test_matrix[group - 1]  # 그룹 1 -> 인덱스 0
    
    # UI 좌표 조회
    coordinates = await get_ui_coordinates(bot.screen_resolution)
    
    # 작업 패턴 생성
    pattern = generate_task_pattern(task_config, coordinates)
    
    # 무작위성 추가 (탐지 회피)
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
