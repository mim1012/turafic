"""
Admin Dashboard API
관리자 대시보드용 통계 및 모니터링 API
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta

from server.core.database import get_session, Bot, Task, Campaign

router = APIRouter()

# ==================== API 엔드포인트 ====================

@router.get("/dashboard")
async def get_dashboard(session: AsyncSession = Depends(get_session)):
    """
    관리자 대시보드 메인 통계
    
    - 전체 봇 수 / 활성 봇 수
    - 전체 작업 수 / 성공 작업 수 / 실패 작업 수
    - 성공률
    - 최근 1시간 작업 처리량
    """
    # 봇 통계
    total_bots_result = await session.execute(select(func.count(Bot.bot_id)))
    total_bots = total_bots_result.scalar()
    
    active_bots_result = await session.execute(
        select(func.count(Bot.bot_id)).where(Bot.status == "active")
    )
    active_bots = active_bots_result.scalar()
    
    # 작업 통계
    total_tasks_result = await session.execute(select(func.count(Task.task_id)))
    total_tasks = total_tasks_result.scalar()
    
    success_tasks_result = await session.execute(
        select(func.count(Task.task_id)).where(Task.status == "success")
    )
    success_tasks = success_tasks_result.scalar()
    
    fail_tasks_result = await session.execute(
        select(func.count(Task.task_id)).where(Task.status == "failed")
    )
    fail_tasks = fail_tasks_result.scalar()
    
    # 성공률
    success_rate = (success_tasks / total_tasks * 100) if total_tasks > 0 else 0
    
    # 최근 1시간 작업 처리량
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    recent_tasks_result = await session.execute(
        select(func.count(Task.task_id)).where(Task.created_at >= one_hour_ago)
    )
    recent_tasks = recent_tasks_result.scalar()
    
    return {
        "bots": {
            "total": total_bots,
            "active": active_bots,
            "inactive": total_bots - active_bots
        },
        "tasks": {
            "total": total_tasks,
            "success": success_tasks,
            "failed": fail_tasks,
            "success_rate": round(success_rate, 2)
        },
        "performance": {
            "tasks_last_hour": recent_tasks,
            "tasks_per_minute": round(recent_tasks / 60, 2) if recent_tasks > 0 else 0
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/bots/statistics")
async def get_bot_statistics(session: AsyncSession = Depends(get_session)):
    """
    봇 통계 (그룹별, 상태별)
    """
    # 그룹별 봇 수
    group_stats = {}
    for group_num in range(1, 10):
        result = await session.execute(
            select(func.count(Bot.bot_id)).where(Bot.group == group_num)
        )
        group_stats[f"group_{group_num}"] = result.scalar()
    
    # 상태별 봇 수
    status_stats = {}
    for status in ["active", "inactive", "error"]:
        result = await session.execute(
            select(func.count(Bot.bot_id)).where(Bot.status == status)
        )
        status_stats[status] = result.scalar()
    
    return {
        "by_group": group_stats,
        "by_status": status_stats
    }


@router.get("/tasks/statistics")
async def get_task_statistics(session: AsyncSession = Depends(get_session)):
    """
    작업 통계 (그룹별 성공률)
    """
    group_stats = {}
    
    for group_num in range(1, 10):
        # 그룹별 전체 작업 수
        total_result = await session.execute(
            select(func.count(Task.task_id)).where(Task.group == group_num)
        )
        total = total_result.scalar()
        
        # 그룹별 성공 작업 수
        success_result = await session.execute(
            select(func.count(Task.task_id)).where(
                Task.group == group_num,
                Task.status == "success"
            )
        )
        success = success_result.scalar()
        
        group_stats[f"group_{group_num}"] = {
            "total": total,
            "success": success,
            "success_rate": round((success / total * 100), 2) if total > 0 else 0
        }
    
    return group_stats


@router.get("/top_performers")
async def get_top_performers(
    limit: int = 10,
    session: AsyncSession = Depends(get_session)
):
    """
    상위 성과 봇 목록 (성공 횟수 기준)
    """
    result = await session.execute(
        select(Bot).order_by(Bot.success_count.desc()).limit(limit)
    )
    top_bots = result.scalars().all()
    
    return {
        "top_performers": [
            {
                "bot_id": bot.bot_id,
                "device_model": bot.device_model,
                "group": bot.group,
                "success_count": bot.success_count,
                "fail_count": bot.fail_count,
                "success_rate": round(
                    (bot.success_count / (bot.success_count + bot.fail_count) * 100), 2
                ) if (bot.success_count + bot.fail_count) > 0 else 0
            }
            for bot in top_bots
        ]
    }


@router.get("/recent_activity")
async def get_recent_activity(
    limit: int = 20,
    session: AsyncSession = Depends(get_session)
):
    """
    최근 활동 로그 (최근 작업 목록)
    """
    result = await session.execute(
        select(Task).order_by(Task.created_at.desc()).limit(limit)
    )
    recent_tasks = result.scalars().all()
    
    return {
        "recent_tasks": [
            {
                "task_id": task.task_id,
                "bot_id": task.bot_id,
                "group": task.group,
                "status": task.status,
                "created_at": task.created_at.isoformat(),
                "completed_at": task.completed_at.isoformat() if task.completed_at else None
            }
            for task in recent_tasks
        ]
    }
