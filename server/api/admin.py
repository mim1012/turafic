"""
Admin Dashboard API
관리자 대시보드용 통계 및 모니터링 API
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta
from typing import Optional, List

from server.core.database import get_session, Bot, Task, Campaign
from server.core.rank_check_scheduler import manual_rank_check, schedule_rank_checks_once

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


# ==================== Rank Check 관련 엔드포인트 ====================

@router.post("/rank_check/trigger")
async def trigger_rank_check(
    product_ids: Optional[List[str]] = None,
    session: AsyncSession = Depends(get_session)
):
    """
    수동 순위 체크 트리거

    Args:
        product_ids: 체크할 상품 ID 리스트 (None이면 모든 active 상품)

    Returns:
        {"total_products": N, "assigned_tasks": M}

    Example:
        POST /api/v1/admin/rank_check/trigger
        {
            "product_ids": ["prod-1", "prod-2"]  // Optional
        }
    """
    result = await manual_rank_check(product_ids)

    return {
        "message": "Rank check tasks assigned",
        "total_products": result["total_products"],
        "assigned_tasks": result["assigned_tasks"],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/rank_check/status")
async def get_rank_check_status(session: AsyncSession = Depends(get_session)):
    """
    순위 체크 스케줄러 상태 조회

    Returns:
        - rank_checker 봇 수
        - active 상품 수
        - 최근 순위 체크 작업 통계
    """
    # Rank Checker 봇 수
    rank_checker_bots = await session.execute(
        select(func.count(Bot.bot_id)).where(
            Bot.role == "rank_checker",
            Bot.status == "active"
        )
    )
    total_rank_checkers = rank_checker_bots.scalar()

    # Active 상품 수
    active_products = await session.execute(
        select(func.count(func.distinct(Campaign.product_id))).where(
            Campaign.status.in_(["completed", "active"])
        )
    )
    total_products = active_products.scalar()

    # 최근 24시간 순위 체크 작업 통계
    one_day_ago = datetime.utcnow() - timedelta(hours=24)
    recent_rank_checks = await session.execute(
        select(func.count(Task.task_id)).where(
            Task.created_at >= one_day_ago,
            Task.pattern.contains([{"action": "report_ranking"}])
        )
    )
    recent_checks = recent_rank_checks.scalar()

    return {
        "scheduler_status": "active",  # TODO: 실제 스케줄러 상태 확인
        "rank_checker_bots": {
            "total": total_rank_checkers,
            "available": total_rank_checkers  # TODO: 실제 가용 봇 수 확인
        },
        "products": {
            "total_to_check": total_products
        },
        "recent_activity": {
            "checks_last_24h": recent_checks,
            "checks_per_hour": round(recent_checks / 24, 2) if recent_checks > 0 else 0
        },
        "next_scheduled_check": "Every 6 hours",  # TODO: 실제 다음 스케줄 시간
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/rank_check/history")
async def get_rank_check_history(
    product_id: Optional[str] = None,
    limit: int = 50,
    session: AsyncSession = Depends(get_session)
):
    """
    순위 체크 이력 조회

    Args:
        product_id: 특정 상품 ID (Optional)
        limit: 최대 결과 수

    Returns:
        순위 체크 작업 이력
    """
    # TODO: 실제 구현 시 ranking_history 테이블 생성 필요
    # 현재는 Task 테이블에서 report_ranking 액션이 포함된 작업 조회

    query = select(Task).where(
        Task.pattern.contains([{"action": "report_ranking"}])
    ).order_by(Task.created_at.desc()).limit(limit)

    if product_id:
        # product_id로 필터링 (pattern 내부에서 검색)
        # SQLAlchemy JSON 검색 사용
        pass  # TODO: JSON 필터링 구현

    result = await session.execute(query)
    tasks = result.scalars().all()

    return {
        "total": len(tasks),
        "history": [
            {
                "task_id": task.task_id,
                "bot_id": task.bot_id,
                "status": task.status,
                "created_at": task.created_at.isoformat(),
                "completed_at": task.completed_at.isoformat() if task.completed_at else None,
                "pattern": task.pattern  # Full pattern including product_id
            }
            for task in tasks
        ]
    }
