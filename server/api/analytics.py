"""
Analytics API
캠페인 성과 분석 및 테스트 케이스 비교
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text, func
from typing import List, Dict, Optional
from datetime import datetime, timedelta

from server.core.database import get_session, Campaign, Task, Bot

router = APIRouter()


@router.get("/campaign/performance")
async def get_campaign_performance(
    test_case: Optional[str] = None,
    session: AsyncSession = Depends(get_session)
):
    """
    캠페인 성과 분석

    Args:
        test_case: 특정 테스트 케이스 필터 (e.g., "TC#001")

    Returns:
        테스트 케이스별 성과 데이터
    """
    query = text("""
        SELECT
            c.test_case,
            c.product_id,
            p.product_name,
            p.naver_product_id,
            c.target_keyword,
            c.target_traffic,
            c.current_traffic_count,
            c.status,
            c.created_at,
            c.completed_at,
            p.initial_rank,
            p.current_rank,
            p.rank_improvement,
            CASE
                WHEN c.completed_at IS NOT NULL THEN
                    EXTRACT(EPOCH FROM (c.completed_at - c.created_at)) / 3600
                ELSE NULL
            END as duration_hours
        FROM campaigns c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.test_case IS NOT NULL
        {filter_clause}
        ORDER BY p.rank_improvement ASC NULLS LAST, c.completed_at DESC
    """)

    filter_clause = ""
    params = {}
    if test_case:
        filter_clause = "AND c.test_case = :test_case"
        params["test_case"] = test_case

    query_str = str(query).format(filter_clause=filter_clause)

    result = await session.execute(text(query_str), params)

    campaigns = []
    for row in result.mappings():
        campaigns.append({
            "test_case": row["test_case"],
            "product_id": row["product_id"],
            "product_name": row["product_name"],
            "naver_product_id": row["naver_product_id"],
            "target_keyword": row["target_keyword"],
            "target_traffic": row["target_traffic"],
            "current_traffic_count": row["current_traffic_count"],
            "progress_percent": round((row["current_traffic_count"] / row["target_traffic"]) * 100, 2) if row["target_traffic"] > 0 else 0,
            "status": row["status"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "completed_at": row["completed_at"].isoformat() if row["completed_at"] else None,
            "duration_hours": round(row["duration_hours"], 2) if row["duration_hours"] else None,
            "ranking": {
                "initial_rank": row["initial_rank"],
                "current_rank": row["current_rank"],
                "improvement": row["rank_improvement"]
            }
        })

    return {
        "total_campaigns": len(campaigns),
        "campaigns": campaigns
    }


@router.get("/test_case/comparison")
async def compare_test_cases(session: AsyncSession = Depends(get_session)):
    """
    테스트 케이스 간 성과 비교

    Returns:
        각 테스트 케이스의 평균 성과 지표
    """
    query = text("""
        SELECT
            c.test_case,
            COUNT(c.campaign_id) as total_campaigns,
            SUM(CASE WHEN c.status = 'completed' THEN 1 ELSE 0 END) as completed_campaigns,
            AVG(p.rank_improvement) as avg_rank_improvement,
            MIN(p.rank_improvement) as best_rank_improvement,
            MAX(p.rank_improvement) as worst_rank_improvement,
            AVG(c.current_traffic_count) as avg_traffic_generated,
            AVG(
                CASE
                    WHEN c.completed_at IS NOT NULL THEN
                        EXTRACT(EPOCH FROM (c.completed_at - c.created_at)) / 3600
                    ELSE NULL
                END
            ) as avg_duration_hours
        FROM campaigns c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.test_case IS NOT NULL
        GROUP BY c.test_case
        ORDER BY avg_rank_improvement ASC NULLS LAST
    """)

    result = await session.execute(query)

    test_cases = []
    for row in result.mappings():
        test_cases.append({
            "test_case": row["test_case"],
            "total_campaigns": row["total_campaigns"],
            "completed_campaigns": row["completed_campaigns"],
            "completion_rate": round((row["completed_campaigns"] / row["total_campaigns"]) * 100, 2) if row["total_campaigns"] > 0 else 0,
            "ranking_performance": {
                "avg_improvement": round(row["avg_rank_improvement"], 2) if row["avg_rank_improvement"] else None,
                "best_improvement": row["best_rank_improvement"],
                "worst_improvement": row["worst_rank_improvement"]
            },
            "traffic": {
                "avg_generated": round(row["avg_traffic_generated"], 2) if row["avg_traffic_generated"] else 0
            },
            "avg_duration_hours": round(row["avg_duration_hours"], 2) if row["avg_duration_hours"] else None
        })

    # 통계 요약
    if test_cases:
        best_test_case = min(test_cases, key=lambda x: x["ranking_performance"]["avg_improvement"] or float('inf'))
        worst_test_case = max(test_cases, key=lambda x: x["ranking_performance"]["avg_improvement"] or float('-inf'))
    else:
        best_test_case = None
        worst_test_case = None

    return {
        "total_test_cases": len(test_cases),
        "best_performing_test_case": best_test_case,
        "worst_performing_test_case": worst_test_case,
        "all_test_cases": test_cases
    }


@router.get("/ranking/history")
async def get_ranking_history(
    product_id: Optional[str] = None,
    naver_product_id: Optional[str] = None,
    limit: int = 100,
    session: AsyncSession = Depends(get_session)
):
    """
    상품 순위 변동 이력 조회

    Args:
        product_id: DB 상품 ID (Optional)
        naver_product_id: 네이버 상품 ID (Optional)
        limit: 최대 결과 수

    Returns:
        순위 변동 이력
    """
    # TODO: 실제 구현 시 ranking_history 테이블 생성 필요
    # 현재는 products 테이블의 현재 상태만 반환

    if product_id:
        query = text("""
            SELECT
                p.product_id,
                p.naver_product_id,
                p.product_name,
                p.initial_rank,
                p.current_rank,
                p.rank_improvement,
                p.last_checked_at,
                c.test_case,
                c.target_keyword
            FROM products p
            LEFT JOIN campaigns c ON p.product_id = c.product_id
            WHERE p.product_id = :product_id
        """)
        result = await session.execute(query, {"product_id": product_id})
    elif naver_product_id:
        query = text("""
            SELECT
                p.product_id,
                p.naver_product_id,
                p.product_name,
                p.initial_rank,
                p.current_rank,
                p.rank_improvement,
                p.last_checked_at,
                c.test_case,
                c.target_keyword
            FROM products p
            LEFT JOIN campaigns c ON p.product_id = c.product_id
            WHERE p.naver_product_id = :naver_product_id
        """)
        result = await session.execute(query, {"naver_product_id": naver_product_id})
    else:
        # 모든 상품의 순위 이력
        query = text("""
            SELECT
                p.product_id,
                p.naver_product_id,
                p.product_name,
                p.initial_rank,
                p.current_rank,
                p.rank_improvement,
                p.last_checked_at,
                c.test_case,
                c.target_keyword
            FROM products p
            LEFT JOIN campaigns c ON p.product_id = c.product_id
            WHERE p.rank_improvement IS NOT NULL
            ORDER BY p.rank_improvement ASC
            LIMIT :limit
        """)
        result = await session.execute(query, {"limit": limit})

    history = []
    for row in result.mappings():
        history.append({
            "product_id": row["product_id"],
            "naver_product_id": row["naver_product_id"],
            "product_name": row["product_name"],
            "test_case": row["test_case"],
            "target_keyword": row["target_keyword"],
            "ranking": {
                "initial": row["initial_rank"],
                "current": row["current_rank"],
                "improvement": row["rank_improvement"]
            },
            "last_checked_at": row["last_checked_at"].isoformat() if row["last_checked_at"] else None
        })

    return {
        "total": len(history),
        "history": history
    }


@router.get("/performance/summary")
async def get_performance_summary(session: AsyncSession = Depends(get_session)):
    """
    전체 성과 요약

    Returns:
        - 전체 캠페인 통계
        - 평균 순위 개선도
        - 최고/최저 성과 테스트 케이스
        - 시간대별 성과
    """
    # 전체 캠페인 통계
    campaign_stats = await session.execute(
        select(
            func.count(Campaign.campaign_id).label("total"),
            func.count(Campaign.campaign_id).filter(Campaign.status == "completed").label("completed"),
            func.count(Campaign.campaign_id).filter(Campaign.status == "active").label("active"),
            func.sum(Campaign.current_traffic_count).label("total_traffic")
        )
    )
    stats = campaign_stats.one()

    # 평균 순위 개선도
    rank_stats = await session.execute(
        text("""
            SELECT
                AVG(p.rank_improvement) as avg_improvement,
                MIN(p.rank_improvement) as best_improvement,
                MAX(p.rank_improvement) as worst_improvement,
                COUNT(CASE WHEN p.rank_improvement < 0 THEN 1 END) as improved_count,
                COUNT(CASE WHEN p.rank_improvement > 0 THEN 1 END) as declined_count,
                COUNT(CASE WHEN p.rank_improvement = 0 THEN 1 END) as unchanged_count
            FROM products p
            WHERE p.rank_improvement IS NOT NULL
        """)
    )
    rank_row = rank_stats.mappings().one()

    # 최고/최저 성과 테스트 케이스
    best_tc = await session.execute(
        text("""
            SELECT c.test_case, AVG(p.rank_improvement) as avg_improvement
            FROM campaigns c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.test_case IS NOT NULL AND p.rank_improvement IS NOT NULL
            GROUP BY c.test_case
            ORDER BY avg_improvement ASC
            LIMIT 1
        """)
    )
    best_test_case = best_tc.mappings().one_or_none()

    worst_tc = await session.execute(
        text("""
            SELECT c.test_case, AVG(p.rank_improvement) as avg_improvement
            FROM campaigns c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.test_case IS NOT NULL AND p.rank_improvement IS NOT NULL
            GROUP BY c.test_case
            ORDER BY avg_improvement DESC
            LIMIT 1
        """)
    )
    worst_test_case = worst_tc.mappings().one_or_none()

    return {
        "campaigns": {
            "total": stats.total,
            "completed": stats.completed,
            "active": stats.active,
            "completion_rate": round((stats.completed / stats.total) * 100, 2) if stats.total > 0 else 0
        },
        "traffic": {
            "total_generated": stats.total_traffic or 0
        },
        "ranking_performance": {
            "avg_improvement": round(rank_row["avg_improvement"], 2) if rank_row["avg_improvement"] else None,
            "best_improvement": rank_row["best_improvement"],
            "worst_improvement": rank_row["worst_improvement"],
            "distribution": {
                "improved": rank_row["improved_count"],
                "declined": rank_row["declined_count"],
                "unchanged": rank_row["unchanged_count"]
            }
        },
        "best_test_case": {
            "test_case": best_test_case["test_case"] if best_test_case else None,
            "avg_improvement": round(best_test_case["avg_improvement"], 2) if best_test_case else None
        },
        "worst_test_case": {
            "test_case": worst_test_case["test_case"] if worst_test_case else None,
            "avg_improvement": round(worst_test_case["avg_improvement"], 2) if worst_test_case else None
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/bot/performance")
async def get_bot_performance(
    role: Optional[str] = None,
    ranking_group_id: Optional[str] = None,
    session: AsyncSession = Depends(get_session)
):
    """
    봇별 성과 분석

    Args:
        role: 봇 역할 필터 (leader, follower, rank_checker)
        ranking_group_id: 랭킹 그룹 ID 필터

    Returns:
        봇별 성과 데이터
    """
    query = select(Bot)

    if role:
        query = query.where(Bot.role == role)

    if ranking_group_id:
        query = query.where(Bot.ranking_group_id == ranking_group_id)

    query = query.order_by(Bot.success_count.desc())

    result = await session.execute(query)
    bots = result.scalars().all()

    return {
        "total_bots": len(bots),
        "bots": [
            {
                "bot_id": bot.bot_id,
                "role": bot.role,
                "ranking_group_id": bot.ranking_group_id,
                "assigned_campaign_id": bot.assigned_campaign_id,
                "device_model": bot.device_model,
                "status": bot.status,
                "performance": {
                    "success_count": bot.success_count,
                    "fail_count": bot.fail_count,
                    "total_traffic_generated": bot.total_traffic_generated,
                    "success_rate": round(
                        (bot.success_count / (bot.success_count + bot.fail_count)) * 100, 2
                    ) if (bot.success_count + bot.fail_count) > 0 else 0
                },
                "last_task_at": bot.last_task_at.isoformat() if bot.last_task_at else None,
                "last_seen_at": bot.last_seen_at.isoformat() if bot.last_seen_at else None
            }
            for bot in bots
        ]
    }
