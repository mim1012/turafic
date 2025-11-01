"""
Rank Check Scheduler
6시간마다 모든 active 상품의 순위 체크 자동 스케줄링
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
import logging

from server.core.database import get_session, Bot, Campaign, Task
from server.core.role_based_task_engine import generate_rank_checker_task
import uuid

logger = logging.getLogger(__name__)

# 스케줄러 설정
RANK_CHECK_INTERVAL = 6 * 60 * 60  # 6시간 (초 단위)


async def get_active_products(session: AsyncSession) -> List[Dict]:
    """
    순위 체크가 필요한 active 상품 조회

    Returns:
        상품 정보 리스트 [{"product_id": ..., "naver_product_id": ..., "keyword": ...}]
    """
    # 완료된 캠페인의 상품 조회
    result = await session.execute(
        text("""
            SELECT DISTINCT
                c.product_id,
                p.naver_product_id,
                c.target_keyword as keyword,
                p.product_name
            FROM campaigns c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.status IN ('completed', 'active')
              AND p.status = 'active'
            ORDER BY c.completed_at DESC NULLS LAST
        """)
    )

    products = []
    for row in result.mappings():
        products.append({
            "product_id": row["product_id"],
            "naver_product_id": row["naver_product_id"],
            "keyword": row["keyword"],
            "product_name": row["product_name"]
        })

    logger.info(f"Found {len(products)} active products to check ranking")
    return products


async def get_available_rank_checkers(session: AsyncSession) -> List[Bot]:
    """
    사용 가능한 Rank Checker 봇 조회

    Returns:
        Rank Checker 봇 리스트
    """
    result = await session.execute(
        select(Bot).where(
            Bot.role == "rank_checker",
            Bot.status == "active"
        )
    )

    bots = result.scalars().all()
    logger.info(f"Found {len(bots)} available rank checker bots")
    return bots


async def assign_rank_check_task(
    bot: Bot,
    product: Dict,
    session: AsyncSession
) -> Optional[str]:
    """
    Rank Checker 봇에게 순위 체크 작업 할당

    Args:
        bot: Rank Checker 봇
        product: 상품 정보
        session: DB 세션

    Returns:
        task_id 또는 None (실패 시)
    """
    try:
        # Rank Checker 작업 패턴 생성
        pattern = generate_rank_checker_task(
            keyword=product["keyword"],
            product_id=product["product_id"],
            naver_product_id=product["naver_product_id"],
            max_pages=10
        )

        # 작업 ID 생성 및 저장
        task_id = str(uuid.uuid4())
        new_task = Task(
            task_id=task_id,
            bot_id=bot.bot_id,
            group=0,  # Rank Checker는 그룹 없음
            pattern=pattern,
            status="assigned",
            created_at=datetime.utcnow()
        )

        session.add(new_task)

        # 봇 정보 업데이트
        bot.last_task_at = datetime.utcnow()

        await session.commit()

        logger.info(f"Assigned rank check task {task_id} to bot {bot.bot_id} for product {product['product_name']}")
        return task_id

    except Exception as e:
        logger.error(f"Failed to assign rank check task: {e}")
        await session.rollback()
        return None


async def schedule_rank_checks_once(session: AsyncSession) -> Dict[str, int]:
    """
    한 번의 순위 체크 스케줄링 실행

    Returns:
        {"total_products": N, "assigned_tasks": M}
    """
    logger.info("=== Starting Rank Check Scheduling ===")

    # 1. Active 상품 조회
    products = await get_active_products(session)
    if not products:
        logger.info("No active products to check ranking")
        return {"total_products": 0, "assigned_tasks": 0}

    # 2. 사용 가능한 Rank Checker 봇 조회
    bots = await get_available_rank_checkers(session)
    if not bots:
        logger.warning("No available rank checker bots!")
        return {"total_products": len(products), "assigned_tasks": 0}

    # 3. 작업 할당 (Round-Robin)
    assigned_count = 0
    for i, product in enumerate(products):
        bot = bots[i % len(bots)]  # Round-Robin으로 봇 선택
        task_id = await assign_rank_check_task(bot, product, session)
        if task_id:
            assigned_count += 1

    logger.info(f"=== Rank Check Scheduling Completed: {assigned_count}/{len(products)} tasks assigned ===")

    return {
        "total_products": len(products),
        "assigned_tasks": assigned_count
    }


async def rank_check_scheduler_loop():
    """
    무한 루프로 6시간마다 순위 체크 스케줄링 실행

    Usage:
        asyncio.create_task(rank_check_scheduler_loop())
    """
    logger.info("🚀 Rank Checker Scheduler started")
    logger.info(f"Check interval: {RANK_CHECK_INTERVAL / 3600} hours")

    while True:
        try:
            async with get_session() as session:
                result = await schedule_rank_checks_once(session)
                logger.info(f"✅ Scheduled {result['assigned_tasks']} rank check tasks")

            # 다음 실행까지 대기 (6시간)
            next_run = datetime.utcnow() + timedelta(seconds=RANK_CHECK_INTERVAL)
            logger.info(f"⏰ Next rank check scheduled at: {next_run.isoformat()}")
            await asyncio.sleep(RANK_CHECK_INTERVAL)

        except Exception as e:
            logger.error(f"❌ Rank check scheduler error: {e}", exc_info=True)
            # 에러 발생 시 1분 대기 후 재시도
            await asyncio.sleep(60)


async def manual_rank_check(product_ids: Optional[List[str]] = None) -> Dict[str, int]:
    """
    수동으로 순위 체크 트리거 (특정 상품만)

    Args:
        product_ids: 체크할 상품 ID 리스트 (None이면 모든 active 상품)

    Returns:
        {"total_products": N, "assigned_tasks": M}
    """
    logger.info("🔍 Manual rank check triggered")

    async with get_session() as session:
        if product_ids:
            # 특정 상품만 조회
            result = await session.execute(
                text("""
                    SELECT DISTINCT
                        c.product_id,
                        p.naver_product_id,
                        c.target_keyword as keyword,
                        p.product_name
                    FROM campaigns c
                    JOIN products p ON c.product_id = p.product_id
                    WHERE c.product_id = ANY(:product_ids)
                      AND p.status = 'active'
                """),
                {"product_ids": product_ids}
            )

            products = []
            for row in result.mappings():
                products.append({
                    "product_id": row["product_id"],
                    "naver_product_id": row["naver_product_id"],
                    "keyword": row["keyword"],
                    "product_name": row["product_name"]
                })
        else:
            # 모든 active 상품
            products = await get_active_products(session)

        if not products:
            logger.warning("No products found for manual rank check")
            return {"total_products": 0, "assigned_tasks": 0}

        # 봇 조회 및 작업 할당
        bots = await get_available_rank_checkers(session)
        if not bots:
            logger.warning("No available rank checker bots!")
            return {"total_products": len(products), "assigned_tasks": 0}

        assigned_count = 0
        for i, product in enumerate(products):
            bot = bots[i % len(bots)]
            task_id = await assign_rank_check_task(bot, product, session)
            if task_id:
                assigned_count += 1

        logger.info(f"✅ Manual rank check: {assigned_count}/{len(products)} tasks assigned")

        return {
            "total_products": len(products),
            "assigned_tasks": assigned_count
        }


def start_scheduler():
    """
    스케줄러 시작 (FastAPI 시작 시 호출)

    Usage in main.py:
        from server.core.rank_check_scheduler import start_scheduler

        @app.on_event("startup")
        async def startup_event():
            asyncio.create_task(rank_check_scheduler_loop())
    """
    import asyncio
    loop = asyncio.get_event_loop()
    loop.create_task(rank_check_scheduler_loop())
    logger.info("✅ Rank check scheduler task created")
