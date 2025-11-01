"""
Background Tasks
APScheduler를 사용한 백그라운드 작업 스케줄링

추가된 기능:
- 대장-쫄병 그룹 헬스 체크 (5분 주기)
- IP 로테이션 자동 실행 (30초 주기 체크)
- 쫄병 수 자동 조정 (5분 주기)
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
from typing import Optional
import logging
import asyncio

from .ranking_scheduler import RankingScheduler

# 로거 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 글로벌 스케줄러 인스턴스
scheduler: Optional[AsyncIOScheduler] = None


def init_scheduler():
    """APScheduler 초기화 및 자동 작업 등록"""
    global scheduler

    if scheduler is not None:
        logger.warning("Scheduler already initialized")
        return

    scheduler = AsyncIOScheduler()

    # 1. IP 로테이션 체크 (30초 주기)
    scheduler.add_job(
        func=ip_rotation_check_job,
        trigger=IntervalTrigger(seconds=30),
        id="ip_rotation_check",
        name="IP 로테이션 자동 체크",
        replace_existing=True
    )

    # 2. 그룹 헬스 체크 및 쫄병 수 자동 조정 (5분 주기)
    scheduler.add_job(
        func=health_check_and_adjust_job,
        trigger=IntervalTrigger(minutes=5),
        id="health_check_adjust",
        name="그룹 헬스 체크 및 쫄병 수 조정",
        replace_existing=True
    )

    # 3. 순위 체크 (12시간 주기) - 기존 기능
    # scheduler.add_job(
    #     func=check_ranking_job,
    #     trigger=IntervalTrigger(hours=12),
    #     id="ranking_check_job",
    #     name="12시간 주기 순위 체크",
    #     replace_existing=True
    # )

    logger.info("✅ APScheduler initialized with automated tasks")


def start_scheduler():
    """스케줄러 시작"""
    global scheduler

    if scheduler is None:
        init_scheduler()

    if not scheduler.running:
        scheduler.start()
        logger.info("✅ APScheduler started")
    else:
        logger.warning("Scheduler is already running")


def shutdown_scheduler():
    """스케줄러 종료"""
    global scheduler

    if scheduler and scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("✅ APScheduler stopped")


# ==================== 백그라운드 작업 함수들 ====================

async def check_ranking_job():
    """
    12시간 주기 순위 체크 작업

    주의: 이 함수는 동기 RankingScheduler를 비동기 환경에서 실행할 수 없으므로,
    실제 운영 시에는 다음 중 하나의 방식을 사용해야 합니다:

    1. asyncio.to_thread()로 동기 함수를 별도 스레드에서 실행
    2. RankingScheduler를 비동기로 재작성
    3. 외부 워커(Celery 등)에 위임
    """
    logger.info(f"[{datetime.now()}] 순위 체크 작업 시작")

    try:
        # 방법 1: asyncio.to_thread 사용 (Python 3.9+)
        import asyncio
        from functools import partial

        # RankingScheduler 실행 (동기 함수를 별도 스레드에서)
        # await asyncio.to_thread(run_ranking_check, "프로틴 쉐이크")

        # 현재는 로그만 출력
        logger.info("순위 체크 스케줄러 실행 (실제 구현 필요)")

    except Exception as e:
        logger.error(f"순위 체크 작업 실패: {e}")


def run_ranking_check(keyword: str):
    """동기 방식 순위 체크 (별도 스레드에서 실행)"""
    scheduler = RankingScheduler(product_keyword=keyword, delay_hours=12)

    # 단일 순위 체크만 수행 (배치 실행 안함)
    rank = scheduler._check_product_rank()
    logger.info(f"순위 측정 완료: {rank}위")

    return rank


# ==================== 수동 작업 추가 API ====================

def add_ranking_check_job(
    job_id: str,
    keyword: str,
    interval_hours: int = 12,
    campaign_id: Optional[str] = None
):
    """
    수동으로 순위 체크 작업 추가

    Args:
        job_id: 작업 고유 ID
        keyword: 검색 키워드
        interval_hours: 실행 주기 (시간)
        campaign_id: 캠페인 ID (선택)
    """
    global scheduler

    if scheduler is None:
        init_scheduler()

    scheduler.add_job(
        func=check_ranking_job,
        trigger=IntervalTrigger(hours=interval_hours),
        id=job_id,
        name=f"순위 체크: {keyword}",
        replace_existing=True,
        kwargs={"keyword": keyword, "campaign_id": campaign_id}
    )

    logger.info(f"✅ 순위 체크 작업 추가: {job_id} (주기: {interval_hours}시간)")


def remove_ranking_check_job(job_id: str):
    """순위 체크 작업 제거"""
    global scheduler

    if scheduler:
        try:
            scheduler.remove_job(job_id)
            logger.info(f"✅ 순위 체크 작업 제거: {job_id}")
        except Exception as e:
            logger.error(f"작업 제거 실패: {e}")


def list_all_jobs():
    """현재 등록된 모든 작업 목록"""
    global scheduler

    if scheduler:
        jobs = scheduler.get_jobs()
        return [
            {
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger)
            }
            for job in jobs
        ]
    return []


# ==================== 실시간 순위 체크 (비동기) ====================

async def check_rank_async(keyword: str, product_id: Optional[str] = None, max_pages: int = 10):
    """
    비동기 순위 체크 (즉시 실행)

    Args:
        keyword: 검색 키워드
        product_id: 상품 ID (선택)
        max_pages: 최대 검색 페이지

    Returns:
        순위 정보 딕셔너리 또는 None
    """
    import asyncio
    from functools import partial

    rank_checker = RankChecker()

    # 동기 함수를 별도 스레드에서 실행
    rank_info = await asyncio.to_thread(
        rank_checker.check_product_rank,
        keyword=keyword,
        product_id=product_id,
        max_pages=max_pages
    )

    return rank_info


# ==================== 대장-쫄병 시스템 자동화 작업 ====================

async def ip_rotation_check_job():
    """
    IP 로테이션 자동 체크 작업 (30초 주기)

    모든 활성화된 그룹에 대해 IP 변경 시점을 체크하고,
    조건이 충족되면 자동으로 IP 변경을 실행합니다.
    """
    try:
        from server.core.database import get_session, RankingGroup
        from server.core.ip_rotation_manager import IPRotationManager
        from sqlalchemy import select

        # 세션 생성
        async for session in get_session():
            manager = IPRotationManager(session)

            # 활성화된 모든 그룹 조회
            result = await session.execute(
                select(RankingGroup).where(RankingGroup.status == "active")
            )
            groups = result.scalars().all()

            for group in groups:
                # IP 변경 시점 체크
                decision = await manager.should_change_ip(group.group_id)

                if decision["should_change"]:
                    # IP 변경 실행
                    result = await manager.execute_ip_change(
                        group_id=group.group_id,
                        reason=decision["reason"],
                        wait_duration=decision["wait_duration"],
                        completed_minions=decision["completed_minions"],
                        total_minions=decision["total_minions"]
                    )

                    if result["success"]:
                        logger.info(
                            f"✅ [IP 로테이션] {group.group_name}: "
                            f"{result['old_ip']} → {result['new_ip']} "
                            f"(이유: {decision['reason']}, 대기: {decision['wait_duration']}초)"
                        )
                    else:
                        logger.error(f"❌ [IP 로테이션] {group.group_name}: {result.get('error')}")

            break  # 첫 세션만 사용

    except Exception as e:
        logger.error(f"❌ IP 로테이션 체크 작업 실패: {e}")


async def health_check_and_adjust_job():
    """
    그룹 헬스 체크 및 쫄병 수 자동 조정 작업 (5분 주기)

    대장 봇의 배터리, 온도 등 상태를 확인하고,
    필요 시 쫄병 수를 자동으로 조정합니다.
    """
    try:
        from server.core.database import get_session, RankingGroup
        from server.core.ranking_group_manager import RankingGroupManager
        from sqlalchemy import select

        # 세션 생성
        async for session in get_session():
            manager = RankingGroupManager(session)

            # 활성화된 모든 그룹 조회
            result = await session.execute(
                select(RankingGroup).where(RankingGroup.status == "active")
            )
            groups = result.scalars().all()

            for group in groups:
                # 쫄병 수 자동 조정
                adjust_result = await manager.adjust_minion_count(
                    group_id=group.group_id,
                    force=False  # 변경 필요 시에만 조정
                )

                if adjust_result.get("adjusted"):
                    logger.info(
                        f"✅ [쫄병 수 조정] {group.group_name}: "
                        f"{adjust_result['old_count']} → {adjust_result['new_count']} "
                        f"(이유: {adjust_result['reason']}, 레벨: {adjust_result['level']})"
                    )

            break  # 첫 세션만 사용

    except Exception as e:
        logger.error(f"❌ 헬스 체크 및 쫄병 수 조정 작업 실패: {e}")
