"""
Ranking API
네이버 쇼핑 순위 체크 및 조회 API
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from server.core.database import (
    get_session,
    RankingCheck,
    RankingChange,
    BatchExecution,
    Campaign
)
from src.ranking.checker import RankChecker
from src.utils.helpers import calculate_rank, calculate_rank_change

router = APIRouter(prefix="/api/v1/ranking", tags=["Ranking"])

# ==================== Pydantic 모델 ====================

class RankCheckRequest(BaseModel):
    """순위 체크 요청"""
    bot_id: str
    campaign_id: str
    keyword: str
    max_pages: Optional[int] = 10


class RankReportRequest(BaseModel):
    """봇이 순위 측정 결과 보고"""
    bot_id: str
    campaign_id: str
    keyword: str
    rank_position: int
    page_number: Optional[int] = None
    position_in_page: Optional[int] = None
    product_id: Optional[str] = None
    product_name: Optional[str] = None
    product_url: Optional[str] = None
    check_type: Optional[str] = None  # 'baseline', 'batch_1', ...


class RankCheckResponse(BaseModel):
    """순위 체크 응답"""
    check_id: str
    campaign_id: str
    keyword: str
    rank_position: int
    page_number: Optional[int]
    measured_at: datetime
    message: str


class RankingHistoryResponse(BaseModel):
    """순위 이력 조회 응답"""
    campaign_id: str
    keyword: str
    baseline_rank: Optional[int]
    checkpoints: List[Dict[str, Any]]
    statistics: Dict[str, Any]


class RankingOverviewResponse(BaseModel):
    """전체 캠페인 순위 현황"""
    campaigns: List[Dict[str, Any]]


# ==================== 봇용 API ====================

@router.post("/request_check", response_model=RankCheckResponse)
async def request_rank_check(
    request: RankCheckRequest,
    db: AsyncSession = Depends(get_session)
):
    """
    봇이 순위 체크를 요청

    실제로는 서버가 직접 RankChecker를 실행하여 순위를 측정합니다.
    봇은 이 API를 통해 순위 체크 작업을 트리거할 수 있습니다.
    """
    try:
        # 캠페인 존재 여부 확인
        stmt = select(Campaign).where(Campaign.campaign_id == request.campaign_id)
        result = await db.execute(stmt)
        campaign = result.scalar_one_or_none()

        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")

        # 순위 체크 실행
        rank_checker = RankChecker()
        rank_info = rank_checker.check_product_rank(
            keyword=request.keyword,
            product_id=None,  # product_id를 모르는 경우 키워드만으로 검색
            max_pages=request.max_pages
        )

        if rank_info and rank_info.get("product_id"):
            # 순위 발견
            rank_position = rank_info["absolute_rank"]
            page_number = rank_info["page"]
            position_in_page = rank_info["position"]
            product_id = rank_info["product_id"]
            product_name = rank_info.get("product_name", "")
            product_url = rank_info.get("product_url", "")

            # DB에 저장
            check_id = str(uuid.uuid4())
            rank_check = RankingCheck(
                check_id=check_id,
                campaign_id=request.campaign_id,
                product_keyword=request.keyword,
                rank_position=rank_position,
                page_number=page_number,
                position_in_page=position_in_page,
                product_id=product_id,
                product_name=product_name,
                product_url=product_url,
                measured_by=request.bot_id,
                measurement_method="bot"
            )

            db.add(rank_check)
            await db.commit()

            return RankCheckResponse(
                check_id=check_id,
                campaign_id=request.campaign_id,
                keyword=request.keyword,
                rank_position=rank_position,
                page_number=page_number,
                measured_at=rank_check.measured_at,
                message=f"순위 측정 완료: {rank_position}위"
            )
        else:
            # 순위를 찾지 못함
            raise HTTPException(
                status_code=404,
                detail=f"상품을 {request.max_pages}페이지 내에서 찾지 못했습니다."
            )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"순위 체크 실패: {str(e)}")


@router.post("/report", response_model=RankCheckResponse)
async def report_rank(
    request: RankReportRequest,
    db: AsyncSession = Depends(get_session)
):
    """
    봇이 순위 측정 결과를 보고

    봇이 직접 네이버 쇼핑 검색을 수행하고, 발견한 순위를 서버에 보고합니다.
    """
    try:
        # 캠페인 존재 여부 확인
        stmt = select(Campaign).where(Campaign.campaign_id == request.campaign_id)
        result = await db.execute(stmt)
        campaign = result.scalar_one_or_none()

        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")

        # DB에 저장
        check_id = str(uuid.uuid4())
        rank_check = RankingCheck(
            check_id=check_id,
            campaign_id=request.campaign_id,
            product_keyword=request.keyword,
            check_type=request.check_type,
            rank_position=request.rank_position,
            page_number=request.page_number,
            position_in_page=request.position_in_page,
            product_id=request.product_id,
            product_name=request.product_name,
            product_url=request.product_url,
            measured_by=request.bot_id,
            measurement_method="bot"
        )

        db.add(rank_check)

        # 이전 순위와 비교하여 변동 기록
        stmt = (
            select(RankingCheck)
            .where(RankingCheck.campaign_id == request.campaign_id)
            .where(RankingCheck.check_id != check_id)
            .order_by(desc(RankingCheck.measured_at))
            .limit(1)
        )
        result = await db.execute(stmt)
        last_check = result.scalar_one_or_none()

        if last_check:
            # 순위 변동 계산
            rank_change_value = calculate_rank_change(
                last_check.rank_position,
                request.rank_position
            )

            change_id = str(uuid.uuid4())
            rank_change = RankingChange(
                change_id=change_id,
                campaign_id=request.campaign_id,
                before_check_id=last_check.check_id,
                after_check_id=check_id,
                before_rank=last_check.rank_position,
                after_rank=request.rank_position,
                rank_change=rank_change_value,
                improved=(rank_change_value < 0)  # 음수 = 상승
            )

            db.add(rank_change)

        await db.commit()

        return RankCheckResponse(
            check_id=check_id,
            campaign_id=request.campaign_id,
            keyword=request.keyword,
            rank_position=request.rank_position,
            page_number=request.page_number,
            measured_at=rank_check.measured_at,
            message="순위 보고 완료"
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"순위 보고 실패: {str(e)}")


# ==================== 관리자용 API ====================

@router.get("/campaigns/{campaign_id}/history", response_model=RankingHistoryResponse)
async def get_ranking_history(
    campaign_id: str,
    db: AsyncSession = Depends(get_session)
):
    """
    캠페인 순위 변동 이력 조회
    """
    try:
        # 캠페인 정보
        stmt = select(Campaign).where(Campaign.campaign_id == campaign_id)
        result = await db.execute(stmt)
        campaign = result.scalar_one_or_none()

        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")

        # 순위 체크 이력
        stmt = (
            select(RankingCheck)
            .where(RankingCheck.campaign_id == campaign_id)
            .order_by(RankingCheck.measured_at)
        )
        result = await db.execute(stmt)
        checks = result.scalars().all()

        if not checks:
            return RankingHistoryResponse(
                campaign_id=campaign_id,
                keyword=campaign.target_keyword,
                baseline_rank=None,
                checkpoints=[],
                statistics={}
            )

        # Baseline (첫 번째 순위)
        baseline_rank = checks[0].rank_position

        # Checkpoints 구성
        checkpoints = []
        for i, check in enumerate(checks):
            checkpoint = {
                "iteration": i + 1,
                "check_type": check.check_type,
                "rank": check.rank_position,
                "page": check.page_number,
                "position": check.position_in_page,
                "timestamp": check.measured_at.isoformat(),
                "measured_by": check.measured_by
            }

            # 변동 계산 (이전 체크와 비교)
            if i > 0:
                change = calculate_rank_change(checks[i-1].rank_position, check.rank_position)
                checkpoint["change"] = change
                checkpoint["improved"] = (change < 0)
            else:
                checkpoint["change"] = 0
                checkpoint["improved"] = None

            checkpoints.append(checkpoint)

        # 통계 계산
        ranks = [c.rank_position for c in checks]
        statistics = {
            "total_checks": len(checks),
            "best_rank": min(ranks),
            "worst_rank": max(ranks),
            "average_rank": round(sum(ranks) / len(ranks), 2),
            "total_change": calculate_rank_change(baseline_rank, checks[-1].rank_position),
            "improvements": len([c for c in checkpoints if c.get("improved") == True]),
            "declines": len([c for c in checkpoints if c.get("improved") == False]),
        }

        return RankingHistoryResponse(
            campaign_id=campaign_id,
            keyword=campaign.target_keyword,
            baseline_rank=baseline_rank,
            checkpoints=checkpoints,
            statistics=statistics
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"순위 이력 조회 실패: {str(e)}")


@router.get("/campaigns/{campaign_id}/current")
async def get_current_rank(
    campaign_id: str,
    db: AsyncSession = Depends(get_session)
):
    """
    실시간 순위 조회 (최신 측정값)
    """
    try:
        # 최신 순위 체크
        stmt = (
            select(RankingCheck)
            .where(RankingCheck.campaign_id == campaign_id)
            .order_by(desc(RankingCheck.measured_at))
            .limit(1)
        )
        result = await db.execute(stmt)
        latest_check = result.scalar_one_or_none()

        if not latest_check:
            raise HTTPException(status_code=404, detail="순위 기록이 없습니다.")

        return {
            "campaign_id": campaign_id,
            "keyword": latest_check.product_keyword,
            "current_rank": latest_check.rank_position,
            "page": latest_check.page_number,
            "position": latest_check.position_in_page,
            "last_checked_at": latest_check.measured_at.isoformat(),
            "measured_by": latest_check.measured_by
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"현재 순위 조회 실패: {str(e)}")


@router.get("/dashboard/overview", response_model=RankingOverviewResponse)
async def ranking_overview(db: AsyncSession = Depends(get_session)):
    """
    전체 캠페인의 순위 현황 한눈에 보기
    """
    try:
        # 모든 활성 캠페인
        stmt = select(Campaign).where(Campaign.status == "active")
        result = await db.execute(stmt)
        campaigns = result.scalars().all()

        overview = []
        for campaign in campaigns:
            # 최신 순위 체크
            stmt = (
                select(RankingCheck)
                .where(RankingCheck.campaign_id == campaign.campaign_id)
                .order_by(desc(RankingCheck.measured_at))
                .limit(1)
            )
            result = await db.execute(stmt)
            latest_check = result.scalar_one_or_none()

            # Baseline (첫 번째 순위)
            stmt = (
                select(RankingCheck)
                .where(RankingCheck.campaign_id == campaign.campaign_id)
                .order_by(RankingCheck.measured_at)
                .limit(1)
            )
            result = await db.execute(stmt)
            baseline_check = result.scalar_one_or_none()

            campaign_data = {
                "campaign_id": campaign.campaign_id,
                "campaign_name": campaign.name,
                "keyword": campaign.target_keyword,
                "baseline_rank": baseline_check.rank_position if baseline_check else None,
                "current_rank": latest_check.rank_position if latest_check else None,
                "change": None,
                "last_checked": latest_check.measured_at.isoformat() if latest_check else None
            }

            if baseline_check and latest_check:
                campaign_data["change"] = calculate_rank_change(
                    baseline_check.rank_position,
                    latest_check.rank_position
                )

            overview.append(campaign_data)

        return RankingOverviewResponse(campaigns=overview)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"순위 현황 조회 실패: {str(e)}")


@router.get("/analyze")
async def analyze_ranking_effect(db: AsyncSession = Depends(get_session)):
    """
    ANOVA 분석: 어느 테스트 케이스가 효과적인지

    TODO: scipy.stats.f_oneway를 사용한 본격적인 ANOVA 분석
    현재는 테스트 케이스별 평균 순위 변동만 계산
    """
    try:
        # 모든 순위 변동 가져오기
        stmt = select(RankingChange).where(RankingChange.test_case_id.isnot(None))
        result = await db.execute(stmt)
        changes = result.scalars().all()

        if not changes:
            return {
                "message": "분석할 데이터가 없습니다.",
                "test_case_effects": {}
            }

        # 테스트 케이스별 그룹화
        test_case_groups = {}
        for change in changes:
            tc_id = change.test_case_id
            if tc_id not in test_case_groups:
                test_case_groups[tc_id] = []
            test_case_groups[tc_id].append(change.rank_change)

        # 평균 효과 계산
        effects = {}
        for tc_id, changes_list in test_case_groups.items():
            avg_change = sum(changes_list) / len(changes_list)
            effects[tc_id] = {
                "average_change": round(avg_change, 2),
                "sample_size": len(changes_list),
                "interpretation": "상승" if avg_change < 0 else "하락"
            }

        # 가장 효과적인 케이스
        best_case = min(effects.items(), key=lambda x: x[1]["average_change"])
        worst_case = max(effects.items(), key=lambda x: x[1]["average_change"])

        return {
            "total_test_cases": len(effects),
            "total_samples": len(changes),
            "test_case_effects": effects,
            "best_case": {
                "test_case_id": best_case[0],
                "average_change": best_case[1]["average_change"],
                "sample_size": best_case[1]["sample_size"]
            },
            "worst_case": {
                "test_case_id": worst_case[0],
                "average_change": worst_case[1]["average_change"],
                "sample_size": worst_case[1]["sample_size"]
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ANOVA 분석 실패: {str(e)}")
