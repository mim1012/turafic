"""
Campaign Management API
캠페인 생성, 조회, 통계 API
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
from typing import Optional
import uuid

from server.core.database import get_session, Campaign

router = APIRouter()

# ==================== 요청/응답 모델 ====================

class CampaignCreate(BaseModel):
    name: str
    description: Optional[str] = None
    target_keyword: str
    target_traffic: int  # 목표 트래픽 수 (예: 100)


class CampaignResponse(BaseModel):
    campaign_id: str
    name: str
    description: Optional[str]
    target_keyword: str
    target_traffic: int
    current_traffic_count: int
    status: str
    created_at: str
    completed_at: Optional[str]


# ==================== API 엔드포인트 ====================

@router.post("/campaigns", response_model=CampaignResponse)
async def create_campaign(
    campaign: CampaignCreate,
    session: AsyncSession = Depends(get_session)
):
    """
    캠페인 생성
    
    예시:
    {
        "name": "단백질쉐이크 100회 트래픽",
        "target_keyword": "단백질쉐이크",
        "target_traffic": 100
    }
    """
    campaign_id = str(uuid.uuid4())
    
    new_campaign = Campaign(
        campaign_id=campaign_id,
        name=campaign.name,
        description=campaign.description,
        target_keyword=campaign.target_keyword,
        target_traffic=campaign.target_traffic,
        status="active",  # 생성 즉시 활성화
        created_at=datetime.utcnow(),
        started_at=datetime.utcnow()
    )
    
    session.add(new_campaign)
    await session.commit()
    await session.refresh(new_campaign)
    
    return CampaignResponse(
        campaign_id=new_campaign.campaign_id,
        name=new_campaign.name,
        description=new_campaign.description,
        target_keyword=new_campaign.target_keyword,
        target_traffic=new_campaign.target_traffic,
        current_traffic_count=new_campaign.current_traffic_count,
        status=new_campaign.status,
        created_at=new_campaign.created_at.isoformat(),
        completed_at=new_campaign.completed_at.isoformat() if new_campaign.completed_at else None
    )


@router.get("/campaigns/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    campaign_id: str,
    session: AsyncSession = Depends(get_session)
):
    """캠페인 정보 조회"""
    result = await session.execute(
        select(Campaign).where(Campaign.campaign_id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return CampaignResponse(
        campaign_id=campaign.campaign_id,
        name=campaign.name,
        description=campaign.description,
        target_keyword=campaign.target_keyword,
        target_traffic=campaign.target_traffic,
        current_traffic_count=campaign.current_traffic_count,
        status=campaign.status,
        created_at=campaign.created_at.isoformat(),
        completed_at=campaign.completed_at.isoformat() if campaign.completed_at else None
    )


@router.get("/campaigns")
async def list_campaigns(
    status: Optional[str] = None,
    session: AsyncSession = Depends(get_session)
):
    """
    캠페인 목록 조회
    
    Query Parameters:
    - status: 'active', 'completed', 'paused' (선택)
    """
    query = select(Campaign)
    
    if status:
        query = query.where(Campaign.status == status)
    
    query = query.order_by(Campaign.created_at.desc())
    
    result = await session.execute(query)
    campaigns = result.scalars().all()
    
    return {
        "total": len(campaigns),
        "campaigns": [
            {
                "campaign_id": c.campaign_id,
                "name": c.name,
                "target_keyword": c.target_keyword,
                "target_traffic": c.target_traffic,
                "current_traffic_count": c.current_traffic_count,
                "progress": f"{c.current_traffic_count}/{c.target_traffic}",
                "status": c.status,
                "created_at": c.created_at.isoformat()
            }
            for c in campaigns
        ]
    }


@router.patch("/campaigns/{campaign_id}/status")
async def update_campaign_status(
    campaign_id: str,
    status: str,  # 'active', 'paused', 'completed'
    session: AsyncSession = Depends(get_session)
):
    """캠페인 상태 변경 (일시정지, 재개, 종료)"""
    result = await session.execute(
        select(Campaign).where(Campaign.campaign_id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    if status not in ["active", "paused", "completed"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    campaign.status = status
    
    if status == "completed":
        campaign.completed_at = datetime.utcnow()
    
    await session.commit()
    
    return {
        "message": f"Campaign status updated to {status}",
        "campaign_id": campaign_id,
        "status": status
    }
