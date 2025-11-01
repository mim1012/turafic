"""
Ranking Group API
대장-쫄병 그룹 관리 API 엔드포인트
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from server.core.database import get_session
from server.core.ranking_group_manager import RankingGroupManager
from server.core.ip_rotation_manager import IPRotationManager


router = APIRouter()


# ==================== Request/Response Models ====================

class CreateGroupRequest(BaseModel):
    """그룹 생성 요청"""
    group_name: str
    group_type: str  # 'traffic' or 'rank_checker'
    leader_bot_id: str
    initial_minion_count: int = 7


class AssignMinionRequest(BaseModel):
    """쫄병 할당 요청"""
    bot_id: str


class HealthUpdateRequest(BaseModel):
    """대장 봇 헬스 업데이트 요청"""
    battery_level: int
    memory_available_mb: int
    hotspot_stability_score: float
    network_latency_ms: int
    device_temperature: float


class TaskCompletionRequest(BaseModel):
    """작업 완료 보고 요청"""
    bot_id: str
    task_id: str


class GroupStatusResponse(BaseModel):
    """그룹 상태 응답"""
    group_id: str
    group_name: str
    group_type: str
    status: str
    leader: dict
    minions: List[dict]
    health_summary: dict


# ==================== API Endpoints ====================

@router.post("/groups/create")
async def create_group(
    request: CreateGroupRequest,
    session: AsyncSession = Depends(get_session)
):
    """
    1. 새 대장-쫄병 그룹 생성

    **요청 예시**:
    ```json
    {
        "group_name": "Traffic Group 1",
        "group_type": "traffic",
        "leader_bot_id": "bot-uuid-1234",
        "initial_minion_count": 7
    }
    ```

    **응답 예시**:
    ```json
    {
        "success": true,
        "group_id": "group-uuid-5678",
        "group_name": "Traffic Group 1"
    }
    ```
    """
    manager = RankingGroupManager(session)

    result = await manager.create_group(
        group_name=request.group_name,
        group_type=request.group_type,
        leader_bot_id=request.leader_bot_id,
        initial_minion_count=request.initial_minion_count
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.post("/groups/{group_id}/minions/assign")
async def assign_minion(
    group_id: str,
    request: AssignMinionRequest,
    session: AsyncSession = Depends(get_session)
):
    """
    2. 쫄병을 그룹에 할당

    **요청 예시**:
    ```json
    {
        "bot_id": "bot-uuid-9999"
    }
    ```

    **응답 예시**:
    ```json
    {
        "success": true,
        "bot_id": "bot-uuid-9999",
        "group_id": "group-uuid-5678"
    }
    ```
    """
    manager = RankingGroupManager(session)

    result = await manager.assign_minion(
        group_id=group_id,
        bot_id=request.bot_id
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.delete("/groups/{group_id}/minions/{bot_id}")
async def remove_minion(
    group_id: str,
    bot_id: str,
    session: AsyncSession = Depends(get_session)
):
    """
    3. 쫄병을 그룹에서 제거

    **응답 예시**:
    ```json
    {
        "success": true,
        "bot_id": "bot-uuid-9999"
    }
    ```
    """
    manager = RankingGroupManager(session)

    result = await manager.remove_minion(
        group_id=group_id,
        bot_id=bot_id
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.post("/groups/{group_id}/leader/health")
async def update_leader_health(
    group_id: str,
    request: HealthUpdateRequest,
    session: AsyncSession = Depends(get_session)
):
    """
    4. 대장 봇 헬스 정보 업데이트

    **요청 예시**:
    ```json
    {
        "battery_level": 75,
        "memory_available_mb": 1500,
        "hotspot_stability_score": 95.0,
        "network_latency_ms": 50,
        "device_temperature": 35.0
    }
    ```

    **응답 예시**:
    ```json
    {
        "success": true,
        "health_score": 87.5,
        "recommended_minion_count": 7,
        "reason": "정상 상태",
        "level": "normal"
    }
    ```
    """
    manager = RankingGroupManager(session)

    # 그룹에서 대장 봇 ID 조회
    from server.core.database import RankingGroup
    from sqlalchemy import select

    result = await session.execute(
        select(RankingGroup).where(RankingGroup.group_id == group_id)
    )
    group = result.scalar_one_or_none()

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # 헬스 정보 업데이트
    result = await manager.update_leader_health(
        bot_id=group.leader_bot_id,
        battery_level=request.battery_level,
        memory_available_mb=request.memory_available_mb,
        hotspot_stability_score=request.hotspot_stability_score,
        network_latency_ms=request.network_latency_ms,
        device_temperature=request.device_temperature
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.post("/groups/{group_id}/adjust")
async def adjust_minion_count(
    group_id: str,
    force: bool = False,
    session: AsyncSession = Depends(get_session)
):
    """
    5. 쫄병 수 자동 조정

    **쿼리 파라미터**:
    - `force`: 강제 조정 여부 (기본 False)

    **응답 예시**:
    ```json
    {
        "adjusted": true,
        "old_count": 7,
        "new_count": 6,
        "reason": "배터리 25% / 온도 38° (경고)",
        "level": "warning"
    }
    ```
    """
    manager = RankingGroupManager(session)

    result = await manager.adjust_minion_count(
        group_id=group_id,
        force=force
    )

    if result.get("adjusted") == False and "error" in result:
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.get("/groups/{group_id}/status")
async def get_group_status(
    group_id: str,
    session: AsyncSession = Depends(get_session)
):
    """
    6. 그룹 상태 조회

    **응답 예시**:
    ```json
    {
        "group_id": "group-uuid-5678",
        "group_name": "Traffic Group 1",
        "group_type": "traffic",
        "status": "active",
        "leader": {
            "bot_id": "bot-uuid-1234",
            "battery_level": 75,
            "device_temperature": 35.0,
            "health_score": 87.5,
            "current_ip": "192.168.1.100"
        },
        "minions": [
            {
                "bot_id": "bot-uuid-2222",
                "connection_status": "connected",
                "task_status": "working"
            },
            {
                "bot_id": "bot-uuid-3333",
                "connection_status": "connected",
                "task_status": "completed"
            }
        ],
        "health_summary": {
            "leader_health_score": 87.5,
            "leader_battery": 75,
            "leader_temperature": 35.0,
            "current_minion_count": 7,
            "target_minion_count": 7,
            "connected_minions": 6
        }
    }
    ```
    """
    manager = RankingGroupManager(session)

    result = await manager.get_group_status(group_id)

    if "error" in result:
        raise HTTPException(status_code=404, detail=result.get("error"))

    return result


@router.post("/groups/{group_id}/ip/check")
async def check_ip_change(
    group_id: str,
    session: AsyncSession = Depends(get_session)
):
    """
    7-1. IP 변경 시점 체크

    **응답 예시**:
    ```json
    {
        "should_change": true,
        "reason": "all_completed",
        "wait_duration": 285,
        "completed_minions": 7,
        "total_minions": 7
    }
    ```
    """
    manager = IPRotationManager(session)

    result = await manager.should_change_ip(group_id)

    return result


@router.post("/groups/{group_id}/ip/execute")
async def execute_ip_change(
    group_id: str,
    session: AsyncSession = Depends(get_session)
):
    """
    7-2. IP 변경 즉시 실행

    **응답 예시**:
    ```json
    {
        "success": true,
        "old_ip": "192.168.1.100",
        "new_ip": "192.168.2.50",
        "leader_bot_id": "bot-uuid-1234"
    }
    ```
    """
    # 1. IP 변경 시점 체크
    ip_manager = IPRotationManager(session)
    decision = await ip_manager.should_change_ip(group_id)

    # 2. IP 변경 실행
    result = await ip_manager.execute_ip_change(
        group_id=group_id,
        reason=decision.get("reason", "manual"),
        wait_duration=decision.get("wait_duration", 0),
        completed_minions=decision.get("completed_minions", 0),
        total_minions=decision.get("total_minions", 0)
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.post("/groups/{group_id}/tasks/complete")
async def report_task_completion(
    group_id: str,
    request: TaskCompletionRequest,
    session: AsyncSession = Depends(get_session)
):
    """
    7-3. 쫄병 작업 완료 보고

    **요청 예시**:
    ```json
    {
        "bot_id": "bot-uuid-2222",
        "task_id": "task-uuid-7777"
    }
    ```

    **응답 예시**:
    ```json
    {
        "success": true,
        "all_completed": true,
        "message": "모든 쫄병이 작업 완료. IP 변경 준비됨."
    }
    ```
    """
    manager = IPRotationManager(session)

    # 작업 완료 보고 처리
    all_completed = await manager.report_task_completion(
        group_id=group_id,
        bot_id=request.bot_id,
        task_id=request.task_id
    )

    return {
        "success": True,
        "all_completed": all_completed,
        "message": "모든 쫄병이 작업 완료. IP 변경 준비됨." if all_completed else "작업 완료 신호 수신."
    }


@router.get("/groups/list")
async def list_groups(
    group_type: Optional[str] = None,
    session: AsyncSession = Depends(get_session)
):
    """
    전체 그룹 목록 조회

    **쿼리 파라미터**:
    - `group_type`: 필터링할 그룹 타입 (선택사항)

    **응답 예시**:
    ```json
    {
        "groups": [
            {
                "group_id": "group-uuid-1",
                "group_name": "Traffic Group 1",
                "group_type": "traffic",
                "status": "active",
                "current_minion_count": 7,
                "target_minion_count": 7
            },
            {
                "group_id": "group-uuid-2",
                "group_name": "Rank Checker Group",
                "group_type": "rank_checker",
                "status": "active",
                "current_minion_count": 6,
                "target_minion_count": 7
            }
        ]
    }
    ```
    """
    from server.core.database import RankingGroup
    from sqlalchemy import select

    # 그룹 조회
    query = select(RankingGroup)
    if group_type:
        query = query.where(RankingGroup.group_type == group_type)

    result = await session.execute(query)
    groups = result.scalars().all()

    return {
        "groups": [
            {
                "group_id": g.group_id,
                "group_name": g.group_name,
                "group_type": g.group_type,
                "status": g.status,
                "current_minion_count": g.current_minion_count,
                "target_minion_count": g.target_minion_count,
                "current_ip": g.current_ip,
                "last_ip_change_at": g.last_ip_change_at.isoformat() if g.last_ip_change_at else None
            } for g in groups
        ]
    }
