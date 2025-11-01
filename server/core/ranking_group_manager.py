"""
Ranking Group Manager
쫄병 수 자동 조정 및 그룹 관리
"""

from datetime import datetime
from typing import Optional, Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from uuid import uuid4

from server.core.database import Bot, RankingGroup


class RankingGroupManager:
    """
    대장-쫄병 그룹 관리자

    - 대장 폰 상태에 따른 쫄병 수 자동 조정
    - 보수적 정책: 기본 7대, 필요 시에만 감소
    - Health Score 기반 결정
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    # ==================== Health Score 계산 ====================

    def calculate_health_score(
        self,
        battery_level: int,
        memory_available_mb: int,
        hotspot_stability_score: float,
        network_latency_ms: int,
        device_temperature: float
    ) -> float:
        """
        대장 봇의 Health Score 계산 (0~100)

        가중치:
        - 배터리: 30%
        - 메모리: 25%
        - 핫스팟 안정성: 25%
        - 네트워크 지연: 15%
        - 온도: 5%

        Returns:
            float: 0~100 범위의 Health Score
        """
        # 1. 배터리 점수 (0~100)
        battery_score = battery_level  # 이미 0~100 범위

        # 2. 메모리 점수 (0~100)
        # 가정: 2GB 이상이면 100점, 500MB 이하면 0점
        memory_score = min(100, max(0, (memory_available_mb - 500) / 15))

        # 3. 핫스팟 안정성 점수 (0~100)
        hotspot_score = hotspot_stability_score  # 이미 0~100 범위

        # 4. 네트워크 지연 점수 (0~100)
        # 가정: 50ms 이하면 100점, 500ms 이상이면 0점
        network_score = min(100, max(0, 100 - (network_latency_ms - 50) / 4.5))

        # 5. 온도 점수 (0~100)
        # 가정: 25도 이하면 100점, 50도 이상이면 0점
        temp_score = min(100, max(0, 100 - (device_temperature - 25) * 4))

        # 6. 가중 평균
        health_score = (
            battery_score * 0.30 +
            memory_score * 0.25 +
            hotspot_score * 0.25 +
            network_score * 0.15 +
            temp_score * 0.05
        )

        return round(health_score, 2)

    def determine_minion_count(
        self,
        battery_level: int,
        device_temperature: float,
        health_score: float
    ) -> Dict[str, any]:
        """
        대장 폰 상태에 따른 쫄병 수 결정

        보수적 정책:
        - 기본: 7대
        - 경고 (배터리 <30% OR 온도 >40°): 6대
        - 위험 (배터리 <15% OR 온도 >45°): 5대

        Returns:
            {
                "target_count": int,
                "reason": str,
                "level": str  # "normal", "warning", "critical"
            }
        """
        # 1. 위험 수준 판단
        if battery_level < 15 or device_temperature > 45:
            return {
                "target_count": 5,
                "reason": f"배터리 {battery_level}% / 온도 {device_temperature}° (위험)",
                "level": "critical"
            }

        # 2. 경고 수준 판단
        if battery_level < 30 or device_temperature > 40:
            return {
                "target_count": 6,
                "reason": f"배터리 {battery_level}% / 온도 {device_temperature}° (경고)",
                "level": "warning"
            }

        # 3. 정상
        return {
            "target_count": 7,
            "reason": "정상 상태",
            "level": "normal"
        }

    # ==================== 쫄병 수 조정 ====================

    async def adjust_minion_count(
        self,
        group_id: str,
        force: bool = False
    ) -> Dict[str, any]:
        """
        그룹의 쫄병 수 자동 조정

        Args:
            group_id: 그룹 ID
            force: 강제 조정 여부 (기본 False)

        Returns:
            {
                "adjusted": bool,
                "old_count": int,
                "new_count": int,
                "reason": str
            }
        """
        # 1. 그룹 조회
        group = await self._get_group(group_id)
        if not group:
            return {"adjusted": False, "error": "group_not_found"}

        # 2. 대장 봇 조회
        leader = await self._get_leader_bot(group.leader_bot_id)
        if not leader:
            return {"adjusted": False, "error": "leader_not_found"}

        # 3. 쫄병 수 결정
        decision = self.determine_minion_count(
            battery_level=leader.battery_level,
            device_temperature=leader.device_temperature,
            health_score=leader.health_score
        )

        target_count = decision["target_count"]
        current_count = group.current_minion_count

        # 4. 변경 필요 여부 판단
        if target_count == current_count and not force:
            return {
                "adjusted": False,
                "old_count": current_count,
                "new_count": target_count,
                "reason": "no_change_needed"
            }

        # 5. 쫄병 수 조정 실행
        if target_count > current_count:
            # 쫄병 추가
            result = await self._add_minions(group_id, target_count - current_count)
        else:
            # 쫄병 제거
            result = await self._remove_minions(group_id, current_count - target_count)

        # 6. 그룹 정보 업데이트
        group.target_minion_count = target_count
        group.current_minion_count = target_count
        group.last_resize_at = datetime.utcnow()
        group.resize_reason = decision["reason"]

        await self.session.commit()

        return {
            "adjusted": True,
            "old_count": current_count,
            "new_count": target_count,
            "reason": decision["reason"],
            "level": decision["level"]
        }

    # ==================== 그룹 생성 및 관리 ====================

    async def create_group(
        self,
        group_name: str,
        group_type: str,
        leader_bot_id: str,
        initial_minion_count: int = 7
    ) -> Dict[str, any]:
        """
        새 대장-쫄병 그룹 생성

        Args:
            group_name: 그룹 이름
            group_type: 'traffic' or 'rank_checker'
            leader_bot_id: 대장 봇 ID
            initial_minion_count: 초기 쫄병 수 (기본 7)

        Returns:
            {
                "success": bool,
                "group_id": str,
                "group_name": str
            }
        """
        # 1. 대장 봇 검증
        leader = await self._get_bot(leader_bot_id)
        if not leader:
            return {"success": False, "error": "leader_not_found"}

        # 2. 그룹 생성
        group_id = str(uuid4())
        group = RankingGroup(
            group_id=group_id,
            group_name=group_name,
            group_type=group_type,
            leader_bot_id=leader_bot_id,
            target_minion_count=initial_minion_count,
            current_minion_count=0
        )
        self.session.add(group)

        # 3. 대장 봇 설정
        leader.is_leader = True
        leader.bot_type = group_type
        leader.ranking_group_id = group_id
        leader.max_minion_capacity = 7

        await self.session.commit()

        return {
            "success": True,
            "group_id": group_id,
            "group_name": group_name
        }

    async def assign_minion(
        self,
        group_id: str,
        bot_id: str
    ) -> Dict[str, any]:
        """
        봇을 쫄병으로 그룹에 할당

        Returns:
            {
                "success": bool,
                "bot_id": str,
                "group_id": str
            }
        """
        # 1. 그룹 조회
        group = await self._get_group(group_id)
        if not group:
            return {"success": False, "error": "group_not_found"}

        # 2. 쫄병 봇 조회
        bot = await self._get_bot(bot_id)
        if not bot:
            return {"success": False, "error": "bot_not_found"}

        # 3. 최대 수용 인원 체크
        if group.current_minion_count >= group.max_minions:
            return {"success": False, "error": "group_full"}

        # 4. 쫄병 설정
        bot.is_leader = False
        bot.bot_type = group.group_type
        bot.ranking_group_id = group_id
        bot.leader_bot_id = group.leader_bot_id
        bot.connection_status = "disconnected"

        # 5. 그룹 카운트 증가
        group.current_minion_count += 1

        await self.session.commit()

        return {
            "success": True,
            "bot_id": bot_id,
            "group_id": group_id
        }

    async def remove_minion(
        self,
        group_id: str,
        bot_id: str
    ) -> Dict[str, any]:
        """
        쫄병을 그룹에서 제거

        Returns:
            {
                "success": bool,
                "bot_id": str
            }
        """
        # 1. 그룹 조회
        group = await self._get_group(group_id)
        if not group:
            return {"success": False, "error": "group_not_found"}

        # 2. 쫄병 봇 조회
        bot = await self._get_bot(bot_id)
        if not bot:
            return {"success": False, "error": "bot_not_found"}

        # 3. 쫄병 설정 해제
        bot.ranking_group_id = None
        bot.leader_bot_id = None
        bot.connection_status = "disconnected"

        # 4. 그룹 카운트 감소
        group.current_minion_count = max(0, group.current_minion_count - 1)

        await self.session.commit()

        return {
            "success": True,
            "bot_id": bot_id
        }

    # ==================== 헬스 체크 ====================

    async def update_leader_health(
        self,
        bot_id: str,
        battery_level: int,
        memory_available_mb: int,
        hotspot_stability_score: float,
        network_latency_ms: int,
        device_temperature: float
    ) -> Dict[str, any]:
        """
        대장 봇의 헬스 정보 업데이트

        Returns:
            {
                "success": bool,
                "health_score": float,
                "recommended_minion_count": int
            }
        """
        # 1. 대장 봇 조회
        leader = await self._get_bot(bot_id)
        if not leader:
            return {"success": False, "error": "bot_not_found"}

        # 2. Health Score 계산
        health_score = self.calculate_health_score(
            battery_level=battery_level,
            memory_available_mb=memory_available_mb,
            hotspot_stability_score=hotspot_stability_score,
            network_latency_ms=network_latency_ms,
            device_temperature=device_temperature
        )

        # 3. 대장 봇 정보 업데이트
        leader.battery_level = battery_level
        leader.memory_available_mb = memory_available_mb
        leader.hotspot_stability_score = hotspot_stability_score
        leader.network_latency_ms = network_latency_ms
        leader.device_temperature = device_temperature
        leader.health_score = health_score
        leader.last_health_check_at = datetime.utcnow()

        await self.session.commit()

        # 4. 추천 쫄병 수 계산
        decision = self.determine_minion_count(
            battery_level=battery_level,
            device_temperature=device_temperature,
            health_score=health_score
        )

        return {
            "success": True,
            "health_score": health_score,
            "recommended_minion_count": decision["target_count"],
            "reason": decision["reason"],
            "level": decision["level"]
        }

    async def get_group_status(self, group_id: str) -> Dict[str, any]:
        """
        그룹 상태 조회

        Returns:
            {
                "group_id": str,
                "group_name": str,
                "leader": {...},
                "minions": [...],
                "health_summary": {...}
            }
        """
        # 1. 그룹 조회
        group = await self._get_group(group_id)
        if not group:
            return {"error": "group_not_found"}

        # 2. 대장 봇 조회
        leader = await self._get_leader_bot(group.leader_bot_id)

        # 3. 쫄병들 조회
        minions = await self._get_minions(group_id)

        # 4. 헬스 요약
        health_summary = {
            "leader_health_score": leader.health_score if leader else 0,
            "leader_battery": leader.battery_level if leader else 0,
            "leader_temperature": leader.device_temperature if leader else 0,
            "current_minion_count": group.current_minion_count,
            "target_minion_count": group.target_minion_count,
            "connected_minions": sum(1 for m in minions if m.connection_status == "connected")
        }

        return {
            "group_id": group.group_id,
            "group_name": group.group_name,
            "group_type": group.group_type,
            "status": group.status,
            "leader": {
                "bot_id": leader.bot_id if leader else None,
                "battery_level": leader.battery_level if leader else 0,
                "device_temperature": leader.device_temperature if leader else 0,
                "health_score": leader.health_score if leader else 0,
                "current_ip": leader.current_ip if leader else None
            },
            "minions": [
                {
                    "bot_id": m.bot_id,
                    "connection_status": m.connection_status,
                    "task_status": m.task_status
                } for m in minions
            ],
            "health_summary": health_summary
        }

    # ==================== Private Methods ====================

    async def _get_group(self, group_id: str) -> Optional[RankingGroup]:
        """그룹 조회"""
        result = await self.session.execute(
            select(RankingGroup).where(RankingGroup.group_id == group_id)
        )
        return result.scalar_one_or_none()

    async def _get_bot(self, bot_id: str) -> Optional[Bot]:
        """봇 조회"""
        result = await self.session.execute(
            select(Bot).where(Bot.bot_id == bot_id)
        )
        return result.scalar_one_or_none()

    async def _get_leader_bot(self, bot_id: str) -> Optional[Bot]:
        """대장 봇 조회"""
        return await self._get_bot(bot_id)

    async def _get_minions(self, group_id: str) -> List[Bot]:
        """그룹의 쫄병들 조회"""
        result = await self.session.execute(
            select(Bot).where(
                Bot.ranking_group_id == group_id,
                Bot.is_leader == False
            )
        )
        return result.scalars().all()

    async def _add_minions(self, group_id: str, count: int) -> bool:
        """
        쫄병 추가 (미할당 봇 자동 할당)

        Returns:
            bool: 성공 여부
        """
        # 1. 미할당 봇 조회
        result = await self.session.execute(
            select(Bot).where(
                Bot.ranking_group_id == None,
                Bot.status == "active"
            ).limit(count)
        )
        available_bots = result.scalars().all()

        # 2. 각 봇을 쫄병으로 할당
        for bot in available_bots:
            await self.assign_minion(group_id, bot.bot_id)

        return len(available_bots) == count

    async def _remove_minions(self, group_id: str, count: int) -> bool:
        """
        쫄병 제거 (우선순위: 대기 상태 봇부터)

        Returns:
            bool: 성공 여부
        """
        # 1. 제거할 쫄병 조회 (우선순위: idle > completed > working)
        result = await self.session.execute(
            select(Bot).where(
                Bot.ranking_group_id == group_id,
                Bot.is_leader == False
            ).order_by(
                Bot.task_status  # 'completed' < 'idle' < 'working' (알파벳 순)
            ).limit(count)
        )
        minions_to_remove = result.scalars().all()

        # 2. 각 봇 제거
        for bot in minions_to_remove:
            await self.remove_minion(group_id, bot.bot_id)

        return len(minions_to_remove) == count
