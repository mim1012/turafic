"""
IP Rotation Manager
하이브리드 IP 변경 전략 관리
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from uuid import uuid4

from server.core.database import Bot, RankingGroup, IPChangeHistory, TaskCompletionSignal


class IPRotationManager:
    """
    IP 로테이션 관리자

    전략: "wait_for_completion" (하이브리드)
    - 기본 주기: 5분 (300초)
    - 작업 완료 대기: 최대 3분 (180초)
    - 모든 쫄병이 작업 완료 시 즉시 IP 변경
    - 3분 초과 시 강제 IP 변경
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def should_change_ip(self, group_id: str) -> Dict[str, any]:
        """
        IP 변경 시점 판단

        Returns:
            {
                "should_change": bool,
                "reason": str,  # "scheduled", "all_completed", "timeout"
                "wait_duration": int,  # 초
                "completed_minions": int,
                "total_minions": int
            }
        """
        # 1. 그룹 정보 조회
        group = await self._get_group(group_id)
        if not group:
            return {
                "should_change": False,
                "reason": "group_not_found",
                "wait_duration": 0,
                "completed_minions": 0,
                "total_minions": 0
            }

        # 2. 마지막 IP 변경 시각 확인
        last_change = group.last_ip_change_at or datetime.utcnow()
        elapsed = (datetime.utcnow() - last_change).total_seconds()

        # 3. 쫄병들의 작업 상태 조회
        minion_status = await self._get_minion_status(group_id)

        working = minion_status["working"]
        completed = minion_status["completed"]
        total = minion_status["total"]

        # 4. 전략별 판단
        if group.ip_change_strategy == "wait_for_completion":
            # 하이브리드 전략

            # 4-1. 모든 쫄병이 작업 완료한 경우
            if working == 0 and total > 0:
                return {
                    "should_change": True,
                    "reason": "all_completed",
                    "wait_duration": int(elapsed),
                    "completed_minions": completed,
                    "total_minions": total
                }

            # 4-2. 최대 대기 시간 초과 (강제 변경)
            if elapsed >= group.max_wait_time_sec:
                return {
                    "should_change": True,
                    "reason": "timeout",
                    "wait_duration": int(elapsed),
                    "completed_minions": completed,
                    "total_minions": total
                }

            # 4-3. 기본 주기 도달 + 작업 중인 쫄병 없음
            if elapsed >= group.ip_change_interval_sec and working == 0:
                return {
                    "should_change": True,
                    "reason": "scheduled",
                    "wait_duration": int(elapsed),
                    "completed_minions": completed,
                    "total_minions": total
                }

            # 4-4. 아직 변경 시점 아님
            return {
                "should_change": False,
                "reason": "waiting",
                "wait_duration": int(elapsed),
                "completed_minions": completed,
                "total_minions": total
            }

        elif group.ip_change_strategy == "fixed_interval":
            # 고정 주기 전략
            if elapsed >= group.ip_change_interval_sec:
                return {
                    "should_change": True,
                    "reason": "scheduled",
                    "wait_duration": int(elapsed),
                    "completed_minions": completed,
                    "total_minions": total
                }
            return {
                "should_change": False,
                "reason": "waiting",
                "wait_duration": int(elapsed),
                "completed_minions": completed,
                "total_minions": total
            }

        else:  # manual
            return {
                "should_change": False,
                "reason": "manual_mode",
                "wait_duration": int(elapsed),
                "completed_minions": completed,
                "total_minions": total
            }

    async def execute_ip_change(
        self,
        group_id: str,
        reason: str,
        wait_duration: int,
        completed_minions: int,
        total_minions: int
    ) -> Dict[str, any]:
        """
        IP 변경 실행 및 기록

        Returns:
            {
                "success": bool,
                "old_ip": str,
                "new_ip": str,
                "leader_bot_id": str
            }
        """
        # 1. 그룹 정보 조회
        group = await self._get_group(group_id)
        if not group:
            return {"success": False, "error": "group_not_found"}

        # 2. 대장 봇 조회
        leader = await self._get_leader_bot(group.leader_bot_id)
        if not leader:
            return {"success": False, "error": "leader_not_found"}

        old_ip = group.current_ip

        # 3. 대장 봇에게 IP 변경 명령 전송 (실제 구현 시 API 호출)
        # TODO: 대장 봇 API 호출 (비행기 모드 토글)
        # new_ip = await self._trigger_airplane_mode(leader.bot_id)
        new_ip = f"192.168.{uuid4().int % 256}.{uuid4().int % 256}"  # Mock IP

        # 4. 그룹 IP 정보 업데이트
        group.current_ip = new_ip
        group.last_ip_change_at = datetime.utcnow()
        group.total_ip_changes += 1

        # 5. 대장 봇 IP 정보 업데이트
        leader.current_ip = new_ip
        leader.last_ip_change_at = datetime.utcnow()
        leader.ip_change_count += 1

        # 6. IP 변경 이력 저장
        history = IPChangeHistory(
            group_id=group_id,
            leader_bot_id=leader.bot_id,
            old_ip=old_ip,
            new_ip=new_ip,
            change_reason=reason,
            minions_completed=completed_minions,
            minions_total=total_minions,
            wait_duration_sec=wait_duration
        )
        self.session.add(history)

        # 7. 작업 완료 신호 초기화 (다음 사이클 준비)
        await self._clear_completion_signals(group_id)

        # 8. 모든 쫄병의 task_status를 'idle'로 리셋
        await self._reset_minion_task_status(group_id)

        await self.session.commit()

        return {
            "success": True,
            "old_ip": old_ip,
            "new_ip": new_ip,
            "leader_bot_id": leader.bot_id
        }

    async def report_task_completion(
        self,
        group_id: str,
        bot_id: str,
        task_id: str
    ) -> bool:
        """
        쫄병의 작업 완료 보고 처리

        Returns:
            bool: 모든 쫄병이 완료했는지 여부
        """
        # 1. 봇 task_status 업데이트
        bot = await self._get_bot(bot_id)
        if bot:
            bot.task_status = "completed"
            bot.task_completed_at = datetime.utcnow()

        # 2. 완료 신호 저장
        signal = TaskCompletionSignal(
            signal_id=str(uuid4()),
            group_id=group_id,
            bot_id=bot_id,
            task_id=task_id
        )
        self.session.add(signal)
        await self.session.commit()

        # 3. 모든 쫄병이 완료했는지 확인
        minion_status = await self._get_minion_status(group_id)
        return minion_status["working"] == 0 and minion_status["total"] > 0

    # ==================== Private Methods ====================

    async def _get_group(self, group_id: str) -> Optional[RankingGroup]:
        """그룹 조회"""
        result = await self.session.execute(
            select(RankingGroup).where(RankingGroup.group_id == group_id)
        )
        return result.scalar_one_or_none()

    async def _get_leader_bot(self, bot_id: str) -> Optional[Bot]:
        """대장 봇 조회"""
        result = await self.session.execute(
            select(Bot).where(Bot.bot_id == bot_id)
        )
        return result.scalar_one_or_none()

    async def _get_bot(self, bot_id: str) -> Optional[Bot]:
        """봇 조회"""
        result = await self.session.execute(
            select(Bot).where(Bot.bot_id == bot_id)
        )
        return result.scalar_one_or_none()

    async def _get_minion_status(self, group_id: str) -> Dict[str, int]:
        """
        쫄병들의 작업 상태 집계

        Returns:
            {
                "working": int,      # 작업 중인 쫄병 수
                "completed": int,    # 완료한 쫄병 수
                "idle": int,         # 대기 중인 쫄병 수
                "total": int         # 전체 쫄병 수
            }
        """
        # 쫄병들 조회 (is_leader=False)
        result = await self.session.execute(
            select(
                Bot.task_status,
                func.count(Bot.bot_id).label("count")
            ).where(
                Bot.ranking_group_id == group_id,
                Bot.is_leader == False
            ).group_by(Bot.task_status)
        )

        status_counts = {row.task_status: row.count for row in result}

        working = status_counts.get("working", 0)
        completed = status_counts.get("completed", 0)
        idle = status_counts.get("idle", 0)
        total = working + completed + idle

        return {
            "working": working,
            "completed": completed,
            "idle": idle,
            "total": total
        }

    async def _clear_completion_signals(self, group_id: str):
        """작업 완료 신호 초기화"""
        await self.session.execute(
            select(TaskCompletionSignal).where(
                TaskCompletionSignal.group_id == group_id
            )
        )
        # 삭제는 필요 시 구현 (이력 보관 정책에 따라)

    async def _reset_minion_task_status(self, group_id: str):
        """모든 쫄병의 task_status를 'idle'로 리셋"""
        result = await self.session.execute(
            select(Bot).where(
                Bot.ranking_group_id == group_id,
                Bot.is_leader == False
            )
        )
        minions = result.scalars().all()

        for minion in minions:
            minion.task_status = "idle"
            minion.task_completed_at = None

        await self.session.commit()


class IPRotationScheduler:
    """
    IP 로테이션 스케줄러
    백그라운드에서 주기적으로 IP 변경 시점을 체크
    """

    def __init__(self, session: AsyncSession):
        self.manager = IPRotationManager(session)
        self.running = False

    async def start(self, check_interval: int = 30):
        """
        스케줄러 시작

        Args:
            check_interval: 체크 주기 (초)
        """
        self.running = True

        while self.running:
            try:
                # 모든 활성화된 그룹 조회
                groups = await self._get_active_groups()

                for group in groups:
                    # IP 변경 시점 체크
                    decision = await self.manager.should_change_ip(group.group_id)

                    if decision["should_change"]:
                        # IP 변경 실행
                        result = await self.manager.execute_ip_change(
                            group_id=group.group_id,
                            reason=decision["reason"],
                            wait_duration=decision["wait_duration"],
                            completed_minions=decision["completed_minions"],
                            total_minions=decision["total_minions"]
                        )

                        if result["success"]:
                            print(f"✅ IP 변경 완료: {group.group_name} "
                                  f"({result['old_ip']} → {result['new_ip']}) "
                                  f"[{decision['reason']}]")

                # 다음 체크까지 대기
                await asyncio.sleep(check_interval)

            except Exception as e:
                print(f"❌ IP 로테이션 스케줄러 오류: {e}")
                await asyncio.sleep(check_interval)

    async def stop(self):
        """스케줄러 중지"""
        self.running = False

    async def _get_active_groups(self) -> List[RankingGroup]:
        """활성화된 모든 그룹 조회"""
        result = await self.manager.session.execute(
            select(RankingGroup).where(RankingGroup.status == "active")
        )
        return result.scalars().all()
