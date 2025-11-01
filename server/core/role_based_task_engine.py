"""
Role-based Task Engine
역할별 작업 패턴 생성 로직 - Leader, Follower, Rank Checker
"""

import random
from typing import Dict, List, Optional
from server.core.task_engine import generate_task_pattern, add_randomness_to_pattern


def generate_leader_task(
    task_config: Dict,
    coordinates: Dict,
    keyword: str,
    ranking_group_id: str
) -> List[Dict]:
    """
    Leader Bot용 작업 패턴 생성

    특징:
    - 일반 트래픽 작업 수행
    - 작업 완료 후 쫄병 완료 대기 신호 포함
    - IP 변경 (비행기 모드 토글) 포함

    Args:
        task_config: 테스트 케이스 설정
        coordinates: UI 좌표 맵
        keyword: 검색 키워드
        ranking_group_id: 랭킹 그룹 ID

    Returns:
        JSON 작업 패턴 리스트
    """
    # 기본 트래픽 작업 패턴 생성
    pattern = generate_task_pattern(task_config, coordinates, keyword)

    # Leader 전용 추가 액션
    leader_actions = [
        {
            "action": "wait_for_followers",
            "ranking_group_id": ranking_group_id,
            "max_wait_time": 180000,  # 3분
            "description": "쫄병 작업 완료 대기 (최대 3분)"
        },
        {
            "action": "airplane_mode_toggle",
            "description": "IP 변경 (비행기 모드 토글)"
        },
        {
            "action": "wait",
            "duration": 5000,
            "description": "네트워크 재연결 대기"
        }
    ]

    # 패턴에 추가
    pattern.extend(leader_actions)

    return add_randomness_to_pattern(pattern)


def generate_follower_task(
    task_config: Dict,
    coordinates: Dict,
    keyword: str,
    ranking_group_id: str
) -> List[Dict]:
    """
    Follower Bot용 작업 패턴 생성

    특징:
    - 일반 트래픽 작업 수행
    - 작업 완료 후 그룹 완료 신호 전송
    - Leader의 IP 변경 대기

    Args:
        task_config: 테스트 케이스 설정
        coordinates: UI 좌표 맵
        keyword: 검색 키워드
        ranking_group_id: 랭킹 그룹 ID

    Returns:
        JSON 작업 패턴 리스트
    """
    # 기본 트래픽 작업 패턴 생성
    pattern = generate_task_pattern(task_config, coordinates, keyword)

    # Follower 전용 추가 액션
    follower_actions = [
        {
            "action": "report_completion",
            "ranking_group_id": ranking_group_id,
            "description": "그룹 완료 신호 전송"
        },
        {
            "action": "wait_for_ip_change",
            "ranking_group_id": ranking_group_id,
            "max_wait_time": 180000,  # 3분
            "description": "Leader IP 변경 대기"
        },
        {
            "action": "wait",
            "duration": 5000,
            "description": "네트워크 재연결 대기"
        }
    ]

    # 패턴에 추가
    pattern.extend(follower_actions)

    return add_randomness_to_pattern(pattern)


def generate_rank_checker_task(
    keyword: str,
    target_product_id: str,
    max_pages: int = 10
) -> List[Dict]:
    """
    Rank Checker Bot용 작업 패턴 생성

    특징:
    - 네이버 쇼핑 검색 실행
    - 페이지별 상품 순위 찾기
    - 순위 데이터 서버 보고

    Args:
        keyword: 검색 키워드
        target_product_id: 찾을 상품 ID
        max_pages: 최대 검색 페이지 수 (기본 10페이지)

    Returns:
        JSON 작업 패턴 리스트
    """
    pattern = [
        {
            "action": "kill",
            "target": "com.sec.android.app.sbrowser",
            "description": "삼성 브라우저 강제 종료"
        },
        {
            "action": "wait",
            "duration": 2000,
            "description": "2초 대기"
        },
        {
            "action": "start",
            "target": "com.sec.android.app.sbrowser",
            "description": "삼성 브라우저 시작"
        },
        {
            "action": "wait",
            "duration": 3000,
            "description": "브라우저 로딩 대기"
        },
        {
            "action": "open_url",
            "url": f"https://m.shopping.naver.com/search?query={keyword}",
            "description": f"네이버 쇼핑 검색: {keyword}"
        },
        {
            "action": "wait",
            "duration": 3000,
            "description": "검색 결과 로딩 대기"
        }
    ]

    # 페이지별 순위 찾기
    for page in range(1, max_pages + 1):
        pattern.extend([
            {
                "action": "find_product_rank",
                "target_product_id": target_product_id,
                "page": page,
                "description": f"{page}페이지에서 상품 찾기"
            },
            {
                "action": "scroll",
                "direction": "down",
                "distance": 800,
                "duration": 300,
                "description": "다음 페이지로 스크롤"
            },
            {
                "action": "wait",
                "duration": 2000,
                "description": "페이지 로딩 대기"
            }
        ])

    # 순위 보고
    pattern.append({
        "action": "report_ranking",
        "keyword": keyword,
        "target_product_id": target_product_id,
        "description": "순위 데이터 서버 보고"
    })

    return pattern


def get_task_by_role(
    role: str,
    bot_id: str,
    task_config: Dict = None,
    coordinates: Dict = None,
    keyword: str = None,
    ranking_group_id: str = None,
    target_product_id: str = None
) -> Optional[List[Dict]]:
    """
    봇 역할에 따른 작업 패턴 생성

    Args:
        role: 봇 역할 ("leader", "follower", "rank_checker")
        bot_id: 봇 ID
        task_config: 테스트 케이스 설정 (traffic bots용)
        coordinates: UI 좌표 맵 (traffic bots용)
        keyword: 검색 키워드
        ranking_group_id: 랭킹 그룹 ID (leader/follower용)
        target_product_id: 대상 상품 ID (rank_checker용)

    Returns:
        JSON 작업 패턴 리스트 또는 None
    """
    if role == "leader":
        if not all([task_config, coordinates, keyword, ranking_group_id]):
            return None
        return generate_leader_task(task_config, coordinates, keyword, ranking_group_id)

    elif role == "follower":
        if not all([task_config, coordinates, keyword, ranking_group_id]):
            return None
        return generate_follower_task(task_config, coordinates, keyword, ranking_group_id)

    elif role == "rank_checker":
        if not all([keyword, target_product_id]):
            return None
        return generate_rank_checker_task(keyword, target_product_id)

    else:
        # Unknown role
        return None


def get_task_priority_by_role(role: str) -> int:
    """
    역할별 작업 우선순위 반환

    Args:
        role: 봇 역할

    Returns:
        우선순위 (낮을수록 높은 우선순위)
    """
    priorities = {
        "rank_checker": 1,  # 순위 체크는 최우선
        "leader": 2,        # 대장 봇
        "follower": 3       # 쫄병 봇
    }
    return priorities.get(role, 999)


def validate_task_pattern(pattern: List[Dict], role: str) -> bool:
    """
    작업 패턴 유효성 검증

    Args:
        pattern: 작업 패턴
        role: 봇 역할

    Returns:
        유효 여부
    """
    if not pattern:
        return False

    # 필수 액션 확인
    required_actions = {
        "leader": ["wait_for_followers", "airplane_mode_toggle"],
        "follower": ["report_completion", "wait_for_ip_change"],
        "rank_checker": ["find_product_rank", "report_ranking"]
    }

    if role in required_actions:
        actions = [step.get("action") for step in pattern]
        for required in required_actions[role]:
            if required not in actions:
                return False

    return True


def estimate_task_duration(pattern: List[Dict]) -> int:
    """
    작업 패턴의 총 소요 시간 예측 (초 단위)

    Args:
        pattern: 작업 패턴

    Returns:
        예상 소요 시간 (초)
    """
    total_ms = 0

    for step in pattern:
        action = step.get("action")

        # wait 액션
        if action == "wait":
            total_ms += step.get("duration", 0)

        # 특수 액션의 예상 시간
        elif action == "wait_for_followers":
            total_ms += 180000  # 최대 3분
        elif action == "wait_for_ip_change":
            total_ms += 30000  # 평균 30초
        elif action == "airplane_mode_toggle":
            total_ms += 8000  # 8초 (3초 ON + 5초 OFF)
        elif action == "find_product_rank":
            total_ms += 2000  # 페이지당 2초
        elif action == "scroll":
            total_ms += step.get("duration", 300)

    return total_ms // 1000  # 밀리초 → 초


def get_role_description(role: str) -> str:
    """
    역할 설명 반환

    Args:
        role: 봇 역할

    Returns:
        역할 설명
    """
    descriptions = {
        "leader": "대장 봇 - 핫스팟 제공 및 IP 로테이션 관리",
        "follower": "쫄병 봇 - 대장 핫스팟 연결하여 트래픽 생성",
        "rank_checker": "순위 체크 봇 - 네이버 쇼핑 상품 순위 확인"
    }
    return descriptions.get(role, "Unknown role")
