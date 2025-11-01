"""
Task Assignment Engine
작업 할당 로직 - A/B 테스트 그룹 관리 및 작업 패턴 생성
"""

import json
import random
from typing import Dict, List
from pathlib import Path
from server.core.coordinate_loader import load_coordinates, generate_coordinates_for_pattern

# 테스트 매트릭스 로드 (minimal_test_matrix.json)
TEST_MATRIX_PATH = Path(__file__).parent.parent.parent / "config" / "test_matrix.json"

def load_test_matrix() -> List[Dict]:
    """
    테스트 매트릭스 로드
    
    Returns:
        테스트 케이스 리스트 (9개 조합)
    """
    if TEST_MATRIX_PATH.exists():
        with open(TEST_MATRIX_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("test_cases", [])
    
    # 파일이 없으면 기본 매트릭스 반환
    return [
        {"id": 1, "engagement_level": "low", "fingerprint": "profile_a"},
        {"id": 2, "engagement_level": "low", "fingerprint": "profile_b"},
        {"id": 3, "engagement_level": "low", "fingerprint": "profile_c"},
        {"id": 4, "engagement_level": "medium", "fingerprint": "profile_a"},
        {"id": 5, "engagement_level": "medium", "fingerprint": "profile_b"},
        {"id": 6, "engagement_level": "medium", "fingerprint": "profile_c"},
        {"id": 7, "engagement_level": "high", "fingerprint": "profile_a"},
        {"id": 8, "engagement_level": "high", "fingerprint": "profile_b"},
        {"id": 9, "engagement_level": "high", "fingerprint": "profile_c"},
    ]


def assign_group(bot_count: int) -> int:
    """
    봇에게 테스트 그룹 할당 (라운드 로빈 방식)
    
    Args:
        bot_count: 현재까지 등록된 봇 수
    
    Returns:
        그룹 번호 (1~9)
    """
    return (bot_count % 9) + 1


def generate_task_pattern(
    task_config: Dict,
    coordinates: Dict,
    keyword: str = "단백질쉐이크",
    naver_product_id: str = None
) -> List[Dict]:
    """
    작업 패턴 생성 (JSON 형태)

    IP 로테이션 타이밍 충돌 해결을 위한 작업 시간 제한:
    - High: 최대 90초 (기존 120~180초에서 단축)
    - Medium: 최대 60초 (기존 60~90초 유지)
    - Low: 최대 45초 (기존 15~30초에서 증가하여 균형)

    Args:
        task_config: 테스트 케이스 설정 (engagement_level, fingerprint)
        coordinates: UI 좌표 맵
        keyword: 검색 키워드
        naver_product_id: 네이버 상품 ID (특정 상품 클릭용, 선택사항)

    Returns:
        JSON 작업 패턴 리스트
    """
    engagement_level = task_config.get("engagement_level", "medium")

    # 참여 수준에 따른 체류 시간 결정 (IP 로테이션 타이밍 충돌 해결)
    # 목표: 모든 작업을 90초 이내에 완료하여 5분 IP 변경 주기와 충돌 방지
    if engagement_level == "low":
        dwell_time = random.randint(30, 45)  # 30~45초 (기존 15~30 → 증가)
    elif engagement_level == "medium":
        dwell_time = random.randint(45, 60)  # 45~60초 (기존 60~90 → 단축)
    else:  # high
        dwell_time = random.randint(60, 90)  # 60~90초 (기존 120~180 → 대폭 단축)
    
    # JSON 패턴 생성
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
            "action": "tap",
            "x": coordinates["search_bar"]["x"],
            "y": coordinates["search_bar"]["y"],
            "description": "검색창 터치"
        },
        {
            "action": "wait",
            "duration": 1000
        },
        {
            "action": "text",
            "value": keyword,
            "description": f"'{keyword}' 입력"
        },
        {
            "action": "wait",
            "duration": 2000,
            "description": "검색 결과 로딩 대기"
        }
    ]

    # 상품 클릭 로직 (naver_product_id가 있으면 특정 상품 찾기)
    if naver_product_id:
        pattern.extend([
            {
                "action": "find_product_by_id",
                "naver_product_id": naver_product_id,
                "max_scroll_attempts": 10,
                "description": f"상품 ID {naver_product_id} 찾기"
            },
            {
                "action": "tap_found_product",
                "description": "찾은 상품 클릭"
            }
        ])
    else:
        # 기존 방식 (첫 번째 상품 클릭 - 하위 호환성)
        pattern.append({
            "action": "tap",
            "x": coordinates["product_item_1"]["x"],
            "y": coordinates["product_item_1"]["y"],
            "description": "첫 번째 상품 클릭"
        })

    # 상품 페이지 체류 및 종료
    pattern.extend([
        {
            "action": "wait",
            "duration": dwell_time * 1000,  # 밀리초 단위
            "description": f"상품 페이지 체류 ({dwell_time}초)"
        },
        {
            "action": "back",
            "description": "뒤로 가기"
        },
    ]
    
    # 높은 참여 수준일 경우 추가 행동
    if engagement_level == "high":
        pattern.extend([
            {
                "action": "scroll",
                "direction": "down",
                "distance": 500,
                "description": "아래로 스크롤"
            },
            {
                "action": "wait",
                "duration": 3000
            },
            {
                "action": "tap",
                "x": coordinates["product_item_2"]["x"],
                "y": coordinates["product_item_2"]["y"],
                "description": "두 번째 상품 클릭"
            },
            {
                "action": "wait",
                "duration": random.randint(30, 60) * 1000,
                "description": "추가 상품 탐색"
            },
            {
                "action": "back",
                "description": "뒤로 가기"
            },
        ])
    
    return pattern


def add_randomness_to_pattern(pattern: List[Dict]) -> List[Dict]:
    """
    작업 패턴에 무작위성 추가 (탐지 회피)

    Args:
        pattern: 원본 작업 패턴

    Returns:
        무작위성이 추가된 작업 패턴
    """
    randomized_pattern = []

    for step in pattern:
        new_step = step.copy()

        # tap 액션의 좌표에 ±10 픽셀 노이즈 추가
        if step["action"] == "tap":
            new_step["x"] = step["x"] + random.randint(-10, 10)
            new_step["y"] = step["y"] + random.randint(-10, 10)

        # wait 액션의 시간에 ±20% 노이즈 추가
        if step["action"] == "wait":
            duration = step["duration"]
            noise = int(duration * random.uniform(-0.2, 0.2))
            new_step["duration"] = max(500, duration + noise)  # 최소 500ms

        randomized_pattern.append(new_step)

    return randomized_pattern


def calculate_pattern_duration(pattern: List[Dict]) -> int:
    """
    작업 패턴의 총 소요 시간 계산

    Args:
        pattern: 작업 패턴 리스트

    Returns:
        총 소요 시간 (초 단위)
    """
    total_ms = 0

    for step in pattern:
        if step["action"] == "wait" and "duration" in step:
            total_ms += step["duration"]

    return total_ms // 1000  # 밀리초 → 초


def get_task_time_limits() -> Dict[str, int]:
    """
    참여 수준별 작업 시간 제한 반환

    Returns:
        {
            "low": 45,
            "medium": 60,
            "high": 90
        }
    """
    return {
        "low": 45,      # 최대 45초
        "medium": 60,   # 최대 60초
        "high": 90      # 최대 90초
    }
