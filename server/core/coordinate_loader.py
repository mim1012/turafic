"""
UI Coordinate Loader
해상도별 UI 좌표 맵을 로드하고 캐싱하는 모듈
이전 가이드(ff8122c) 방식: 단일 통합 JSON 파일 사용
"""

import json
from pathlib import Path
from typing import Dict, Optional
from server.core.cache import get_redis

# 좌표 맵 파일 경로 (이전 가이드 방식)
COORDINATES_FILE = Path(__file__).parent.parent / "data" / "ui_coordinates.json"

# 백업: 개별 파일 디렉토리 (현재 구현 방식)
COORDINATES_DIR = Path(__file__).parent.parent.parent / "config" / "ui_coordinates"


async def load_coordinates(resolution: str) -> Optional[Dict]:
    """
    해상도별 UI 좌표 맵 로드 (Redis 캐싱)

    우선순위:
    1. server/data/ui_coordinates.json (통합 파일, 이전 가이드 방식)
    2. config/ui_coordinates/{resolution}.json (개별 파일, 백업)

    Args:
        resolution: 해상도 문자열 (예: "1080x2340", "1440x3200", "720x1560")

    Returns:
        좌표 맵 딕셔너리 또는 None
    """
    redis = await get_redis()
    cache_key = f"ui_coordinates:{resolution}"

    # 1. Redis 캐시 확인
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    # 2. 통합 JSON 파일에서 로드 (이전 가이드 방식)
    if COORDINATES_FILE.exists():
        with open(COORDINATES_FILE, "r", encoding="utf-8") as f:
            all_coordinates = json.load(f)

        if resolution in all_coordinates:
            coordinates = all_coordinates[resolution]

            # Redis에 캐싱 (TTL: 24시간)
            await redis.setex(cache_key, 86400, json.dumps(coordinates))

            return coordinates

    # 3. 개별 파일에서 로드 (백업)
    patterns = [
        f"{resolution}.json",
        f"{resolution}_samsung_s7.json",
        f"{resolution}_samsung_s24.json",
    ]

    for pattern in patterns:
        filepath = COORDINATES_DIR / pattern
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                coordinates = json.load(f)

            # Redis에 캐싱 (TTL: 24시간)
            await redis.setex(cache_key, 86400, json.dumps(coordinates))

            return coordinates

    # 4. 파일이 없으면 None 반환
    return None


async def get_coordinate(resolution: str, element_path: str) -> Optional[Dict]:
    """
    특정 UI 요소의 좌표 조회

    Args:
        resolution: 해상도 문자열
        element_path: 요소 경로 (예: "naver_shopping.product_item_1")

    Returns:
        좌표 딕셔너리 {"x": 270, "y": 600, "width": 520, "height": 300}

    Examples:
        >>> await get_coordinate("1080x2340", "naver_shopping.product_item_1")
        {"x": 270, "y": 600, "width": 520, "height": 300, "description": "..."}
    """
    coordinates = await load_coordinates(resolution)
    if not coordinates:
        return None

    # 경로 파싱 (예: "naver_shopping.product_item_1" → coordinates["naver_shopping"]["product_item_1"])
    keys = element_path.split(".")
    current = coordinates

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None

    return current if isinstance(current, dict) else None


def generate_coordinates_for_pattern(coordinates_map: Dict) -> Dict:
    """
    작업 패턴 생성에 사용할 간소화된 좌표 맵 생성

    Args:
        coordinates_map: 전체 좌표 맵

    Returns:
        간소화된 좌표 맵 (중심점만 포함)
        {
            "search_bar": {"x": 540, "y": 200},
            "product_item_1": {"x": 270, "y": 600},
            ...
        }
    """
    simplified = {}

    # 검색창
    if "naver_main" in coordinates_map:
        search_bar = coordinates_map["naver_main"].get("search_bar", {})
        simplified["search_bar"] = {"x": search_bar.get("x"), "y": search_bar.get("y")}

    # 쇼핑 탭
    if "naver_search_result" in coordinates_map:
        tab_shopping = coordinates_map["naver_search_result"].get("tab_shopping", {})
        simplified["tab_shopping"] = {"x": tab_shopping.get("x"), "y": tab_shopping.get("y")}

    # 상품 아이템들
    if "naver_shopping" in coordinates_map:
        for i in range(1, 5):
            item_key = f"product_item_{i}"
            if item_key in coordinates_map["naver_shopping"]:
                item = coordinates_map["naver_shopping"][item_key]
                simplified[item_key] = {"x": item.get("x"), "y": item.get("y")}

    # 상품 상세 페이지 버튼들
    if "product_detail_page" in coordinates_map:
        detail_page = coordinates_map["product_detail_page"]

        # 장바구니/구매 버튼
        if "add_to_cart_button" in detail_page:
            btn = detail_page["add_to_cart_button"]
            simplified["add_to_cart_button"] = {"x": btn.get("x"), "y": btn.get("y")}

        if "buy_now_button" in detail_page:
            btn = detail_page["buy_now_button"]
            simplified["buy_now_button"] = {"x": btn.get("x"), "y": btn.get("y")}

        # 리뷰/문의 탭
        if "review_tab" in detail_page:
            tab = detail_page["review_tab"]
            simplified["review_tab"] = {"x": tab.get("x"), "y": tab.get("y")}

        if "qna_tab" in detail_page:
            tab = detail_page["qna_tab"]
            simplified["qna_tab"] = {"x": tab.get("x"), "y": tab.get("y")}

    return simplified


async def get_scroll_config(resolution: str) -> Dict:
    """
    스크롤 설정 조회

    Args:
        resolution: 해상도 문자열

    Returns:
        스크롤 설정 딕셔너리
        {
            "screen_width": 1080,
            "screen_height": 2340,
            "safe_start_y": 1200,
            "safe_end_y": 800,
            "swipe_duration": 300
        }
    """
    coordinates = await load_coordinates(resolution)
    if not coordinates or "scroll_config" not in coordinates:
        # 기본값 반환
        width, height = map(int, resolution.split("x"))
        return {
            "screen_width": width,
            "screen_height": height,
            "safe_start_y": int(height * 0.6),
            "safe_end_y": int(height * 0.4),
            "swipe_duration": 300
        }

    return coordinates["scroll_config"]


async def list_available_resolutions() -> list:
    """
    사용 가능한 해상도 목록 조회

    Returns:
        해상도 문자열 리스트 (예: ["1080x2340", "1440x3200", "720x1560"])
    """
    # 1. 통합 JSON 파일에서 조회 (이전 가이드 방식)
    if COORDINATES_FILE.exists():
        with open(COORDINATES_FILE, "r", encoding="utf-8") as f:
            all_coordinates = json.load(f)
        return sorted(all_coordinates.keys())

    # 2. 개별 파일에서 조회 (백업)
    resolutions = []
    for filepath in COORDINATES_DIR.glob("*.json"):
        filename = filepath.stem  # 확장자 제거
        # "1080x2340_samsung_s7" → "1080x2340"
        resolution = filename.split("_")[0]
        if resolution not in resolutions:
            resolutions.append(resolution)

    return sorted(resolutions)
