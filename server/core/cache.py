"""
Redis Cache for UI Coordinate Maps
UI 좌표 맵을 Redis에 캐싱하여 빠른 조회 제공
"""

import json
import os
from typing import Optional, Dict

# Redis 사용 여부 (환경 변수로 제어)
USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"

if USE_REDIS:
    import redis.asyncio as redis
    redis_client = None
else:
    # Redis 미사용 시 인메모리 딕셔너리 사용
    memory_cache = {}

# 기본 UI 좌표 맵 (하드코딩)
DEFAULT_UI_COORDINATES = {
    "1080x2340": {  # 갤럭시 S22
        "search_bar": {"x": 540, "y": 150},
        "product_item_1": {"x": 540, "y": 600},
        "product_item_2": {"x": 540, "y": 900},
        "buy_button": {"x": 540, "y": 1800},
        "back_button": {"x": 100, "y": 100}
    },
    "720x1560": {  # 갤럭시 A23
        "search_bar": {"x": 360, "y": 100},
        "product_item_1": {"x": 360, "y": 400},
        "product_item_2": {"x": 360, "y": 600},
        "buy_button": {"x": 360, "y": 1200},
        "back_button": {"x": 70, "y": 70}
    },
    "1440x3200": {  # 갤럭시 Note 9
        "search_bar": {"x": 720, "y": 200},
        "product_item_1": {"x": 720, "y": 800},
        "product_item_2": {"x": 720, "y": 1200},
        "buy_button": {"x": 720, "y": 2400},
        "back_button": {"x": 130, "y": 130}
    }
}

async def init_cache():
    """캐시 초기화"""
    global redis_client, memory_cache
    
    if USE_REDIS:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        redis_client = await redis.from_url(redis_url, decode_responses=True)
        
        # 기본 UI 좌표 맵을 Redis에 저장
        for resolution, coordinates in DEFAULT_UI_COORDINATES.items():
            await redis_client.set(
                f"ui_coordinates:{resolution}",
                json.dumps(coordinates)
            )
        print("✅ Redis cache initialized with default UI coordinates")
    else:
        # 인메모리 캐시 초기화
        memory_cache = DEFAULT_UI_COORDINATES.copy()
        print("✅ In-memory cache initialized with default UI coordinates")


async def close_cache():
    """캐시 연결 종료"""
    global redis_client
    
    if USE_REDIS and redis_client:
        await redis_client.close()
        print("✅ Redis connection closed")


async def get_ui_coordinates(resolution: str) -> Optional[Dict]:
    """
    해상도에 맞는 UI 좌표 맵 조회
    
    Args:
        resolution: 해상도 문자열 (예: "1080x2340")
    
    Returns:
        UI 좌표 맵 딕셔너리 또는 None
    """
    if USE_REDIS:
        data = await redis_client.get(f"ui_coordinates:{resolution}")
        if data:
            return json.loads(data)
    else:
        return memory_cache.get(resolution)
    
    # 해당 해상도가 없으면 기본값 반환 (1080x2340)
    return DEFAULT_UI_COORDINATES.get("1080x2340")


async def set_ui_coordinates(resolution: str, coordinates: Dict):
    """
    UI 좌표 맵 업데이트 (자가 치유 시스템에서 사용)
    
    Args:
        resolution: 해상도 문자열
        coordinates: UI 좌표 맵 딕셔너리
    """
    if USE_REDIS:
        await redis_client.set(
            f"ui_coordinates:{resolution}",
            json.dumps(coordinates)
        )
    else:
        memory_cache[resolution] = coordinates
    
    print(f"✅ UI coordinates updated for resolution: {resolution}")
