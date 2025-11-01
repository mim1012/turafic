"""
HTTP 모드 작업 패턴 생성기
Appium 없이 HTTP 요청만으로 트래픽을 생성하는 패턴
"""

import random
from typing import List, Dict, Any


def generate_http_pattern(
    keyword: str,
    identity: Dict[str, Any],
    engagement_level: str = "medium"
) -> List[Dict[str, Any]]:
    """
    HTTP 모드 작업 패턴 생성
    
    Args:
        keyword: 검색 키워드
        identity: 신원 프로필 정보
        engagement_level: 참여 수준 (low, medium, high)
    
    Returns:
        HTTP 요청 시퀀스
    """
    pattern = []
    
    # 1. 네이버 쇼핑 메인 페이지 접속
    pattern.append({
        "action": "http_get",
        "url": "https://shopping.naver.com",
        "headers": {
            "User-Agent": identity["user_agent"],
            **identity.get("headers", {})
        },
        "cookies": identity.get("cookies", []),
        "wait_after": random.uniform(1.0, 2.5)  # 1~2.5초 대기
    })
    
    # 2. 검색 요청
    pattern.append({
        "action": "http_get",
        "url": f"https://search.shopping.naver.com/search/all?query={keyword}",
        "headers": {
            "User-Agent": identity["user_agent"],
            "Referer": "https://shopping.naver.com",
            **identity.get("headers", {})
        },
        "cookies": identity.get("cookies", []),
        "wait_after": random.uniform(2.0, 4.0)  # 검색 결과 확인 시간
    })
    
    # 3. 참여 수준에 따른 추가 행동
    if engagement_level in ["medium", "high"]:
        # 상품 상세 페이지 조회 (첫 번째 상품)
        pattern.append({
            "action": "http_get",
            "url": f"https://search.shopping.naver.com/catalog/PRODUCT_ID_PLACEHOLDER",  # 실제로는 검색 결과에서 추출
            "headers": {
                "User-Agent": identity["user_agent"],
                "Referer": f"https://search.shopping.naver.com/search/all?query={keyword}",
                **identity.get("headers", {})
            },
            "cookies": identity.get("cookies", []),
            "wait_after": random.uniform(5.0, 10.0) if engagement_level == "high" else random.uniform(3.0, 5.0)
        })
    
    if engagement_level == "high":
        # 리뷰 페이지 조회
        pattern.append({
            "action": "http_get",
            "url": f"https://search.shopping.naver.com/catalog/PRODUCT_ID_PLACEHOLDER/review",
            "headers": {
                "User-Agent": identity["user_agent"],
                "Referer": f"https://search.shopping.naver.com/catalog/PRODUCT_ID_PLACEHOLDER",
                **identity.get("headers", {})
            },
            "cookies": identity.get("cookies", []),
            "wait_after": random.uniform(8.0, 15.0)  # 리뷰 읽기 시간
        })
    
    return pattern


def generate_appium_pattern(
    keyword: str,
    identity: Dict[str, Any],
    ui_coordinates: Dict[str, Dict[str, int]],
    engagement_level: str = "medium"
) -> List[Dict[str, Any]]:
    """
    Appium 모드 작업 패턴 생성
    
    Args:
        keyword: 검색 키워드
        identity: 신원 프로필 정보
        ui_coordinates: UI 좌표 맵
        engagement_level: 참여 수준 (low, medium, high)
    
    Returns:
        Appium 행동 시퀀스
    """
    pattern = []
    
    # 1. 삼성 브라우저 강제 종료
    pattern.append({
        "action": "kill",
        "target": "com.sec.android.app.sbrowser"
    })
    
    pattern.append({
        "action": "wait",
        "duration": 2000  # 2초 대기
    })
    
    # 2. 삼성 브라우저 시작
    pattern.append({
        "action": "start",
        "target": "com.sec.android.app.sbrowser"
    })
    
    pattern.append({
        "action": "wait",
        "duration": 3000  # 3초 대기
    })
    
    # 3. 검색창 터치
    search_bar = ui_coordinates.get("search_bar", {"x": 540, "y": 150})
    pattern.append({
        "action": "tap",
        "x": search_bar["x"] + random.randint(-10, 10),  # 노이즈 추가
        "y": search_bar["y"] + random.randint(-5, 5)
    })
    
    pattern.append({
        "action": "wait",
        "duration": random.randint(800, 1500)
    })
    
    # 4. 키워드 입력
    pattern.append({
        "action": "text",
        "value": keyword
    })
    
    pattern.append({
        "action": "wait",
        "duration": random.randint(1000, 2000)
    })
    
    # 5. 검색 버튼 터치 (Enter 키)
    pattern.append({
        "action": "keyevent",
        "keycode": 66  # KEYCODE_ENTER
    })
    
    pattern.append({
        "action": "wait",
        "duration": random.randint(3000, 5000)  # 검색 결과 로딩 대기
    })
    
    # 6. 참여 수준에 따른 추가 행동
    if engagement_level in ["medium", "high"]:
        # 첫 번째 상품 터치
        product_item = ui_coordinates.get("product_item_1", {"x": 540, "y": 600})
        pattern.append({
            "action": "tap",
            "x": product_item["x"] + random.randint(-20, 20),
            "y": product_item["y"] + random.randint(-10, 10)
        })
        
        wait_time = random.randint(5000, 10000) if engagement_level == "high" else random.randint(3000, 5000)
        pattern.append({
            "action": "wait",
            "duration": wait_time
        })
    
    if engagement_level == "high":
        # 스크롤 다운 (리뷰 보기)
        pattern.append({
            "action": "scroll",
            "direction": "down",
            "distance": 800
        })
        
        pattern.append({
            "action": "wait",
            "duration": random.randint(8000, 15000)  # 리뷰 읽기 시간
        })
    
    return pattern
