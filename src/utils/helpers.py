"""
유틸리티 헬퍼 함수
"""
import time
import random
import requests
from typing import Optional, Dict, Any
from datetime import datetime
from src.utils.logger import log


# User-Agent 목록 (봇 탐지 회피)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
]


def get_random_user_agent() -> str:
    """랜덤 User-Agent 반환"""
    return random.choice(USER_AGENTS)


def random_wait(min_seconds: float = 1.0, max_seconds: float = 3.0):
    """랜덤 대기 (봇 탐지 회피)"""
    wait_time = random.uniform(min_seconds, max_seconds)
    log.debug(f"대기 중: {wait_time:.2f}초")
    time.sleep(wait_time)


def calculate_rank(page: int, position: int) -> int:
    """
    순위 계산

    Args:
        page: 페이지 번호 (1부터 시작)
        position: 페이지 내 위치 (1-20)

    Returns:
        전체 순위

    Examples:
        >>> calculate_rank(1, 1)
        1
        >>> calculate_rank(4, 1)
        61
        >>> calculate_rank(4, 20)
        80
    """
    return (page - 1) * 20 + position


def calculate_rank_change(before_rank: int, after_rank: int) -> int:
    """
    순위 변동 계산

    Args:
        before_rank: 이전 순위
        after_rank: 이후 순위

    Returns:
        순위 변동 (음수 = 상승, 양수 = 하락)

    Examples:
        >>> calculate_rank_change(52, 28)
        -24
        >>> calculate_rank_change(28, 52)
        24
    """
    return after_rank - before_rank


def get_timestamp() -> str:
    """현재 타임스탬프 반환 (ISO 8601 형식)"""
    return datetime.now().isoformat()


def safe_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = 10,
    max_retries: int = 3,
) -> Optional[requests.Response]:
    """
    안전한 HTTP 요청 (재시도 로직 포함)

    Args:
        url: 요청 URL
        method: HTTP 메소드
        headers: 헤더
        params: 쿼리 파라미터
        timeout: 타임아웃 (초)
        max_retries: 최대 재시도 횟수

    Returns:
        Response 객체 또는 None
    """
    if headers is None:
        headers = {}

    # User-Agent 자동 추가
    if "User-Agent" not in headers:
        headers["User-Agent"] = get_random_user_agent()

    for attempt in range(1, max_retries + 1):
        try:
            log.debug(f"HTTP 요청 시도 {attempt}/{max_retries}: {url}")

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                timeout=timeout,
            )

            response.raise_for_status()
            log.debug(f"요청 성공: {url} (상태코드: {response.status_code})")
            return response

        except requests.exceptions.HTTPError as e:
            log.warning(f"HTTP 에러 (시도 {attempt}/{max_retries}): {e}")
            if response.status_code in [403, 429]:  # 접근 차단 또는 요청 제한
                log.warning("접근 차단 감지, 대기 시간 증가")
                random_wait(5, 10)
            elif attempt < max_retries:
                random_wait(2, 4)

        except requests.exceptions.Timeout as e:
            log.warning(f"타임아웃 (시도 {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                random_wait(1, 2)

        except requests.exceptions.RequestException as e:
            log.error(f"요청 실패 (시도 {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                random_wait(1, 2)

    log.error(f"최대 재시도 횟수 초과: {url}")
    return None


def extract_product_id_from_url(url: str) -> Optional[str]:
    """
    URL에서 상품 ID 추출

    Args:
        url: 네이버 쇼핑 상품 URL

    Returns:
        상품 ID 또는 None

    Examples:
        >>> extract_product_id_from_url("https://shopping.naver.com/window-products/12345678")
        "12345678"
    """
    import re

    # 패턴: /products/{product_id} 또는 /window-products/{product_id}
    pattern = r"/(?:window-)?products/(\d+)"
    match = re.search(pattern, url)

    if match:
        return match.group(1)

    return None


def format_rank_info(rank_data: Dict[str, Any]) -> str:
    """
    순위 정보를 사람이 읽기 쉬운 형식으로 포맷

    Args:
        rank_data: 순위 데이터 딕셔너리

    Returns:
        포맷된 문자열
    """
    if rank_data is None:
        return "순위권 밖"

    page = rank_data.get("page", 0)
    position = rank_data.get("position", 0)
    absolute_rank = rank_data.get("absolute_rank", 0)

    return f"{absolute_rank}위 (페이지 {page}, {position}번째)"


def normalize_keyword(keyword: str) -> str:
    """
    검색 키워드 정규화 (공백 제거 등)

    Args:
        keyword: 원본 키워드

    Returns:
        정규화된 키워드
    """
    return " ".join(keyword.strip().split())


if __name__ == "__main__":
    # 테스트
    print("User-Agent:", get_random_user_agent())
    print("Rank:", calculate_rank(4, 1))
    print("Rank Change:", calculate_rank_change(52, 28))
    print("Timestamp:", get_timestamp())
    print("Product ID:", extract_product_id_from_url("https://shopping.naver.com/window-products/12345678"))
