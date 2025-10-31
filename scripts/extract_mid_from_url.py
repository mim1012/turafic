"""
네이버 쇼핑 URL에서 mid 값 추출

mid = 상품 코드 (실제 상품 ID)
단일상품을 고유하게 식별하는 값
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))
from src.utils.logger import get_logger

log = get_logger()


def extract_mid_from_url(url: str) -> Optional[str]:
    """
    네이버 쇼핑 URL에서 mid 값 추출

    Args:
        url: 네이버 쇼핑 상품 URL

    Returns:
        mid 값 (상품 코드) 또는 None

    Examples:
        >>> url1 = "https://smartstore.naver.com/product/detail?mid=12345678"
        >>> extract_mid_from_url(url1)
        '12345678'

        >>> url2 = "https://shopping.naver.com/window-products/8809115891052?mid=9876543"
        >>> extract_mid_from_url(url2)
        '9876543'
    """
    try:
        # URL 파싱
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # mid 파라미터 추출
        if 'mid' in query_params:
            mid = query_params['mid'][0]
            return mid

        # URL 경로에서 추출 시도
        # 예: /product/12345678 형태
        path_match = re.search(r'/product[s]?/(\d+)', parsed.path)
        if path_match:
            return path_match.group(1)

        # window-products 뒤의 숫자
        window_match = re.search(r'/window-products/(\d+)', parsed.path)
        if window_match:
            return window_match.group(1)

        return None

    except Exception as e:
        log.error(f"mid 추출 실패: {e}")
        return None


def parse_product_url(url: str) -> Dict:
    """
    상품 URL 전체 파싱

    Returns:
        {
            'mid': 상품 코드,
            'is_single': 단일상품 여부,
            'url_type': URL 타입,
            'seller_id': 판매자 ID (있으면),
            'full_url': 전체 URL
        }
    """
    result = {
        'mid': None,
        'is_single': False,
        'url_type': 'unknown',
        'seller_id': None,
        'full_url': url
    }

    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # mid 추출
        result['mid'] = extract_mid_from_url(url)

        # URL 타입 판별
        if 'smartstore.naver.com' in url:
            result['is_single'] = True
            result['url_type'] = 'smartstore'

            # 판매자 ID 추출 (smartstore.naver.com/seller_id)
            seller_match = re.search(r'smartstore\.naver\.com/([^/\?]+)', url)
            if seller_match:
                result['seller_id'] = seller_match.group(1)

        elif 'window-products' in url:
            result['is_single'] = True
            result['url_type'] = 'window-products'

        elif 'catalog' in url:
            result['is_single'] = False
            result['url_type'] = 'catalog'

        elif 'brand.naver.com' in url:
            result['is_single'] = True
            result['url_type'] = 'brand'

        return result

    except Exception as e:
        log.error(f"URL 파싱 실패: {e}")
        return result


def build_product_url(mid: str, seller_id: Optional[str] = None) -> str:
    """
    mid 값으로 상품 URL 생성

    Args:
        mid: 상품 코드
        seller_id: 판매자 ID (스마트스토어의 경우)

    Returns:
        상품 URL
    """
    if seller_id:
        # 스마트스토어 URL
        return f"https://smartstore.naver.com/{seller_id}/products/{mid}"
    else:
        # window-products URL (더 범용적)
        return f"https://shopping.naver.com/window-products/{mid}"


def validate_mid(mid: str) -> bool:
    """
    mid 값 유효성 검증

    Args:
        mid: 상품 코드

    Returns:
        유효하면 True
    """
    if not mid:
        return False

    # mid는 보통 숫자로만 구성
    if not mid.isdigit():
        log.warning(f"mid가 숫자가 아님: {mid}")
        return False

    # 길이 체크 (보통 10-13자리)
    if len(mid) < 8 or len(mid) > 15:
        log.warning(f"mid 길이가 비정상: {len(mid)}자리")
        return False

    return True


def main():
    """테스트"""
    log.info("mid 추출 테스트\n")

    test_urls = [
        "https://smartstore.naver.com/abc-store/products/8809115891052?mid=9876543",
        "https://shopping.naver.com/window-products/8809115891052",
        "https://search.shopping.naver.com/catalog/12345678",
        "https://smartstore.naver.com/mystore/products/7708226780941",
        "https://brand.naver.com/samsung/products/6607337669830",
    ]

    for url in test_urls:
        log.info(f"URL: {url[:60]}...")

        # mid 추출
        mid = extract_mid_from_url(url)
        log.info(f"  mid: {mid}")

        # 전체 파싱
        parsed = parse_product_url(url)
        log.info(f"  단일상품: {parsed['is_single']}")
        log.info(f"  타입: {parsed['url_type']}")
        log.info(f"  판매자: {parsed['seller_id']}")

        # 유효성 검증
        if mid:
            is_valid = validate_mid(mid)
            log.info(f"  유효성: {'✅' if is_valid else '❌'}")

        log.info("")

    # mid로 URL 생성 테스트
    log.info("\nmid로 URL 생성 테스트:")
    test_mid = "8809115891052"
    test_seller = "abc-store"

    url1 = build_product_url(test_mid)
    url2 = build_product_url(test_mid, test_seller)

    log.info(f"기본 URL: {url1}")
    log.info(f"스마트스토어 URL: {url2}")


if __name__ == "__main__":
    main()
