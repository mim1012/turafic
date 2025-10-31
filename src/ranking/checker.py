"""
네이버 쇼핑 순위 체크 모듈
"""
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode
from bs4 import BeautifulSoup
from config.settings import config
from src.utils.logger import log
from src.utils.helpers import (
    safe_request,
    random_wait,
    calculate_rank,
    get_timestamp,
    normalize_keyword,
)


class RankChecker:
    """네이버 쇼핑 순위 체크 클래스"""

    def __init__(self):
        self.base_url = config.NAVER_SHOPPING_URL
        self.items_per_page = 20  # 1페이지당 상품 수

    def build_search_url(self, keyword: str, page: int = 1) -> str:
        """
        검색 URL 생성

        Args:
            keyword: 검색 키워드
            page: 페이지 번호

        Returns:
            네이버 쇼핑 검색 URL
        """
        # 네이버 쇼핑 검색 파라미터
        params = {
            "query": keyword,
            "pagingIndex": page,  # 페이지 번호
            "pagingSize": self.items_per_page,  # 페이지당 아이템 수
            "viewType": "list",  # 리스트 뷰
            "sort": "rel",  # 정렬: rel=관련도순, price_asc=낮은가격순, price_dsc=높은가격순
        }

        search_url = f"{self.base_url}/search/all?{urlencode(params)}"
        log.debug(f"검색 URL 생성: {search_url}")
        return search_url

    def parse_products_from_html(self, html: str, page: int) -> List[Dict[str, Any]]:
        """
        HTML에서 상품 목록 파싱 (광고 제외)

        Args:
            html: 페이지 HTML
            page: 현재 페이지 번호

        Returns:
            상품 정보 리스트 (광고 제외)
        """
        soup = BeautifulSoup(html, "lxml")
        products = []

        # 네이버 쇼핑 상품 리스트 선택자 (2024년 기준)
        # 실제 HTML 구조에 따라 선택자 조정 필요
        product_elements = soup.select("div.product_item, div.basicList_item__0T9JD, ul.list_basis > li")

        if not product_elements:
            log.warning(f"페이지 {page}에서 상품을 찾을 수 없습니다. 선택자 확인 필요")
            return products

        # 광고 제외 카운팅을 위한 변수
        organic_position = 0  # 광고 제외한 실제 순위
        total_count = 0  # 전체 아이템 수 (광고 포함)

        for idx, element in enumerate(product_elements, start=1):
            total_count += 1

            try:
                # 광고 여부 체크 (여러 패턴 확인)
                is_ad = self._is_advertisement(element)

                if is_ad:
                    log.debug(f"[페이지 {page}] 위치 {idx}: 광고 상품 (순위 카운팅 제외)")
                    continue

                # 광고가 아닌 경우에만 카운팅
                organic_position += 1

                # 상품 링크에서 ID 추출
                link_element = element.select_one("a[href*='/products/'], a[href*='/window-products/']")
                if not link_element:
                    continue

                product_url = link_element.get("href", "")
                if not product_url:
                    continue

                # 상품 ID 추출
                product_id = self._extract_product_id(product_url)
                if not product_id:
                    continue

                # 상품명
                name_element = element.select_one(
                    "div.product_title, div.basicList_link__1MaTN, a.product_name"
                )
                product_name = name_element.get_text(strip=True) if name_element else ""

                # 가격
                price_element = element.select_one(
                    "span.price_num, span.basicList_num__3R4w2, span.product_price"
                )
                price = price_element.get_text(strip=True) if price_element else "0"

                # 광고 제외한 실제 순위 계산
                absolute_rank = (page - 1) * self.items_per_page + organic_position

                product_info = {
                    "product_id": product_id,
                    "product_name": product_name,
                    "product_url": product_url if product_url.startswith("http") else f"https://shopping.naver.com{product_url}",
                    "price": price,
                    "page": page,
                    "position": organic_position,  # 광고 제외한 위치
                    "absolute_rank": absolute_rank,  # 광고 제외한 절대 순위
                    "is_ad": False,
                }

                products.append(product_info)
                log.debug(f"상품 파싱: {product_id} - {product_name} (순위: {absolute_rank}위, 광고 제외)")

            except Exception as e:
                log.warning(f"상품 파싱 실패 (페이지 {page}, 위치 {idx}): {e}")
                continue

        log.info(f"페이지 {page}에서 {len(products)}개 일반 상품 파싱 완료 (전체 {total_count}개 중)")
        return products

    def _is_advertisement(self, element) -> bool:
        """
        광고 상품 여부 확인 (파워링크 포함)

        Args:
            element: BeautifulSoup 요소

        Returns:
            True if 광고/파워링크, False if 일반 상품
        """
        # 1. "광고" 텍스트 포함 여부
        ad_text_elements = element.select(
            "span.ad_badge, span.ad, div.ad_badge, "
            "span[class*='ad'], div[class*='ad'], "
            "span.basicList_ad__LEz5E, div.product_ad"
        )

        for ad_elem in ad_text_elements:
            text = ad_elem.get_text(strip=True)
            if "광고" in text or "AD" in text.upper():
                return True

        # 2. 파워링크 배지 체크 (SVG 아이콘)
        # 파워링크는 SVG 또는 특정 클래스로 표시됨
        powerlink_elements = element.select(
            "svg[class*='power'], "
            "span[class*='power'], "
            "div[class*='power'], "
            "svg.A4ub2IBr, "  # 파워링크 SVG 클래스
            "svg.hHtxeo9d"    # 파워링크 SVG 클래스
        )

        if powerlink_elements:
            return True

        # SVG 텍스트 확인 (파워링크 배지 안의 텍스트)
        svg_elements = element.select("svg")
        for svg_elem in svg_elements:
            # SVG 내부 텍스트 확인
            svg_text = svg_elem.get_text(strip=True)
            if "파워링크" in svg_text or "POWER" in svg_text.upper():
                return True

            # SVG 속성 확인
            viewbox = svg_elem.get("viewBox", "")
            # 파워링크 SVG는 특정 viewBox를 가짐
            if viewbox == "0 0 39 16":
                return True

        # 3. data-ad 속성 체크
        if element.get('data-ad') == 'true' or element.get('data-is-ad') == 'true':
            return True

        # 4. 클래스명에 'powerlink', 'power_link' 포함
        class_names = ' '.join(element.get('class', []))
        if 'powerlink' in class_names.lower() or 'power_link' in class_names.lower():
            return True

        # 5. 클래스명에 'ad' 포함 (주의: 너무 넓은 범위)
        if 'advertisement' in class_names.lower() or 'sponsored' in class_names.lower():
            return True

        # 6. URL에 '/ad/' 또는 파워링크 파라미터 포함 체크
        link_element = element.select_one("a")
        if link_element:
            href = link_element.get("href", "")
            if '/ad/' in href or 'adcr=' in href or 'ad_id=' in href:
                return True
            # 파워링크 URL 패턴
            if 'nv_ad=' in href or 'powerlink' in href.lower():
                return True

        # 7. 부모 요소가 광고 영역인지 체크
        parent = element.parent
        if parent and parent.get('data-ad-area'):
            return True

        # 8. data-nv-ad 속성 체크 (네이버 광고 마크)
        if element.get('data-nv-ad'):
            return True

        return False

    def _extract_product_id(self, url: str) -> Optional[str]:
        """
        URL에서 상품 ID (mid 값) 추출

        우선순위:
        1. mid 파라미터 (가장 정확)
        2. URL 경로의 숫자
        """
        import re
        from urllib.parse import urlparse, parse_qs

        try:
            # 1. mid 파라미터 확인 (가장 정확)
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            if 'mid' in query_params:
                mid = query_params['mid'][0]
                if mid and mid.isdigit():
                    return mid

            # 2. URL 경로에서 추출
            # 패턴: /products/{id} 또는 /window-products/{id}
            pattern = r"/(?:window-)?products/(\d+)"
            match = re.search(pattern, url)

            if match:
                return match.group(1)

            return None

        except Exception as e:
            log.debug(f"상품 ID 추출 실패: {e}")
            return None

    def check_product_rank(
        self,
        keyword: str,
        product_id: str,
        max_page: int = None,
    ) -> Optional[Dict[str, Any]]:
        """
        특정 상품의 순위 체크

        Args:
            keyword: 검색 키워드
            product_id: 찾을 상품 ID
            max_page: 최대 검색 페이지 (기본값: config)

        Returns:
            순위 정보 딕셔너리 또는 None (순위권 밖)
            {
                "product_id": "12345678",
                "keyword": "검색키워드",
                "page": 3,
                "position": 12,
                "absolute_rank": 52,
                "product_name": "상품명",
                "product_url": "URL",
                "checked_at": "2025-01-01T00:00:00"
            }
        """
        if max_page is None:
            max_page = config.RANK_CHECK_MAX_PAGE

        keyword = normalize_keyword(keyword)
        log.info(f"순위 체크 시작: 키워드='{keyword}', 상품ID={product_id}, 최대페이지={max_page}")

        for page in range(1, max_page + 1):
            log.debug(f"페이지 {page} 검색 중...")

            # URL 생성
            search_url = self.build_search_url(keyword, page)

            # 요청 전 랜덤 대기 (봇 탐지 회피)
            random_wait(config.ACTION_WAIT_MIN, config.ACTION_WAIT_MAX)

            # HTTP 요청
            response = safe_request(search_url)
            if response is None:
                log.error(f"페이지 {page} 요청 실패")
                continue

            # HTML 파싱
            products = self.parse_products_from_html(response.text, page)

            # 상품 찾기
            for product in products:
                if product["product_id"] == product_id:
                    log.success(
                        f"상품 발견! {product['absolute_rank']}위 "
                        f"(페이지 {product['page']}, 위치 {product['position']})"
                    )

                    return {
                        "product_id": product_id,
                        "keyword": keyword,
                        "page": product["page"],
                        "position": product["position"],
                        "absolute_rank": product["absolute_rank"],
                        "product_name": product["product_name"],
                        "product_url": product["product_url"],
                        "checked_at": get_timestamp(),
                    }

        log.warning(f"상품을 찾을 수 없음: {product_id} (키워드: {keyword}, {max_page}페이지 내)")
        return None

    def check_multiple_products(
        self,
        keyword: str,
        product_ids: List[str],
        max_page: int = None,
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        여러 상품의 순위를 한 번에 체크

        Args:
            keyword: 검색 키워드
            product_ids: 상품 ID 리스트
            max_page: 최대 검색 페이지

        Returns:
            {product_id: rank_info} 딕셔너리
        """
        if max_page is None:
            max_page = config.RANK_CHECK_MAX_PAGE

        keyword = normalize_keyword(keyword)
        log.info(f"다중 상품 순위 체크: 키워드='{keyword}', 상품수={len(product_ids)}")

        results = {pid: None for pid in product_ids}
        remaining_products = set(product_ids)

        for page in range(1, max_page + 1):
            if not remaining_products:
                break

            log.debug(f"페이지 {page} 검색 중... (남은 상품: {len(remaining_products)}개)")

            # URL 생성 및 요청
            search_url = self.build_search_url(keyword, page)
            random_wait(config.ACTION_WAIT_MIN, config.ACTION_WAIT_MAX)

            response = safe_request(search_url)
            if response is None:
                continue

            # 상품 파싱
            products = self.parse_products_from_html(response.text, page)

            # 매칭 확인
            for product in products:
                if product["product_id"] in remaining_products:
                    results[product["product_id"]] = {
                        "product_id": product["product_id"],
                        "keyword": keyword,
                        "page": product["page"],
                        "position": product["position"],
                        "absolute_rank": product["absolute_rank"],
                        "product_name": product["product_name"],
                        "product_url": product["product_url"],
                        "checked_at": get_timestamp(),
                    }
                    remaining_products.remove(product["product_id"])
                    log.success(f"상품 발견: {product['product_id']} - {product['absolute_rank']}위")

        # 결과 요약
        found_count = sum(1 for v in results.values() if v is not None)
        log.info(f"순위 체크 완료: {found_count}/{len(product_ids)}개 발견")

        return results


# 편의 함수
def check_rank(keyword: str, product_id: str, max_page: int = 10) -> Optional[Dict[str, Any]]:
    """
    순위 체크 편의 함수

    Args:
        keyword: 검색 키워드
        product_id: 상품 ID
        max_page: 최대 검색 페이지

    Returns:
        순위 정보 또는 None
    """
    checker = RankChecker()
    return checker.check_product_rank(keyword, product_id, max_page)


if __name__ == "__main__":
    # 테스트
    # 실제 테스트 시 유효한 키워드와 상품 ID 필요
    test_keyword = "무선 이어폰"
    test_product_id = "12345678"

    print(f"\n순위 체크 테스트: {test_keyword}")
    result = check_rank(test_keyword, test_product_id, max_page=3)

    if result:
        print(f"\n상품 발견:")
        print(f"  - 순위: {result['absolute_rank']}위")
        print(f"  - 페이지: {result['page']}")
        print(f"  - 위치: {result['position']}")
        print(f"  - 상품명: {result['product_name']}")
    else:
        print(f"\n상품을 찾을 수 없습니다. (3페이지 이내)")
