"""
단일상품(스마트스토어 상품) 자동 필터링

네이버 쇼핑 검색 결과에서 단일상품만 추출
"""

import requests
from bs4 import BeautifulSoup
import time
import random
from typing import List, Dict, Optional
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))
from src.utils.logger import get_logger

log = get_logger()


class SingleProductFinder:
    """단일상품 찾기"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9',
        })

    def search_products(
        self,
        keyword: str,
        max_page: int = 3
    ) -> List[Dict]:
        """
        키워드로 상품 검색하여 단일상품만 추출

        Args:
            keyword: 검색 키워드
            max_page: 검색할 최대 페이지 수

        Returns:
            단일상품 리스트
        """
        log.info(f"검색 키워드: {keyword}")
        log.info(f"검색 범위: {max_page} 페이지")

        all_products = []

        for page in range(1, max_page + 1):
            log.info(f"\n페이지 {page} 검색 중...")

            # 네이버 쇼핑 검색 URL
            search_url = (
                f"https://search.shopping.naver.com/search/all"
                f"?query={keyword}"
                f"&pagingIndex={page}"
                f"&pagingSize=40"
            )

            try:
                response = self.session.get(search_url, timeout=10)
                response.raise_for_status()

                # HTML 파싱
                products = self._parse_search_results(response.text, page)

                # 단일상품만 필터링
                single_products = [p for p in products if p['is_single']]

                log.info(f"  총 상품: {len(products)}개")
                log.info(f"  단일상품: {len(single_products)}개")

                all_products.extend(single_products)

                # 페이지 간 딜레이
                if page < max_page:
                    time.sleep(random.uniform(1.5, 2.5))

            except Exception as e:
                log.error(f"페이지 {page} 검색 실패: {e}")
                continue

        log.info(f"\n총 {len(all_products)}개 단일상품 발견")
        return all_products

    def _parse_search_results(
        self,
        html: str,
        page: int
    ) -> List[Dict]:
        """검색 결과 HTML 파싱"""
        soup = BeautifulSoup(html, 'lxml')
        products = []

        # 상품 아이템 선택자 (네이버 쇼핑 구조에 따라 변경 가능)
        # 여러 선택자 시도
        selectors = [
            'div.product_item',
            'div.product_info_area',
            'li.basicList_item__0T9JD',
            'div.basicList_inner__xCM3J',
        ]

        items = []
        for selector in selectors:
            items = soup.select(selector)
            if items:
                break

        if not items:
            log.warning(f"상품 아이템을 찾을 수 없음 (선택자 업데이트 필요)")
            return products

        for idx, item in enumerate(items, 1):
            try:
                # 상품 링크 추출
                link_elem = item.select_one('a')
                if not link_elem or not link_elem.get('href'):
                    continue

                product_url = link_elem.get('href')

                # 전체 URL로 변환
                if product_url.startswith('//'):
                    product_url = 'https:' + product_url
                elif product_url.startswith('/'):
                    product_url = 'https://shopping.naver.com' + product_url

                # 단일상품 여부 확인
                is_single = self._is_single_product(product_url)

                # 상품명 추출
                name_elem = item.select_one('div.product_title, a.product_link, div.basicList_title__VfX3c')
                product_name = name_elem.get_text(strip=True) if name_elem else "상품명 없음"

                # 가격 추출
                price_elem = item.select_one('span.price, span.price_num, strong.basicList_price__Y4ADF')
                price = price_elem.get_text(strip=True) if price_elem else "가격 없음"

                # 판매자 추출
                seller_elem = item.select_one('span.product_mall, a.product_mall, div.basicList_mall__REos8')
                seller = seller_elem.get_text(strip=True) if seller_elem else "판매자 없음"

                # 상품 ID 추출
                product_id = self._extract_product_id(product_url)

                product = {
                    'page': page,
                    'position': idx,
                    'absolute_rank': (page - 1) * 40 + idx,
                    'product_id': product_id,
                    'product_name': product_name[:50],  # 50자 제한
                    'product_url': product_url,
                    'price': price,
                    'seller': seller,
                    'is_single': is_single,
                    'url_type': 'window-products' if is_single else 'catalog'
                }

                products.append(product)

            except Exception as e:
                log.debug(f"상품 파싱 실패 (idx={idx}): {e}")
                continue

        return products

    def _is_single_product(self, url: str) -> bool:
        """
        단일상품 여부 확인

        단일상품: window-products 포함
        통합검색형: catalog 포함
        """
        if 'window-products' in url:
            return True
        elif 'catalog' in url:
            return False
        else:
            # URL에서 판단 불가 시 False (보수적)
            return False

    def _extract_product_id(self, url: str) -> Optional[str]:
        """URL에서 상품 ID 추출"""
        try:
            # window-products/12345678 형태
            if 'window-products/' in url:
                parts = url.split('window-products/')
                if len(parts) > 1:
                    product_id = parts[1].split('?')[0].split('/')[0]
                    return product_id

            # catalog/12345678 형태
            elif 'catalog/' in url:
                parts = url.split('catalog/')
                if len(parts) > 1:
                    product_id = parts[1].split('?')[0].split('/')[0]
                    return product_id

            return None

        except:
            return None

    def print_results(self, products: List[Dict]):
        """결과 출력"""
        if not products:
            log.warning("발견된 단일상품이 없습니다.")
            return

        log.info(f"\n{'='*80}")
        log.info("단일상품 목록 (스마트스토어 상품)")
        log.info(f"{'='*80}\n")

        for i, p in enumerate(products, 1):
            log.info(f"{i}. [{p['absolute_rank']}위] {p['product_name']}")
            log.info(f"   ID: {p['product_id']}")
            log.info(f"   가격: {p['price']}")
            log.info(f"   판매자: {p['seller']}")
            log.info(f"   URL: {p['product_url']}")
            log.info("")

    def filter_by_rank_range(
        self,
        products: List[Dict],
        min_rank: int = 21,
        max_rank: int = 100
    ) -> List[Dict]:
        """
        순위 범위로 필터링

        Args:
            products: 상품 리스트
            min_rank: 최소 순위 (기본: 21위, 2페이지부터)
            max_rank: 최대 순위 (기본: 100위, 5페이지까지)

        Returns:
            필터링된 상품 리스트
        """
        filtered = [
            p for p in products
            if min_rank <= p['absolute_rank'] <= max_rank
        ]

        log.info(f"\n순위 필터링: {min_rank}~{max_rank}위")
        log.info(f"결과: {len(filtered)}개 상품")

        return filtered

    def save_to_json(self, products: List[Dict], filename: str = "single_products.json"):
        """JSON으로 저장"""
        import json

        output_dir = Path("data/product_search")
        output_dir.mkdir(parents=True, exist_ok=True)

        output_file = output_dir / filename

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'total_count': len(products),
                'products': products
            }, f, indent=2, ensure_ascii=False)

        log.info(f"\n✅ 저장 완료: {output_file}")


def main():
    """메인 함수"""
    import argparse

    parser = argparse.ArgumentParser(description='네이버 쇼핑 단일상품 찾기')
    parser.add_argument('keyword', help='검색 키워드')
    parser.add_argument('--pages', type=int, default=3, help='검색할 페이지 수 (기본: 3)')
    parser.add_argument('--min-rank', type=int, default=21, help='최소 순위 (기본: 21)')
    parser.add_argument('--max-rank', type=int, default=100, help='최대 순위 (기본: 100)')
    parser.add_argument('--save', action='store_true', help='JSON 파일로 저장')

    args = parser.parse_args()

    log.info("\n" + "="*80)
    log.info("네이버 쇼핑 단일상품 검색")
    log.info("="*80 + "\n")

    finder = SingleProductFinder()

    # 1. 검색
    products = finder.search_products(
        keyword=args.keyword,
        max_page=args.pages
    )

    if not products:
        log.warning("단일상품을 찾을 수 없습니다.")
        log.info("\n가능한 원인:")
        log.info("1. 해당 키워드로 스마트스토어 상품이 없음")
        log.info("2. HTML 구조 변경 (선택자 업데이트 필요)")
        log.info("3. 네이버 차단 (User-Agent 변경 필요)")
        return

    # 2. 순위 필터링
    filtered = finder.filter_by_rank_range(
        products,
        min_rank=args.min_rank,
        max_rank=args.max_rank
    )

    # 3. 결과 출력
    finder.print_results(filtered)

    # 4. 저장 (옵션)
    if args.save:
        finder.save_to_json(filtered, f"{args.keyword}_products.json")

    # 5. 요약
    log.info(f"\n{'='*80}")
    log.info("검색 요약")
    log.info(f"{'='*80}")
    log.info(f"검색 키워드: {args.keyword}")
    log.info(f"검색 페이지: {args.pages}개")
    log.info(f"발견된 단일상품: {len(products)}개")
    log.info(f"순위 필터링 후: {len(filtered)}개 ({args.min_rank}~{args.max_rank}위)")
    log.info(f"{'='*80}\n")


if __name__ == "__main__":
    main()
