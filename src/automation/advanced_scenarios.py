"""
고급 시나리오 - 카테고리별, 행동 패턴별, 쿠키 조작

다양한 테스트 케이스:
1. 카테고리별 접근 패턴
2. 쿠키 조작 (로그인 상태, 관심사 등)
3. 행동 패턴 변화
4. 유입 경로 다변화
"""

import requests
import random
import time
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlencode

# 프로젝트 루트 경로 추가
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.automation.http_traffic import (
    HTTPTrafficGenerator,
    SessionManager,
    UserAgentPool
)
from src.utils.logger import get_logger

log = get_logger()


class NaverCookieManipulator:
    """네이버 쿠키 조작 및 관리"""

    @staticmethod
    def create_realistic_cookies() -> Dict[str, str]:
        """
        실제 사용자처럼 보이는 쿠키 생성

        네이버 주요 쿠키:
        - NID_AUT: 자동 로그인 토큰
        - NID_SES: 세션 쿠키
        - NID_JKL: 로그인 유지
        - nid_inf: 사용자 정보
        - page_uid: 페이지 고유 ID
        """
        cookies = {
            # 기본 추적 쿠키
            'page_uid': NaverCookieManipulator._generate_page_uid(),

            # 타임스탬프 기반
            'nx_ssl': 'v2',
            '_naver_usersession_': NaverCookieManipulator._generate_session_token(),

            # 방문 기록
            'nid_inf': NaverCookieManipulator._generate_nid_inf(),

            # 쇼핑 관련
            'srt': 'rel',  # 정렬 방식
            'vt': 'rel',   # 뷰 타입

            # A/B 테스트 그룹
            'ab_test': random.choice(['A', 'B', 'C']),
        }

        return cookies

    @staticmethod
    def _generate_page_uid() -> str:
        """페이지 고유 ID 생성"""
        timestamp = int(time.time() * 1000)
        random_val = random.randint(100000, 999999)
        return f"{timestamp}_{random_val}"

    @staticmethod
    def _generate_session_token() -> str:
        """세션 토큰 생성"""
        import hashlib
        data = f"{time.time()}{random.randint(10000, 99999)}"
        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def _generate_nid_inf() -> str:
        """사용자 정보 쿠키 생성"""
        # 실제로는 복잡한 구조, 여기서는 간단히
        user_hash = random.randint(1000000, 9999999)
        timestamp = int(time.time())
        return f"{user_hash}:{timestamp}"

    @staticmethod
    def simulate_login_cookies() -> Dict[str, str]:
        """
        로그인 상태 쿠키 시뮬레이션

        ⚠️ 주의: 실제 로그인 없이는 완전한 시뮬레이션 불가
        하지만 로그인 "처럼 보이는" 쿠키는 생성 가능
        """
        cookies = NaverCookieManipulator.create_realistic_cookies()

        # 로그인 관련 쿠키 추가
        cookies.update({
            'NID_AUT': NaverCookieManipulator._generate_session_token(),
            'NID_SES': NaverCookieManipulator._generate_session_token(),
            'NID_JKL': NaverCookieManipulator._generate_session_token(),

            # 로그인 유지
            'nid_slevel': '1',

            # 사용자 선호 설정
            'nid_buk': 'shopping',  # 북마크
        })

        return cookies

    @staticmethod
    def simulate_interest_cookies(categories: List[str]) -> Dict[str, str]:
        """
        관심 카테고리 기반 쿠키 생성

        Args:
            categories: 관심 카테고리 리스트 ['전자기기', '패션', ...]
        """
        cookies = NaverCookieManipulator.create_realistic_cookies()

        # 카테고리 관심도를 쿠키에 인코딩
        category_codes = {
            '전자기기': 'E001',
            '패션의류': 'F001',
            '식품': 'FD01',
            '뷰티': 'B001',
            '생활용품': 'L001',
            '스포츠': 'S001',
            '도서': 'BK01',
            '가구': 'H001',
        }

        interests = [category_codes.get(cat, 'OTH') for cat in categories]
        cookies['user_interests'] = ','.join(interests)

        return cookies


class CategoryBasedScenarios:
    """카테고리별 행동 패턴"""

    # 카테고리별 특성 정의
    CATEGORY_PATTERNS = {
        '전자기기': {
            'avg_dwell_time': (120, 180),  # 긴 체류 (스펙 확인)
            'scroll_depth': (5, 8),         # 깊은 스크롤
            'compare_probability': 0.8,     # 비교 확률 높음
            'review_probability': 0.7,      # 리뷰 확인 높음
            'q_a_probability': 0.5,
            'price_sensitive': True,
        },
        '패션의류': {
            'avg_dwell_time': (60, 90),     # 중간 체류
            'scroll_depth': (4, 6),
            'compare_probability': 0.6,
            'review_probability': 0.8,      # 리뷰 매우 중요
            'q_a_probability': 0.3,
            'image_focus': True,            # 이미지 중심
        },
        '식품': {
            'avg_dwell_time': (40, 60),     # 짧은 체류
            'scroll_depth': (2, 4),
            'compare_probability': 0.4,
            'review_probability': 0.6,
            'q_a_probability': 0.2,
            'repurchase_rate': 0.7,         # 재구매율 높음
        },
        '뷰티': {
            'avg_dwell_time': (90, 120),
            'scroll_depth': (5, 7),
            'compare_probability': 0.7,
            'review_probability': 0.9,      # 리뷰 가장 중요
            'q_a_probability': 0.4,
            'ingredient_check': True,       # 성분 확인
        },
        '생활용품': {
            'avg_dwell_time': (50, 80),
            'scroll_depth': (3, 5),
            'compare_probability': 0.5,
            'review_probability': 0.5,
            'q_a_probability': 0.3,
            'practical_focus': True,
        },
    }

    @classmethod
    def get_pattern(cls, category: str) -> Dict:
        """카테고리별 행동 패턴 가져오기"""
        return cls.CATEGORY_PATTERNS.get(category, {
            'avg_dwell_time': (60, 90),
            'scroll_depth': (3, 5),
            'compare_probability': 0.5,
            'review_probability': 0.5,
            'q_a_probability': 0.3,
        })


class EntryPathGenerator:
    """다양한 유입 경로 생성"""

    @staticmethod
    def from_naver_search(keyword: str) -> Dict:
        """네이버 통합검색 유입"""
        return {
            'referer': f"https://search.naver.com/search.naver?query={quote(keyword)}",
            'utm_source': 'naver',
            'utm_medium': 'organic',
            'entry_type': 'search',
        }

    @staticmethod
    def from_shopping_direct(keyword: str) -> Dict:
        """네이버쇼핑 직접 검색"""
        return {
            'referer': f"https://search.shopping.naver.com/search/all?query={quote(keyword)}",
            'utm_source': 'shopping',
            'utm_medium': 'direct',
            'entry_type': 'shopping_search',
        }

    @staticmethod
    def from_category_browse(category: str) -> Dict:
        """카테고리 탐색 유입"""
        category_map = {
            '전자기기': '50000006',
            '패션의류': '50000007',
            '식품': '50000008',
            '뷰티': '50000002',
        }
        category_id = category_map.get(category, '50000000')

        return {
            'referer': f"https://shopping.naver.com/category/{category_id}",
            'utm_source': 'shopping',
            'utm_medium': 'category',
            'entry_type': 'category_browse',
        }

    @staticmethod
    def from_ranking_page() -> Dict:
        """랭킹/베스트 페이지 유입"""
        return {
            'referer': 'https://shopping.naver.com/best/home',
            'utm_source': 'shopping',
            'utm_medium': 'ranking',
            'entry_type': 'ranking',
        }

    @staticmethod
    def from_deal_page() -> Dict:
        """특가/타임딜 유입"""
        return {
            'referer': 'https://shopping.naver.com/deal/index.nhn',
            'utm_source': 'shopping',
            'utm_medium': 'deal',
            'entry_type': 'time_deal',
        }

    @staticmethod
    def from_blog_review(blog_url: str = "https://blog.naver.com") -> Dict:
        """블로그 리뷰 유입"""
        return {
            'referer': blog_url,
            'utm_source': 'blog',
            'utm_medium': 'review',
            'utm_campaign': 'organic_review',
            'entry_type': 'blog_referral',
        }

    @staticmethod
    def from_cafe_post(cafe_url: str = "https://cafe.naver.com") -> Dict:
        """카페 추천 유입"""
        return {
            'referer': cafe_url,
            'utm_source': 'cafe',
            'utm_medium': 'recommendation',
            'entry_type': 'cafe_referral',
        }

    @staticmethod
    def from_google_search(keyword: str) -> Dict:
        """구글 검색 유입"""
        return {
            'referer': f"https://www.google.com/search?q={quote(keyword)}",
            'utm_source': 'google',
            'utm_medium': 'organic',
            'entry_type': 'external_search',
        }

    @staticmethod
    def from_price_comparison(site: str = "danawa") -> Dict:
        """가격비교 사이트 유입"""
        sites = {
            'danawa': 'https://www.danawa.com',
            'enuri': 'https://www.enuri.com',
        }

        return {
            'referer': sites.get(site, sites['danawa']),
            'utm_source': site,
            'utm_medium': 'price_comparison',
            'entry_type': 'price_compare',
        }


class AdvancedTrafficGenerator(HTTPTrafficGenerator):
    """고급 트래픽 생성기 - 모든 조작 기능 포함"""

    def __init__(self):
        super().__init__()
        self.cookie_manipulator = NaverCookieManipulator()

    def execute_category_scenario(
        self,
        product_url: str,
        category: str,
        entry_path_type: str = 'search',
        search_keyword: Optional[str] = None,
        use_login_cookies: bool = False
    ) -> Dict:
        """
        카테고리별 맞춤 시나리오 실행

        Args:
            product_url: 상품 URL
            category: 카테고리명
            entry_path_type: 유입 경로 ('search', 'category', 'ranking', 'blog', ...)
            search_keyword: 검색 키워드
            use_login_cookies: 로그인 쿠키 사용 여부
        """
        log.info(f"\n{'='*60}")
        log.info(f"카테고리별 시나리오 실행")
        log.info(f"카테고리: {category}")
        log.info(f"유입 경로: {entry_path_type}")
        log.info(f"{'='*60}\n")

        # 1. 세션 생성
        session_id = self._get_session_id()
        session = self.session_manager.get_session(session_id)

        # 2. 쿠키 설정
        if use_login_cookies:
            cookies = self.cookie_manipulator.simulate_login_cookies()
        else:
            cookies = self.cookie_manipulator.simulate_interest_cookies([category])

        for name, value in cookies.items():
            session.cookies.set(name, value)

        log.info(f"✅ 쿠키 설정 완료: {len(cookies)}개")

        # 3. 유입 경로 설정
        entry_path = self._get_entry_path(entry_path_type, search_keyword, category)
        referer = entry_path.get('referer')

        log.info(f"📍 유입 경로: {referer[:80]}...")

        # 4. 카테고리별 행동 패턴 가져오기
        pattern = CategoryBasedScenarios.get_pattern(category)

        dwell_min, dwell_max = pattern['avg_dwell_time']
        scroll_min, scroll_max = pattern['scroll_depth']

        # 5. 경쟁사 비교 (확률적)
        if random.random() < pattern['compare_probability']:
            log.info("🔍 경쟁사 비교 진행")
            # 간단히 2-3초 대기 (실제로는 경쟁사 URL 방문)
            time.sleep(random.uniform(2, 3))

        # 6. 타겟 상품 방문
        log.info("🎯 타겟 상품 접근")
        response = self.visit_page(
            url=product_url,
            session_id=session_id,
            referer=referer,
            simulate_scroll=True
        )

        if not response:
            return {'success': False, 'error': 'Page visit failed'}

        # 7. 행동 패턴 실행
        dwell_time = random.randint(dwell_min, dwell_max)
        scroll_count = random.randint(scroll_min, scroll_max)

        log.info(f"📜 스크롤: {scroll_count}회")
        log.info(f"⏱️ 체류: {dwell_time}초")

        # 스크롤 시뮬레이션
        scroll_interval = dwell_time / (scroll_count + 1)

        for i in range(scroll_count):
            time.sleep(scroll_interval)
            log.debug(f"  스크롤 {i+1}/{scroll_count}")

            # 리뷰 확인 (확률적)
            if i == scroll_count // 2 and random.random() < pattern['review_probability']:
                log.info("⭐ 리뷰 영역 확인")
                time.sleep(random.uniform(2, 4))

        # 남은 체류 시간
        time.sleep(scroll_interval)

        # 8. 추가 액션
        actions_taken = []

        if random.random() < pattern.get('q_a_probability', 0.3):
            log.info("❓ Q&A 영역 확인")
            actions_taken.append('qa_check')
            time.sleep(random.uniform(1, 2))

        # 카테고리별 특수 액션
        if pattern.get('ingredient_check') and random.random() < 0.5:
            log.info("🧪 성분 정보 확인")
            actions_taken.append('ingredient_check')
            time.sleep(random.uniform(2, 3))

        if pattern.get('image_focus') and random.random() < 0.6:
            log.info("🖼️ 이미지 확대 보기")
            actions_taken.append('image_zoom')
            time.sleep(random.uniform(1, 2))

        # 9. 세션 저장
        self.session_manager.save_session(session_id)

        log.info(f"\n{'='*60}")
        log.info(f"✅ 카테고리 시나리오 완료")
        log.info(f"{'='*60}\n")

        return {
            'success': True,
            'session_id': session_id,
            'category': category,
            'entry_type': entry_path_type,
            'dwell_time': dwell_time,
            'scroll_count': scroll_count,
            'actions_taken': actions_taken,
            'cookies_used': len(cookies),
        }

    def _get_entry_path(
        self,
        entry_type: str,
        keyword: Optional[str],
        category: Optional[str]
    ) -> Dict:
        """유입 경로 정보 가져오기"""
        if entry_type == 'search' and keyword:
            return EntryPathGenerator.from_naver_search(keyword)
        elif entry_type == 'shopping' and keyword:
            return EntryPathGenerator.from_shopping_direct(keyword)
        elif entry_type == 'category' and category:
            return EntryPathGenerator.from_category_browse(category)
        elif entry_type == 'ranking':
            return EntryPathGenerator.from_ranking_page()
        elif entry_type == 'deal':
            return EntryPathGenerator.from_deal_page()
        elif entry_type == 'blog':
            return EntryPathGenerator.from_blog_review()
        elif entry_type == 'cafe':
            return EntryPathGenerator.from_cafe_post()
        elif entry_type == 'google' and keyword:
            return EntryPathGenerator.from_google_search(keyword)
        elif entry_type == 'price_compare':
            return EntryPathGenerator.from_price_comparison()
        else:
            # 기본값
            return EntryPathGenerator.from_naver_search(keyword or "상품")


if __name__ == "__main__":
    """테스트"""
    log.info("고급 시나리오 테스트")

    generator = AdvancedTrafficGenerator()

    # 테스트 데이터
    test_cases = [
        {
            'product_url': 'https://shopping.naver.com/window-products/8809115891052',
            'category': '전자기기',
            'entry_path': 'search',
            'keyword': '무선이어폰',
        },
        {
            'product_url': 'https://shopping.naver.com/window-products/8809115891052',
            'category': '전자기기',
            'entry_path': 'blog',
            'keyword': None,
        },
        {
            'product_url': 'https://shopping.naver.com/window-products/8809115891052',
            'category': '전자기기',
            'entry_path': 'price_compare',
            'keyword': None,
        },
    ]

    for i, test in enumerate(test_cases, 1):
        log.info(f"\n\n### 테스트 케이스 {i} ###")

        result = generator.execute_category_scenario(
            product_url=test['product_url'],
            category=test['category'],
            entry_path_type=test['entry_path'],
            search_keyword=test.get('keyword'),
            use_login_cookies=(i % 2 == 0)  # 격 케이스마다 로그인 쿠키
        )

        log.info(f"\n결과: {json.dumps(result, indent=2, ensure_ascii=False)}")

        # 케이스 간 간격
        if i < len(test_cases):
            log.info("\n다음 케이스까지 10초 대기...")
            time.sleep(10)
