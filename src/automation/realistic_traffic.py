"""
실제 패킷 분석 기반 현실적인 트래픽 생성

패킷 분석 데이터 (2023-02-03):
- 267개 실제 트래픽 기록
- Samsung Browser 중심 (17.0, 19.0)
- Android 9~12 기기 (SM-N950N, SM-F926N, SM-A235N, SM-G996N, SM-G991N, SM-S901N, SM-N960N)
- IP 패턴: 175.223.x.x, 110.70.x.x, 39.7.x.x, 223.38.x.x
- 타이밍: 2-5분 간격
- PC 식별자: PC_006 ~ PC_035
"""

import requests
import random
import time
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import quote, urlencode
import sys

sys.path.append(str(Path(__file__).parent.parent.parent))

from src.utils.logger import get_logger
from src.automation.http_traffic import UserAgentPool, SessionManager

log = get_logger()


class IPPatternGenerator:
    """
    실제 트래픽 데이터 기반 IP 패턴 생성

    실제 데이터에서 관찰된 IP 패턴:
    - 175.223.x.x (가장 많음, ~60%)
    - 110.70.x.x (~20%)
    - 39.7.x.x (~15%)
    - 223.38.x.x (~5%)
    """

    IP_PATTERNS = [
        {
            'prefix': '175.223',
            'third_octet_range': (0, 255),
            'fourth_octet_range': (1, 254),
            'weight': 0.60
        },
        {
            'prefix': '110.70',
            'third_octet_range': (0, 255),
            'fourth_octet_range': (1, 254),
            'weight': 0.20
        },
        {
            'prefix': '39.7',
            'third_octet_range': (0, 255),
            'fourth_octet_range': (1, 254),
            'weight': 0.15
        },
        {
            'prefix': '223.38',
            'third_octet_range': (0, 255),
            'fourth_octet_range': (1, 254),
            'weight': 0.05
        },
    ]

    @classmethod
    def generate_ip(cls) -> str:
        """
        실제 패턴 기반 IP 생성

        Returns:
            가중치 기반 랜덤 IP 주소
        """
        # 가중치 기반 패턴 선택
        patterns = cls.IP_PATTERNS
        weights = [p['weight'] for p in patterns]
        selected_pattern = random.choices(patterns, weights=weights, k=1)[0]

        # IP 생성
        third = random.randint(
            selected_pattern['third_octet_range'][0],
            selected_pattern['third_octet_range'][1]
        )
        fourth = random.randint(
            selected_pattern['fourth_octet_range'][0],
            selected_pattern['fourth_octet_range'][1]
        )

        ip = f"{selected_pattern['prefix']}.{third}.{fourth}"
        return ip


class TimingPattern:
    """
    실제 트래픽 타이밍 패턴

    관찰된 패턴:
    - 평균 간격: 2.5분 (150초)
    - 최소 간격: 2분 (120초)
    - 최대 간격: 5분 (300초)
    - 정규분포: μ=150, σ=30
    """

    @staticmethod
    def get_next_interval() -> int:
        """
        다음 요청까지 대기 시간 (초)

        정규분포 기반: 평균 150초, 표준편차 30초
        최소 120초, 최대 300초
        """
        import numpy as np

        interval = int(np.random.normal(150, 30))
        interval = max(120, min(300, interval))  # 120~300초 범위

        return interval

    @staticmethod
    def get_dwell_time(category: str = "전자기기") -> int:
        """
        체류 시간 생성 (카테고리별)

        Args:
            category: 상품 카테고리

        Returns:
            체류 시간 (초)
        """
        import numpy as np

        category_patterns = {
            '전자기기': (120, 180, 20),  # (최소, 최대, 표준편차)
            '패션의류': (60, 90, 15),
            '식품': (40, 60, 10),
            '뷰티': (90, 120, 15),
            '생활용품': (50, 80, 12),
        }

        min_time, max_time, std = category_patterns.get(
            category, (60, 90, 15)
        )

        avg = (min_time + max_time) / 2
        dwell = int(np.random.normal(avg, std))
        dwell = max(min_time, min(max_time, dwell))

        return dwell


class RealisticTrafficGenerator:
    """
    실제 패킷 패턴 기반 트래픽 생성기

    핵심 기능:
    - 모바일: m.naver.com 검색
    - PC: naver.com 검색
    - 실제 User-Agent 사용
    - IP 패턴 시뮬레이션
    - 타이밍 패턴 적용
    - 예외(빵꾸) 처리
    """

    def __init__(self):
        self.session_manager = SessionManager()
        self.pc_identifier = UserAgentPool.get_random_pc_identifier()
        self.ip_address = IPPatternGenerator.generate_ip()

        log.info(f"트래픽 생성기 초기화")
        log.info(f"  PC 식별자: {self.pc_identifier}")
        log.info(f"  시뮬레이션 IP: {self.ip_address}")

    def _create_session(self, is_mobile: bool = True) -> requests.Session:
        """
        세션 생성 (모바일/PC 구분)

        Args:
            is_mobile: True=모바일, False=PC

        Returns:
            설정된 Session 객체
        """
        session = requests.Session()

        # User-Agent 설정
        if is_mobile:
            user_agent = UserAgentPool.get_random_mobile()
        else:
            user_agent = UserAgentPool.get_random_desktop()

        # 헤더 설정
        session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        })

        # X-Forwarded-For로 IP 시뮬레이션 (일부 서버에서 인식)
        session.headers.update({
            'X-Forwarded-For': self.ip_address,
            'X-Real-IP': self.ip_address,
        })

        log.debug(f"세션 생성: {'모바일' if is_mobile else 'PC'}")
        log.debug(f"  User-Agent: {user_agent[:80]}...")

        return session

    def search_from_mobile_naver(
        self,
        keyword: str,
        session: Optional[requests.Session] = None
    ) -> Optional[str]:
        """
        모바일 네이버 통합검색 (m.naver.com)

        Args:
            keyword: 검색 키워드
            session: 기존 세션 (None이면 새로 생성)

        Returns:
            쇼핑 탭 URL
        """
        if session is None:
            session = self._create_session(is_mobile=True)

        # 1. m.naver.com 접속
        try:
            log.info(f"[모바일] 네이버 메인 접속")
            response = session.get("https://m.naver.com", timeout=10)
            response.raise_for_status()
            time.sleep(random.uniform(1.0, 2.0))

            # 2. 통합검색
            search_url = f"https://m.search.naver.com/search.naver?query={quote(keyword)}"
            log.info(f"[모바일] 검색: {keyword}")

            response = session.get(search_url, timeout=10)
            response.raise_for_status()
            time.sleep(random.uniform(1.5, 2.5))

            # 3. 쇼핑 탭 URL 생성
            shopping_url = f"https://msearch.shopping.naver.com/search/all?query={quote(keyword)}"

            log.info(f"[모바일] 쇼핑 탭 이동")
            return shopping_url

        except requests.exceptions.RequestException as e:
            log.error(f"모바일 검색 실패: {e}")
            return None

    def search_from_pc_naver(
        self,
        keyword: str,
        session: Optional[requests.Session] = None
    ) -> Optional[str]:
        """
        PC 네이버 통합검색 (naver.com)

        Args:
            keyword: 검색 키워드
            session: 기존 세션 (None이면 새로 생성)

        Returns:
            쇼핑 탭 URL
        """
        if session is None:
            session = self._create_session(is_mobile=False)

        # 1. naver.com 접속
        try:
            log.info(f"[PC] 네이버 메인 접속")
            response = session.get("https://www.naver.com", timeout=10)
            response.raise_for_status()
            time.sleep(random.uniform(1.0, 2.0))

            # 2. 통합검색
            search_url = f"https://search.naver.com/search.naver?query={quote(keyword)}"
            log.info(f"[PC] 검색: {keyword}")

            response = session.get(search_url, timeout=10)
            response.raise_for_status()
            time.sleep(random.uniform(1.5, 2.5))

            # 3. 쇼핑 탭 URL 생성
            shopping_url = f"https://search.shopping.naver.com/search/all?query={quote(keyword)}"

            log.info(f"[PC] 쇼핑 탭 이동")
            return shopping_url

        except requests.exceptions.RequestException as e:
            log.error(f"PC 검색 실패: {e}")
            return None

    def visit_product_page(
        self,
        product_url: str,
        category: str = "전자기기",
        entry_path: str = "search",
        session: Optional[requests.Session] = None,
        handle_exception: bool = True
    ) -> Dict:
        """
        상품 페이지 방문 (예외 처리 포함)

        Args:
            product_url: 상품 URL
            category: 상품 카테고리
            entry_path: 진입 경로 (search, blog, cafe, etc)
            session: 세션
            handle_exception: 예외(빵꾸) 처리 여부

        Returns:
            결과 딕셔너리
        """
        if session is None:
            # 모바일/PC 랜덤 선택 (70% 모바일)
            is_mobile = random.random() < 0.7
            session = self._create_session(is_mobile=is_mobile)

        try:
            # 체류 시간 결정
            dwell_time = TimingPattern.get_dwell_time(category)
            scroll_count = random.randint(3, 6)

            log.info(f"=== 상품 페이지 방문 ===")
            log.info(f"URL: {product_url[:80]}...")
            log.info(f"카테고리: {category}")
            log.info(f"체류 시간: {dwell_time}초")
            log.info(f"스크롤: {scroll_count}회")

            # 1. 페이지 방문
            response = session.get(product_url, timeout=10)
            response.raise_for_status()

            # 2. 예외 처리 (빵꾸 시뮬레이션)
            if handle_exception and random.random() < 0.05:  # 5% 확률
                log.warning("⚠️ 예외 발생: 네트워크 타임아웃 시뮬레이션")
                time.sleep(random.uniform(3, 5))

                # 재시도
                log.info("재시도 중...")
                response = session.get(product_url, timeout=10)
                response.raise_for_status()

            # 3. 스크롤 시뮬레이션
            scroll_interval = dwell_time / (scroll_count + 1)

            for i in range(scroll_count):
                time.sleep(scroll_interval)
                log.debug(f"스크롤 {i+1}/{scroll_count}")

                # 랜덤 예외: 스크롤 중 멈춤 (3% 확률)
                if handle_exception and random.random() < 0.03:
                    pause_time = random.uniform(2, 4)
                    log.debug(f"⚠️ 스크롤 일시 정지 ({pause_time:.1f}초)")
                    time.sleep(pause_time)

            # 4. 남은 체류 시간
            time.sleep(scroll_interval)

            # 5. 추가 액션 (확률적)
            actions_taken = []

            # 리뷰 클릭 (40%)
            if random.random() < 0.4:
                log.debug("리뷰 영역 확인")
                time.sleep(random.uniform(5, 10))
                actions_taken.append("review_view")

            # Q&A 클릭 (20%)
            if random.random() < 0.2:
                log.debug("Q&A 확인")
                time.sleep(random.uniform(3, 6))
                actions_taken.append("qna_view")

            # 옵션 선택 (30%)
            if random.random() < 0.3:
                log.debug("옵션 선택")
                time.sleep(random.uniform(2, 4))
                actions_taken.append("option_select")

            log.info(f"✅ 상품 페이지 방문 완료")
            log.info(f"실제 체류 시간: ~{dwell_time}초")
            log.info(f"액션: {', '.join(actions_taken) if actions_taken else '없음'}")

            return {
                'success': True,
                'status_code': response.status_code,
                'dwell_time': dwell_time,
                'scroll_count': scroll_count,
                'actions': actions_taken,
                'exception_occurred': False
            }

        except requests.exceptions.Timeout:
            log.error("❌ 타임아웃 발생 (실제 네트워크 문제)")
            return {
                'success': False,
                'error': 'timeout',
                'exception_occurred': True
            }

        except requests.exceptions.RequestException as e:
            log.error(f"❌ 요청 실패: {e}")
            return {
                'success': False,
                'error': str(e),
                'exception_occurred': True
            }

    def execute_full_scenario(
        self,
        keyword: str,
        product_url: str,
        category: str = "전자기기",
        use_mobile: bool = True
    ) -> Dict:
        """
        완전한 트래픽 시나리오 실행

        1. 네이버 검색 (m.naver.com or naver.com)
        2. 쇼핑 탭 클릭
        3. 상품 검색 결과 확인
        4. 상품 페이지 방문

        Args:
            keyword: 검색 키워드
            product_url: 상품 URL
            category: 상품 카테고리
            use_mobile: True=모바일, False=PC

        Returns:
            실행 결과
        """
        log.info("\n" + "="*80)
        log.info(f"완전 시나리오 실행 시작")
        log.info(f"  플랫폼: {'모바일' if use_mobile else 'PC'}")
        log.info(f"  키워드: {keyword}")
        log.info(f"  카테고리: {category}")
        log.info("="*80 + "\n")

        # 세션 생성
        session = self._create_session(is_mobile=use_mobile)

        # 1. 네이버 검색
        if use_mobile:
            shopping_url = self.search_from_mobile_naver(keyword, session)
        else:
            shopping_url = self.search_from_pc_naver(keyword, session)

        if not shopping_url:
            return {'success': False, 'error': 'search_failed'}

        # 2. 쇼핑 검색 결과 페이지 방문
        try:
            log.info("쇼핑 검색 결과 확인")
            response = session.get(shopping_url, timeout=10)
            response.raise_for_status()
            time.sleep(random.uniform(2, 4))  # 검색 결과 확인 시간

        except requests.exceptions.RequestException as e:
            log.error(f"쇼핑 검색 결과 로드 실패: {e}")
            return {'success': False, 'error': 'shopping_search_failed'}

        # 3. 상품 페이지 방문
        result = self.visit_product_page(
            product_url=product_url,
            category=category,
            entry_path='search',
            session=session,
            handle_exception=True
        )

        log.info("\n" + "="*80)
        log.info("완전 시나리오 실행 완료 ✅")
        log.info("="*80 + "\n")

        return result


if __name__ == "__main__":
    """테스트"""
    log.info("현실적인 트래픽 생성기 테스트\n")

    generator = RealisticTrafficGenerator()

    # 테스트 케이스
    test_keyword = "무선이어폰"
    test_product_url = "https://shopping.naver.com/window-products/8809115891052"

    # 모바일 시나리오
    log.info("\n[테스트 1] 모바일 시나리오")
    result = generator.execute_full_scenario(
        keyword=test_keyword,
        product_url=test_product_url,
        category="전자기기",
        use_mobile=True
    )

    log.info(f"\n결과: {result}")

    # 대기 (실제 패턴)
    wait_time = TimingPattern.get_next_interval()
    log.info(f"\n다음 요청까지 대기: {wait_time}초 ({wait_time/60:.1f}분)")
