"""
HTTP 요청 기반 트래픽 생성

실제 기기 대신 HTTP 요청을 직접 조작하여 트래픽 생성
- User-Agent 로테이션
- 쿠키/세션 관리
- Referer 조작
- 패킷 헤더 커스터마이징
"""

import requests
import random
import time
import json
from typing import Dict, List, Optional
from pathlib import Path
import hashlib
from datetime import datetime

# 프로젝트 루트 경로 추가
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.utils.logger import get_logger

log = get_logger()


class UserAgentPool:
    """
    User-Agent 풀 관리

    실제 트래픽 데이터 분석 기반 (2023-02-03 패킷 분석)
    - 모든 User-Agent는 Samsung Browser 기반
    - Android 9~12 버전 분포
    - Chrome 96.0 / 102.0 버전
    - Samsung Browser 17.0 / 19.0 버전
    """

    # 실제 트래픽 데이터 기반 모바일 User-Agent 풀
    MOBILE_USER_AGENTS = [
        # SM-N950N (Android 9, Samsung Browser 17.0)
        "Mozilla/5.0 (Linux; Android 9; SAMSUNG SM-N950N/KSU5DUI1) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36",

        # SM-N950N (Android 9, Samsung Browser 19.0)
        "Mozilla/5.0 (Linux; Android 9; SAMSUNG SM-N950N/KSU5DUI1) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/19.0 Chrome/102.0.5005.125 Mobile Safari/537.36",

        # SM-F926N (Android 12, Samsung Browser 17.0)
        "Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-F926N/KSU1CVA3) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36",

        # SM-F926N (Android 12, Samsung Browser 19.0)
        "Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-F926N/KSU1CVA3) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/19.0 Chrome/102.0.5005.125 Mobile Safari/537.36",

        # SM-A235N (Android 12, Samsung Browser 17.0)
        "Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-A235N/KSU1BVE2) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36",

        # SM-A235N (Android 12, Samsung Browser 19.0)
        "Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-A235N/KSU1BVE2) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/19.0 Chrome/102.0.5005.125 Mobile Safari/537.36",

        # SM-G996N (Android 12, Samsung Browser 17.0)
        "Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-G996N/KSU2DUJA) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36",

        # SM-G996N (Android 12, Samsung Browser 19.0)
        "Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-G996N/KSU2DUJA) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/19.0 Chrome/102.0.5005.125 Mobile Safari/537.36",

        # SM-G991N (Android 11, Samsung Browser 17.0)
        "Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-G991N/KSU1DUJ1) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36",

        # SM-G991N (Android 11, Samsung Browser 19.0)
        "Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-G991N/KSU1DUJ1) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/19.0 Chrome/102.0.5005.125 Mobile Safari/537.36",

        # SM-S901N (Android 12, Samsung Browser 17.0)
        "Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-S901N/KSU1BUJA) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36",

        # SM-S901N (Android 12, Samsung Browser 19.0)
        "Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-S901N/KSU1BUJA) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/19.0 Chrome/102.0.5005.125 Mobile Safari/537.36",

        # SM-N960N (Android 10, Samsung Browser 17.0)
        "Mozilla/5.0 (Linux; Android 10; SAMSUNG SM-N960N/KSU3FTJ2) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36",

        # SM-N960N (Android 10, Samsung Browser 19.0)
        "Mozilla/5.0 (Linux; Android 10; SAMSUNG SM-N960N/KSU3FTJ2) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/19.0 Chrome/102.0.5005.125 Mobile Safari/537.36",
    ]

    # PC 데스크톱 User-Agent (Windows/Mac 혼합)
    DESKTOP_USER_AGENTS = [
        # Windows 10 Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",

        # Windows 10 Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.48",

        # Windows 11 Chrome
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",

        # Mac Chrome
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",

        # Mac Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    ]

    # PC 식별자 풀 (실제 데이터 기반: PC_006 ~ PC_035)
    PC_IDENTIFIERS = [
        f"PC_{str(i).zfill(3)}" for i in range(6, 36)  # PC_006 ~ PC_035
    ]

    @classmethod
    def get_random_mobile(cls) -> str:
        """랜덤 모바일 User-Agent (실제 데이터 기반)"""
        return random.choice(cls.MOBILE_USER_AGENTS)

    @classmethod
    def get_random_desktop(cls) -> str:
        """랜덤 데스크톱 User-Agent"""
        return random.choice(cls.DESKTOP_USER_AGENTS)

    @classmethod
    def get_random(cls, mobile_probability: float = 0.7) -> str:
        """랜덤 User-Agent (모바일 70%, 데스크톱 30%)"""
        if random.random() < mobile_probability:
            return cls.get_random_mobile()
        return cls.get_random_desktop()

    @classmethod
    def get_random_pc_identifier(cls) -> str:
        """랜덤 PC 식별자 (PC_006 ~ PC_035)"""
        return random.choice(cls.PC_IDENTIFIERS)


class SessionManager:
    """쿠키 및 세션 관리"""

    def __init__(self):
        self.sessions: Dict[str, requests.Session] = {}
        self.session_data_dir = Path("data/sessions")
        self.session_data_dir.mkdir(parents=True, exist_ok=True)

    def create_session(self, session_id: str) -> requests.Session:
        """새 세션 생성"""
        session = requests.Session()

        # 기본 헤더 설정
        session.headers.update({
            'User-Agent': UserAgentPool.get_random(),
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

        self.sessions[session_id] = session
        log.info(f"새 세션 생성: {session_id}")

        return session

    def get_session(self, session_id: str) -> requests.Session:
        """기존 세션 가져오기 (없으면 생성)"""
        if session_id not in self.sessions:
            return self.create_session(session_id)
        return self.sessions[session_id]

    def save_session(self, session_id: str):
        """세션 쿠키 저장"""
        if session_id not in self.sessions:
            return

        session = self.sessions[session_id]
        session_file = self.session_data_dir / f"{session_id}.json"

        # 쿠키를 딕셔너리로 변환
        cookies = requests.utils.dict_from_cookiejar(session.cookies)

        with open(session_file, 'w', encoding='utf-8') as f:
            json.dump({
                'cookies': cookies,
                'headers': dict(session.headers),
                'saved_at': datetime.now().isoformat()
            }, f, indent=2)

        log.debug(f"세션 저장: {session_file}")

    def load_session(self, session_id: str) -> Optional[requests.Session]:
        """저장된 세션 로드"""
        session_file = self.session_data_dir / f"{session_id}.json"

        if not session_file.exists():
            return None

        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            session = requests.Session()

            # 쿠키 복원
            for name, value in data['cookies'].items():
                session.cookies.set(name, value)

            # 헤더 복원
            session.headers.update(data['headers'])

            self.sessions[session_id] = session
            log.info(f"세션 로드: {session_id}")

            return session

        except Exception as e:
            log.error(f"세션 로드 실패: {e}")
            return None

    def delete_session(self, session_id: str):
        """세션 삭제"""
        if session_id in self.sessions:
            del self.sessions[session_id]

        session_file = self.session_data_dir / f"{session_id}.json"
        if session_file.exists():
            session_file.unlink()


class HTTPTrafficGenerator:
    """HTTP 요청 기반 트래픽 생성기"""

    def __init__(self):
        self.session_manager = SessionManager()
        self.request_count = 0
        self.last_request_time = 0

    def _get_session_id(self) -> str:
        """고유 세션 ID 생성 (IP 변경 시뮬레이션용)"""
        # 타임스탬프 + 랜덤값으로 고유 ID
        timestamp = str(time.time())
        random_val = str(random.randint(10000, 99999))
        session_id = hashlib.md5(f"{timestamp}{random_val}".encode()).hexdigest()[:16]
        return session_id

    def _random_delay(self, min_sec: float = 1.0, max_sec: float = 3.0):
        """랜덤 딜레이 (봇 탐지 회피)"""
        delay = random.uniform(min_sec, max_sec)
        time.sleep(delay)

    def _update_referer(self, session: requests.Session, referer: str):
        """Referer 헤더 업데이트"""
        session.headers.update({'Referer': referer})

    def visit_page(
        self,
        url: str,
        session_id: Optional[str] = None,
        referer: Optional[str] = None,
        simulate_scroll: bool = True
    ) -> Optional[requests.Response]:
        """
        페이지 방문

        Args:
            url: 방문할 URL
            session_id: 세션 ID (None이면 새로 생성)
            referer: Referer URL
            simulate_scroll: 스크롤 시뮬레이션 여부

        Returns:
            Response 객체
        """
        # 세션 가져오기
        if session_id is None:
            session_id = self._get_session_id()

        session = self.session_manager.get_session(session_id)

        # Referer 설정
        if referer:
            self._update_referer(session, referer)

        try:
            log.info(f"페이지 방문: {url[:80]}...")

            # 요청 전 딜레이
            self._random_delay(0.5, 1.5)

            # HTTP 요청
            response = session.get(url, timeout=10)
            response.raise_for_status()

            self.request_count += 1
            self.last_request_time = time.time()

            log.info(f"응답: {response.status_code}, 크기: {len(response.content)} bytes")

            # 스크롤 시뮬레이션 (추가 리소스 로드)
            if simulate_scroll:
                self._simulate_scroll_requests(session, url, response)

            # 세션 저장
            self.session_manager.save_session(session_id)

            return response

        except requests.exceptions.RequestException as e:
            log.error(f"페이지 방문 실패: {e}")
            return None

    def _simulate_scroll_requests(
        self,
        session: requests.Session,
        page_url: str,
        initial_response: requests.Response
    ):
        """
        스크롤 시 발생하는 추가 요청 시뮬레이션
        (이미지 lazy loading, AJAX 요청 등)
        """
        # 실제로는 페이지 HTML 파싱해서 이미지/스크립트 URL 추출
        # 여기서는 간단히 딜레이만 추가
        log.debug("스크롤 시뮬레이션: 추가 리소스 로드")

        scroll_count = random.randint(2, 4)
        for i in range(scroll_count):
            self._random_delay(0.3, 0.8)
            # 실제로는 이미지 등을 GET 요청
            log.debug(f"  스크롤 {i+1}/{scroll_count}")

    def simulate_product_view(
        self,
        product_url: str,
        dwell_time: int = 60,
        scroll_count: int = 3,
        referer: Optional[str] = None
    ) -> Dict:
        """
        상품 페이지 보기 시뮬레이션

        Args:
            product_url: 상품 URL
            dwell_time: 체류 시간 (초)
            scroll_count: 스크롤 횟수
            referer: 유입 경로

        Returns:
            결과 딕셔너리
        """
        session_id = self._get_session_id()

        log.info(f"=== 상품 페이지 시뮬레이션 시작 ===")
        log.info(f"URL: {product_url}")
        log.info(f"체류 시간: {dwell_time}초")
        log.info(f"스크롤: {scroll_count}회")

        # 1. 페이지 방문
        response = self.visit_page(
            url=product_url,
            session_id=session_id,
            referer=referer,
            simulate_scroll=True
        )

        if not response:
            return {'success': False, 'error': 'Page visit failed'}

        # 2. 스크롤 시뮬레이션
        scroll_interval = dwell_time / (scroll_count + 1)

        for i in range(scroll_count):
            time.sleep(scroll_interval)
            log.debug(f"스크롤 {i+1}/{scroll_count}")
            # 실제로는 AJAX 요청 등 추가 가능

        # 3. 남은 체류 시간
        time.sleep(scroll_interval)

        log.info(f"✅ 상품 페이지 시뮬레이션 완료")

        return {
            'success': True,
            'session_id': session_id,
            'status_code': response.status_code,
            'dwell_time': dwell_time,
            'scroll_count': scroll_count
        }

    def simulate_case_s3(
        self,
        competitor_urls: List[str],
        target_url: str,
        search_keyword: str
    ) -> Dict:
        """
        CASE_S3 시나리오 시뮬레이션 (HTTP 요청 버전)

        Args:
            competitor_urls: 경쟁사 URL 리스트
            target_url: 타겟 상품 URL
            search_keyword: 검색 키워드
        """
        log.info("\n" + "="*60)
        log.info("CASE_S3 HTTP 시뮬레이션 시작")
        log.info("="*60 + "\n")

        session_id = self._get_session_id()

        # Referer: 네이버 검색
        search_referer = f"https://search.naver.com/search.naver?query={search_keyword}"

        try:
            # 1. 경쟁 상품 A 확인
            log.info("=== 경쟁 상품 1 확인 ===")
            self.visit_page(
                url=competitor_urls[0],
                session_id=session_id,
                referer=search_referer,
                simulate_scroll=True
            )
            time.sleep(random.randint(25, 35))  # 체류 시간

            # 2. 경쟁 상품 B 확인
            log.info("=== 경쟁 상품 2 확인 ===")
            self.visit_page(
                url=competitor_urls[1],
                session_id=session_id,
                referer=search_referer,
                simulate_scroll=True
            )
            time.sleep(random.randint(25, 35))

            # 3. 타겟 상품 상세 확인
            log.info("=== 타겟 상품 상세 확인 ===")
            self.visit_page(
                url=target_url,
                session_id=session_id,
                referer=search_referer,
                simulate_scroll=True
            )

            # 깊은 스크롤 시뮬레이션
            scroll_count = random.randint(4, 6)
            dwell_time = random.randint(90, 120)

            for i in range(scroll_count):
                time.sleep(dwell_time / (scroll_count + 1))
                log.debug(f"타겟 상품 스크롤 {i+1}/{scroll_count}")

            # 남은 체류 시간
            time.sleep(dwell_time / (scroll_count + 1))

            log.info("\n" + "="*60)
            log.info("CASE_S3 HTTP 시뮬레이션 완료 ✅")
            log.info("="*60 + "\n")

            return {
                'success': True,
                'session_id': session_id,
                'total_requests': self.request_count
            }

        except Exception as e:
            log.error(f"CASE_S3 시뮬레이션 실패: {e}")
            return {'success': False, 'error': str(e)}


class ProxyRotator:
    """프록시 로테이션 (선택적)"""

    def __init__(self, proxy_list: Optional[List[str]] = None):
        """
        Args:
            proxy_list: 프록시 리스트 ['http://ip:port', ...]
        """
        self.proxy_list = proxy_list or []
        self.current_index = 0

    def get_next_proxy(self) -> Optional[Dict]:
        """다음 프록시 가져오기"""
        if not self.proxy_list:
            return None

        proxy = self.proxy_list[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxy_list)

        return {
            'http': proxy,
            'https': proxy
        }


if __name__ == "__main__":
    """단독 테스트"""
    log.info("HTTP 트래픽 생성기 테스트")

    generator = HTTPTrafficGenerator()

    # 테스트 URL
    test_product_url = "https://shopping.naver.com/window-products/8809115891052"

    # 상품 페이지 방문 시뮬레이션
    result = generator.simulate_product_view(
        product_url=test_product_url,
        dwell_time=30,
        scroll_count=3,
        referer="https://search.naver.com/search.naver?query=무선이어폰"
    )

    log.info(f"\n결과: {result}")
