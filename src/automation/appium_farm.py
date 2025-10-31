"""
Appium 기반 에뮬레이터 팜 관리

27개 Android 에뮬레이터 인스턴스를 관리하고 병렬 실행
"""
import sys
from pathlib import Path
from typing import List, Dict, Optional
import subprocess
import time
import threading
import random

sys.path.append(str(Path(__file__).parent.parent.parent))

from appium import webdriver
from appium.options.android import UiAutomator2Options
from appium.webdriver.common.appiumby import AppiumBy
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from src.utils.logger import get_logger
from src.automation.realistic_traffic import TimingPattern, IPPatternGenerator
from config.settings import config

log = get_logger()


class EmulatorInstance:
    """단일 에뮬레이터 인스턴스"""

    def __init__(self, pc_id: str, avd_name: str, port: int, user_agent: str):
        self.pc_id = pc_id
        self.avd_name = avd_name
        self.port = port
        self.user_agent = user_agent
        self.driver: Optional[webdriver.Remote] = None
        self.process: Optional[subprocess.Popen] = None
        self.device_name = f"emulator-{port}"

    def start_emulator(self):
        """에뮬레이터 프로세스 시작"""
        try:
            log.info(f"[{self.pc_id}] 에뮬레이터 시작: {self.avd_name}")

            # 에뮬레이터 시작 (경량 모드)
            self.process = subprocess.Popen([
                'emulator',
                '-avd', self.avd_name,
                '-port', str(self.port),
                '-no-window',      # GUI 없음 (리소스 절약)
                '-no-audio',       # 오디오 없음
                '-no-boot-anim',   # 부팅 애니메이션 스킵
                '-memory', '2048', # RAM 2GB
                '-cores', '2',     # CPU 2코어
                '-gpu', 'swiftshader_indirect',  # 소프트웨어 렌더링
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # 부팅 대기
            self._wait_for_boot()

            log.success(f"[{self.pc_id}] 에뮬레이터 시작 완료: {self.device_name}")
            return True

        except Exception as e:
            log.error(f"[{self.pc_id}] 에뮬레이터 시작 실패: {e}")
            return False

    def _wait_for_boot(self, timeout: int = 120):
        """에뮬레이터 부팅 완료 대기"""
        log.debug(f"[{self.pc_id}] 부팅 대기 중...")

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # ADB로 부팅 상태 확인
                result = subprocess.run(
                    ['adb', '-s', self.device_name, 'shell', 'getprop', 'sys.boot_completed'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0 and result.stdout.strip() == '1':
                    log.success(f"[{self.pc_id}] 부팅 완료 ({int(time.time() - start_time)}초)")
                    time.sleep(5)  # 안정화 대기
                    return True

            except Exception as e:
                log.debug(f"[{self.pc_id}] 부팅 확인 중: {e}")

            time.sleep(5)

        raise TimeoutError(f"[{self.pc_id}] 에뮬레이터 부팅 타임아웃 ({timeout}초)")

    def connect_appium(self, appium_url: str = 'http://localhost:4723'):
        """Appium 서버에 연결"""
        try:
            log.info(f"[{self.pc_id}] Appium 연결 중...")

            # Appium 옵션 설정
            options = UiAutomator2Options()
            options.platform_name = "Android"
            options.automation_name = "UiAutomator2"
            options.device_name = self.device_name
            options.browser_name = "Chrome"
            options.no_reset = True
            options.new_command_timeout = 300  # 5분

            # User-Agent 설정 (Chrome DevTools Protocol)
            # 주의: User-Agent는 Chrome 실행 후 CDP로 설정해야 함

            # 드라이버 생성
            self.driver = webdriver.Remote(appium_url, options=options)

            log.success(f"[{self.pc_id}] Appium 연결 완료")
            return True

        except Exception as e:
            log.error(f"[{self.pc_id}] Appium 연결 실패: {e}")
            return False

    def execute_traffic(self, keyword: str, product_url: str, category: str = "전자기기"):
        """트래픽 생성 작업 실행"""
        if not self.driver:
            log.error(f"[{self.pc_id}] 드라이버 미연결")
            return False

        try:
            log.info(f"[{self.pc_id}] 트래픽 생성 시작: {keyword}")

            # 1. 네이버 모바일 접속
            self.driver.get('https://m.naver.com')
            time.sleep(random.uniform(2, 4))

            # 2. 검색창 찾기 (여러 선택자 시도)
            search_box = None
            selectors = [
                (AppiumBy.ID, 'query'),
                (AppiumBy.NAME, 'query'),
                (AppiumBy.XPATH, "//input[@type='search']"),
                (AppiumBy.CSS_SELECTOR, "input.search_input"),
            ]

            for by, selector in selectors:
                try:
                    search_box = WebDriverWait(self.driver, 10).until(
                        EC.presence_of_element_located((by, selector))
                    )
                    if search_box:
                        break
                except:
                    continue

            if not search_box:
                raise Exception("검색창을 찾을 수 없음")

            # 3. 검색어 입력
            search_box.clear()
            search_box.send_keys(keyword)
            time.sleep(random.uniform(1, 2))
            search_box.submit()

            # 4. 쇼핑탭 클릭
            time.sleep(random.uniform(2, 3))
            try:
                shopping_tab = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((AppiumBy.XPATH, "//a[contains(text(), '쇼핑')]"))
                )
                shopping_tab.click()
            except:
                log.warning(f"[{self.pc_id}] 쇼핑탭 클릭 실패, URL 직접 이동")
                self.driver.get(f'https://search.shopping.naver.com/search/all?query={keyword}')

            time.sleep(random.uniform(2, 4))

            # 5. 상품 페이지 접근
            log.info(f"[{self.pc_id}] 상품 페이지 접근: {product_url}")
            self.driver.get(product_url)
            time.sleep(random.uniform(3, 5))

            # 6. 자연스러운 사용자 행동 시뮬레이션
            self._simulate_user_behavior(category)

            log.success(f"[{self.pc_id}] 트래픽 생성 완료")
            return True

        except Exception as e:
            log.error(f"[{self.pc_id}] 트래픽 생성 실패: {e}")
            return False

    def _simulate_user_behavior(self, category: str):
        """자연스러운 사용자 행동 시뮬레이션"""
        try:
            # 카테고리별 체류 시간 (초)
            dwell_times = {
                '전자기기': (120, 180),
                '패션의류': (60, 90),
                '식품': (40, 60),
                '뷰티': (90, 120),
                '생활용품': (50, 80),
            }

            min_time, max_time = dwell_times.get(category, (60, 90))

            # 1. 스크롤 (3~5회)
            scroll_count = random.randint(3, 5)
            for i in range(scroll_count):
                scroll_amount = random.randint(300, 600)
                self.driver.execute_script(f"window.scrollBy(0, {scroll_amount});")
                time.sleep(random.uniform(2, 4))

            # 2. 중간 체류
            mid_dwell = random.uniform(min_time * 0.4, min_time * 0.6)
            time.sleep(mid_dwell)

            # 3. 추가 스크롤 (리뷰 영역)
            if random.random() < 0.7:  # 70% 확률
                self.driver.execute_script("window.scrollBy(0, 800);")
                time.sleep(random.uniform(3, 5))

            # 4. 나머지 체류 시간
            remaining = random.uniform(min_time * 0.4, max_time - mid_dwell)
            time.sleep(remaining)

            log.debug(f"[{self.pc_id}] 사용자 행동 시뮬레이션 완료")

        except Exception as e:
            log.warning(f"[{self.pc_id}] 사용자 행동 시뮬레이션 중 오류: {e}")

    def stop(self):
        """에뮬레이터 및 드라이버 종료"""
        try:
            if self.driver:
                self.driver.quit()
                log.debug(f"[{self.pc_id}] 드라이버 종료")

            if self.process:
                self.process.terminate()
                self.process.wait(timeout=10)
                log.debug(f"[{self.pc_id}] 에뮬레이터 프로세스 종료")

            log.success(f"[{self.pc_id}] 정상 종료")

        except Exception as e:
            log.error(f"[{self.pc_id}] 종료 중 오류: {e}")


class EmulatorFarm:
    """27개 에뮬레이터 팜 관리"""

    def __init__(self, num_instances: int = 27, start_port: int = 5554):
        self.num_instances = num_instances
        self.start_port = start_port
        self.instances: List[EmulatorInstance] = []

    def create_instances(self, user_agents: List[str]):
        """에뮬레이터 인스턴스 생성"""
        log.info(f"{self.num_instances}개 에뮬레이터 인스턴스 생성 중...")

        for i in range(self.num_instances):
            pc_id = f"PC_{str(6 + i).zfill(3)}"  # PC_006 ~ PC_035
            avd_name = f"Emulator_{pc_id}"
            port = self.start_port + (i * 2)  # 5554, 5556, 5558, ...
            user_agent = user_agents[i % len(user_agents)]  # 순환 선택

            instance = EmulatorInstance(pc_id, avd_name, port, user_agent)
            self.instances.append(instance)

        log.success(f"{len(self.instances)}개 인스턴스 생성 완료")

    def start_all(self, batch_size: int = 5, batch_delay: int = 30):
        """모든 에뮬레이터 시작 (단계적)"""
        log.info(f"에뮬레이터 팜 시작 ({batch_size}개씩 단계적 시작)...")

        # 배치 단위로 시작
        for i in range(0, len(self.instances), batch_size):
            batch = self.instances[i:i + batch_size]
            threads = []

            log.info(f"배치 {i//batch_size + 1}: {len(batch)}개 시작 중...")

            for instance in batch:
                thread = threading.Thread(target=instance.start_emulator)
                thread.start()
                threads.append(thread)

            # 모든 스레드 완료 대기
            for thread in threads:
                thread.join()

            # 다음 배치 전 대기
            if i + batch_size < len(self.instances):
                log.info(f"{batch_delay}초 후 다음 배치 시작...")
                time.sleep(batch_delay)

        log.success(f"모든 에뮬레이터 시작 완료 ({len(self.instances)}개)")

    def connect_all_appium(self, appium_url: str = 'http://localhost:4723'):
        """모든 인스턴스를 Appium에 연결"""
        log.info("Appium 연결 중...")

        threads = []
        for instance in self.instances:
            thread = threading.Thread(target=instance.connect_appium, args=(appium_url,))
            thread.start()
            threads.append(thread)
            time.sleep(2)  # 동시 연결 부하 방지

        for thread in threads:
            thread.join()

        connected = sum(1 for inst in self.instances if inst.driver is not None)
        log.success(f"Appium 연결 완료: {connected}/{len(self.instances)}개")

    def execute_parallel_traffic(self, keyword: str, product_url: str, category: str = "전자기기"):
        """모든 인스턴스에서 병렬 트래픽 생성"""
        log.info(f"{len(self.instances)}개 인스턴스에서 병렬 트래픽 생성 시작...")

        threads = []
        for instance in self.instances:
            if instance.driver:
                thread = threading.Thread(
                    target=instance.execute_traffic,
                    args=(keyword, product_url, category)
                )
                thread.start()
                threads.append(thread)
                time.sleep(random.uniform(1, 3))  # 요청 간격 랜덤화

        for thread in threads:
            thread.join()

        log.success("병렬 트래픽 생성 완료")

    def stop_all(self):
        """모든 에뮬레이터 종료"""
        log.info("에뮬레이터 팜 종료 중...")

        threads = []
        for instance in self.instances:
            thread = threading.Thread(target=instance.stop)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        log.success("모든 에뮬레이터 종료 완료")


# 편의 함수
def test_single_emulator():
    """단일 에뮬레이터 테스트"""
    log.info("\n=== 단일 에뮬레이터 테스트 ===\n")

    from src.automation.http_traffic import UserAgentPool

    # 인스턴스 생성
    user_agent = UserAgentPool.get_random_mobile()
    instance = EmulatorInstance("PC_006", "Emulator_PC_006", 5554, user_agent)

    # 에뮬레이터 시작
    if instance.start_emulator():
        # Appium 연결
        if instance.connect_appium():
            # 트래픽 생성
            instance.execute_traffic(
                keyword="무선이어폰",
                product_url="https://shopping.naver.com/window-products/8809115891052",
                category="전자기기"
            )

        # 종료
        instance.stop()


if __name__ == "__main__":
    test_single_emulator()
