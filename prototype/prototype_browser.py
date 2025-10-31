"""
프로토타입 브라우저 자동화 - CASE_S3 (비교 쇼핑 후 최종 선택)

CASE_S3 시나리오:
1. 검색 결과 페이지에서 경쟁 상품 A 클릭 (30초 체류)
2. 뒤로가기
3. 경쟁 상품 B 클릭 (30초 체류)
4. 뒤로가기
5. 타겟 상품 클릭 (상세 확인 90-120초)
6. 장바구니 담기 (확률적)
"""

import time
import random
import json
from typing import Dict, Optional
from pathlib import Path

# 프로젝트 루트 경로 추가
import sys
sys.path.append(str(Path(__file__).parent.parent))

from src.automation.mobile import ADBController
from src.utils.logger import get_logger

log = get_logger()


class PrototypeBrowser:
    """프로토타입용 CASE_S3 브라우저 제어"""

    def __init__(self, controller: ADBController, config: Dict):
        self.controller = controller
        self.config = config
        self.screen = config['screen']
        self.coords = config['coordinates']
        self.timing = config['timing']
        self.case_s3 = config['case_s3_config']

    def open_url(self, url: str) -> bool:
        """URL 열기"""
        log.info(f"URL 열기: {url}")
        success = self.controller.open_url(url)
        if success:
            time.sleep(self.timing['page_load_wait'])
        return success

    def go_back(self) -> bool:
        """뒤로가기"""
        log.info("뒤로가기")
        success = self.controller.press_back()
        time.sleep(self.timing['page_load_wait'])
        return success

    def scroll_page(self, count: int) -> None:
        """페이지 스크롤"""
        log.info(f"스크롤 {count}회")
        for i in range(count):
            self.controller.swipe(
                self.coords['scroll_start']['x'],
                self.coords['scroll_start']['y'],
                self.coords['scroll_end']['x'],
                self.coords['scroll_end']['y'],
                duration=self.timing['scroll_duration']
            )
            time.sleep(self.timing['wait_after_scroll'])

    def click_cart_button(self) -> bool:
        """장바구니 버튼 클릭 (좌표 미세 변화)"""
        # 클릭 좌표를 ±10px 랜덤하게 변화
        x = self.coords['cart_button']['x'] + random.randint(-10, 10)
        y = self.coords['cart_button']['y'] + random.randint(-10, 10)

        log.info(f"장바구니 버튼 클릭 (x={x}, y={y})")
        success = self.controller.tap(x, y)
        time.sleep(1)
        return success

    def simulate_interest_actions(self) -> None:
        """관심 표시 액션 (확률적)"""
        if random.random() < self.case_s3['show_interest_probability']:
            log.info("관심 액션: 이미지 영역 탭 (확대 보기)")
            # 상품 이미지 영역 대략 위치
            image_x = self.screen['width'] // 2
            image_y = int(self.screen['height'] * 0.3)
            self.controller.tap(image_x, image_y)
            time.sleep(1)
            self.controller.press_back()  # 확대 이미지 닫기

    def dwell_time(self, min_sec: int, max_sec: int) -> None:
        """체류 시간 (정규분포 적용)"""
        # 평균과 표준편차 계산
        mean = (min_sec + max_sec) / 2
        std = (max_sec - min_sec) / 4

        # 정규분포에서 샘플링 (범위 제한)
        dwell = int(random.gauss(mean, std))
        dwell = max(min_sec, min(max_sec, dwell))

        log.info(f"체류 중: {dwell}초")
        time.sleep(dwell)

    def view_competitor_product(self, competitor_url: str, index: int) -> bool:
        """경쟁 상품 보기 (간단히 확인)"""
        log.info(f"=== 경쟁 상품 {index} 확인 ===")

        # 1. 경쟁 상품 페이지 열기
        if not self.open_url(competitor_url):
            log.error(f"경쟁 상품 {index} URL 열기 실패")
            return False

        # 2. 간단히 스크롤 (2-3회)
        scroll_count = random.randint(
            self.case_s3['competitor_scroll_count_min'],
            self.case_s3['competitor_scroll_count_max']
        )
        self.scroll_page(scroll_count)

        # 3. 짧은 체류 (25-35초)
        self.dwell_time(
            self.timing['competitor_dwell_min'],
            self.timing['competitor_dwell_max']
        )

        # 4. 뒤로가기
        self.go_back()

        log.info(f"경쟁 상품 {index} 확인 완료")
        return True

    def view_target_product(self, target_url: str) -> bool:
        """타겟 상품 상세 보기 (꼼꼼히 확인)"""
        log.info("=== 타겟 상품 상세 확인 ===")

        # 1. 타겟 상품 페이지 열기
        if not self.open_url(target_url):
            log.error("타겟 상품 URL 열기 실패")
            return False

        # 2. 깊게 스크롤 (4-6회)
        scroll_count = random.randint(
            self.case_s3['target_scroll_count_min'],
            self.case_s3['target_scroll_count_max']
        )
        self.scroll_page(scroll_count)

        # 3. 관심 액션 (확률적)
        self.simulate_interest_actions()

        # 4. 장바구니 담기 (확률적)
        if random.random() < self.case_s3['add_to_cart_probability']:
            self.click_cart_button()
            time.sleep(2)
            # 장바구니 팝업 닫기 (뒤로가기)
            self.go_back()

        # 5. 긴 체류 시간 (90-120초)
        self.dwell_time(
            self.timing['target_dwell_min'],
            self.timing['target_dwell_max']
        )

        log.info("타겟 상품 상세 확인 완료")
        return True

    def execute_case_s3_scenario(self) -> bool:
        """CASE_S3 시나리오 전체 실행"""
        log.info("\n" + "="*60)
        log.info("CASE_S3 시나리오 시작: 비교 쇼핑 후 최종 선택")
        log.info("="*60 + "\n")

        try:
            product = self.config['test_product']
            competitors = product.get('competitor_urls', [])

            if len(competitors) < 2:
                log.warning("경쟁사 URL이 2개 미만입니다. 설정 확인 필요")
                # 경쟁사 없이 타겟만 진행
                return self.view_target_product(product['product_url'])

            # 1단계: 경쟁 상품 A 확인
            if not self.view_competitor_product(competitors[0], 1):
                log.warning("경쟁 상품 1 확인 실패, 계속 진행")

            # 2단계: 경쟁 상품 B 확인
            if not self.view_competitor_product(competitors[1], 2):
                log.warning("경쟁 상품 2 확인 실패, 계속 진행")

            # 3단계: 타겟 상품 상세 확인
            if not self.view_target_product(product['product_url']):
                log.error("타겟 상품 확인 실패")
                return False

            log.info("\n" + "="*60)
            log.info("CASE_S3 시나리오 완료 ✅")
            log.info("="*60 + "\n")

            return True

        except Exception as e:
            log.error(f"CASE_S3 시나리오 실행 중 에러: {e}")
            import traceback
            log.error(traceback.format_exc())
            return False


def load_config(config_path: str = "prototype/prototype_config.json") -> Optional[Dict]:
    """설정 파일 로드"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        log.info("설정 파일 로드 완료")
        return config
    except Exception as e:
        log.error(f"설정 파일 로드 실패: {e}")
        return None


if __name__ == "__main__":
    """단독 테스트용"""
    log.info("프로토타입 브라우저 단독 테스트")

    # 설정 로드
    config = load_config()
    if not config:
        log.error("설정을 불러올 수 없습니다.")
        exit(1)

    # ADB 컨트롤러 초기화
    try:
        controller = ADBController()
        log.info("ADB 컨트롤러 초기화 완료")
    except Exception as e:
        log.error(f"ADB 컨트롤러 초기화 실패: {e}")
        exit(1)

    # 브라우저 초기화
    browser = PrototypeBrowser(controller, config)

    # 시나리오 실행
    log.info("CASE_S3 시나리오 테스트 시작...")
    success = browser.execute_case_s3_scenario()

    if success:
        log.info("✅ 시나리오 테스트 성공")
    else:
        log.error("❌ 시나리오 테스트 실패")
