"""
상호작용 효과 측정 테스트 실행 스크립트

브라우저 지문 × 사용자 행동 패턴 × 카테고리의 상호작용 효과 측정
"""
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List

sys.path.append(str(Path(__file__).parent))

from src.utils.logger import get_logger
from src.automation.browser_fingerprint import FingerprintProfiles, FingerprintInjector
from src.automation.http_traffic import HTTPTrafficGenerator
from src.automation.realistic_traffic import BehaviorPattern
from src.ranking.checker import RankChecker

log = get_logger()


class InteractionTestRunner:
    """상호작용 효과 측정 테스트 실행기"""

    # 단순화된 테스트 매트릭스 (카테고리 제거)
    # 브라우저 지문 × 행동 패턴 = 12개 조합
    TEST_MATRIX = [
        # Profile A (일반 사용자)
        {"tc": "IT-001", "profile": "A", "behavior": "빠른이탈"},
        {"tc": "IT-002", "profile": "A", "behavior": "일반둘러보기"},
        {"tc": "IT-003", "profile": "A", "behavior": "심층탐색"},
        {"tc": "IT-004", "profile": "A", "behavior": "비교쇼핑"},

        # Profile B (고사양 사용자)
        {"tc": "IT-005", "profile": "B", "behavior": "빠른이탈"},
        {"tc": "IT-006", "profile": "B", "behavior": "일반둘러보기"},
        {"tc": "IT-007", "profile": "B", "behavior": "심층탐색"},
        {"tc": "IT-008", "profile": "B", "behavior": "비교쇼핑"},

        # Profile C (모바일 사용자)
        {"tc": "IT-009", "profile": "C", "behavior": "빠른이탈"},
        {"tc": "IT-010", "profile": "C", "behavior": "일반둘러보기"},
        {"tc": "IT-011", "profile": "C", "behavior": "심층탐색"},
        {"tc": "IT-012", "profile": "C", "behavior": "비교쇼핑"},
    ]

    def __init__(self, iterations_per_case: int = 100):
        self.iterations_per_case = iterations_per_case
        self.rank_checker = RankChecker()
        self.results = {
            "test_start": datetime.now().isoformat(),
            "test_type": "interaction_effects",
            "iterations_per_case": iterations_per_case,
            "test_cases": []
        }

    def run_test_case(self, test_case: Dict, product: Dict) -> Dict:
        """단일 테스트 케이스 실행"""
        tc_id = test_case["tc"]
        profile_name = test_case["profile"]
        behavior_name = test_case["behavior"]

        log.info(f"\n{'='*80}")
        log.info(f"테스트 케이스: {tc_id}")
        log.info(f"  브라우저 지문: Profile {profile_name}")
        log.info(f"  행동 패턴: {behavior_name}")
        log.info(f"  반복 횟수: {self.iterations_per_case}회")
        log.info(f"{'='*80}\n")

        # 브라우저 지문 프로필 가져오기
        fingerprint = FingerprintProfiles.get_profile(profile_name)

        # HTTP 헤더 생성
        headers = FingerprintInjector.generate_http_headers(fingerprint)

        # 행동 패턴 매핑
        behavior_map = {
            "빠른이탈": "quick_bounce",
            "일반둘러보기": "normal_browsing",
            "심층탐색": "deep_exploration",
            "비교쇼핑": "comparison_shopping"
        }
        behavior_type = behavior_map.get(behavior_name, "normal_browsing")

        # HTTP 트래픽 생성기 초기화
        traffic_gen = HTTPTrafficGenerator()

        # ADB 컨트롤러 초기화 (비행기모드 IP 변경용)
        from src.automation.mobile import ADBController
        adb = ADBController()

        # 초기 순위 체크
        product_id = self._extract_product_id(product["product_url"])
        initial_rank = self.rank_checker.check_product_rank(
            keyword=product["search_keyword"],
            product_id=product_id,
            max_page=10
        )

        if initial_rank:
            log.info(f"초기 순위: {initial_rank['absolute_rank']}위")
        else:
            log.warning("초기 순위권 밖 (100위 이하)")

        # 반복 트래픽 생성
        rank_changes = []

        for i in range(1, self.iterations_per_case + 1):
            if i % 10 == 0:
                log.info(f"[{i}/{self.iterations_per_case}] 진행 중...")

            # Before 순위
            before_rank = self.rank_checker.check_product_rank(
                keyword=product["search_keyword"],
                product_id=product_id,
                max_page=10
            )
            before_rank_value = before_rank["absolute_rank"] if before_rank else None

            # 트래픽 생성 (지문 + 행동 패턴 적용, 카테고리 제거)
            success = traffic_gen.generate_traffic(
                product=product,
                custom_headers=headers,
                behavior_type=behavior_type
            )

            if not success:
                log.warning(f"[{i}] 트래픽 생성 실패")
                continue

            # IP 변경: 비행기모드 토글 (실제 물리적 IP 변경)
            log.info(f"[{i}] IP 변경 중 (비행기모드 토글)...")
            if adb.toggle_airplane_mode(duration=3):
                # 네트워크 재연결 대기
                if adb.wait_for_network(timeout=30):
                    new_ip = adb.get_ip_address()
                    log.success(f"[{i}] IP 변경 완료: {new_ip}")
                else:
                    log.warning(f"[{i}] 네트워크 재연결 타임아웃")
            else:
                log.warning(f"[{i}] 비행기모드 토글 실패")

            # After 순위 (IP 변경 후 체크)
            import time
            time.sleep(random.uniform(2, 5))  # 안정화 대기

            after_rank = self.rank_checker.check_product_rank(
                keyword=product["search_keyword"],
                product_id=product_id,
                max_page=10
            )
            after_rank_value = after_rank["absolute_rank"] if after_rank else None

            # 순위 변동 기록
            if before_rank_value and after_rank_value:
                rank_change = after_rank_value - before_rank_value
                rank_changes.append(rank_change)

            # 다음 반복 간격 (짧게: 3-7초)
            time.sleep(random.uniform(3, 7))

        # 통계 계산
        import numpy as np

        if rank_changes:
            mean_change = float(np.mean(rank_changes))
            std_change = float(np.std(rank_changes))
            median_change = float(np.median(rank_changes))
            min_change = int(min(rank_changes))
            max_change = int(max(rank_changes))
            improvement_rate = sum(1 for r in rank_changes if r < 0) / len(rank_changes)
        else:
            mean_change = 0
            std_change = 0
            median_change = 0
            min_change = 0
            max_change = 0
            improvement_rate = 0

        # 결과 요약
        log.info(f"\n{tc_id} 결과:")
        log.info(f"  평균 순위 변화: {mean_change:.2f}위")
        log.info(f"  표준편차: {std_change:.2f}")
        log.info(f"  개선율: {improvement_rate*100:.1f}%")
        log.info(f"  최대 상승: {abs(min_change)}위")

        return {
            "test_case_id": tc_id,
            "profile": profile_name,
            "behavior": behavior_name,
            "iterations": self.iterations_per_case,
            "statistics": {
                "mean_rank_change": mean_change,
                "std_rank_change": std_change,
                "median_rank_change": median_change,
                "min_rank_change": min_change,
                "max_rank_change": max_change,
                "improvement_rate": improvement_rate,
            },
            "raw_data": rank_changes,
            "timestamp": datetime.now().isoformat()
        }

    def run_all_tests(self, product: Dict, pilot_mode: bool = False):
        """모든 테스트 케이스 실행"""
        log.info("\n" + "="*100)
        log.info("상호작용 효과 측정 테스트 시작")
        log.info("="*100)

        # 파일럿 모드: 4개만 실행
        if pilot_mode:
            log.warning("⚠️ 파일럿 모드: 4개 테스트 케이스만 실행")
            test_cases = [
                self.TEST_MATRIX[0],   # IT-001
                self.TEST_MATRIX[5],   # IT-006
                self.TEST_MATRIX[9],   # IT-010
                self.TEST_MATRIX[11],  # IT-012
            ]
        else:
            test_cases = self.TEST_MATRIX

        # 각 테스트 케이스 실행
        for i, test_case in enumerate(test_cases, 1):
            log.info(f"\n진행 상황: {i}/{len(test_cases)}")

            result = self.run_test_case(test_case, product)
            self.results["test_cases"].append(result)

            # 중간 저장 (10개마다)
            if i % 10 == 0:
                self._save_intermediate_results()

        # 최종 저장
        self._save_results()

        # 요약 출력
        self._print_summary()

    def _extract_product_id(self, url: str) -> str:
        """URL에서 상품 ID 추출"""
        from urllib.parse import urlparse, parse_qs
        import re

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if 'mid' in query_params:
            return query_params['mid'][0]

        pattern = r"/(?:window-)?products/(\\d+)"
        match = re.search(pattern, url)
        if match:
            return match.group(1)

        return ""

    def _save_intermediate_results(self):
        """중간 결과 저장"""
        output_dir = Path("data/interaction_results")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"interaction_test_intermediate_{timestamp}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        log.debug(f"중간 결과 저장: {output_file}")

    def _save_results(self):
        """최종 결과 저장"""
        self.results["test_end"] = datetime.now().isoformat()

        output_dir = Path("data/interaction_results")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"interaction_test_{timestamp}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        log.success(f"\n✅ 결과 저장: {output_file}")

    def _print_summary(self):
        """결과 요약 출력"""
        log.info("\n" + "="*100)
        log.info("상호작용 테스트 결과 요약")
        log.info("="*100)

        # Profile별 평균
        profiles = {}
        for tc in self.results["test_cases"]:
            profile = tc["profile"]
            if profile not in profiles:
                profiles[profile] = []
            profiles[profile].append(tc["statistics"]["mean_rank_change"])

        log.info("\n📊 브라우저 지문 프로필별 평균:")
        for profile, changes in sorted(profiles.items()):
            import numpy as np
            mean = np.mean(changes)
            log.info(f"  Profile {profile}: {mean:.2f}위 (n={len(changes)})")

        # Behavior별 평균
        behaviors = {}
        for tc in self.results["test_cases"]:
            behavior = tc["behavior"]
            if behavior not in behaviors:
                behaviors[behavior] = []
            behaviors[behavior].append(tc["statistics"]["mean_rank_change"])

        log.info("\n📊 행동 패턴별 평균:")
        for behavior, changes in behaviors.items():
            mean = np.mean(changes)
            log.info(f"  {behavior}: {mean:.2f}위 (n={len(changes)})")

        log.info("\n" + "="*100 + "\n")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='상호작용 효과 측정 테스트'
    )

    parser.add_argument(
        '--iterations',
        type=int,
        default=100,
        help='케이스당 반복 횟수 (기본: 100)'
    )

    parser.add_argument(
        '--pilot',
        action='store_true',
        help='파일럿 모드 (4개 케이스만 실행)'
    )

    parser.add_argument(
        '--product-id',
        type=int,
        default=1,
        help='테스트 상품 ID (기본: 1)'
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config/test_matrix.json',
        help='설정 파일 경로'
    )

    args = parser.parse_args()

    # 설정 파일 로드
    config_file = Path(args.config)
    if not config_file.exists():
        log.error(f"설정 파일 없음: {args.config}")
        return

    with open(config_file, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

    # 상품 선택
    all_products = config_data.get('test_products', [])
    if not all_products:
        log.error("테스트 상품이 없습니다.")
        return

    if args.product_id > len(all_products):
        log.error(f"유효하지 않은 상품 ID: {args.product_id}")
        return

    product = all_products[args.product_id - 1]

    # 테스트 실행
    try:
        runner = InteractionTestRunner(iterations_per_case=args.iterations)
        runner.run_all_tests(product, pilot_mode=args.pilot)

    except KeyboardInterrupt:
        log.warning("\n사용자 중단 (Ctrl+C)")

    except Exception as e:
        log.error(f"테스트 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    import random
    main()
