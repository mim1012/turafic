"""
Appium 기반 트래픽 테스트 실행 스크립트

단일 또는 다중 에뮬레이터로 테스트 실행
"""
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict

sys.path.append(str(Path(__file__).parent))

from src.utils.logger import get_logger
from src.automation.appium_farm import EmulatorFarm
from src.automation.http_traffic import UserAgentPool
from src.ranking.checker import RankChecker

log = get_logger()


class AppiumTestRunner:
    """Appium 기반 테스트 실행기"""

    def __init__(self, num_instances: int = 5):
        self.num_instances = num_instances
        self.farm = EmulatorFarm(num_instances=num_instances)
        self.rank_checker = RankChecker()
        self.results = {
            "test_start": datetime.now().isoformat(),
            "num_instances": num_instances,
            "iterations": [],
            "summary": {}
        }

    def run_test(self, product: Dict, iterations: int = 10):
        """테스트 실행"""
        log.info("\n" + "="*100)
        log.info(f"Appium 기반 트래픽 테스트 시작")
        log.info(f"에뮬레이터: {self.num_instances}개")
        log.info(f"반복 횟수: {iterations}회")
        log.info(f"상품: {product['product_name']}")
        log.info("="*100 + "\n")

        # 1. 에뮬레이터 인스턴스 생성
        user_agents = UserAgentPool.MOBILE_USER_AGENTS
        self.farm.create_instances(user_agents)

        # 2. 에뮬레이터 팜 시작 (5개씩 단계적)
        self.farm.start_all(batch_size=5, batch_delay=30)

        # 3. Appium 연결
        self.farm.connect_all_appium()

        # 4. 초기 순위 체크
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

        # 5. 반복 트래픽 생성
        for i in range(1, iterations + 1):
            log.info(f"\n[{i}/{iterations}] 트래픽 생성")

            # Before 순위
            before_rank = self.rank_checker.check_product_rank(
                keyword=product["search_keyword"],
                product_id=product_id,
                max_page=10
            )

            before_rank_value = before_rank["absolute_rank"] if before_rank else None

            # 병렬 트래픽 생성 (모든 에뮬레이터)
            self.farm.execute_parallel_traffic(
                keyword=product["search_keyword"],
                product_url=product["product_url"],
                category=product.get("category", "전자기기")
            )

            # 순위 반영 대기 (30분 권장, 테스트용 30초)
            import time
            wait_time = 30  # 테스트용 30초 (실전: 1800초)
            log.info(f"순위 반영 대기: {wait_time}초")
            time.sleep(wait_time)

            # After 순위
            after_rank = self.rank_checker.check_product_rank(
                keyword=product["search_keyword"],
                product_id=product_id,
                max_page=10
            )

            after_rank_value = after_rank["absolute_rank"] if after_rank else None

            # 순위 변동 계산
            rank_change = None
            if before_rank_value and after_rank_value:
                rank_change = after_rank_value - before_rank_value

                if rank_change < 0:
                    log.success(f"✅ 순위 상승: {abs(rank_change)}위")
                elif rank_change > 0:
                    log.warning(f"⚠️ 순위 하락: {rank_change}위")
                else:
                    log.info("→ 순위 변동 없음")

            # 결과 기록
            iteration_result = {
                "iteration": i,
                "num_instances": self.num_instances,
                "before_rank": before_rank_value,
                "after_rank": after_rank_value,
                "rank_change": rank_change,
                "timestamp": datetime.now().isoformat()
            }

            self.results["iterations"].append(iteration_result)

            # 다음 반복 전 대기
            if i < iterations:
                from src.automation.realistic_traffic import TimingPattern
                interval = TimingPattern.get_next_interval()
                log.info(f"다음 반복까지 대기: {interval}초 ({interval/60:.1f}분)")
                time.sleep(interval)

        # 6. 에뮬레이터 팜 종료
        self.farm.stop_all()

        # 7. 최종 순위
        final_rank = self.rank_checker.check_product_rank(
            keyword=product["search_keyword"],
            product_id=product_id,
            max_page=10
        )

        if final_rank:
            log.info(f"\n최종 순위: {final_rank['absolute_rank']}위")

        # 8. 통계 계산 및 저장
        self._calculate_summary()
        self._save_results(product)

    def _extract_product_id(self, url: str) -> str:
        """URL에서 상품 ID 추출"""
        from urllib.parse import urlparse, parse_qs
        import re

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if 'mid' in query_params:
            return query_params['mid'][0]

        pattern = r"/(?:window-)?products/(\d+)"
        match = re.search(pattern, url)
        if match:
            return match.group(1)

        return ""

    def _calculate_summary(self):
        """통계 계산"""
        rank_changes = [
            it["rank_change"] for it in self.results["iterations"]
            if it["rank_change"] is not None
        ]

        if rank_changes:
            import numpy as np

            improvements = [r for r in rank_changes if r < 0]
            declines = [r for r in rank_changes if r > 0]

            self.results["summary"] = {
                "total_iterations": len(self.results["iterations"]),
                "rank_improvements": len(improvements),
                "rank_declines": len(declines),
                "rank_no_change": len([r for r in rank_changes if r == 0]),
                "improvement_rate": len(improvements) / len(rank_changes) if rank_changes else 0,
                "avg_rank_change": float(np.mean(rank_changes)),
                "std_rank_change": float(np.std(rank_changes)),
                "median_rank_change": float(np.median(rank_changes)),
                "max_rank_up": int(min(rank_changes)) if rank_changes else 0,
                "max_rank_down": int(max(rank_changes)) if rank_changes else 0,
            }

    def _save_results(self, product: Dict):
        """결과 저장"""
        self.results["test_end"] = datetime.now().isoformat()
        self.results["product"] = product

        output_dir = Path("data/appium_results")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"appium_test_{timestamp}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        log.success(f"\n✅ 결과 저장: {output_file}")

        # 요약 출력
        self._print_summary()

    def _print_summary(self):
        """결과 요약 출력"""
        log.info("\n" + "="*100)
        log.info("Appium 테스트 결과 요약")
        log.info("="*100)

        summary = self.results.get("summary", {})
        if summary:
            log.info(f"\n에뮬레이터: {self.num_instances}개")
            log.info(f"총 반복: {summary.get('total_iterations', 0)}회")
            log.info(f"평균 순위 변화: {summary.get('avg_rank_change', 0):.2f}위")
            log.info(f"표준편차: {summary.get('std_rank_change', 0):.2f}")
            log.info(f"개선율: {summary.get('improvement_rate', 0)*100:.1f}%")
            log.info(f"순위 상승: {summary.get('rank_improvements', 0)}회")
            log.info(f"순위 하락: {summary.get('rank_declines', 0)}회")
            log.info(f"최대 상승: {abs(summary.get('max_rank_up', 0))}위")

        log.info("\n" + "="*100 + "\n")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='Appium 기반 트래픽 테스트'
    )

    parser.add_argument(
        '--instances',
        type=int,
        default=5,
        help='에뮬레이터 인스턴스 수 (기본: 5, 최대: 27)'
    )

    parser.add_argument(
        '--iterations',
        type=int,
        default=10,
        help='반복 횟수 (기본: 10)'
    )

    parser.add_argument(
        '--product-id',
        type=int,
        default=1,
        help='테스트 상품 ID (config/test_matrix.json 기준, 기본: 1)'
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config/test_matrix.json',
        help='설정 파일 경로'
    )

    args = parser.parse_args()

    # 인스턴스 수 제한
    if args.instances > 27:
        log.warning(f"인스턴스 수를 27개로 제한 (요청: {args.instances})")
        args.instances = 27

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
        log.error(f"유효하지 않은 상품 ID: {args.product_id} (최대: {len(all_products)})")
        return

    product = all_products[args.product_id - 1]

    # 테스트 실행
    try:
        runner = AppiumTestRunner(num_instances=args.instances)
        runner.run_test(product, iterations=args.iterations)

    except KeyboardInterrupt:
        log.warning("\n사용자 중단 (Ctrl+C)")

    except Exception as e:
        log.error(f"테스트 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
