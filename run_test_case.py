"""
테스트 케이스 실행 스크립트

특정 테스트 케이스(TC)를 실행하고 결과를 저장합니다.
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import time

sys.path.append(str(Path(__file__).parent))

from src.utils.logger import get_logger
from src.automation.realistic_traffic import (
    RealisticTrafficGenerator,
    TimingPattern
)
from src.ranking.checker import RankChecker

log = get_logger()


# 테스트 케이스 정의
TEST_CASES = {
    "TC-001": {
        "name": "모바일 전용 테스트",
        "description": "100% 모바일 트래픽으로 기본 효과 측정",
        "variables": {
            "platform": "mobile",
            "platform_ratio": 1.0,
            "entry_path": "search",
            "behavior_pattern": "normal_browsing",
            "dwell_time_range": (60, 90),
            "traffic_volume": 10
        }
    },
    "TC-002": {
        "name": "PC 전용 테스트",
        "description": "100% PC 트래픽으로 기본 효과 측정",
        "variables": {
            "platform": "pc",
            "platform_ratio": 0.0,
            "entry_path": "search",
            "behavior_pattern": "normal_browsing",
            "dwell_time_range": (60, 90),
            "traffic_volume": 10
        }
    },
    "TC-003": {
        "name": "모바일/PC 혼합 (7:3)",
        "description": "모바일 70%, PC 30% 혼합 트래픽",
        "variables": {
            "platform": "mixed",
            "platform_ratio": 0.7,
            "entry_path": "search",
            "behavior_pattern": "normal_browsing",
            "dwell_time_range": (60, 90),
            "traffic_volume": 10
        }
    },
    "TC-004": {
        "name": "통합검색 경로",
        "description": "네이버 메인 → 검색 → 쇼핑탭 경로",
        "variables": {
            "platform": "mixed",
            "platform_ratio": 0.7,
            "entry_path": "search",
            "behavior_pattern": "normal_browsing",
            "dwell_time_range": (60, 90),
            "traffic_volume": 20
        }
    },
    "TC-005": {
        "name": "쇼핑 직접검색",
        "description": "shopping.naver.com 직접 검색",
        "variables": {
            "platform": "mixed",
            "platform_ratio": 0.7,
            "entry_path": "shopping_direct",
            "behavior_pattern": "normal_browsing",
            "dwell_time_range": (60, 90),
            "traffic_volume": 20
        }
    },
    "TC-008": {
        "name": "빠른 이탈 패턴",
        "description": "10-30초 짧은 체류 시간",
        "variables": {
            "platform": "mixed",
            "platform_ratio": 0.7,
            "entry_path": "search",
            "behavior_pattern": "quick_exit",
            "dwell_time_range": (10, 30),
            "traffic_volume": 30
        }
    },
    "TC-009": {
        "name": "일반 둘러보기 패턴",
        "description": "60-90초 일반 체류 + 리뷰 확인",
        "variables": {
            "platform": "mixed",
            "platform_ratio": 0.7,
            "entry_path": "search",
            "behavior_pattern": "normal_browsing",
            "dwell_time_range": (60, 90),
            "traffic_volume": 30
        }
    },
    "TC-010": {
        "name": "심층 탐색 패턴",
        "description": "120-180초 긴 체류 + 상세 확인",
        "variables": {
            "platform": "mixed",
            "platform_ratio": 0.7,
            "entry_path": "search",
            "behavior_pattern": "deep_exploration",
            "dwell_time_range": (120, 180),
            "traffic_volume": 30
        }
    },
}


class TestCaseRunner:
    """테스트 케이스 실행기"""

    def __init__(self, test_case_id: str, products: List[Dict]):
        self.test_case_id = test_case_id
        self.test_case = TEST_CASES.get(test_case_id)

        if not self.test_case:
            raise ValueError(f"유효하지 않은 테스트 케이스: {test_case_id}")

        self.products = products
        self.generator = RealisticTrafficGenerator()
        self.rank_checker = RankChecker()

        self.results = {
            "test_case_id": test_case_id,
            "test_case_name": self.test_case["name"],
            "description": self.test_case["description"],
            "variables": self.test_case["variables"],
            "test_date": datetime.now().isoformat(),
            "products": [],
            "summary": {}
        }

    def run(self):
        """테스트 케이스 실행"""
        log.info("\n" + "="*100)
        log.info(f"테스트 케이스 실행: {self.test_case_id}")
        log.info(f"이름: {self.test_case['name']}")
        log.info(f"설명: {self.test_case['description']}")
        log.info("="*100 + "\n")

        variables = self.test_case["variables"]
        traffic_volume = variables["traffic_volume"]

        for product in self.products:
            log.info(f"\n상품 테스트 시작: {product['product_name']}")

            product_result = self.run_product_test(
                product=product,
                traffic_volume=traffic_volume,
                variables=variables
            )

            self.results["products"].append(product_result)

        # 전체 요약 통계
        self.calculate_summary()
        self.save_results()

    def run_product_test(
        self,
        product: Dict,
        traffic_volume: int,
        variables: Dict
    ) -> Dict:
        """개별 상품 테스트"""

        product_result = {
            "product_id": product.get("id"),
            "product_name": product["product_name"],
            "product_url": product["product_url"],
            "category": product.get("category", "전자기기"),
            "keyword": product["search_keyword"],
            "initial_rank": None,
            "final_rank": None,
            "iterations": [],
            "statistics": {}
        }

        # 초기 순위 체크
        log.info("[초기 순위 체크]")
        product_id = self._extract_product_id(product["product_url"])

        initial_rank_info = self.rank_checker.check_product_rank(
            keyword=product["search_keyword"],
            product_id=product_id,
            max_page=10
        )

        if initial_rank_info:
            product_result["initial_rank"] = initial_rank_info["absolute_rank"]
            log.info(f"초기 순위: {initial_rank_info['absolute_rank']}위")
        else:
            log.warning("초기 순위권 밖 (100위 이하)")
            product_result["initial_rank"] = None

        # 트래픽 생성 반복
        rank_changes = []

        for i in range(1, traffic_volume + 1):
            log.info(f"\n[{i}/{traffic_volume}] 트래픽 생성")

            # Before 순위
            before_rank = self.rank_checker.check_product_rank(
                keyword=product["search_keyword"],
                product_id=product_id,
                max_page=10
            )

            before_rank_value = before_rank["absolute_rank"] if before_rank else None

            # 트래픽 생성
            use_mobile = (
                variables["platform"] == "mobile" or
                (variables["platform"] == "mixed" and
                 __import__("random").random() < variables["platform_ratio"])
            )

            dwell_min, dwell_max = variables["dwell_time_range"]
            import random
            dwell_time = random.randint(dwell_min, dwell_max)

            traffic_result = self.generator.execute_full_scenario(
                keyword=product["search_keyword"],
                product_url=product["product_url"],
                category=product_result["category"],
                use_mobile=use_mobile
            )

            # 대기 (순위 반영 시간)
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
                rank_changes.append(rank_change)

                if rank_change < 0:
                    log.success(f"✅ 순위 상승: {abs(rank_change)}위")
                elif rank_change > 0:
                    log.warning(f"⚠️ 순위 하락: {rank_change}위")
                else:
                    log.info("→ 순위 변동 없음")

            # 기록
            iteration_result = {
                "iteration": i,
                "platform": "mobile" if use_mobile else "pc",
                "before_rank": before_rank_value,
                "after_rank": after_rank_value,
                "rank_change": rank_change,
                "dwell_time": dwell_time,
                "success": traffic_result.get("success", False)
            }

            product_result["iterations"].append(iteration_result)

            # 다음 반복 전 대기
            if i < traffic_volume:
                interval = TimingPattern.get_next_interval()
                log.info(f"다음 반복까지 대기: {interval}초 ({interval/60:.1f}분)")
                time.sleep(interval)

        # 최종 순위
        final_rank_info = self.rank_checker.check_product_rank(
            keyword=product["search_keyword"],
            product_id=product_id,
            max_page=10
        )

        if final_rank_info:
            product_result["final_rank"] = final_rank_info["absolute_rank"]
            log.info(f"\n최종 순위: {final_rank_info['absolute_rank']}위")
        else:
            product_result["final_rank"] = None

        # 통계 계산
        if rank_changes:
            import numpy as np

            improvements = [r for r in rank_changes if r < 0]
            declines = [r for r in rank_changes if r > 0]

            product_result["statistics"] = {
                "total_iterations": traffic_volume,
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

        return product_result

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

    def calculate_summary(self):
        """전체 요약 통계"""
        all_rank_changes = []
        total_improvements = 0
        total_declines = 0

        for product_result in self.results["products"]:
            stats = product_result.get("statistics", {})
            if "avg_rank_change" in stats:
                all_rank_changes.append(stats["avg_rank_change"])
                total_improvements += stats.get("rank_improvements", 0)
                total_declines += stats.get("rank_declines", 0)

        if all_rank_changes:
            import numpy as np

            self.results["summary"] = {
                "total_products": len(self.products),
                "avg_rank_change_across_products": float(np.mean(all_rank_changes)),
                "total_improvements": total_improvements,
                "total_declines": total_declines,
                "overall_improvement_rate": total_improvements / (total_improvements + total_declines) if (total_improvements + total_declines) > 0 else 0
            }

    def save_results(self):
        """결과 저장"""
        output_dir = Path("data/test_results")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"{self.test_case_id}_{timestamp}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        log.info(f"\n✅ 결과 저장: {output_file}")

        # 요약 출력
        self.print_summary()

    def print_summary(self):
        """결과 요약 출력"""
        log.info("\n" + "="*100)
        log.info("테스트 케이스 결과 요약")
        log.info("="*100)

        log.info(f"\nTC ID: {self.test_case_id}")
        log.info(f"이름: {self.test_case['name']}")
        log.info(f"테스트 상품 수: {len(self.products)}")

        summary = self.results.get("summary", {})
        if summary:
            log.info(f"\n전체 평균 순위 변화: {summary.get('avg_rank_change_across_products', 0):.2f}위")
            log.info(f"전체 개선율: {summary.get('overall_improvement_rate', 0)*100:.1f}%")
            log.info(f"총 순위 상승: {summary.get('total_improvements', 0)}회")
            log.info(f"총 순위 하락: {summary.get('total_declines', 0)}회")

        log.info("\n상품별 결과:")
        for product_result in self.results["products"]:
            log.info(f"\n  - {product_result['product_name']}")
            log.info(f"    초기: {product_result.get('initial_rank', 'N/A')}위")
            log.info(f"    최종: {product_result.get('final_rank', 'N/A')}위")

            stats = product_result.get("statistics", {})
            if stats:
                log.info(f"    평균 변화: {stats.get('avg_rank_change', 0):.2f}위")
                log.info(f"    개선율: {stats.get('improvement_rate', 0)*100:.1f}%")

        log.info("\n" + "="*100 + "\n")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='테스트 케이스 실행'
    )

    parser.add_argument(
        '--tc',
        type=str,
        required=True,
        help='테스트 케이스 ID (예: TC-001)'
    )

    parser.add_argument(
        '--products',
        type=int,
        default=1,
        help='테스트할 상품 개수 (기본: 1)'
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config/test_matrix.json',
        help='설정 파일 경로'
    )

    args = parser.parse_args()

    # 설정 로드
    config_file = Path(args.config)
    if not config_file.exists():
        log.error(f"설정 파일 없음: {args.config}")
        return

    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)

    # 상품 선택
    all_products = config.get('test_products', [])
    if not all_products:
        log.error("테스트 상품이 없습니다.")
        return

    selected_products = all_products[:args.products]

    # 테스트 케이스 실행
    try:
        runner = TestCaseRunner(
            test_case_id=args.tc,
            products=selected_products
        )
        runner.run()

    except KeyboardInterrupt:
        log.warning("\n사용자 중단 (Ctrl+C)")

    except Exception as e:
        log.error(f"테스트 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
