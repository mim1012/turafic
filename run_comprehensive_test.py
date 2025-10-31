"""
종합 테스트 실행 스크립트

카테고리별, 유입경로별, 쿠키 조작별 다양한 시나리오 자동 실행
"""

import json
import random
import time
from pathlib import Path
from typing import Dict, List
import argparse

from src.automation.advanced_scenarios import AdvancedTrafficGenerator
from src.automation.mobile import ADBController
from src.ranking.checker import check_rank
from src.ranking.tracker import RankTracker
from src.utils.logger import get_logger

log = get_logger()


class ComprehensiveTestRunner:
    """종합 테스트 실행기"""

    def __init__(self, config_path: str = "config/test_matrix.json"):
        self.config = self._load_config(config_path)
        self.http_generator = AdvancedTrafficGenerator()
        self.adb_controller = None  # 필요 시 초기화

        # 결과 저장
        self.results = {
            'products': {},
            'scenarios': {},
            'comparison': {
                'http_method': [],
                'adb_method': []
            }
        }

    def _load_config(self, config_path: str) -> Dict:
        """설정 파일 로드"""
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def select_scenario(self) -> str:
        """가중치 기반 시나리오 선택"""
        scenarios = self.config['test_scenarios']

        # 가중치 추출
        scenario_ids = list(scenarios.keys())
        weights = [scenarios[sid]['weight'] for sid in scenario_ids]

        # 가중치 기반 랜덤 선택
        selected = random.choices(scenario_ids, weights=weights, k=1)[0]

        return selected

    def execute_http_scenario(
        self,
        product: Dict,
        scenario_config: Dict
    ) -> Dict:
        """HTTP 기반 시나리오 실행"""
        log.info(f"\n{'='*70}")
        log.info(f"HTTP 시나리오 실행: {scenario_config['name']}")
        log.info(f"{'='*70}")

        try:
            result = self.http_generator.execute_category_scenario(
                product_url=product['product_url'],
                category=product['category'],
                entry_path_type=scenario_config['entry_path'],
                search_keyword=product.get('search_keyword'),
                use_login_cookies=scenario_config.get('use_login_cookies', False)
            )

            return result

        except Exception as e:
            log.error(f"HTTP 시나리오 실행 실패: {e}")
            return {'success': False, 'error': str(e)}

    def execute_adb_scenario(
        self,
        product: Dict,
        scenario_config: Dict
    ) -> Dict:
        """ADB 기반 시나리오 실행"""
        log.info(f"\n{'='*70}")
        log.info(f"ADB 시나리오 실행: {scenario_config['name']}")
        log.info(f"{'='*70}")

        # ADB 컨트롤러 초기화 (필요 시)
        if self.adb_controller is None:
            try:
                self.adb_controller = ADBController()
            except Exception as e:
                log.error(f"ADB 초기화 실패: {e}")
                return {'success': False, 'error': 'ADB not available'}

        # CASE_S3 시나리오 (프로토타입에서 구현됨)
        log.info("ADB 방식은 prototype_browser.py 사용")
        log.info("(여기서는 스킵, 실제로는 prototype 모듈 import)")

        return {
            'success': True,
            'method': 'adb',
            'note': 'Use prototype_browser.py for ADB execution'
        }

    def run_single_iteration(
        self,
        product: Dict,
        iteration: int
    ) -> Dict:
        """단일 iteration 실행"""
        log.info(f"\n\n{'#'*70}")
        log.info(f"#  Iteration {iteration}")
        log.info(f"#  상품: {product['product_name']}")
        log.info(f"{'#'*70}\n")

        # 1. Before 순위 체크
        log.info("📊 Before 순위 체크")
        rank_before = check_rank(
            keyword=product['search_keyword'],
            product_id=product['id'],
            max_page=5
        )

        if rank_before:
            log.info(f"현재 순위: {rank_before['absolute_rank']}위")
        else:
            log.warning("순위권 밖")

        # 2. 시나리오 선택
        scenario_id = self.select_scenario()
        scenario_config = self.config['test_scenarios'][scenario_id]

        log.info(f"\n선택된 시나리오: {scenario_config['name']}")
        log.info(f"설명: {scenario_config['description']}")

        # 3. 시나리오 실행
        if scenario_config['method'] == 'http':
            result = self.execute_http_scenario(product, scenario_config)
        else:  # adb
            result = self.execute_adb_scenario(product, scenario_config)

        if not result.get('success'):
            log.error(f"시나리오 실행 실패")
            return {
                'iteration': iteration,
                'success': False,
                'scenario': scenario_id,
                'error': result.get('error')
            }

        # 4. IP 변경 (HTTP 방식은 세션 새로 생성으로 대체)
        if scenario_config['method'] == 'http':
            log.info("💡 HTTP 방식: 다음 iteration에서 새 세션 사용")
        else:
            log.info("📱 ADB 방식: 비행기모드 토글")
            # self.adb_controller.toggle_airplane_mode()

        # 5. 대기
        wait_time = self.config['test_execution']['wait_after_traffic']
        log.info(f"⏱️ 순위 반영 대기: {wait_time}초")
        time.sleep(wait_time)

        # 6. After 순위 체크
        log.info("📊 After 순위 체크")
        rank_after = check_rank(
            keyword=product['search_keyword'],
            product_id=product['id'],
            max_page=5
        )

        if rank_after:
            log.info(f"변경 순위: {rank_after['absolute_rank']}위")
        else:
            log.warning("순위권 밖")

        # 7. 결과 저장
        iteration_result = {
            'iteration': iteration,
            'success': True,
            'scenario': scenario_id,
            'scenario_name': scenario_config['name'],
            'method': scenario_config['method'],
            'rank_before': rank_before['absolute_rank'] if rank_before else None,
            'rank_after': rank_after['absolute_rank'] if rank_after else None,
            'rank_change': None,
        }

        if rank_before and rank_after:
            change = rank_after['absolute_rank'] - rank_before['absolute_rank']
            iteration_result['rank_change'] = change

            if change < 0:
                log.info(f"✅ 순위 상승: {abs(change)}위 ↑")
            elif change > 0:
                log.warning(f"⚠️ 순위 하락: {change}위 ↓")
            else:
                log.info("➡️ 순위 유지")

        return iteration_result

    def run_product_test(
        self,
        product: Dict,
        iterations: int
    ):
        """특정 상품에 대한 전체 테스트"""
        log.info(f"\n{'#'*70}")
        log.info(f"#")
        log.info(f"#  상품 테스트 시작: {product['product_name']}")
        log.info(f"#  카테고리: {product['category']}")
        log.info(f"#  반복 횟수: {iterations}회")
        log.info(f"#")
        log.info(f"{'#'*70}\n")

        product_id = product['id']
        self.results['products'][product_id] = {
            'product_info': product,
            'iterations': []
        }

        for i in range(1, iterations + 1):
            try:
                result = self.run_single_iteration(product, i)
                self.results['products'][product_id]['iterations'].append(result)

                # 시나리오별 통계
                scenario_id = result.get('scenario')
                if scenario_id:
                    if scenario_id not in self.results['scenarios']:
                        self.results['scenarios'][scenario_id] = {
                            'total': 0,
                            'success': 0,
                            'rank_improvements': 0,
                            'total_change': 0
                        }

                    stats = self.results['scenarios'][scenario_id]
                    stats['total'] += 1

                    if result.get('success'):
                        stats['success'] += 1

                    if result.get('rank_change') and result['rank_change'] < 0:
                        stats['rank_improvements'] += 1
                        stats['total_change'] += result['rank_change']

                # Iteration 간 대기
                if i < iterations:
                    wait = self.config['test_execution']['wait_between_iterations']
                    log.info(f"\n다음 iteration까지 {wait}초 대기...\n")
                    time.sleep(wait)

            except KeyboardInterrupt:
                log.warning(f"\n사용자 중단 (iteration {i})")
                break
            except Exception as e:
                log.error(f"Iteration {i} 실행 중 에러: {e}")
                import traceback
                log.error(traceback.format_exc())

        # 상품별 통계 출력
        self._print_product_statistics(product_id)

    def _print_product_statistics(self, product_id: str):
        """상품별 통계 출력"""
        data = self.results['products'][product_id]
        iterations = data['iterations']

        log.info(f"\n\n{'='*70}")
        log.info(f"상품 테스트 완료: {data['product_info']['product_name']}")
        log.info(f"{'='*70}")

        total = len(iterations)
        success = sum(1 for it in iterations if it.get('success'))

        log.info(f"\n=== 실행 통계 ===")
        log.info(f"총 실행: {total}회")
        log.info(f"성공: {success}회")

        # 순위 변동 분석
        rank_changes = [it['rank_change'] for it in iterations if it.get('rank_change') is not None]

        if rank_changes:
            improvements = sum(1 for c in rank_changes if c < 0)
            avg_change = sum(rank_changes) / len(rank_changes)

            log.info(f"\n=== 순위 변동 ===")
            log.info(f"순위 개선: {improvements}/{len(rank_changes)}회 ({improvements/len(rank_changes)*100:.1f}%)")
            log.info(f"평균 변동: {avg_change:.2f}")

            if avg_change < 0:
                log.info(f"✅ 평균 {abs(avg_change):.1f}위 상승")
            elif avg_change > 0:
                log.info(f"⚠️ 평균 {avg_change:.1f}위 하락")

    def run_all_products(self):
        """모든 상품 테스트"""
        products = self.config['test_products']
        iterations = self.config['test_execution']['iterations_per_product']

        for i, product in enumerate(products, 1):
            log.info(f"\n\n{'#'*70}")
            log.info(f"# 상품 {i}/{len(products)}")
            log.info(f"{'#'*70}")

            self.run_product_test(product, iterations)

            # 상품 간 휴식
            if i < len(products):
                log.info("\n다음 상품까지 5분 휴식...")
                time.sleep(300)

        # 최종 통계
        self._print_final_statistics()

    def _print_final_statistics(self):
        """최종 종합 통계"""
        log.info(f"\n\n{'#'*70}")
        log.info("#")
        log.info("#  전체 테스트 완료")
        log.info("#")
        log.info(f"{'#'*70}\n")

        log.info("=== 시나리오별 효과 ===\n")

        scenario_stats = []
        for scenario_id, stats in self.results['scenarios'].items():
            scenario_name = self.config['test_scenarios'][scenario_id]['name']

            if stats['total'] > 0:
                success_rate = stats['success'] / stats['total']
                improvement_rate = stats['rank_improvements'] / stats['total']
                avg_change = stats['total_change'] / stats['rank_improvements'] if stats['rank_improvements'] > 0 else 0

                scenario_stats.append({
                    'id': scenario_id,
                    'name': scenario_name,
                    'total': stats['total'],
                    'improvement_rate': improvement_rate,
                    'avg_change': avg_change
                })

        # 효과 순으로 정렬
        scenario_stats.sort(key=lambda x: x['improvement_rate'], reverse=True)

        for rank, stat in enumerate(scenario_stats, 1):
            log.info(f"{rank}. {stat['name']}")
            log.info(f"   실행: {stat['total']}회")
            log.info(f"   개선율: {stat['improvement_rate']*100:.1f}%")
            log.info(f"   평균 상승: {abs(stat['avg_change']):.1f}위")
            log.info("")

        # 결과 JSON 저장
        result_file = Path("data/results/comprehensive_test_results.json")
        result_file.parent.mkdir(parents=True, exist_ok=True)

        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        log.info(f"📊 상세 결과 저장: {result_file}")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='종합 트래픽 테스트 실행')
    parser.add_argument('--config', default='config/test_matrix.json', help='설정 파일 경로')
    parser.add_argument('--product', type=int, help='특정 상품만 테스트 (인덱스)')
    parser.add_argument('--iterations', type=int, help='반복 횟수 오버라이드')

    args = parser.parse_args()

    log.info("\n" + "="*70)
    log.info("종합 트래픽 테스트 시작")
    log.info("="*70 + "\n")

    runner = ComprehensiveTestRunner(args.config)

    if args.product is not None:
        # 특정 상품만 테스트
        products = runner.config['test_products']
        if 0 <= args.product < len(products):
            product = products[args.product]
            iterations = args.iterations or runner.config['test_execution']['iterations_per_product']
            runner.run_product_test(product, iterations)
        else:
            log.error(f"잘못된 상품 인덱스: {args.product}")
    else:
        # 모든 상품 테스트
        runner.run_all_products()


if __name__ == "__main__":
    main()
