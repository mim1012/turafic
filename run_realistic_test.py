"""
실제 패킷 패턴 기반 트래픽 테스트

실제 데이터 분석 결과를 반영한 현실적인 트래픽 생성 테스트
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
    TimingPattern,
    IPPatternGenerator,
    UserAgentPool
)
from src.ranking.checker import RankChecker

log = get_logger()


class RealisticTestRunner:
    """
    실제 패킷 패턴 기반 테스트 러너

    특징:
    - 실제 트래픽 데이터 (267개 레코드) 패턴 적용
    - Samsung Browser User-Agent 사용
    - IP 로테이션 (175.223.x.x 중심)
    - 타이밍: 평균 2.5분 간격
    - 모바일/PC 검색 경로 구분
    - 예외(빵꾸) 처리
    """

    def __init__(self, config_path: str = "config/test_matrix.json"):
        self.config = self._load_config(config_path)
        self.generator = RealisticTrafficGenerator()
        self.rank_checker = RankChecker()

        self.results = {
            'test_start': datetime.now().isoformat(),
            'iterations': [],
            'rank_changes': [],
            'success_count': 0,
            'failure_count': 0,
            'total_time': 0
        }

    def _load_config(self, config_path: str) -> Dict:
        """설정 파일 로드"""
        config_file = Path(config_path)

        if not config_file.exists():
            log.error(f"설정 파일 없음: {config_path}")
            return {'test_products': []}

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                log.info(f"설정 로드: {len(config.get('test_products', []))}개 상품")
                return config
        except Exception as e:
            log.error(f"설정 로드 실패: {e}")
            return {'test_products': []}

    def run_single_iteration(
        self,
        product: Dict,
        iteration: int,
        use_mobile: bool = True
    ) -> Dict:
        """
        단일 반복 실행

        Args:
            product: 테스트 상품 정보
            iteration: 반복 번호
            use_mobile: True=모바일, False=PC

        Returns:
            결과 딕셔너리
        """
        log.info("\n" + "="*80)
        log.info(f"반복 {iteration} 시작")
        log.info(f"  상품: {product['product_name']}")
        log.info(f"  키워드: {product['search_keyword']}")
        log.info(f"  플랫폼: {'모바일 (m.naver.com)' if use_mobile else 'PC (naver.com)'}")
        log.info("="*80 + "\n")

        iteration_start = time.time()

        # 1. Before 순위 체크
        log.info("[Step 1] Before 순위 체크")
        product_id = self._extract_product_id(product['product_url'])

        before_rank = self.rank_checker.check_product_rank(
            keyword=product['search_keyword'],
            product_id=product_id,
            max_page=10
        )

        if before_rank:
            log.info(f"  현재 순위: {before_rank['absolute_rank']}위")
        else:
            log.warning("  순위권 밖 (100위 이하)")

        # 2. 트래픽 생성
        log.info("\n[Step 2] 트래픽 생성")

        result = self.generator.execute_full_scenario(
            keyword=product['search_keyword'],
            product_url=product['product_url'],
            category=product.get('category', '전자기기'),
            use_mobile=use_mobile
        )

        if not result.get('success'):
            log.error("트래픽 생성 실패")
            self.results['failure_count'] += 1
            return {
                'success': False,
                'iteration': iteration,
                'error': result.get('error')
            }

        # 3. IP 변경 (모바일만)
        if use_mobile:
            log.info("\n[Step 3] IP 로테이션")
            new_ip = IPPatternGenerator.generate_ip()
            log.info(f"  새 IP: {new_ip}")

            # 실제로는 ADB 비행기모드 토글
            # 여기서는 시뮬레이션만
            self.generator.ip_address = new_ip
        else:
            log.info("\n[Step 3] IP 변경 스킵 (PC)")

        # 4. 순위 반영 대기
        log.info("\n[Step 4] 순위 반영 대기")
        wait_time = 30  # 30초 (테스트용, 실전은 30분)
        log.info(f"  대기 시간: {wait_time}초")

        for i in range(wait_time):
            if i % 10 == 0:
                log.debug(f"  {wait_time - i}초 남음...")
            time.sleep(1)

        # 5. After 순위 체크
        log.info("\n[Step 5] After 순위 체크")

        after_rank = self.rank_checker.check_product_rank(
            keyword=product['search_keyword'],
            product_id=product_id,
            max_page=10
        )

        if after_rank:
            log.info(f"  변경 후 순위: {after_rank['absolute_rank']}위")
        else:
            log.warning("  순위권 밖 (100위 이하)")

        # 6. 순위 변동 계산
        rank_change = self._calculate_rank_change(before_rank, after_rank)

        if rank_change:
            if rank_change < 0:
                log.success(f"✅ 순위 상승: {abs(rank_change)}위")
            elif rank_change > 0:
                log.warning(f"⚠️ 순위 하락: {rank_change}위")
            else:
                log.info("→ 순위 변동 없음")

        # 7. 결과 저장
        iteration_time = time.time() - iteration_start

        iteration_result = {
            'success': True,
            'iteration': iteration,
            'platform': 'mobile' if use_mobile else 'pc',
            'before_rank': before_rank['absolute_rank'] if before_rank else None,
            'after_rank': after_rank['absolute_rank'] if after_rank else None,
            'rank_change': rank_change,
            'execution_time': iteration_time,
            'timestamp': datetime.now().isoformat()
        }

        self.results['iterations'].append(iteration_result)
        self.results['success_count'] += 1

        if rank_change:
            self.results['rank_changes'].append(rank_change)

        log.info("\n" + "="*80)
        log.info(f"반복 {iteration} 완료 ({iteration_time:.1f}초)")
        log.info("="*80 + "\n")

        return iteration_result

    def _extract_product_id(self, url: str) -> str:
        """URL에서 상품 ID 추출 (mid 우선)"""
        from urllib.parse import urlparse, parse_qs
        import re

        # mid 파라미터 확인
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if 'mid' in query_params:
            return query_params['mid'][0]

        # URL 경로에서 추출
        pattern = r"/(?:window-)?products/(\d+)"
        match = re.search(pattern, url)

        if match:
            return match.group(1)

        return ""

    def _calculate_rank_change(
        self,
        before: Dict = None,
        after: Dict = None
    ) -> int:
        """
        순위 변동 계산

        Returns:
            음수 = 상승, 양수 = 하락, 0 = 변동 없음, None = 계산 불가
        """
        if not before or not after:
            return None

        before_rank = before.get('absolute_rank')
        after_rank = after.get('absolute_rank')

        if before_rank is None or after_rank is None:
            return None

        return after_rank - before_rank

    def run_product_test(
        self,
        product: Dict,
        iterations: int = 10,
        mobile_ratio: float = 0.7
    ):
        """
        상품 테스트 실행

        Args:
            product: 테스트 상품
            iterations: 반복 횟수
            mobile_ratio: 모바일 비율 (0.0~1.0)
        """
        log.info("\n" + "="*100)
        log.info("상품 테스트 시작")
        log.info(f"  상품명: {product['product_name']}")
        log.info(f"  키워드: {product['search_keyword']}")
        log.info(f"  카테고리: {product.get('category', '전자기기')}")
        log.info(f"  반복 횟수: {iterations}")
        log.info(f"  모바일 비율: {mobile_ratio*100:.0f}%")
        log.info("="*100 + "\n")

        for i in range(1, iterations + 1):
            # 모바일/PC 선택 (확률 기반)
            import random
            use_mobile = random.random() < mobile_ratio

            # 반복 실행
            result = self.run_single_iteration(
                product=product,
                iteration=i,
                use_mobile=use_mobile
            )

            # 다음 반복 전 대기 (마지막 반복 제외)
            if i < iterations:
                wait_time = TimingPattern.get_next_interval()
                log.info(f"\n⏱️ 다음 반복까지 대기: {wait_time}초 ({wait_time/60:.1f}분)")

                for j in range(wait_time):
                    if j % 30 == 0:
                        log.debug(f"  {wait_time - j}초 남음...")
                    time.sleep(1)

        # 최종 통계
        self._print_final_statistics(product)

    def _print_final_statistics(self, product: Dict):
        """최종 통계 출력"""
        log.info("\n" + "="*100)
        log.info("테스트 완료 - 최종 통계")
        log.info("="*100 + "\n")

        log.info(f"상품명: {product['product_name']}")
        log.info(f"총 반복: {len(self.results['iterations'])}회")
        log.info(f"성공: {self.results['success_count']}회")
        log.info(f"실패: {self.results['failure_count']}회")

        # 순위 변동 통계
        if self.results['rank_changes']:
            rank_changes = self.results['rank_changes']

            improvements = [r for r in rank_changes if r < 0]
            declines = [r for r in rank_changes if r > 0]
            no_changes = [r for r in rank_changes if r == 0]

            log.info(f"\n순위 변동:")
            log.info(f"  상승: {len(improvements)}회 (평균 {abs(sum(improvements)/len(improvements)) if improvements else 0:.1f}위)")
            log.info(f"  하락: {len(declines)}회 (평균 {sum(declines)/len(declines) if declines else 0:.1f}위)")
            log.info(f"  변동 없음: {len(no_changes)}회")

            # 개선율
            if rank_changes:
                improvement_rate = len(improvements) / len(rank_changes) * 100
                log.info(f"\n개선율: {improvement_rate:.1f}%")

        # 플랫폼별 통계
        mobile_iterations = [i for i in self.results['iterations'] if i['platform'] == 'mobile']
        pc_iterations = [i for i in self.results['iterations'] if i['platform'] == 'pc']

        log.info(f"\n플랫폼별 분포:")
        log.info(f"  모바일: {len(mobile_iterations)}회")
        log.info(f"  PC: {len(pc_iterations)}회")

        log.info("\n" + "="*100 + "\n")

    def save_results(self, output_file: str = None):
        """결과 저장"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"data/results/realistic_test_{timestamp}.json"

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        self.results['test_end'] = datetime.now().isoformat()
        self.results['total_time'] = (
            datetime.fromisoformat(self.results['test_end']) -
            datetime.fromisoformat(self.results['test_start'])
        ).total_seconds()

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        log.info(f"✅ 결과 저장: {output_path}")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='실제 패킷 패턴 기반 트래픽 테스트'
    )

    parser.add_argument(
        '--product',
        type=int,
        default=0,
        help='테스트할 상품 인덱스 (기본: 0)'
    )

    parser.add_argument(
        '--iterations',
        type=int,
        default=10,
        help='반복 횟수 (기본: 10)'
    )

    parser.add_argument(
        '--mobile-ratio',
        type=float,
        default=0.7,
        help='모바일 비율 0.0~1.0 (기본: 0.7 = 70%%)'
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config/test_matrix.json',
        help='설정 파일 경로'
    )

    args = parser.parse_args()

    # 테스트 러너 생성
    runner = RealisticTestRunner(config_path=args.config)

    # 테스트 상품 선택
    products = runner.config.get('test_products', [])

    if not products:
        log.error("테스트 상품이 없습니다. config/test_matrix.json을 확인하세요.")
        return

    if args.product >= len(products):
        log.error(f"유효하지 않은 상품 인덱스: {args.product} (최대: {len(products)-1})")
        return

    product = products[args.product]

    # 테스트 실행
    log.info("\n🚀 실제 패킷 패턴 기반 트래픽 테스트 시작\n")
    log.info("실제 데이터 기반:")
    log.info("  - User-Agent: Samsung Browser 17.0/19.0")
    log.info("  - IP 패턴: 175.223.x.x (60%), 110.70.x.x (20%), ...")
    log.info("  - 타이밍: 평균 2.5분 간격 (정규분포)")
    log.info("  - 검색 경로: m.naver.com (모바일), naver.com (PC)")
    log.info("  - 예외 처리: 타임아웃, 재시도 등\n")

    try:
        runner.run_product_test(
            product=product,
            iterations=args.iterations,
            mobile_ratio=args.mobile_ratio
        )

        # 결과 저장
        runner.save_results()

    except KeyboardInterrupt:
        log.warning("\n사용자 중단 (Ctrl+C)")
        runner.save_results()

    except Exception as e:
        log.error(f"테스트 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
