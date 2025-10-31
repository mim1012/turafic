"""
프로토타입 메인 실행 스크립트

목표: 1개 상품, CASE_S3 시나리오, 10회 반복
각 반복마다: Before 순위 체크 → 시나리오 실행 → IP 변경 → After 순위 체크
"""

import json
import time
from pathlib import Path
from typing import Dict, Optional

# 프로젝트 루트 경로 추가
import sys
sys.path.append(str(Path(__file__).parent.parent))

from prototype.prototype_browser import PrototypeBrowser, load_config
from src.automation.mobile import ADBController
from src.ranking.checker import check_rank
from src.ranking.tracker import RankTracker
from src.utils.logger import get_logger

log = get_logger()


class PrototypeTestRunner:
    """프로토타입 테스트 실행기"""

    def __init__(self, config: Dict):
        self.config = config
        self.product = config['test_product']
        self.controller = ADBController()
        self.browser = PrototypeBrowser(self.controller, config)
        self.tracker = RankTracker(self.product['id'])
        self.total_iterations = 10

    def check_ranking(self, label: str) -> Optional[Dict]:
        """순위 체크"""
        log.info(f"\n{'='*60}")
        log.info(f"{label} 순위 체크 중...")
        log.info(f"{'='*60}")

        try:
            rank_info = check_rank(
                keyword=self.product['search_keyword'],
                product_id=str(self.product['id']),
                max_page=5
            )

            if rank_info:
                log.info(f"✅ 순위 발견: {rank_info['absolute_rank']}위")
                log.info(f"   페이지: {rank_info['page']}, 위치: {rank_info['position']}")
            else:
                log.warning("⚠️ 순위권 밖 (5페이지 이내 없음)")

            return rank_info

        except Exception as e:
            log.error(f"순위 체크 실패: {e}")
            return None

    def change_ip(self) -> bool:
        """IP 변경 (비행기모드 토글)"""
        log.info(f"\n{'='*60}")
        log.info("IP 변경 시작...")
        log.info(f"{'='*60}")

        try:
            # Before IP
            ip_before = self.controller.get_ip_address()
            log.info(f"현재 IP: {ip_before}")

            # 비행기모드 토글
            log.info("비행기모드 ON → OFF...")
            self.controller.toggle_airplane_mode(duration=3)

            # 네트워크 재연결 대기
            log.info("네트워크 재연결 대기 중...")
            if not self.controller.wait_for_network(timeout=30):
                log.warning("네트워크 재연결 타임아웃")
                return False

            # After IP
            ip_after = self.controller.get_ip_address()
            log.info(f"변경된 IP: {ip_after}")

            if ip_before != ip_after:
                log.info(f"✅ IP 변경 성공: {ip_before} → {ip_after}")
                return True
            else:
                log.warning(f"⚠️ IP 변경 안됨 (동일 IP: {ip_before})")
                return False

        except Exception as e:
            log.error(f"IP 변경 실패: {e}")
            return False

    def run_single_iteration(self, iteration: int) -> bool:
        """단일 iteration 실행"""
        log.info(f"\n\n{'#'*70}")
        log.info(f"#  Iteration {iteration}/{self.total_iterations}")
        log.info(f"#  상품: {self.product['product_name']}")
        log.info(f"#  시나리오: CASE_S3 (비교 쇼핑 후 최종 선택)")
        log.info(f"{'#'*70}\n")

        try:
            # 1. Before 순위 체크
            rank_before = self.check_ranking(f"[{iteration}] BEFORE")

            # 2. 트래픽 생성 (CASE_S3 시나리오 실행)
            log.info(f"\n{'='*60}")
            log.info(f"[{iteration}] 트래픽 생성 시작")
            log.info(f"{'='*60}")

            scenario_success = self.browser.execute_case_s3_scenario()

            if not scenario_success:
                log.error(f"[{iteration}] 시나리오 실행 실패")
                return False

            log.info(f"✅ [{iteration}] 트래픽 생성 완료")

            # 3. IP 변경
            ip_changed = self.change_ip()

            # 4. After 순위 체크 (대기 시간)
            log.info(f"\n{'='*60}")
            log.info(f"[{iteration}] 순위 반영 대기 중...")
            log.info(f"{'='*60}")

            # 프로토타입: 5분 대기 (실제는 30분 권장)
            wait_time = 300  # 5분
            log.info(f"대기 시간: {wait_time}초 ({wait_time//60}분)")
            log.info("(실제 테스트에서는 30분 권장)")

            time.sleep(wait_time)

            rank_after = self.check_ranking(f"[{iteration}] AFTER")

            # 5. 결과 저장
            self.tracker.add_record(
                rank_info=rank_after,
                iteration=iteration,
                test_case_id="CASE_S3",
                notes=f"프로토타입 테스트 - CASE_S3 비교 쇼핑 시나리오"
            )

            # 6. 순위 변동 분석
            if rank_before and rank_after:
                before_rank = rank_before['absolute_rank']
                after_rank = rank_after['absolute_rank']
                change = after_rank - before_rank

                log.info(f"\n{'='*60}")
                log.info(f"[{iteration}] 순위 변동 결과")
                log.info(f"{'='*60}")
                log.info(f"Before: {before_rank}위")
                log.info(f"After:  {after_rank}위")

                if change < 0:
                    log.info(f"✅ 순위 상승: {abs(change)}위 ↑")
                elif change > 0:
                    log.warning(f"⬇️ 순위 하락: {change}위 ↓")
                else:
                    log.info(f"➡️ 순위 유지")

                log.info(f"{'='*60}\n")

            return True

        except KeyboardInterrupt:
            log.warning(f"\n[{iteration}] 사용자에 의해 중단됨")
            raise
        except Exception as e:
            log.error(f"[{iteration}] Iteration 실행 중 에러: {e}")
            import traceback
            log.error(traceback.format_exc())
            return False

    def run_test(self):
        """전체 테스트 실행"""
        log.info(f"\n{'#'*70}")
        log.info("#")
        log.info("#  프로토타입 테스트 시작")
        log.info("#")
        log.info(f"{'#'*70}")
        log.info(f"상품 ID: {self.product['id']}")
        log.info(f"상품명: {self.product['product_name']}")
        log.info(f"검색 키워드: {self.product['search_keyword']}")
        log.info(f"시나리오: CASE_S3 (비교 쇼핑 후 최종 선택)")
        log.info(f"반복 횟수: {self.total_iterations}회")
        log.info(f"{'#'*70}\n")

        success_count = 0
        failure_count = 0

        try:
            for i in range(1, self.total_iterations + 1):
                success = self.run_single_iteration(i)

                if success:
                    success_count += 1
                else:
                    failure_count += 1

                # Iteration 간 짧은 휴식 (1분)
                if i < self.total_iterations:
                    log.info(f"\n다음 iteration까지 60초 대기...\n")
                    time.sleep(60)

        except KeyboardInterrupt:
            log.warning("\n\n사용자에 의해 테스트 중단됨")

        finally:
            # 최종 통계 출력
            self.print_final_statistics(success_count, failure_count)

    def print_final_statistics(self, success_count: int, failure_count: int):
        """최종 통계 출력"""
        log.info(f"\n\n{'#'*70}")
        log.info("#")
        log.info("#  프로토타입 테스트 완료")
        log.info("#")
        log.info(f"{'#'*70}")

        log.info(f"\n=== 실행 통계 ===")
        log.info(f"총 시도: {success_count + failure_count}회")
        log.info(f"성공: {success_count}회")
        log.info(f"실패: {failure_count}회")

        # 순위 통계
        stats = self.tracker.get_statistics()

        if stats.get('total_records', 0) > 0:
            log.info(f"\n=== 순위 통계 ===")
            log.info(f"총 기록: {stats['total_records']}회")
            log.info(f"평균 순위: {stats.get('average_rank', 0):.1f}위")
            log.info(f"최고 순위: {stats.get('best_rank', '-')}위")
            log.info(f"최저 순위: {stats.get('worst_rank', '-')}위")

            if 'average_change' in stats:
                avg_change = stats['average_change']
                log.info(f"\n평균 순위 변동: {avg_change:.2f}")

                if avg_change < 0:
                    log.info(f"✅ 평균 {abs(avg_change):.1f}위 상승")
                elif avg_change > 0:
                    log.info(f"⚠️ 평균 {avg_change:.1f}위 하락")
                else:
                    log.info("➡️ 평균 순위 유지")

            improvement_rate = stats.get('improvement_rate', 0)
            log.info(f"\n순위 개선율: {improvement_rate*100:.1f}%")

        # CSV 내보내기
        csv_path = self.tracker.export_to_csv()
        log.info(f"\n📊 결과 저장 완료: {csv_path}")

        log.info(f"\n{'#'*70}\n")


def validate_config(config: Dict) -> bool:
    """설정 검증"""
    log.info("설정 검증 중...")

    required_fields = ['test_product', 'screen', 'coordinates', 'timing', 'case_s3_config']
    for field in required_fields:
        if field not in config:
            log.error(f"필수 설정 누락: {field}")
            return False

    product = config['test_product']
    required_product_fields = ['id', 'product_name', 'product_url', 'search_keyword']
    for field in required_product_fields:
        if field not in product:
            log.error(f"상품 정보 누락: {field}")
            return False

    log.info("✅ 설정 검증 완료")
    return True


def main():
    """메인 함수"""
    log.info("\n" + "="*70)
    log.info("프로토타입 테스트 시작 준비")
    log.info("="*70 + "\n")

    # 1. 설정 로드
    log.info("1. 설정 파일 로드 중...")
    config = load_config()
    if not config:
        log.error("❌ 설정 파일을 로드할 수 없습니다.")
        return

    # 2. 설정 검증
    log.info("2. 설정 검증 중...")
    if not validate_config(config):
        log.error("❌ 설정 검증 실패")
        return

    # 3. ADB 연결 확인
    log.info("3. ADB 연결 확인 중...")
    try:
        controller = ADBController()
        device_info = controller.get_device_info()
        log.info(f"✅ 기기 연결됨: {device_info.get('model', 'Unknown')}")
        log.info(f"   해상도: {device_info.get('screen_width')}x{device_info.get('screen_height')}")
    except Exception as e:
        log.error(f"❌ ADB 연결 실패: {e}")
        return

    # 4. 사용자 확인
    log.info("\n" + "="*70)
    log.info("테스트 준비 완료!")
    log.info("="*70)
    log.info(f"상품: {config['test_product']['product_name']}")
    log.info(f"시나리오: CASE_S3 (비교 쇼핑 후 최종 선택)")
    log.info(f"반복 횟수: 10회")
    log.info(f"예상 소요 시간: 약 90분 (iteration당 약 9분)")
    log.info("="*70 + "\n")

    response = input("테스트를 시작하시겠습니까? (y/n): ")
    if response.lower() != 'y':
        log.info("테스트 취소됨")
        return

    # 5. 테스트 실행
    try:
        runner = PrototypeTestRunner(config)
        runner.run_test()
    except KeyboardInterrupt:
        log.warning("\n\n프로그램이 중단되었습니다.")
    except Exception as e:
        log.error(f"\n\n프로그램 실행 중 에러: {e}")
        import traceback
        log.error(traceback.format_exc())


if __name__ == "__main__":
    main()
