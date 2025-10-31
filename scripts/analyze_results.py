"""
테스트 결과 통계 분석 스크립트

Phase별 결과를 분석하여 통계표 및 요약 생성
"""
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import numpy as np
from scipy import stats

sys.path.append(str(Path(__file__).parent.parent))
from src.utils.logger import get_logger

log = get_logger()


class ResultAnalyzer:
    """테스트 결과 분석기"""

    def __init__(self, results_dir: Path):
        self.results_dir = results_dir
        self.results = []

    def load_results(self, test_case_pattern: str = None):
        """결과 파일 로드"""
        if test_case_pattern:
            # 특정 테스트 케이스만
            pattern = f"{test_case_pattern}_*.json"
        else:
            # 모든 결과
            pattern = "*.json"

        result_files = list(self.results_dir.glob(pattern))
        log.info(f"{len(result_files)}개 결과 파일 발견")

        for file in result_files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.results.append(data)
            except Exception as e:
                log.warning(f"파일 로드 실패: {file} - {e}")

        return len(self.results)

    def analyze_platform_comparison(self) -> Dict:
        """플랫폼별 비교 분석 (Phase 1)"""
        log.info("\n=== 플랫폼별 효과 비교 분석 ===")

        # TC-001 (모바일), TC-002 (PC), TC-003 (혼합)
        mobile_results = self._filter_by_tc("TC-001")
        pc_results = self._filter_by_tc("TC-002")
        mixed_results = self._filter_by_tc("TC-003")

        analysis = {
            "mobile": self._calculate_stats(mobile_results, "모바일 100%"),
            "pc": self._calculate_stats(pc_results, "PC 100%"),
            "mixed": self._calculate_stats(mixed_results, "혼합 70:30"),
        }

        # t-test: 모바일 vs PC
        if mobile_results and pc_results:
            mobile_changes = self._extract_rank_changes(mobile_results)
            pc_changes = self._extract_rank_changes(pc_results)

            t_stat, p_value = stats.ttest_ind(mobile_changes, pc_changes)
            analysis["mobile"]["p_value_vs_pc"] = p_value
            analysis["pc"]["p_value_vs_mobile"] = p_value

            log.info(f"\nt-test (모바일 vs PC): t={t_stat:.3f}, p={p_value:.4f}")
            if p_value < 0.05:
                log.success("✅ 통계적으로 유의미한 차이 (p < 0.05)")
            else:
                log.info("→ 통계적으로 유의미하지 않음 (p >= 0.05)")

        return analysis

    def analyze_path_comparison(self) -> Dict:
        """경로별 비교 분석 (Phase 2)"""
        log.info("\n=== 진입 경로별 효과 비교 분석 ===")

        # TC-004 (통합검색), TC-005 (쇼핑검색), TC-006 (블로그), TC-007 (카페)
        search_results = self._filter_by_tc("TC-004")
        shopping_results = self._filter_by_tc("TC-005")
        blog_results = self._filter_by_tc("TC-006")
        cafe_results = self._filter_by_tc("TC-007")

        analysis = {
            "search": self._calculate_stats(search_results, "통합검색"),
            "shopping": self._calculate_stats(shopping_results, "쇼핑검색"),
            "blog": self._calculate_stats(blog_results, "블로그"),
            "cafe": self._calculate_stats(cafe_results, "카페"),
        }

        # ANOVA: 여러 경로 비교
        if all([search_results, shopping_results, blog_results, cafe_results]):
            search_changes = self._extract_rank_changes(search_results)
            shopping_changes = self._extract_rank_changes(shopping_results)
            blog_changes = self._extract_rank_changes(blog_results)
            cafe_changes = self._extract_rank_changes(cafe_results)

            f_stat, p_value = stats.f_oneway(
                search_changes,
                shopping_changes,
                blog_changes,
                cafe_changes
            )

            analysis["anova"] = {
                "f_statistic": f_stat,
                "p_value": p_value,
                "significant": p_value < 0.05
            }

            log.info(f"\nANOVA (경로 비교): F={f_stat:.3f}, p={p_value:.4f}")
            if p_value < 0.05:
                log.success("✅ 경로 간 통계적으로 유의미한 차이 존재")
            else:
                log.info("→ 경로 간 차이가 통계적으로 유의미하지 않음")

        return analysis

    def analyze_behavior_patterns(self) -> Dict:
        """행동 패턴별 분석 (Phase 3)"""
        log.info("\n=== 행동 패턴별 효과 비교 분석 ===")

        # TC-008 (빠른 이탈), TC-009 (일반), TC-010 (심층), TC-011 (비교)
        quick_results = self._filter_by_tc("TC-008")
        normal_results = self._filter_by_tc("TC-009")
        deep_results = self._filter_by_tc("TC-010")
        compare_results = self._filter_by_tc("TC-011")

        analysis = {
            "quick_exit": self._calculate_stats(quick_results, "빠른 이탈"),
            "normal_browsing": self._calculate_stats(normal_results, "일반 둘러보기"),
            "deep_exploration": self._calculate_stats(deep_results, "심층 탐색"),
            "comparison_shopping": self._calculate_stats(compare_results, "비교 쇼핑"),
        }

        # 상관관계 분석: 체류 시간 vs 순위 상승
        dwell_times = []
        rank_changes = []

        for result in self.results:
            if result.get("test_case_id") in ["TC-008", "TC-009", "TC-010", "TC-011"]:
                avg_dwell = result.get("variables", {}).get("dwell_time_range", [0, 0])
                avg_dwell_time = (avg_dwell[0] + avg_dwell[1]) / 2

                for product in result.get("products", []):
                    stats_data = product.get("statistics", {})
                    avg_change = stats_data.get("avg_rank_change", 0)

                    if avg_change != 0:
                        dwell_times.append(avg_dwell_time)
                        rank_changes.append(avg_change)

        if len(dwell_times) > 2:
            correlation, p_value = stats.pearsonr(dwell_times, rank_changes)
            analysis["correlation"] = {
                "dwell_time_vs_rank_change": correlation,
                "p_value": p_value,
                "significant": p_value < 0.05
            }

            log.info(f"\n상관관계 (체류시간 vs 순위변화): r={correlation:.3f}, p={p_value:.4f}")
            if abs(correlation) > 0.6:
                log.success(f"✅ 강한 상관관계 (|r| > 0.6)")
            elif abs(correlation) > 0.3:
                log.info(f"→ 중간 상관관계 (|r| > 0.3)")
            else:
                log.info(f"→ 약한 상관관계")

        return analysis

    def analyze_scale_effect(self) -> Dict:
        """스케일 효과 분석 (Phase 4)"""
        log.info("\n=== 트래픽 양별 효과 분석 ===")

        # TC-012 (10회), TC-013 (50회), TC-014 (100회)
        small_results = self._filter_by_tc("TC-012")
        medium_results = self._filter_by_tc("TC-013")
        large_results = self._filter_by_tc("TC-014")

        analysis = {
            "small_10": self._calculate_stats(small_results, "소량 (10회)"),
            "medium_50": self._calculate_stats(medium_results, "중량 (50회)"),
            "large_100": self._calculate_stats(large_results, "대량 (100회)"),
        }

        # ROI 계산 (순위 상승폭 / 소요 시간)
        for key, data in analysis.items():
            if data:
                avg_rank_change = abs(data.get("mean_rank_change", 0))
                # 각 트래픽당 평균 3분 소요 가정
                traffic_volume = int(key.split("_")[1])
                total_time_minutes = traffic_volume * 3

                data["roi"] = avg_rank_change / total_time_minutes if total_time_minutes > 0 else 0
                data["total_time_minutes"] = total_time_minutes

        return analysis

    def analyze_category_comparison(self) -> Dict:
        """카테고리별 비교 분석 (Phase 5)"""
        log.info("\n=== 카테고리별 효과 비교 분석 ===")

        # TC-015 (전자기기), TC-016 (패션), TC-017 (식품), TC-018 (뷰티)
        electronics_results = self._filter_by_tc("TC-015")
        fashion_results = self._filter_by_tc("TC-016")
        food_results = self._filter_by_tc("TC-017")
        beauty_results = self._filter_by_tc("TC-018")

        analysis = {
            "electronics": self._calculate_stats(electronics_results, "전자기기"),
            "fashion": self._calculate_stats(fashion_results, "패션의류"),
            "food": self._calculate_stats(food_results, "식품"),
            "beauty": self._calculate_stats(beauty_results, "뷰티"),
        }

        return analysis

    def _filter_by_tc(self, tc_id: str) -> List[Dict]:
        """특정 테스트 케이스 결과 필터링"""
        return [r for r in self.results if r.get("test_case_id") == tc_id]

    def _extract_rank_changes(self, results: List[Dict]) -> List[float]:
        """순위 변화량 추출"""
        rank_changes = []

        for result in results:
            for product in result.get("products", []):
                for iteration in product.get("iterations", []):
                    change = iteration.get("rank_change")
                    if change is not None:
                        rank_changes.append(change)

        return rank_changes

    def _calculate_stats(self, results: List[Dict], name: str) -> Dict:
        """기본 통계 계산"""
        if not results:
            log.warning(f"{name}: 결과 없음")
            return None

        rank_changes = self._extract_rank_changes(results)

        if not rank_changes:
            log.warning(f"{name}: 순위 변화 데이터 없음")
            return None

        # numpy array 변환
        rank_changes_arr = np.array(rank_changes)

        # 개선/하락/변동없음 카운트
        improvements = sum(1 for r in rank_changes if r < 0)
        declines = sum(1 for r in rank_changes if r > 0)
        no_change = sum(1 for r in rank_changes if r == 0)

        # 통계 계산
        stats_dict = {
            "name": name,
            "test_count": len(results),
            "iteration_count": len(rank_changes),
            "mean_rank_change": float(np.mean(rank_changes_arr)),
            "std_rank_change": float(np.std(rank_changes_arr)),
            "median_rank_change": float(np.median(rank_changes_arr)),
            "min_rank_change": float(np.min(rank_changes_arr)),
            "max_rank_change": float(np.max(rank_changes_arr)),
            "improvements": improvements,
            "declines": declines,
            "no_change": no_change,
            "improvement_rate": improvements / len(rank_changes) if rank_changes else 0,
        }

        # Cohen's d (효과 크기)
        if stats_dict["std_rank_change"] != 0:
            stats_dict["effect_size"] = abs(stats_dict["mean_rank_change"] / stats_dict["std_rank_change"])
        else:
            stats_dict["effect_size"] = 0

        log.info(f"\n{name}:")
        log.info(f"  테스트 수: {stats_dict['test_count']}")
        log.info(f"  반복 횟수: {stats_dict['iteration_count']}")
        log.info(f"  평균 순위 변화: {stats_dict['mean_rank_change']:.2f}위")
        log.info(f"  표준편차: {stats_dict['std_rank_change']:.2f}")
        log.info(f"  개선율: {stats_dict['improvement_rate']*100:.1f}%")
        log.info(f"  효과 크기 (Cohen's d): {stats_dict['effect_size']:.2f}")

        return stats_dict

    def generate_summary_report(self) -> Dict:
        """종합 요약 보고서 생성"""
        log.info("\n" + "="*100)
        log.info("테스트 결과 종합 분석 보고서")
        log.info("="*100)

        report = {
            "generated_at": datetime.now().isoformat(),
            "total_results": len(self.results),
            "phase_1_platform": self.analyze_platform_comparison(),
            "phase_2_path": self.analyze_path_comparison(),
            "phase_3_behavior": self.analyze_behavior_patterns(),
            "phase_4_scale": self.analyze_scale_effect(),
            "phase_5_category": self.analyze_category_comparison(),
        }

        return report

    def save_report(self, report: Dict, output_file: Path):
        """보고서 저장"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        log.success(f"\n✅ 분석 보고서 저장: {output_file}")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='테스트 결과 통계 분석'
    )

    parser.add_argument(
        '--results-dir',
        type=str,
        default='data/test_results',
        help='결과 디렉토리 경로'
    )

    parser.add_argument(
        '--tc-pattern',
        type=str,
        default=None,
        help='특정 테스트 케이스 패턴 (예: TC-001)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='data/analysis/summary_report.json',
        help='출력 파일 경로'
    )

    args = parser.parse_args()

    # 디렉토리 확인
    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        log.error(f"결과 디렉토리 없음: {results_dir}")
        return

    # 분석기 생성
    analyzer = ResultAnalyzer(results_dir)

    # 결과 로드
    count = analyzer.load_results(args.tc_pattern)
    if count == 0:
        log.error("분석할 결과 없음")
        return

    # 분석 실행
    report = analyzer.generate_summary_report()

    # 보고서 저장
    output_file = Path(args.output)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    analyzer.save_report(report, output_file)

    # 요약 출력
    log.info("\n" + "="*100)
    log.info("분석 완료")
    log.info("="*100)
    log.info(f"총 결과 파일: {count}개")
    log.info(f"보고서: {output_file}")


if __name__ == "__main__":
    main()
