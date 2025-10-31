"""
테스트 케이스별 비교 분석 모듈
"""
import json
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict
import statistics
from config.settings import config
from src.utils.logger import log


class CaseComparisonAnalyzer:
    """테스트 케이스별 효과성 비교 분석 클래스"""

    def __init__(self, test_products_file: Path = None):
        """
        Args:
            test_products_file: 테스트 상품 JSON 파일 경로
        """
        if test_products_file is None:
            test_products_file = config.TEST_PRODUCTS_FILE

        self.test_products_file = test_products_file
        self.test_cases = {}
        self.products = []
        self._load_test_data()

    def _load_test_data(self):
        """테스트 데이터 로드"""
        try:
            with open(self.test_products_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.test_cases = data.get("test_cases", {})
            self.products = data.get("products", [])

            log.info(f"테스트 케이스 {len(self.test_cases)}개, 상품 {len(self.products)}개 로드 완료")

        except Exception as e:
            log.error(f"테스트 데이터 로드 실패: {e}")
            raise

    def get_products_by_case(self, case_id: str) -> List[Dict[str, Any]]:
        """
        특정 케이스에 속한 상품 목록 반환

        Args:
            case_id: 케이스 ID (예: CASE_1)

        Returns:
            상품 리스트
        """
        return [p for p in self.products if p.get("test_case_id") == case_id]

    def load_rank_history(self, product_id: str) -> List[Dict[str, Any]]:
        """
        상품의 순위 히스토리 로드

        Args:
            product_id: 상품 ID

        Returns:
            순위 히스토리 리스트
        """
        history_file = config.RANKINGS_DIR / f"rank_history_{product_id}.json"

        if not history_file.exists():
            log.warning(f"히스토리 파일 없음: {product_id}")
            return []

        try:
            with open(history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("history", [])
        except Exception as e:
            log.error(f"히스토리 로드 실패 ({product_id}): {e}")
            return []

    def calculate_case_statistics(self, case_id: str) -> Dict[str, Any]:
        """
        특정 케이스의 통계 계산

        Args:
            case_id: 케이스 ID

        Returns:
            통계 딕셔너리
        """
        products = self.get_products_by_case(case_id)

        if not products:
            return {"error": "상품 없음"}

        all_rank_changes = []
        all_ranks = []
        improvement_count = 0
        decline_count = 0
        unchanged_count = 0

        for product in products:
            history = self.load_rank_history(product["product_id"])

            if not history:
                continue

            # 순위 변동 추출
            for record in history:
                rank_change = record.get("rank_change")
                if rank_change is not None:
                    all_rank_changes.append(rank_change)

                    if rank_change < 0:
                        improvement_count += 1
                    elif rank_change > 0:
                        decline_count += 1
                    else:
                        unchanged_count += 1

                # 절대 순위 추출
                rank_info = record.get("rank_info")
                if rank_info:
                    all_ranks.append(rank_info.get("absolute_rank", 0))

        if not all_rank_changes:
            return {
                "case_id": case_id,
                "case_name": self.test_cases.get(case_id, {}).get("name", ""),
                "product_count": len(products),
                "error": "순위 변동 데이터 없음"
            }

        # 통계 계산
        stats = {
            "case_id": case_id,
            "case_name": self.test_cases.get(case_id, {}).get("name", ""),
            "product_count": len(products),
            "total_records": len(all_rank_changes),

            # 순위 변동 통계
            "avg_rank_change": round(statistics.mean(all_rank_changes), 2),
            "median_rank_change": statistics.median(all_rank_changes),
            "stdev_rank_change": round(statistics.stdev(all_rank_changes), 2) if len(all_rank_changes) > 1 else 0,

            # 개선/하락/유지 비율
            "improvement_count": improvement_count,
            "decline_count": decline_count,
            "unchanged_count": unchanged_count,
            "improvement_rate": round(improvement_count / len(all_rank_changes) * 100, 1),

            # 최대/최소 변동
            "max_improvement": min(all_rank_changes),  # 가장 많이 상승 (음수)
            "max_decline": max(all_rank_changes),  # 가장 많이 하락 (양수)

            # 순위 통계
            "avg_rank": round(statistics.mean(all_ranks), 1) if all_ranks else 0,
            "best_rank": min(all_ranks) if all_ranks else 0,
            "worst_rank": max(all_ranks) if all_ranks else 0,
        }

        log.info(f"케이스 {case_id} 통계 계산 완료: 평균 순위변동 {stats['avg_rank_change']}")
        return stats

    def compare_all_cases(self) -> List[Dict[str, Any]]:
        """
        모든 케이스 비교 분석

        Returns:
            케이스별 통계 리스트
        """
        log.info("전체 케이스 비교 분석 시작...")

        results = []

        for case_id in self.test_cases.keys():
            stats = self.calculate_case_statistics(case_id)
            results.append(stats)

        # 평균 순위 변동 기준 정렬 (상승폭 큰 순서)
        results.sort(key=lambda x: x.get("avg_rank_change", 0))

        log.success(f"전체 케이스 비교 분석 완료: {len(results)}개 케이스")
        return results

    def generate_comparison_report(self) -> str:
        """
        비교 분석 리포트 생성 (텍스트)

        Returns:
            리포트 문자열
        """
        results = self.compare_all_cases()

        report = []
        report.append("=" * 100)
        report.append("테스트 케이스별 효과성 비교 분석 리포트")
        report.append("=" * 100)
        report.append("")

        # 요약 테이블
        report.append("┌─────────┬────────────────────┬──────────┬──────────┬──────────┬────────────┐")
        report.append("│ 순위    │ 케이스명           │ 평균변동 │ 개선율   │ 최대상승 │ 표준편차   │")
        report.append("├─────────┼────────────────────┼──────────┼──────────┼──────────┼────────────┤")

        for idx, stats in enumerate(results, 1):
            if "error" in stats:
                continue

            case_name = stats.get("case_name", "")[:18]
            avg_change = stats.get("avg_rank_change", 0)
            improvement_rate = stats.get("improvement_rate", 0)
            max_improvement = stats.get("max_improvement", 0)
            stdev = stats.get("stdev_rank_change", 0)

            report.append(
                f"│ {idx:<7} │ {case_name:<18} │ "
                f"{avg_change:>8.1f} │ {improvement_rate:>7.1f}% │ "
                f"{max_improvement:>8} │ {stdev:>10.1f} │"
            )

        report.append("└─────────┴────────────────────┴──────────┴──────────┴──────────┴────────────┘")
        report.append("")

        # 상세 분석
        report.append("=" * 100)
        report.append("상세 분석")
        report.append("=" * 100)
        report.append("")

        for idx, stats in enumerate(results, 1):
            if "error" in stats:
                report.append(f"【{idx}위】 {stats.get('case_name', '')} - 데이터 부족")
                report.append("")
                continue

            report.append(f"【{idx}위】 {stats['case_name']} ({stats['case_id']})")
            report.append("-" * 100)

            case_info = self.test_cases.get(stats['case_id'], {})
            report.append(f"시나리오: {case_info.get('description', '')}")
            report.append(f"가설: {case_info.get('hypothesis', '')}")
            report.append("")

            report.append(f"상품 수: {stats['product_count']}개")
            report.append(f"총 기록: {stats['total_records']}회")
            report.append("")

            report.append(f"평균 순위 변동: {stats['avg_rank_change']:+.1f}위")
            report.append(f"중앙값: {stats['median_rank_change']:+.1f}위")
            report.append(f"표준편차: {stats['stdev_rank_change']:.1f} (변동 일관성)")
            report.append("")

            report.append(f"순위 개선: {stats['improvement_count']}회 ({stats['improvement_rate']:.1f}%)")
            report.append(f"순위 하락: {stats['decline_count']}회")
            report.append(f"순위 유지: {stats['unchanged_count']}회")
            report.append("")

            report.append(f"최대 상승: {abs(stats['max_improvement'])}위")
            report.append(f"최대 하락: {stats['max_decline']}위")
            report.append("")

            report.append(f"평균 순위: {stats['avg_rank']}위")
            report.append(f"최고 순위: {stats['best_rank']}위")
            report.append(f"최저 순위: {stats['worst_rank']}위")
            report.append("")

        # 결론
        report.append("=" * 100)
        report.append("결론 및 권장사항")
        report.append("=" * 100)
        report.append("")

        if results and "error" not in results[0]:
            best_case = results[0]
            report.append(f"✅ 가장 효과적인 케이스: {best_case['case_name']}")
            report.append(f"   - 평균 {abs(best_case['avg_rank_change']):.1f}위 상승")
            report.append(f"   - 개선율 {best_case['improvement_rate']:.1f}%")
            report.append("")

            case_info = self.test_cases.get(best_case['case_id'], {})
            report.append("권장 트래픽 패턴:")
            report.append(f"   - 진입 경로: {case_info.get('entry_path', '')}")
            report.append(f"   - 스크롤 깊이: {case_info.get('scroll_depth', '')}")
            report.append(f"   - 액션 타입: {case_info.get('action_type', '')}")
            report.append(f"   - 체류 시간: {case_info.get('dwell_time', {})}")
        else:
            report.append("⚠️ 충분한 데이터가 없어 결론을 도출할 수 없습니다.")

        report.append("")
        report.append("=" * 100)

        return "\n".join(report)

    def export_comparison_csv(self, output_path: Path = None) -> Path:
        """
        비교 결과 CSV 내보내기

        Args:
            output_path: 저장 경로

        Returns:
            저장된 파일 경로
        """
        import csv

        if output_path is None:
            output_path = config.RESULTS_DIR / "case_comparison.csv"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        results = self.compare_all_cases()

        try:
            with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)

                # 헤더
                writer.writerow([
                    "순위",
                    "케이스ID",
                    "케이스명",
                    "상품수",
                    "총기록수",
                    "평균순위변동",
                    "중앙값",
                    "표준편차",
                    "개선횟수",
                    "하락횟수",
                    "유지횟수",
                    "개선율(%)",
                    "최대상승",
                    "최대하락",
                    "평균순위",
                    "최고순위",
                    "최저순위",
                ])

                # 데이터
                for idx, stats in enumerate(results, 1):
                    if "error" in stats:
                        continue

                    writer.writerow([
                        idx,
                        stats.get("case_id", ""),
                        stats.get("case_name", ""),
                        stats.get("product_count", 0),
                        stats.get("total_records", 0),
                        stats.get("avg_rank_change", 0),
                        stats.get("median_rank_change", 0),
                        stats.get("stdev_rank_change", 0),
                        stats.get("improvement_count", 0),
                        stats.get("decline_count", 0),
                        stats.get("unchanged_count", 0),
                        stats.get("improvement_rate", 0),
                        abs(stats.get("max_improvement", 0)),
                        stats.get("max_decline", 0),
                        stats.get("avg_rank", 0),
                        stats.get("best_rank", 0),
                        stats.get("worst_rank", 0),
                    ])

            log.success(f"비교 결과 CSV 저장 완료: {output_path}")
            return output_path

        except Exception as e:
            log.error(f"CSV 저장 실패: {e}")
            raise


# 편의 함수
def analyze_cases() -> List[Dict[str, Any]]:
    """케이스 비교 분석 편의 함수"""
    analyzer = CaseComparisonAnalyzer()
    return analyzer.compare_all_cases()


def print_comparison_report():
    """비교 리포트 출력 편의 함수"""
    analyzer = CaseComparisonAnalyzer()
    report = analyzer.generate_comparison_report()
    print(report)


if __name__ == "__main__":
    # 테스트
    print("\n케이스 비교 분석 테스트\n")

    analyzer = CaseComparisonAnalyzer()

    # 리포트 생성
    report = analyzer.generate_comparison_report()
    print(report)

    # CSV 내보내기
    # csv_path = analyzer.export_comparison_csv()
    # print(f"\nCSV 저장: {csv_path}")
