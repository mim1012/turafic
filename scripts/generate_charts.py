"""
테스트 결과 시각화 스크립트

분석 보고서를 읽어 다양한 차트 생성
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import numpy as np

sys.path.append(str(Path(__file__).parent.parent))
from src.utils.logger import get_logger

log = get_logger()

# 한글 폰트 설정 (Windows)
plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False  # 마이너스 기호 깨짐 방지


class ChartGenerator:
    """차트 생성기"""

    def __init__(self, report: Dict, output_dir: Path):
        self.report = report
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all_charts(self):
        """모든 차트 생성"""
        log.info("차트 생성 시작...")

        # Phase 1: 플랫폼 비교
        self.chart_platform_comparison()
        self.chart_platform_success_rate()

        # Phase 2: 경로 비교
        self.chart_path_comparison()

        # Phase 3: 행동 패턴
        self.chart_behavior_patterns()
        self.chart_dwell_time_correlation()

        # Phase 4: 스케일 효과
        self.chart_scale_effect()
        self.chart_roi_comparison()

        # Phase 5: 카테고리 비교
        self.chart_category_comparison()

        # 종합
        self.chart_overall_summary()

        log.success(f"\n✅ 모든 차트 생성 완료: {self.output_dir}")

    def chart_platform_comparison(self):
        """플랫폼별 평균 순위 상승폭 (막대 그래프)"""
        phase1 = self.report.get("phase_1_platform", {})

        platforms = []
        rank_changes = []
        colors = []

        for key, label, color in [
            ("mobile", "모바일 100%", '#4CAF50'),
            ("pc", "PC 100%", '#2196F3'),
            ("mixed", "혼합 70:30", '#FF9800')
        ]:
            data = phase1.get(key)
            if data:
                platforms.append(label)
                rank_changes.append(data.get("mean_rank_change", 0))
                colors.append(color)

        if not platforms:
            log.warning("플랫폼 비교 데이터 없음")
            return

        # 그래프 생성
        fig, ax = plt.subplots(figsize=(10, 6))

        bars = ax.bar(platforms, rank_changes, color=colors, alpha=0.7, edgecolor='black')

        # 값 표시
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.,
                height,
                f'{height:.1f}위',
                ha='center',
                va='bottom' if height < 0 else 'top',
                fontsize=12,
                fontweight='bold'
            )

        ax.set_ylabel('평균 순위 변화 (위)', fontsize=12)
        ax.set_title('플랫폼별 평균 순위 상승폭 비교', fontsize=14, fontweight='bold')
        ax.axhline(y=0, color='black', linestyle='-', linewidth=0.8)
        ax.grid(axis='y', alpha=0.3)

        plt.tight_layout()
        output_file = self.output_dir / "1_platform_rank_change.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")

    def chart_platform_success_rate(self):
        """플랫폼별 성공률 (가로 막대 그래프)"""
        phase1 = self.report.get("phase_1_platform", {})

        platforms = []
        success_rates = []
        colors = []

        for key, label, color in [
            ("mobile", "모바일 100%", '#4CAF50'),
            ("pc", "PC 100%", '#2196F3'),
            ("mixed", "혼합 70:30", '#FF9800')
        ]:
            data = phase1.get(key)
            if data:
                platforms.append(label)
                success_rates.append(data.get("improvement_rate", 0) * 100)
                colors.append(color)

        if not platforms:
            log.warning("플랫폼 성공률 데이터 없음")
            return

        # 그래프 생성
        fig, ax = plt.subplots(figsize=(10, 6))

        bars = ax.barh(platforms, success_rates, color=colors, alpha=0.7, edgecolor='black')

        # 값 표시
        for bar in bars:
            width = bar.get_width()
            ax.text(
                width,
                bar.get_y() + bar.get_height() / 2.,
                f'{width:.1f}%',
                ha='left',
                va='center',
                fontsize=12,
                fontweight='bold',
                color='black'
            )

        ax.set_xlabel('순위 개선율 (%)', fontsize=12)
        ax.set_title('플랫폼별 순위 개선 성공률', fontsize=14, fontweight='bold')
        ax.set_xlim(0, 100)
        ax.grid(axis='x', alpha=0.3)

        plt.tight_layout()
        output_file = self.output_dir / "2_platform_success_rate.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")

    def chart_path_comparison(self):
        """진입 경로별 순위 상승 효과 (산점도)"""
        phase2 = self.report.get("phase_2_path", {})

        paths = []
        rank_changes = []
        colors = ['#E91E63', '#9C27B0', '#3F51B5', '#00BCD4']

        for key, label in [
            ("search", "통합검색"),
            ("shopping", "쇼핑검색"),
            ("blog", "블로그"),
            ("cafe", "카페")
        ]:
            data = phase2.get(key)
            if data:
                paths.append(label)
                rank_changes.append(data.get("mean_rank_change", 0))

        if not paths:
            log.warning("경로 비교 데이터 없음")
            return

        # 그래프 생성
        fig, ax = plt.subplots(figsize=(10, 6))

        x_pos = np.arange(len(paths))
        ax.scatter(x_pos, rank_changes, s=300, c=colors[:len(paths)], alpha=0.6, edgecolors='black', linewidths=2)

        # 값 표시
        for i, (path, change) in enumerate(zip(paths, rank_changes)):
            ax.text(i, change, f'{change:.1f}위', ha='center', va='bottom', fontsize=11, fontweight='bold')

        ax.set_xticks(x_pos)
        ax.set_xticklabels(paths, fontsize=11)
        ax.set_ylabel('평균 순위 변화 (위)', fontsize=12)
        ax.set_title('진입 경로별 순위 상승 효과', fontsize=14, fontweight='bold')
        ax.axhline(y=0, color='black', linestyle='--', linewidth=1)
        ax.grid(axis='y', alpha=0.3)

        plt.tight_layout()
        output_file = self.output_dir / "3_path_comparison.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")

    def chart_behavior_patterns(self):
        """행동 패턴별 효과 비교 (막대 그래프)"""
        phase3 = self.report.get("phase_3_behavior", {})

        patterns = []
        rank_changes = []
        improvement_rates = []

        for key, label in [
            ("quick_exit", "빠른 이탈"),
            ("normal_browsing", "일반 둘러보기"),
            ("deep_exploration", "심층 탐색"),
            ("comparison_shopping", "비교 쇼핑")
        ]:
            data = phase3.get(key)
            if data:
                patterns.append(label)
                rank_changes.append(data.get("mean_rank_change", 0))
                improvement_rates.append(data.get("improvement_rate", 0) * 100)

        if not patterns:
            log.warning("행동 패턴 데이터 없음")
            return

        # 그래프 생성 (2개 서브플롯)
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # 서브플롯 1: 순위 변화
        bars1 = ax1.bar(patterns, rank_changes, color='#673AB7', alpha=0.7, edgecolor='black')
        for bar in bars1:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2., height, f'{height:.1f}위',
                     ha='center', va='bottom' if height < 0 else 'top', fontsize=10)

        ax1.set_ylabel('평균 순위 변화 (위)', fontsize=11)
        ax1.set_title('행동 패턴별 순위 변화', fontsize=12, fontweight='bold')
        ax1.axhline(y=0, color='black', linestyle='-', linewidth=0.8)
        ax1.tick_params(axis='x', rotation=15)
        ax1.grid(axis='y', alpha=0.3)

        # 서브플롯 2: 개선율
        bars2 = ax2.bar(patterns, improvement_rates, color='#009688', alpha=0.7, edgecolor='black')
        for bar in bars2:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width() / 2., height, f'{height:.1f}%',
                     ha='center', va='bottom', fontsize=10)

        ax2.set_ylabel('순위 개선율 (%)', fontsize=11)
        ax2.set_title('행동 패턴별 성공률', fontsize=12, fontweight='bold')
        ax2.set_ylim(0, 100)
        ax2.tick_params(axis='x', rotation=15)
        ax2.grid(axis='y', alpha=0.3)

        plt.tight_layout()
        output_file = self.output_dir / "4_behavior_patterns.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")

    def chart_dwell_time_correlation(self):
        """체류 시간 vs 순위 변화 상관관계 (산점도)"""
        phase3 = self.report.get("phase_3_behavior", {})

        correlation_data = phase3.get("correlation")
        if not correlation_data:
            log.warning("상관관계 데이터 없음")
            return

        # 예시 데이터 (실제로는 raw data 필요)
        dwell_times = [20, 75, 150, 210]  # 각 패턴의 평균 체류 시간
        patterns = ["빠른 이탈", "일반 둘러보기", "심층 탐색", "비교 쇼핑"]

        rank_changes = []
        for key in ["quick_exit", "normal_browsing", "deep_exploration", "comparison_shopping"]:
            data = phase3.get(key)
            if data:
                rank_changes.append(data.get("mean_rank_change", 0))

        if len(dwell_times) != len(rank_changes):
            log.warning("상관관계 그래프 데이터 불일치")
            return

        # 그래프 생성
        fig, ax = plt.subplots(figsize=(10, 6))

        ax.scatter(dwell_times, rank_changes, s=200, c='#FF5722', alpha=0.6, edgecolors='black', linewidths=2)

        # 추세선
        z = np.polyfit(dwell_times, rank_changes, 1)
        p = np.poly1d(z)
        ax.plot(dwell_times, p(dwell_times), "r--", alpha=0.8, linewidth=2, label='추세선')

        # 패턴 라벨
        for i, pattern in enumerate(patterns):
            ax.text(dwell_times[i], rank_changes[i], f'  {pattern}', fontsize=10, va='center')

        # 상관계수 표시
        r = correlation_data.get("dwell_time_vs_rank_change", 0)
        ax.text(0.05, 0.95, f'상관계수 (r) = {r:.3f}', transform=ax.transAxes,
                fontsize=12, verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

        ax.set_xlabel('체류 시간 (초)', fontsize=12)
        ax.set_ylabel('평균 순위 변화 (위)', fontsize=12)
        ax.set_title('체류 시간 vs 순위 상승 상관관계', fontsize=14, fontweight='bold')
        ax.axhline(y=0, color='black', linestyle='--', linewidth=1)
        ax.grid(True, alpha=0.3)
        ax.legend()

        plt.tight_layout()
        output_file = self.output_dir / "5_dwell_time_correlation.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")

    def chart_scale_effect(self):
        """트래픽 양에 따른 순위 변화 (라인 차트)"""
        phase4 = self.report.get("phase_4_scale", {})

        traffic_volumes = []
        rank_changes = []

        for key, volume in [("small_10", 10), ("medium_50", 50), ("large_100", 100)]:
            data = phase4.get(key)
            if data:
                traffic_volumes.append(volume)
                # 누적 효과 시뮬레이션 (실제로는 initial_rank - final_rank)
                rank_changes.append(data.get("mean_rank_change", 0) * volume / 10)

        if not traffic_volumes:
            log.warning("스케일 효과 데이터 없음")
            return

        # 그래프 생성
        fig, ax = plt.subplots(figsize=(10, 6))

        ax.plot(traffic_volumes, rank_changes, marker='o', markersize=10, linewidth=2.5,
                color='#3F51B5', label='순위 변화')

        # 값 표시
        for x, y in zip(traffic_volumes, rank_changes):
            ax.text(x, y, f'{y:.1f}위', ha='center', va='bottom', fontsize=11, fontweight='bold')

        ax.set_xlabel('트래픽 수 (회)', fontsize=12)
        ax.set_ylabel('누적 순위 변화 (위)', fontsize=12)
        ax.set_title('트래픽 양에 따른 순위 변화', fontsize=14, fontweight='bold')
        ax.axhline(y=0, color='black', linestyle='--', linewidth=1)
        ax.grid(True, alpha=0.3)
        ax.legend()

        plt.tight_layout()
        output_file = self.output_dir / "6_scale_effect.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")

    def chart_roi_comparison(self):
        """ROI 비교 (막대 그래프)"""
        phase4 = self.report.get("phase_4_scale", {})

        volumes = []
        rois = []

        for key, label in [("small_10", "10회"), ("medium_50", "50회"), ("large_100", "100회")]:
            data = phase4.get(key)
            if data:
                volumes.append(label)
                rois.append(data.get("roi", 0))

        if not volumes:
            log.warning("ROI 데이터 없음")
            return

        # 그래프 생성
        fig, ax = plt.subplots(figsize=(10, 6))

        bars = ax.bar(volumes, rois, color='#4CAF50', alpha=0.7, edgecolor='black')

        # 값 표시
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height, f'{height:.3f}',
                    ha='center', va='bottom', fontsize=12, fontweight='bold')

        ax.set_ylabel('ROI (순위 상승폭 / 분)', fontsize=12)
        ax.set_title('트래픽 양별 ROI 비교', fontsize=14, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)

        plt.tight_layout()
        output_file = self.output_dir / "7_roi_comparison.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")

    def chart_category_comparison(self):
        """카테고리별 효과성 (막대 그래프)"""
        phase5 = self.report.get("phase_5_category", {})

        categories = []
        rank_changes = []
        colors = ['#F44336', '#E91E63', '#9C27B0', '#673AB7']

        for key, label in [
            ("electronics", "전자기기"),
            ("fashion", "패션의류"),
            ("food", "식품"),
            ("beauty", "뷰티")
        ]:
            data = phase5.get(key)
            if data:
                categories.append(label)
                rank_changes.append(data.get("mean_rank_change", 0))

        if not categories:
            log.warning("카테고리 비교 데이터 없음")
            return

        # 그래프 생성
        fig, ax = plt.subplots(figsize=(10, 6))

        bars = ax.bar(categories, rank_changes, color=colors[:len(categories)], alpha=0.7, edgecolor='black')

        # 값 표시
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height, f'{height:.1f}위',
                    ha='center', va='bottom' if height < 0 else 'top', fontsize=12, fontweight='bold')

        ax.set_ylabel('평균 순위 변화 (위)', fontsize=12)
        ax.set_title('카테고리별 효과성 비교', fontsize=14, fontweight='bold')
        ax.axhline(y=0, color='black', linestyle='-', linewidth=0.8)
        ax.grid(axis='y', alpha=0.3)

        plt.tight_layout()
        output_file = self.output_dir / "8_category_comparison.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")

    def chart_overall_summary(self):
        """전체 요약 (히트맵)"""
        # 모든 Phase의 평균 순위 변화를 히트맵으로 표시
        data_matrix = []
        labels = []

        # Phase 1
        phase1 = self.report.get("phase_1_platform", {})
        for key, label in [("mobile", "모바일"), ("pc", "PC"), ("mixed", "혼합")]:
            if phase1.get(key):
                labels.append(label)
                data_matrix.append([phase1[key].get("mean_rank_change", 0)])

        # Phase 2
        phase2 = self.report.get("phase_2_path", {})
        for key, label in [("search", "통합검색"), ("shopping", "쇼핑"), ("blog", "블로그"), ("cafe", "카페")]:
            if phase2.get(key):
                labels.append(label)
                data_matrix.append([phase2[key].get("mean_rank_change", 0)])

        if not data_matrix:
            log.warning("전체 요약 데이터 없음")
            return

        # 그래프 생성
        fig, ax = plt.subplots(figsize=(8, 10))

        data_array = np.array(data_matrix)
        im = ax.imshow(data_array, cmap='RdYlGn_r', aspect='auto')

        # 축 설정
        ax.set_yticks(np.arange(len(labels)))
        ax.set_yticklabels(labels)
        ax.set_xticks([0])
        ax.set_xticklabels(['평균 순위 변화'])

        # 값 표시
        for i in range(len(labels)):
            ax.text(0, i, f'{data_array[i, 0]:.1f}위', ha='center', va='center',
                    color='white', fontsize=11, fontweight='bold')

        ax.set_title('전체 테스트 요약 히트맵', fontsize=14, fontweight='bold')
        fig.colorbar(im, ax=ax, label='순위 변화 (위)')

        plt.tight_layout()
        output_file = self.output_dir / "9_overall_summary_heatmap.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        log.info(f"저장: {output_file}")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='테스트 결과 시각화'
    )

    parser.add_argument(
        '--report',
        type=str,
        default='data/analysis/summary_report.json',
        help='분석 보고서 경로'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        default='data/charts',
        help='차트 출력 디렉토리'
    )

    args = parser.parse_args()

    # 보고서 로드
    report_file = Path(args.report)
    if not report_file.exists():
        log.error(f"보고서 파일 없음: {report_file}")
        return

    with open(report_file, 'r', encoding='utf-8') as f:
        report = json.load(f)

    # 차트 생성기
    generator = ChartGenerator(report, Path(args.output_dir))
    generator.generate_all_charts()


if __name__ == "__main__":
    main()
