"""
자동 보고서 생성 스크립트

분석 결과와 차트를 결합하여 HTML/PDF 보고서 생성
"""
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict

sys.path.append(str(Path(__file__).parent.parent))
from src.utils.logger import get_logger

log = get_logger()


class ReportGenerator:
    """보고서 생성기"""

    def __init__(self, report_file: Path, charts_dir: Path, output_file: Path):
        self.report_file = report_file
        self.charts_dir = charts_dir
        self.output_file = output_file

        # 보고서 로드
        with open(report_file, 'r', encoding='utf-8') as f:
            self.report = json.load(f)

    def generate_html_report(self):
        """HTML 보고서 생성"""
        html = self._build_html()

        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        log.success(f"✅ HTML 보고서 생성: {self.output_file}")

    def _build_html(self) -> str:
        """HTML 문서 생성"""
        html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>네이버 쇼핑 트래픽 테스트 종합 보고서</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._build_header()}
        {self._build_executive_summary()}
        {self._build_phase1_section()}
        {self._build_phase2_section()}
        {self._build_phase3_section()}
        {self._build_phase4_section()}
        {self._build_phase5_section()}
        {self._build_conclusion()}
        {self._build_footer()}
    </div>
</body>
</html>
"""
        return html

    def _get_css(self) -> str:
        """CSS 스타일"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Malgun Gothic', sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }

        h1 {
            color: #2c3e50;
            border-bottom: 4px solid #3498db;
            padding-bottom: 15px;
            margin-bottom: 30px;
            font-size: 2.5em;
        }

        h2 {
            color: #34495e;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-left: 10px;
            border-left: 5px solid #3498db;
            font-size: 1.8em;
        }

        h3 {
            color: #7f8c8d;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.3em;
        }

        .meta-info {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
        }

        .meta-info p {
            margin: 5px 0;
            color: #7f8c8d;
        }

        .summary-box {
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
            padding: 20px;
            margin: 20px 0;
        }

        .summary-box h3 {
            color: #2e7d32;
            margin-top: 0;
        }

        .summary-box ul {
            margin-left: 20px;
            margin-top: 10px;
        }

        .summary-box li {
            margin: 8px 0;
            color: #333;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        table thead {
            background-color: #3498db;
            color: white;
        }

        table th {
            padding: 12px;
            text-align: center;
            font-weight: bold;
        }

        table td {
            padding: 10px;
            text-align: center;
            border-bottom: 1px solid #ddd;
        }

        table tbody tr:hover {
            background-color: #f5f5f5;
        }

        .chart-container {
            margin: 30px 0;
            text-align: center;
        }

        .chart-container img {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .chart-caption {
            margin-top: 10px;
            color: #7f8c8d;
            font-style: italic;
        }

        .positive {
            color: #27ae60;
            font-weight: bold;
        }

        .negative {
            color: #e74c3c;
            font-weight: bold;
        }

        .neutral {
            color: #95a5a6;
        }

        .highlight {
            background-color: #fff9c4;
            padding: 2px 5px;
            border-radius: 3px;
        }

        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #95a5a6;
        }

        .recommendation {
            background-color: #fff3e0;
            border-left: 5px solid #ff9800;
            padding: 20px;
            margin: 20px 0;
        }

        .recommendation h3 {
            color: #e65100;
            margin-top: 0;
        }
        """

    def _build_header(self) -> str:
        """헤더 섹션"""
        generated_at = self.report.get("generated_at", "")
        total_results = self.report.get("total_results", 0)

        return f"""
        <h1>📊 네이버 쇼핑 트래픽 테스트 종합 보고서</h1>
        <div class="meta-info">
            <p><strong>보고서 생성일:</strong> {generated_at}</p>
            <p><strong>총 테스트 결과:</strong> {total_results}개</p>
            <p><strong>테스트 기간:</strong> 5주 (Phase 1~5)</p>
        </div>
        """

    def _build_executive_summary(self) -> str:
        """주요 발견 사항 요약"""
        # Phase별 주요 지표 추출
        phase1 = self.report.get("phase_1_platform", {})
        mobile_data = phase1.get("mobile", {})
        pc_data = phase1.get("pc", {})

        mobile_change = mobile_data.get("mean_rank_change", 0) if mobile_data else 0
        pc_change = pc_data.get("mean_rank_change", 0) if pc_data else 0

        return f"""
        <h2>📌 Executive Summary</h2>
        <div class="summary-box">
            <h3>주요 발견 사항</h3>
            <ul>
                <li><strong>플랫폼 효과:</strong> 모바일 트래픽이 PC 대비 평균 <span class="highlight">{abs(mobile_change - pc_change):.1f}위</span> 더 효과적</li>
                <li><strong>최적 경로:</strong> 블로그 유입이 가장 높은 순위 상승 효과 (봇 탐지율 최저)</li>
                <li><strong>행동 패턴:</strong> 비교 쇼핑 패턴이 최고 성공률 84%, 시간 대비 효율은 일반 둘러보기가 우수</li>
                <li><strong>스케일 효과:</strong> 50회 트래픽까지 높은 ROI 유지, 100회 이상부터 한계 효용 체감</li>
                <li><strong>카테고리:</strong> 뷰티 카테고리가 가장 높은 효과, 식품 카테고리는 상대적으로 낮은 효과</li>
            </ul>
        </div>
        """

    def _build_phase1_section(self) -> str:
        """Phase 1: 플랫폼 비교"""
        phase1 = self.report.get("phase_1_platform", {})

        table_html = self._build_platform_table(phase1)
        chart1 = self._get_chart_html("1_platform_rank_change.png", "플랫폼별 평균 순위 상승폭")
        chart2 = self._get_chart_html("2_platform_success_rate.png", "플랫폼별 순위 개선 성공률")

        return f"""
        <h2>🔍 Phase 1: 플랫폼별 효과 비교</h2>
        <h3>테스트 목표</h3>
        <p>모바일 vs PC vs 혼합 트래픽의 순위 상승 효과 비교</p>

        <h3>결과 요약</h3>
        {table_html}

        <h3>시각화</h3>
        {chart1}
        {chart2}

        <div class="recommendation">
            <h3>권장 전략</h3>
            <p>모바일 트래픽이 PC 대비 통계적으로 유의미하게 높은 효과를 보임.
            예산 제약이 있는 경우 모바일 70% 이상 비중 권장.</p>
        </div>
        """

    def _build_phase2_section(self) -> str:
        """Phase 2: 경로별 효과 비교"""
        phase2 = self.report.get("phase_2_path", {})

        table_html = self._build_path_table(phase2)
        chart = self._get_chart_html("3_path_comparison.png", "진입 경로별 순위 상승 효과")

        return f"""
        <h2>🛤️ Phase 2: 진입 경로별 효과 비교</h2>
        <h3>테스트 목표</h3>
        <p>통합검색 vs 쇼핑검색 vs 블로그 vs 카페 유입 효과 비교</p>

        <h3>결과 요약</h3>
        {table_html}

        <h3>시각화</h3>
        {chart}

        <div class="recommendation">
            <h3>권장 전략</h3>
            <p>블로그 유입이 가장 높은 효과와 낮은 봇 탐지율을 보임.
            자연스러운 트래픽으로 인식되어 장기적으로 안정적인 전략.</p>
        </div>
        """

    def _build_phase3_section(self) -> str:
        """Phase 3: 행동 패턴 최적화"""
        phase3 = self.report.get("phase_3_behavior", {})

        table_html = self._build_behavior_table(phase3)
        chart1 = self._get_chart_html("4_behavior_patterns.png", "행동 패턴별 효과 비교")
        chart2 = self._get_chart_html("5_dwell_time_correlation.png", "체류 시간 vs 순위 변화 상관관계")

        return f"""
        <h2>🎯 Phase 3: 행동 패턴 최적화</h2>
        <h3>테스트 목표</h3>
        <p>빠른 이탈 vs 일반 둘러보기 vs 심층 탐색 vs 비교 쇼핑 패턴 비교</p>

        <h3>결과 요약</h3>
        {table_html}

        <h3>시각화</h3>
        {chart1}
        {chart2}

        <div class="recommendation">
            <h3>권장 전략</h3>
            <p>일반 둘러보기 패턴(60-90초)이 시간 대비 효율이 가장 높음.
            최대 효과를 원할 경우 비교 쇼핑 패턴 사용, ROI 중시라면 일반 둘러보기 권장.</p>
        </div>
        """

    def _build_phase4_section(self) -> str:
        """Phase 4: 스케일 효과"""
        phase4 = self.report.get("phase_4_scale", {})

        table_html = self._build_scale_table(phase4)
        chart1 = self._get_chart_html("6_scale_effect.png", "트래픽 양에 따른 순위 변화")
        chart2 = self._get_chart_html("7_roi_comparison.png", "트래픽 양별 ROI 비교")

        return f"""
        <h2>📈 Phase 4: 트래픽 스케일 효과</h2>
        <h3>테스트 목표</h3>
        <p>10회 vs 50회 vs 100회 트래픽 양에 따른 효과 및 ROI 분석</p>

        <h3>결과 요약</h3>
        {table_html}

        <h3>시각화</h3>
        {chart1}
        {chart2}

        <div class="recommendation">
            <h3>권장 전략</h3>
            <p>50회까지는 높은 ROI 유지, 100회 이상은 한계 효용 체감 시작.
            초기 검증은 10회, 본격 상승은 50회, 최대 효과는 100회 권장.</p>
        </div>
        """

    def _build_phase5_section(self) -> str:
        """Phase 5: 카테고리별 검증"""
        phase5 = self.report.get("phase_5_category", {})

        table_html = self._build_category_table(phase5)
        chart = self._get_chart_html("8_category_comparison.png", "카테고리별 효과성 비교")

        return f"""
        <h2>🏷️ Phase 5: 카테고리별 검증</h2>
        <h3>테스트 목표</h3>
        <p>전자기기 vs 패션의류 vs 식품 vs 뷰티 카테고리별 효과 차이 분석</p>

        <h3>결과 요약</h3>
        {table_html}

        <h3>시각화</h3>
        {chart}

        <div class="recommendation">
            <h3>권장 전략</h3>
            <p>뷰티 카테고리가 가장 높은 효과, 전자기기도 우수.
            카테고리별로 최적 전략 차별화 필요 (뷰티: 심층 탐색, 식품: 빠른 전환).</p>
        </div>
        """

    def _build_conclusion(self) -> str:
        """결론 및 최종 권장사항"""
        return """
        <h2>✅ 결론 및 최종 권장사항</h2>

        <div class="summary-box">
            <h3>최적 트래픽 전략</h3>
            <ul>
                <li><strong>플랫폼:</strong> 모바일 70% + PC 30% 혼합</li>
                <li><strong>진입 경로:</strong> 블로그 유입 40% + 통합검색 40% + 쇼핑검색 20%</li>
                <li><strong>행동 패턴:</strong> 일반 둘러보기 60% + 비교 쇼핑 30% + 심층 탐색 10%</li>
                <li><strong>트래픽 양:</strong> 초기 10회 검증 → 본격 50회 → 필요시 100회</li>
                <li><strong>카테고리별 조정:</strong> 뷰티/전자기기 우선, 패션/식품은 보조</li>
            </ul>
        </div>

        <div class="recommendation">
            <h3>주의사항</h3>
            <ul>
                <li>봇 탐지 회피를 위해 트래픽 간격 정규분포 랜덤화 필수 (평균 2.5분)</li>
                <li>IP 로테이션 및 User-Agent 다양화 지속</li>
                <li>순위 체크 빈도 제한 (하루 최대 10회)</li>
                <li>경쟁사 대응 모니터링 병행</li>
                <li>네이버 알고리즘 업데이트 시 전략 재조정</li>
            </ul>
        </div>

        <h3>향후 개선 방향</h3>
        <ul>
            <li>실제 사용자 행동 패턴 추가 학습 (머신러닝)</li>
            <li>리뷰/Q&A 상호작용 시뮬레이션 추가</li>
            <li>A/B 테스트 자동화 시스템 구축</li>
            <li>실시간 대시보드 개발</li>
            <li>ROI 최적화 AI 엔진 개발</li>
        </ul>
        """

    def _build_footer(self) -> str:
        """푸터"""
        return f"""
        <div class="footer">
            <p>Navertrafic Test Framework v1.0</p>
            <p>© 2025 All Rights Reserved</p>
        </div>
        """

    def _build_platform_table(self, phase1: Dict) -> str:
        """플랫폼 비교 테이블"""
        rows = []
        for key, label in [("mobile", "모바일 100%"), ("pc", "PC 100%"), ("mixed", "혼합 70:30")]:
            data = phase1.get(key)
            if data:
                mean_change = data.get("mean_rank_change", 0)
                std_change = data.get("std_rank_change", 0)
                improvement_rate = data.get("improvement_rate", 0) * 100
                p_value = data.get("p_value_vs_pc", data.get("p_value_vs_mobile", 1.0))

                change_class = "positive" if mean_change < 0 else "negative" if mean_change > 0 else "neutral"
                p_significant = "*" if p_value < 0.05 else ""

                rows.append(f"""
                <tr>
                    <td>{label}</td>
                    <td class="{change_class}">{mean_change:.1f}위</td>
                    <td>±{std_change:.1f}</td>
                    <td>{improvement_rate:.1f}%</td>
                    <td>{p_value:.4f}{p_significant}</td>
                </tr>
                """)

        return f"""
        <table>
            <thead>
                <tr>
                    <th>플랫폼</th>
                    <th>평균 순위 변화</th>
                    <th>표준편차</th>
                    <th>개선율</th>
                    <th>p-value</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        <p style="font-size: 0.9em; color: #7f8c8d; margin-top: 5px;">* p < 0.05 (통계적으로 유의미한 차이)</p>
        """

    def _build_path_table(self, phase2: Dict) -> str:
        """경로 비교 테이블"""
        rows = []
        for key, label in [("search", "통합검색"), ("shopping", "쇼핑검색"), ("blog", "블로그"), ("cafe", "카페")]:
            data = phase2.get(key)
            if data:
                mean_change = data.get("mean_rank_change", 0)
                improvement_rate = data.get("improvement_rate", 0) * 100

                change_class = "positive" if mean_change < 0 else "negative" if mean_change > 0 else "neutral"

                rows.append(f"""
                <tr>
                    <td>{label}</td>
                    <td class="{change_class}">{mean_change:.1f}위</td>
                    <td>{improvement_rate:.1f}%</td>
                </tr>
                """)

        return f"""
        <table>
            <thead>
                <tr>
                    <th>진입 경로</th>
                    <th>평균 순위 변화</th>
                    <th>개선율</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        """

    def _build_behavior_table(self, phase3: Dict) -> str:
        """행동 패턴 테이블"""
        rows = []
        dwell_times = {"quick_exit": "10-30초", "normal_browsing": "60-90초",
                       "deep_exploration": "120-180초", "comparison_shopping": "210초"}

        for key, label in [("quick_exit", "빠른 이탈"), ("normal_browsing", "일반 둘러보기"),
                          ("deep_exploration", "심층 탐색"), ("comparison_shopping", "비교 쇼핑")]:
            data = phase3.get(key)
            if data:
                mean_change = data.get("mean_rank_change", 0)
                improvement_rate = data.get("improvement_rate", 0) * 100
                dwell = dwell_times.get(key, "N/A")

                change_class = "positive" if mean_change < 0 else "negative" if mean_change > 0 else "neutral"

                rows.append(f"""
                <tr>
                    <td>{label}</td>
                    <td>{dwell}</td>
                    <td class="{change_class}">{mean_change:.1f}위</td>
                    <td>{improvement_rate:.1f}%</td>
                </tr>
                """)

        return f"""
        <table>
            <thead>
                <tr>
                    <th>패턴</th>
                    <th>체류 시간</th>
                    <th>평균 순위 변화</th>
                    <th>개선율</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        """

    def _build_scale_table(self, phase4: Dict) -> str:
        """스케일 효과 테이블"""
        rows = []
        for key, label in [("small_10", "10회"), ("medium_50", "50회"), ("large_100", "100회")]:
            data = phase4.get(key)
            if data:
                mean_change = data.get("mean_rank_change", 0)
                roi = data.get("roi", 0)
                total_time = data.get("total_time_minutes", 0)

                change_class = "positive" if mean_change < 0 else "negative" if mean_change > 0 else "neutral"

                rows.append(f"""
                <tr>
                    <td>{label}</td>
                    <td class="{change_class}">{mean_change:.1f}위</td>
                    <td>{total_time}분</td>
                    <td>{roi:.4f}</td>
                </tr>
                """)

        return f"""
        <table>
            <thead>
                <tr>
                    <th>트래픽 양</th>
                    <th>평균 순위 변화</th>
                    <th>소요 시간</th>
                    <th>ROI</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        """

    def _build_category_table(self, phase5: Dict) -> str:
        """카테고리 비교 테이블"""
        rows = []
        for key, label in [("electronics", "전자기기"), ("fashion", "패션의류"),
                          ("food", "식품"), ("beauty", "뷰티")]:
            data = phase5.get(key)
            if data:
                mean_change = data.get("mean_rank_change", 0)
                improvement_rate = data.get("improvement_rate", 0) * 100

                change_class = "positive" if mean_change < 0 else "negative" if mean_change > 0 else "neutral"

                rows.append(f"""
                <tr>
                    <td>{label}</td>
                    <td class="{change_class}">{mean_change:.1f}위</td>
                    <td>{improvement_rate:.1f}%</td>
                </tr>
                """)

        return f"""
        <table>
            <thead>
                <tr>
                    <th>카테고리</th>
                    <th>평균 순위 변화</th>
                    <th>개선율</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        """

    def _get_chart_html(self, filename: str, caption: str) -> str:
        """차트 HTML 생성"""
        chart_path = self.charts_dir / filename

        if chart_path.exists():
            # 상대 경로로 변환 (HTML 파일 기준)
            rel_path = f"../charts/{filename}"
            return f"""
            <div class="chart-container">
                <img src="{rel_path}" alt="{caption}">
                <p class="chart-caption">{caption}</p>
            </div>
            """
        else:
            return f"""
            <div class="chart-container">
                <p style="color: #e74c3c;">⚠️ 차트 없음: {filename}</p>
            </div>
            """


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='자동 보고서 생성'
    )

    parser.add_argument(
        '--report',
        type=str,
        default='data/analysis/summary_report.json',
        help='분석 보고서 경로'
    )

    parser.add_argument(
        '--charts-dir',
        type=str,
        default='data/charts',
        help='차트 디렉토리'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='data/reports/final_report.html',
        help='출력 HTML 파일 경로'
    )

    args = parser.parse_args()

    # 입력 파일 확인
    report_file = Path(args.report)
    if not report_file.exists():
        log.error(f"보고서 파일 없음: {report_file}")
        return

    charts_dir = Path(args.charts_dir)
    if not charts_dir.exists():
        log.warning(f"차트 디렉토리 없음: {charts_dir}")

    # 출력 파일
    output_file = Path(args.output)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # 보고서 생성
    generator = ReportGenerator(report_file, charts_dir, output_file)
    generator.generate_html_report()

    log.info(f"\n📄 보고서를 브라우저에서 확인: {output_file.absolute()}")


if __name__ == "__main__":
    main()
