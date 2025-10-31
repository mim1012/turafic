#!/bin/bash
# ===================================================================
# Navertrafic 전체 분석 파이프라인 자동 실행 (Linux/Mac)
# ===================================================================

set -e  # 에러 발생 시 즉시 종료

echo ""
echo "==================================================================================================="
echo "네이버 쇼핑 트래픽 테스트 종합 분석 파이프라인"
echo "==================================================================================================="
echo ""

# 현재 날짜/시간
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# 색상 코드
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[1/3] 통계 분석 중...${NC}"
python scripts/analyze_results.py \
  --results-dir data/test_results \
  --output "data/analysis/report_${TIMESTAMP}.json"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 통계 분석 실패${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}[2/3] 차트 생성 중...${NC}"
python scripts/generate_charts.py \
  --report "data/analysis/report_${TIMESTAMP}.json" \
  --output-dir "data/charts/charts_${TIMESTAMP}"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 차트 생성 실패${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}[3/3] HTML 보고서 생성 중...${NC}"
python scripts/generate_report.py \
  --report "data/analysis/report_${TIMESTAMP}.json" \
  --charts-dir "data/charts/charts_${TIMESTAMP}" \
  --output "data/reports/report_${TIMESTAMP}.html"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 보고서 생성 실패${NC}"
    exit 1
fi

echo ""
echo "==================================================================================================="
echo -e "${GREEN}✅ 전체 파이프라인 완료!${NC}"
echo "==================================================================================================="
echo ""
echo "📊 분석 보고서: data/analysis/report_${TIMESTAMP}.json"
echo "📈 차트: data/charts/charts_${TIMESTAMP}/"
echo "📄 HTML 보고서: data/reports/report_${TIMESTAMP}.html"
echo ""

# 운영체제 감지 및 브라우저 열기
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Mac
    echo "브라우저에서 보고서를 여시겠습니까? (y/n)"
    read -r OPEN_BROWSER
    if [[ "$OPEN_BROWSER" == "y" || "$OPEN_BROWSER" == "Y" ]]; then
        open "data/reports/report_${TIMESTAMP}.html"
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    echo "브라우저에서 보고서를 여시겠습니까? (y/n)"
    read -r OPEN_BROWSER
    if [[ "$OPEN_BROWSER" == "y" || "$OPEN_BROWSER" == "Y" ]]; then
        xdg-open "data/reports/report_${TIMESTAMP}.html"
    fi
fi

echo ""
echo "완료!"
