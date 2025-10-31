@echo off
REM ===================================================================
REM Navertrafic 전체 분석 파이프라인 자동 실행 (Windows)
REM ===================================================================

echo.
echo ===================================================================================================
echo 네이버 쇼핑 트래픽 테스트 종합 분석 파이프라인
echo ===================================================================================================
echo.

REM 현재 날짜/시간
set TIMESTAMP=%date:~0,4%%date:~5,2%%date:~8,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%

echo [1/3] 통계 분석 중...
python scripts/analyze_results.py ^
  --results-dir data/test_results ^
  --output data/analysis/report_%TIMESTAMP%.json

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ 통계 분석 실패
    pause
    exit /b 1
)

echo.
echo [2/3] 차트 생성 중...
python scripts/generate_charts.py ^
  --report data/analysis/report_%TIMESTAMP%.json ^
  --output-dir data/charts/charts_%TIMESTAMP%

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ 차트 생성 실패
    pause
    exit /b 1
)

echo.
echo [3/3] HTML 보고서 생성 중...
python scripts/generate_report.py ^
  --report data/analysis/report_%TIMESTAMP%.json ^
  --charts-dir data/charts/charts_%TIMESTAMP% ^
  --output data/reports/report_%TIMESTAMP%.html

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ 보고서 생성 실패
    pause
    exit /b 1
)

echo.
echo ===================================================================================================
echo ✅ 전체 파이프라인 완료!
echo ===================================================================================================
echo.
echo 📊 분석 보고서: data\analysis\report_%TIMESTAMP%.json
echo 📈 차트: data\charts\charts_%TIMESTAMP%\
echo 📄 HTML 보고서: data\reports\report_%TIMESTAMP%.html
echo.
echo 브라우저에서 확인하려면 아래 파일을 더블클릭하세요:
echo data\reports\report_%TIMESTAMP%.html
echo.

REM 자동으로 브라우저 열기 (선택사항)
set /p OPEN_BROWSER="보고서를 브라우저에서 여시겠습니까? (Y/N): "
if /i "%OPEN_BROWSER%"=="Y" (
    start data\reports\report_%TIMESTAMP%.html
)

pause
