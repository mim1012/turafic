@echo off
chcp 65001 > nul
title Naver Traffic Runner

echo ========================================
echo   Naver Shopping Traffic Runner
echo ========================================
echo.

REM 프로젝트 디렉토리로 이동
cd /d "%~dp0..\.."

REM Node.js 확인
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js가 설치되지 않았습니다.
    pause
    exit /b 1
)

REM .env 파일 확인
if not exist ".env" (
    echo [ERROR] .env 파일이 없습니다.
    echo .env.example을 복사하여 .env를 생성하세요.
    pause
    exit /b 1
)

echo [INFO] 트래픽 Runner 시작...
echo.

REM 트래픽 실행
npx tsx scripts/production/naver-traffic-runner.ts

echo.
echo [INFO] 트래픽 Runner 종료
pause
