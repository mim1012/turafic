@echo off
chcp 65001 > nul
title Naver Traffic - Install

echo ========================================
echo   Naver Traffic Runner - 설치
echo ========================================
echo.

REM 프로젝트 디렉토리로 이동
cd /d "%~dp0..\.."

REM Node.js 확인
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js가 설치되지 않았습니다.
    echo https://nodejs.org 에서 Node.js LTS를 설치하세요.
    pause
    exit /b 1
)

echo [INFO] Node.js 버전:
node --version
echo.

REM pnpm 확인 및 설치
where pnpm >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] pnpm 설치 중...
    npm install -g pnpm
)

echo [INFO] 의존성 설치 중...
pnpm install

echo.
echo ========================================
echo   설치 완료!
echo ========================================
echo.
echo 다음 단계:
echo 1. .env 파일 설정 (SUPABASE_PRODUCTION_URL, SUPABASE_PRODUCTION_KEY)
echo 2. run-traffic.bat 실행
echo.
pause
