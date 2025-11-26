@echo off
setlocal enabledelayedexpansion

REM Environment Validation
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed.
    echo.
    echo Please run setup.bat first.
    echo.
    pause
    exit /b 1
)

cd /d "%~dp0"
cd ..

if not exist ".env" (
    echo ERROR: .env file not found.
    echo.
    echo Please run setup.bat first.
    echo.
    pause
    exit /b 1
)

REM Create Log Directory
if not exist "batch-scripts\logs" mkdir batch-scripts\logs

REM Generate Timestamp
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set YEAR=%%a
    set MONTH=%%b
    set DAY=%%c
)
for /f "tokens=1-2 delims=:. " %%a in ('time /t') do (
    set HOUR=%%a
    set MINUTE=%%b
)

set HOUR=%HOUR: =0%
set MINUTE=%MINUTE: =0%

set TIMESTAMP=%YEAR%%MONTH%%DAY%-%HOUR%%MINUTE%
set LOG_FILE=rank-check-%TIMESTAMP%.log

REM Execution Start
echo ================================
echo  Naver Rank Checker - Execute
echo ================================
echo Start time: %date% %time%
echo Log file: batch-scripts\logs\%LOG_FILE%
echo Current directory: %CD%
echo ================================
echo.

REM Execute Main Script
call npx tsx rank-check/batch/check-batch-keywords.ts %* 2>&1 | tee batch-scripts\logs\%LOG_FILE%

set EXIT_CODE=%errorlevel%

REM Execution Result
echo.
echo ================================
if %EXIT_CODE% equ 0 (
    echo SUCCESS: Execution completed
) else (
    echo ERROR: Execution failed - code: %EXIT_CODE%
)
echo ================================
echo End time: %date% %time%
echo Log path: batch-scripts\logs\%LOG_FILE%
echo ================================
echo.

REM Skip pause when running from Task Scheduler
if "%1"=="" (
    pause
)

exit /b %EXIT_CODE%
