@echo off
echo ================================
echo  Naver Rank Checker - Setup
echo ================================
echo.

REM Check Administrator Privileges
echo [1/7] Checking administrator privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Administrator privileges required.
    echo.
    echo Please right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)
echo OK: Administrator privileges confirmed
echo.

REM Check Node.js Installation
echo [2/7] Checking Node.js installation...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Node.js is not installed.
    echo.
    echo Please download and install Node.js LTS from:
    echo https://nodejs.org
    echo.
    echo After installation, run this script again.
    echo.
    start https://nodejs.org
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node --version') do set NODE_VERSION=%%i
echo OK: Node.js %NODE_VERSION% detected
echo.

REM Install pnpm
echo [3/7] Installing pnpm package manager...
call npm install -g pnpm
if %errorlevel% neq 0 (
    echo ERROR: pnpm installation failed
    pause
    exit /b 1
)
echo OK: pnpm installed successfully
echo.

REM Navigate to Project Directory
echo [4/7] Navigating to project directory...
echo Current dir before: %CD%
cd /d "%~dp0"
cd ..
echo Current dir after: %CD%
echo.

REM Create .env File
echo [5/7] Creating .env file...

if exist .env (
    echo WARNING: .env file already exists. Overwriting...
    attrib -R .env 2>nul
)

echo SUPABASE_URL=https://cwsdvgkjptuvbdtxcejt.supabase.co > .env
echo SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN3c2R2Z2tqcHR1dmJkdHhjZWp0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzcwMjIwOTAsImV4cCI6MjA1MjU5ODA5MH0.Dh64z4HFe-qX3YkWYtRBLlAB0JdWqm_2w-U6NtbBJEs >> .env
echo SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN3c2R2Z2tqcHR1dmJkdHhjZWp0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTczNzAyMjA5MCwiZXhwIjoyMDUyNTk4MDkwfQ.zVWXFvPzhQQ1Y1hBQgkCm8KWmpOD47TZ-e9ZjWnfBQo >> .env
echo DATABASE_URL=postgresql://postgres.cwsdvgkjptuvbdtxcejt:EGxhoDsQvygcwY5c@aws-0-ap-northeast-2.pooler.supabase.com:6543/postgres >> .env
echo DIRECT_URL=postgresql://postgres:EGxhoDsQvygcwY5c@db.cwsdvgkjptuvbdtxcejt.supabase.co:5432/postgres >> .env
echo DATABASE_PASSWORD=EGxhoDsQvygcwY5c >> .env
echo NODE_ENV=production >> .env

attrib +R .env

echo OK: .env file created successfully
echo.

REM Install Dependencies
echo [6/7] Installing project dependencies...
echo This may take a few minutes on first run
echo.

call pnpm install --frozen-lockfile
if %errorlevel% neq 0 (
    echo ERROR: Dependency installation failed
    pause
    exit /b 1
)
echo OK: Dependencies installed successfully
echo.

echo [6.1/7] Downloading Puppeteer Chromium...
echo Approximately 200MB, downloaded once
echo.

call npx puppeteer browsers install chrome
if %errorlevel% neq 0 (
    echo ERROR: Chromium download failed
    pause
    exit /b 1
)
echo OK: Chromium downloaded successfully
echo.

REM Run Initial Test
echo [7/7] Running initial test...
echo Testing with 1 keyword to verify setup
echo.
echo Current directory: %CD%
echo.

call npx tsx rank-check/batch/check-batch-keywords.ts --limit=1
if %errorlevel% neq 0 (
    echo.
    echo WARNING: Initial test failed
    echo Please check the error messages above.
    echo.
    pause
    exit /b 1
)

echo.
echo ================================
echo SUCCESS: Setup completed!
echo ================================
echo.
echo Next steps:
echo 1. Run run-rank-check.bat to process all keywords
echo 2. Check README.txt for scheduling instructions
echo.
pause
