@echo off
echo ================================
echo  Naver Rank Checker - Setup
echo ================================
echo.

echo [1/7] Checking administrator privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Administrator privileges required.
    echo Please right-click this file and select "Run as administrator"
    pause
    exit /b 1
)
echo OK: Administrator confirmed
echo.

echo [2/7] Checking Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed.
    echo Please install from https://nodejs.org
    start https://nodejs.org
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node --version') do set NODE_VERSION=%%i
echo OK: Node.js %NODE_VERSION%
echo.

echo [3/7] Installing pnpm...
call npm install -g pnpm
if %errorlevel% neq 0 (
    echo ERROR: pnpm installation failed
    pause
    exit /b 1
)
echo OK: pnpm installed
echo.

echo [4/7] Navigating to project directory...
cd /d "%~dp0"
cd ..
echo OK: %CD%
echo.

echo [5/7] Creating .env file...

if exist .env (
    echo WARNING: .env file exists. Overwriting...
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

echo OK: .env created
echo.

echo [6/7] Installing dependencies...
echo This may take several minutes
echo.

call pnpm install
if %errorlevel% neq 0 (
    echo ERROR: Dependency installation failed
    pause
    exit /b 1
)
echo OK: Dependencies installed
echo.

echo [6.1/7] Chromium download (optional)...
echo You can skip this - it will download on first run
echo Press Ctrl+C to skip, or wait...
echo.

call npx puppeteer browsers install chrome
if %errorlevel% neq 0 (
    echo WARNING: Chromium download failed or skipped
    echo Will download automatically on first run
    echo.
)

echo [7/7] Initial test...
echo.

call npx tsx rank-check/batch/check-batch-keywords.ts --limit=1
if %errorlevel% neq 0 (
    echo WARNING: Test failed
    echo Check errors above
    pause
    exit /b 1
)

echo.
echo ================================
echo SUCCESS: Setup completed!
echo ================================
echo.
echo Next steps:
echo 1. Run run-rank-check.bat
echo 2. Check README.txt for scheduling
echo.
pause
