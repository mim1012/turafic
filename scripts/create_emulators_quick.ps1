# ===================================================================
# 5개 에뮬레이터 빠른 생성 스크립트 (Windows PowerShell)
# ===================================================================

Write-Host ""
Write-Host "====================================================================================================" -ForegroundColor Cyan
Write-Host "Appium 에뮬레이터 빠른 생성 (5개)" -ForegroundColor Cyan
Write-Host "====================================================================================================" -ForegroundColor Cyan
Write-Host ""

# 에뮬레이터 개수
$count = 5

# 시스템 이미지 확인
Write-Host "[1/3] 시스템 이미지 확인 중..." -ForegroundColor Yellow
$systemImages = & sdkmanager --list | Select-String "system-images;android-31;google_apis;x86_64"

if (-not $systemImages) {
    Write-Host ""
    Write-Host "Android 12 (API 31) 시스템 이미지가 설치되지 않았습니다." -ForegroundColor Red
    Write-Host "설치 중... (1~2분 소요)" -ForegroundColor Yellow
    Write-Host ""

    & sdkmanager "system-images;android-31;google_apis;x86_64"

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "시스템 이미지 설치 실패!" -ForegroundColor Red
        Write-Host "수동 설치: Android Studio -> SDK Manager -> SDK Platforms -> Android 12.0" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "✅ 시스템 이미지 설치 완료" -ForegroundColor Green
} else {
    Write-Host "✅ 시스템 이미지 이미 설치됨" -ForegroundColor Green
}

Write-Host ""
Write-Host "[2/3] 에뮬레이터 생성 중..." -ForegroundColor Yellow
Write-Host ""

# 5개 에뮬레이터 생성
$created = 0
for ($i = 6; $i -lt (6 + $count); $i++) {
    $pc_id = "PC_" + $i.ToString("000")
    $avd_name = "Emulator_$pc_id"

    Write-Host "[$($i-5)/$count] $avd_name 생성 중..." -ForegroundColor Cyan

    # 기존 AVD 삭제 (있을 경우)
    & avdmanager delete avd -n $avd_name 2>$null

    # 새 AVD 생성
    echo "no" | avdmanager create avd `
        --name $avd_name `
        --package "system-images;android-31;google_apis;x86_64" `
        --device "pixel_5" `
        --force 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        $created++
        Write-Host "  ✅ $avd_name 생성 완료" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $avd_name 생성 실패" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "[3/3] 생성 결과 확인..." -ForegroundColor Yellow
Write-Host ""

# 생성된 AVD 목록 확인
$avdList = & avdmanager list avd | Select-String "Name:"

Write-Host "생성된 에뮬레이터 목록:" -ForegroundColor Cyan
$avdList | ForEach-Object {
    if ($_ -match "Emulator_PC_") {
        Write-Host "  - $_" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "====================================================================================================" -ForegroundColor Cyan
Write-Host "✅ 에뮬레이터 생성 완료: $created/$count 개" -ForegroundColor Green
Write-Host "====================================================================================================" -ForegroundColor Cyan
Write-Host ""

# 다음 단계 안내
Write-Host "다음 단계:" -ForegroundColor Yellow
Write-Host "  1. 터미널 1: appium" -ForegroundColor White
Write-Host "  2. 터미널 2: python run_appium_test.py --instances $count" -ForegroundColor White
Write-Host ""

# 에뮬레이터 시작 여부 물어보기
$start = Read-Host "에뮬레이터 1개를 테스트로 시작하시겠습니까? (y/n)"

if ($start -eq "y" -or $start -eq "Y") {
    Write-Host ""
    Write-Host "Emulator_PC_006 시작 중... (30초~2분 소요)" -ForegroundColor Yellow
    Write-Host ""

    Start-Process -FilePath "emulator" -ArgumentList "-avd", "Emulator_PC_006" -NoNewWindow

    Write-Host "에뮬레이터가 백그라운드에서 시작되었습니다." -ForegroundColor Green
    Write-Host "부팅 완료까지 30초~2분 소요됩니다." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "ADB 연결 확인:" -ForegroundColor Cyan
    Write-Host "  adb devices" -ForegroundColor White
    Write-Host ""
}

Write-Host "완료!" -ForegroundColor Green
