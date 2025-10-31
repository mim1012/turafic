# Appium 설치 및 설정 가이드

**작성일**: 2025-11-01
**대상**: Windows 환경
**목표**: 27개 Android 에뮬레이터 팜 구축

---

## 📋 목차

1. [사전 요구사항](#1-사전-요구사항)
2. [Node.js 설치](#2-nodejs-설치)
3. [Appium 설치](#3-appium-설치)
4. [Android SDK 설치](#4-android-sdk-설치)
5. [환경 변수 설정](#5-환경-변수-설정)
6. [Appium Doctor 검증](#6-appium-doctor-검증)
7. [Python 클라이언트 설치](#7-python-클라이언트-설치)
8. [에뮬레이터 생성](#8-에뮬레이터-생성)
9. [테스트 실행](#9-테스트-실행)
10. [트러블슈팅](#10-트러블슈팅)

---

## 1. 사전 요구사항

### 시스템 요구사항

**최소 사양**:
- CPU: 8코어 이상 (권장: 16코어)
- RAM: 32GB 이상 (권장: 64GB)
- 디스크: SSD 200GB 이상
- OS: Windows 10/11 64bit

**27개 에뮬레이터 동시 실행 시**:
- CPU: 32코어 이상
- RAM: 64GB 이상
- 디스크: SSD 500GB 이상

### 필수 소프트웨어 체크리스트

- [ ] Node.js 16.x 이상
- [ ] Java JDK 11 이상
- [ ] Android SDK (Android Studio 포함)
- [ ] Python 3.10+
- [ ] Git

---

## 2. Node.js 설치

Appium은 Node.js 기반이므로 먼저 Node.js를 설치해야 합니다.

### 2-1. Node.js 다운로드 및 설치

```bash
# 방법 1: 공식 사이트에서 다운로드
# https://nodejs.org/en/download/
# LTS 버전 다운로드 후 설치

# 방법 2: Chocolatey 사용 (관리자 권한 PowerShell)
choco install nodejs-lts

# 방법 3: Scoop 사용
scoop install nodejs-lts
```

### 2-2. 설치 확인

```bash
# 버전 확인
node --version
# 출력 예시: v18.17.0

npm --version
# 출력 예시: 9.6.7
```

**최소 버전**: Node.js 16.x, npm 8.x

---

## 3. Appium 설치

### 3-1. Appium 2.x 설치 (최신 버전)

```bash
# 전역 설치 (관리자 권한 PowerShell)
npm install -g appium

# 설치 확인
appium --version
# 출력 예시: 2.4.1
```

### 3-2. Appium 드라이버 설치

Android 자동화를 위해 UiAutomator2 드라이버를 설치합니다.

```bash
# UiAutomator2 드라이버 설치
appium driver install uiautomator2

# 설치된 드라이버 확인
appium driver list --installed
# 출력 예시:
# ✔ uiautomator2@2.34.1 [installed (npm)]
```

### 3-3. Appium Inspector 설치 (선택사항)

GUI로 앱 요소를 검사할 수 있는 도구입니다.

```bash
# 다운로드: https://github.com/appium/appium-inspector/releases
# Appium-Inspector-windows-2024.x.x.exe 다운로드 후 설치
```

---

## 4. Android SDK 설치

### 4-1. Android Studio 설치

가장 쉬운 방법은 Android Studio를 설치하는 것입니다.

```bash
# 다운로드: https://developer.android.com/studio
# Android Studio 설치 후 SDK Manager 실행
```

### 4-2. SDK 구성 요소 설치

Android Studio → Tools → SDK Manager 에서 다음 항목 설치:

**SDK Platforms** 탭:
- [ ] Android 12.0 (API Level 31)
- [ ] Android 11.0 (API Level 30)
- [ ] Android 10.0 (API Level 29)
- [ ] Android 9.0 (API Level 28)

**SDK Tools** 탭:
- [ ] Android SDK Build-Tools
- [ ] Android SDK Platform-Tools
- [ ] Android Emulator
- [ ] Intel x86 Emulator Accelerator (HAXM installer)

### 4-3. 명령줄 도구만 설치 (경량 방식)

Android Studio 없이 명령줄 도구만 설치하려면:

```bash
# 다운로드: https://developer.android.com/studio#command-tools
# commandlinetools-win-*.zip 다운로드

# 압축 해제: C:\Android\cmdline-tools\

# SDK Manager로 필요 항목 설치
cd C:\Android\cmdline-tools\bin
sdkmanager "platform-tools" "platforms;android-31" "build-tools;31.0.0" "emulator"
```

---

## 5. 환경 변수 설정

### 5-1. 시스템 환경 변수 추가

**Windows 설정 방법**:

1. `Win + R` → `sysdm.cpl` → Enter
2. "고급" 탭 → "환경 변수" 버튼 클릭

**새로운 시스템 변수 추가**:

| 변수 이름 | 변수 값 (예시) |
|----------|---------------|
| `ANDROID_HOME` | `C:\Users\사용자명\AppData\Local\Android\Sdk` |
| `JAVA_HOME` | `C:\Program Files\Java\jdk-11.0.15` |

**Path 변수에 추가**:

```
%ANDROID_HOME%\platform-tools
%ANDROID_HOME%\emulator
%ANDROID_HOME%\tools
%ANDROID_HOME%\tools\bin
%JAVA_HOME%\bin
```

### 5-2. 환경 변수 확인

```bash
# 새 PowerShell 열어서 확인
echo $env:ANDROID_HOME
# 출력: C:\Users\사용자명\AppData\Local\Android\Sdk

echo $env:JAVA_HOME
# 출력: C:\Program Files\Java\jdk-11.0.15

adb --version
# 출력: Android Debug Bridge version 1.0.41

emulator -version
# 출력: Android emulator version 31.3.10.0
```

---

## 6. Appium Doctor 검증

Appium 환경이 올바르게 설정되었는지 검증합니다.

### 6-1. Appium Doctor 설치

```bash
npm install -g appium-doctor
```

### 6-2. 환경 검증

```bash
# Android 환경 검증
appium-doctor --android

# 출력 예시:
# info AppiumDoctor Appium Doctor v.2.0.0
# info AppiumDoctor ### Diagnostic for necessary dependencies starting ###
# ✔ ANDROID_HOME is set to: C:\Users\PC_1M\AppData\Local\Android\Sdk
# ✔ JAVA_HOME is set to: C:\Program Files\Java\jdk-11.0.15
# ✔ adb exists at: C:\Users\PC_1M\AppData\Local\Android\Sdk\platform-tools\adb.exe
# ✔ android exists at: C:\Users\PC_1M\AppData\Local\Android\Sdk\tools\android.bat
# ✔ emulator exists at: C:\Users\PC_1M\AppData\Local\Android\Sdk\emulator\emulator.exe
# ...
# info AppiumDoctor ### Diagnostic for necessary dependencies completed, no fix needed. ###
```

**모든 항목이 ✔ 표시되어야 합니다.**

---

## 7. Python 클라이언트 설치

### 7-1. Appium Python Client 설치

```bash
# 가상환경 활성화
cd D:\Project\Navertrafic
venv\Scripts\activate

# Appium Python 클라이언트 설치
pip install Appium-Python-Client
```

### 7-2. requirements.txt 업데이트 확인

`requirements.txt`에 이미 포함되어 있는지 확인:

```bash
cat requirements.txt | grep Appium
# 출력: Appium-Python-Client>=3.1.0
```

---

## 8. 에뮬레이터 생성

### 8-1. AVD (Android Virtual Device) 생성

**방법 1: Android Studio GUI 사용**

1. Android Studio → Tools → AVD Manager
2. "Create Virtual Device" 클릭
3. 기기 선택 (예: Pixel 5)
4. 시스템 이미지 선택 (예: Android 12.0 API 31)
5. AVD 이름 설정: `Emulator_PC_006`
6. "Finish" 클릭

**방법 2: 명령줄 사용 (대량 생성)**

```bash
# AVD Manager 명령어
avdmanager create avd -n Emulator_PC_006 -k "system-images;android-31;google_apis;x86_64"
avdmanager create avd -n Emulator_PC_007 -k "system-images;android-31;google_apis;x86_64"
# ... 27개 생성

# 생성된 AVD 목록 확인
avdmanager list avd
```

### 8-2. 자동 생성 스크립트

```powershell
# scripts/create_emulators.ps1

# 27개 에뮬레이터 자동 생성
for ($i=6; $i -le 35; $i++) {
    $pc_id = "PC_" + $i.ToString("000")
    $avd_name = "Emulator_$pc_id"

    Write-Host "Creating $avd_name..."

    avdmanager create avd `
        -n $avd_name `
        -k "system-images;android-31;google_apis;x86_64" `
        --device "pixel_5" `
        --force
}

Write-Host "27개 에뮬레이터 생성 완료!"
```

실행:
```bash
powershell -ExecutionPolicy Bypass -File scripts/create_emulators.ps1
```

### 8-3. 에뮬레이터 시작 테스트

```bash
# 단일 에뮬레이터 시작
emulator -avd Emulator_PC_006

# 백그라운드 시작
emulator -avd Emulator_PC_006 -no-window -no-audio &

# ADB로 연결 확인
adb devices
# 출력:
# List of devices attached
# emulator-5554   device
```

---

## 9. 테스트 실행

### 9-1. 간단한 연결 테스트

```python
# test_appium_connection.py

from appium import webdriver
from appium.options.android import UiAutomator2Options

# Appium 옵션 설정
options = UiAutomator2Options()
options.platform_name = "Android"
options.automation_name = "UiAutomator2"
options.device_name = "emulator-5554"
options.browser_name = "Chrome"

# Appium 서버 연결
driver = webdriver.Remote('http://localhost:4723', options=options)

# 네이버 접속 테스트
driver.get('https://m.naver.com')
print(f"페이지 제목: {driver.title}")

# 종료
driver.quit()
print("✅ Appium 연결 테스트 성공!")
```

### 9-2. 테스트 실행

```bash
# 터미널 1: Appium 서버 시작
appium

# 터미널 2: 에뮬레이터 시작
emulator -avd Emulator_PC_006

# 터미널 3: 테스트 실행
python test_appium_connection.py
```

**예상 출력**:
```
페이지 제목: NAVER
✅ Appium 연결 테스트 성공!
```

---

## 10. 트러블슈팅

### 문제 1: "ANDROID_HOME is not set"

**증상**:
```
error: ANDROID_HOME is not set and "android" command not in your PATH
```

**해결**:
1. 환경 변수 설정 확인 ([5. 환경 변수 설정](#5-환경-변수-설정))
2. PowerShell 재시작
3. `echo $env:ANDROID_HOME` 확인

---

### 문제 2: "Could not find adb"

**증상**:
```
error: Could not find 'adb' in PATH
```

**해결**:
```bash
# Path에 platform-tools 추가
# 환경 변수 Path에 추가:
%ANDROID_HOME%\platform-tools

# PowerShell 재시작 후 확인
adb --version
```

---

### 문제 3: "INSTALL_FAILED_INSUFFICIENT_STORAGE"

**증상**:
```
error: INSTALL_FAILED_INSUFFICIENT_STORAGE
```

**해결**:
```bash
# AVD 디스크 크기 증가
avdmanager create avd -n Emulator_PC_006 \
  -k "system-images;android-31;google_apis;x86_64" \
  -c 4096M  # 4GB 내부 저장소
```

---

### 문제 4: "Connection refused" (Appium 서버 미실행)

**증상**:
```
selenium.common.exceptions.WebDriverException: Message:
Connection refused: Could not connect to Appium server
```

**해결**:
```bash
# Appium 서버 시작 (별도 터미널)
appium

# 또는 특정 포트 지정
appium -p 4723
```

---

### 문제 5: 에뮬레이터가 너무 느림

**증상**: 에뮬레이터 실행이 매우 느리거나 먹통

**해결**:

**방법 1: Intel HAXM 설치 (Intel CPU)**
```bash
# SDK Manager에서 설치
# Intel x86 Emulator Accelerator (HAXM installer)

# 또는 수동 설치
# https://github.com/intel/haxm/releases
```

**방법 2: AMD 프로세서인 경우**
```bash
# Windows Hypervisor Platform 활성화
# 제어판 → 프로그램 → Windows 기능 켜기/끄기
# "Windows Hypervisor Platform" 체크
# 재부팅
```

**방법 3: 에뮬레이터 성능 옵션**
```bash
# GPU 가속 사용
emulator -avd Emulator_PC_006 -gpu host

# 코어 수 증가
emulator -avd Emulator_PC_006 -cores 4

# RAM 증가
emulator -avd Emulator_PC_006 -memory 4096
```

---

### 문제 6: 27개 에뮬레이터 동시 실행 시 리소스 부족

**증상**: 시스템이 느려지거나 에뮬레이터가 죽음

**해결**:

**방법 1: 경량 모드로 실행**
```bash
emulator -avd Emulator_PC_006 \
  -no-window \        # GUI 없음
  -no-audio \         # 오디오 없음
  -no-boot-anim \     # 부팅 애니메이션 없음
  -memory 2048 \      # RAM 2GB로 제한
  -cores 1            # 1코어만 사용
```

**방법 2: 단계적 시작 (5개씩)**
```python
# 27개를 한 번에 시작하지 말고 5개씩 단계적 시작
import subprocess
import time

for i in range(6, 36, 5):  # 6, 11, 16, 21, 26, 31
    for j in range(i, min(i+5, 36)):
        avd_name = f"Emulator_PC_{j:03d}"
        subprocess.Popen([
            'emulator', '-avd', avd_name,
            '-no-window', '-no-audio'
        ])

    time.sleep(30)  # 30초 대기 후 다음 5개 시작
```

**방법 3: 클라우드 에뮬레이터 사용**
- AWS Device Farm
- Firebase Test Lab
- BrowserStack App Automate

---

### 문제 7: Chrome 브라우저 버전 불일치

**증상**:
```
session not created: This version of ChromeDriver only supports Chrome version 96
```

**해결**:
```bash
# Chromedriver 자동 다운로드 설정
pip install webdriver-manager

# 코드에서 자동 관리
from webdriver_manager.chrome import ChromeDriverManager
from selenium import webdriver

driver = webdriver.Chrome(ChromeDriverManager().install())
```

---

## 🎉 완료 체크리스트

설치가 완료되면 다음을 확인하세요:

- [ ] `node --version` 정상 출력
- [ ] `appium --version` 정상 출력
- [ ] `appium driver list --installed` → uiautomator2 표시
- [ ] `adb --version` 정상 출력
- [ ] `emulator -version` 정상 출력
- [ ] `appium-doctor --android` → 모든 항목 ✔
- [ ] `pip list | grep Appium` → Appium-Python-Client 표시
- [ ] 에뮬레이터 1개 시작 성공
- [ ] `test_appium_connection.py` 실행 성공

**모든 항목이 체크되면 다음 단계로 진행할 수 있습니다!**

---

## 📚 다음 단계

1. **에뮬레이터 팜 구현** → `src/automation/appium_farm.py` 작성
2. **스케줄러 구현** → `src/automation/scheduler.py` 작성
3. **테스트 실행** → `run_appium_test.py` 작성

자세한 내용은 `APPIUM_INTEGRATION.md` 참조

---

**작성일**: 2025-11-01
**환경**: Windows 10/11
**Appium 버전**: 2.x
**핵심**: 단계별 설치 후 반드시 검증!
