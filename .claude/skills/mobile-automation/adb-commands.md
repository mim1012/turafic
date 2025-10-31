# ADB 명령어 레퍼런스

Android Debug Bridge (ADB) 명령어 모음입니다.

## 기본 명령어

### 기기 관리
```bash
# ADB 버전 확인
adb --version

# ADB 서버 시작
adb start-server

# ADB 서버 종료
adb kill-server

# 연결된 기기 목록
adb devices

# 특정 기기 선택 (여러 기기 연결 시)
adb -s <device_id> <command>
```

### 셸 접속
```bash
# 셸 접속
adb shell

# 단일 명령 실행
adb shell <command>

# 루트 권한으로 재시작 (루팅 기기만)
adb root
```

## 앱 관리

### 앱 설치/제거
```bash
# APK 설치
adb install app.apk

# 기존 앱 재설치 (데이터 유지)
adb install -r app.apk

# 앱 제거
adb uninstall com.package.name

# 앱 데이터 유지하고 제거
adb uninstall -k com.package.name
```

### 앱 실행
```bash
# 앱 실행
adb shell am start -n com.package.name/.MainActivity

# URL 열기 (Chrome)
adb shell am start -a android.intent.action.VIEW -d "https://naver.com"

# 앱 강제 종료
adb shell am force-stop com.package.name

# 설치된 패키지 목록
adb shell pm list packages

# 특정 패키지 검색
adb shell pm list packages | grep chrome
```

## Input 명령어

### 터치 이벤트
```bash
# 화면 탭 (x, y 좌표)
adb shell input tap 500 1000

# 화면 좌표 확인을 위한 포인터 표시 활성화
adb shell settings put system pointer_location 1
```

### 스와이프 (스크롤)
```bash
# 기본 형식
adb shell input swipe <x1> <y1> <x2> <y2> [duration_ms]

# 위로 스크롤 (화면 하단 → 상단)
adb shell input swipe 500 1500 500 500 300

# 아래로 스크롤 (화면 상단 → 하단)
adb shell input swipe 500 500 500 1500 300

# 좌우 스와이프
adb shell input swipe 800 1000 200 1000 300  # 오른쪽 → 왼쪽
adb shell input swipe 200 1000 800 1000 300  # 왼쪽 → 오른쪽
```

### 텍스트 입력
```bash
# 영문 텍스트 입력
adb shell input text "Hello"

# 공백 처리 (%s 사용)
adb shell input text "Hello%sWorld"

# 한글 입력 (키보드 앱 사용 권장)
# 직접 입력은 인코딩 문제로 어려움
```

### 키 이벤트
```bash
# 뒤로 가기
adb shell input keyevent KEYCODE_BACK

# 홈 버튼
adb shell input keyevent KEYCODE_HOME

# 최근 앱 (멀티태스킹)
adb shell input keyevent KEYCODE_APP_SWITCH

# 전원 버튼
adb shell input keyevent KEYCODE_POWER

# 볼륨 업/다운
adb shell input keyevent KEYCODE_VOLUME_UP
adb shell input keyevent KEYCODE_VOLUME_DOWN

# Enter (검색 실행)
adb shell input keyevent KEYCODE_ENTER

# 메뉴 버튼
adb shell input keyevent KEYCODE_MENU
```

**주요 KeyCode 목록**:
```
KEYCODE_HOME = 3
KEYCODE_BACK = 4
KEYCODE_ENTER = 66
KEYCODE_DEL = 67
KEYCODE_MENU = 82
KEYCODE_POWER = 26
KEYCODE_VOLUME_UP = 24
KEYCODE_VOLUME_DOWN = 25
KEYCODE_APP_SWITCH = 187
```

## 네트워크 관리

### 비행기모드
```bash
# 비행기모드 활성화
adb shell cmd connectivity airplane-mode enable

# 비행기모드 비활성화
adb shell cmd connectivity airplane-mode disable

# 네트워크 상태 확인
adb shell dumpsys connectivity
adb shell dumpsys connectivity | grep "NetworkAgentInfo"

# WiFi 상태 확인
adb shell dumpsys wifi | grep "mWifiInfo"
```

### IP 주소 확인
```bash
# WiFi IP 주소
adb shell ip addr show wlan0

# 모바일 데이터 IP 주소
adb shell ip addr show rmnet_data0
```

## 화면 관련

### 스크린샷
```bash
# 스크린샷 찍기
adb shell screencap /sdcard/screenshot.png

# PC로 가져오기
adb pull /sdcard/screenshot.png .

# 한 번에 실행
adb shell screencap -p /sdcard/screenshot.png && adb pull /sdcard/screenshot.png .
```

### 화면 녹화
```bash
# 화면 녹화 시작 (최대 180초)
adb shell screenrecord /sdcard/demo.mp4

# 시간 제한 설정
adb shell screenrecord --time-limit 30 /sdcard/demo.mp4

# 녹화 중지 (Ctrl+C)

# 파일 가져오기
adb pull /sdcard/demo.mp4 .
```

### 화면 정보
```bash
# 화면 해상도
adb shell wm size

# 화면 밀도 (DPI)
adb shell wm density

# 화면 꺼짐 시간 설정 (밀리초, 0 = 무제한)
adb shell settings put system screen_off_timeout 0

# 화면 밝기 설정 (0~255)
adb shell settings put system screen_brightness 128
```

## 파일 관리

### 파일 전송
```bash
# PC → 기기
adb push local_file.txt /sdcard/

# 기기 → PC
adb pull /sdcard/file.txt .

# 디렉토리 전송
adb push local_folder/ /sdcard/folder/
```

### 파일 시스템
```bash
# 파일 목록
adb shell ls /sdcard/

# 파일 삭제
adb shell rm /sdcard/file.txt

# 디렉토리 생성
adb shell mkdir /sdcard/newfolder

# 디렉토리 삭제
adb shell rm -r /sdcard/folder
```

## 시스템 정보

### 기기 정보
```bash
# 기기 모델
adb shell getprop ro.product.model

# Android 버전
adb shell getprop ro.build.version.release

# SDK 버전
adb shell getprop ro.build.version.sdk

# 제조사
adb shell getprop ro.product.manufacturer

# 일련번호
adb shell getprop ro.serialno

# 배터리 정보
adb shell dumpsys battery

# CPU 정보
adb shell cat /proc/cpuinfo

# 메모리 정보
adb shell cat /proc/meminfo
```

### 설정 확인/변경
```bash
# 설정 목록
adb shell settings list system
adb shell settings list secure
adb shell settings list global

# 특정 설정 확인
adb shell settings get system screen_brightness

# 설정 변경
adb shell settings put system screen_brightness 100
```

## 로그 관리

### Logcat
```bash
# 로그 실시간 출력
adb logcat

# 특정 태그만 필터링
adb logcat -s TAG_NAME

# 로그 저장
adb logcat > logcat.txt

# 로그 초기화
adb logcat -c

# 로그 레벨 필터링
adb logcat *:E  # 에러만
adb logcat *:W  # 경고 이상
adb logcat *:I  # 정보 이상
```

## 개발자 옵션

### USB 디버깅
```bash
# 개발자 옵션 활성화 여부 확인
adb shell settings get global development_settings_enabled

# USB 디버깅 활성화 (루트 필요)
adb shell settings put global adb_enabled 1
```

### 성능 모니터링
```bash
# CPU 사용률
adb shell top

# 메모리 사용률
adb shell dumpsys meminfo

# 특정 프로세스 메모리
adb shell dumpsys meminfo com.android.chrome
```

## 고급 명령어

### 포트 포워딩
```bash
# TCP 포트 포워딩 (PC:9222 → 기기:9222)
adb forward tcp:9222 tcp:9222

# Chrome DevTools Protocol 포워딩
adb forward tcp:9222 localabstract:chrome_devtools_remote

# 포워딩 목록
adb forward --list

# 포워딩 제거
adb forward --remove tcp:9222

# 모든 포워딩 제거
adb forward --remove-all
```

### 무선 ADB (WiFi)
```bash
# 1. USB로 연결된 상태에서 TCP/IP 모드 활성화
adb tcpip 5555

# 2. 기기 IP 주소 확인
adb shell ip addr show wlan0

# 3. USB 연결 해제 후 WiFi로 연결
adb connect 192.168.0.100:5555

# 4. 정상 연결 확인
adb devices

# 5. WiFi 연결 해제
adb disconnect 192.168.0.100:5555

# 6. USB 모드로 복귀 (USB 재연결 필요)
adb usb
```

### 기기 재부팅
```bash
# 일반 재부팅
adb reboot

# 리커버리 모드
adb reboot recovery

# 부트로더 모드
adb reboot bootloader
```

## 실전 예제

### 네이버 쇼핑 자동화 시퀀스
```bash
# 1. Chrome 실행
adb shell am start -n com.android.chrome/.Main

# 2. URL 열기
adb shell am start -a android.intent.action.VIEW -d "https://shopping.naver.com"

# 3. 검색창 탭 (좌표는 기기별로 조정)
sleep 2
adb shell input tap 540 200

# 4. 검색어 입력
adb shell input text "wireless%searphone"

# 5. 검색 실행 (Enter)
adb shell input keyevent KEYCODE_ENTER

# 6. 스크롤 (자연스럽게)
sleep 3
adb shell input swipe 500 1500 500 800 300
sleep 1
adb shell input swipe 500 1500 500 600 300

# 7. 상품 클릭 (좌표는 순위에 따라 계산)
adb shell input tap 540 800

# 8. 체류 시간 (45초)
sleep 45

# 9. 뒤로 가기
adb shell input keyevent KEYCODE_BACK
```

### 비행기모드 토글 스크립트
```bash
#!/bin/bash
# airplane_toggle.sh

echo "비행기모드 활성화..."
adb shell cmd connectivity airplane-mode enable

echo "3초 대기..."
sleep 3

echo "비행기모드 비활성화..."
adb shell cmd connectivity airplane-mode disable

echo "네트워크 재연결 대기..."
for i in {1..10}; do
    if adb shell dumpsys connectivity | grep -q "CONNECTED"; then
        echo "네트워크 재연결 완료 (${i}초)"
        exit 0
    fi
    sleep 1
done

echo "네트워크 재연결 타임아웃"
exit 1
```

## 문제 해결

### 기기가 인식되지 않음
```bash
# 1. USB 디버깅 활성화 확인
adb shell getprop persist.sys.usb.config

# 2. ADB 서버 재시작
adb kill-server
adb start-server

# 3. 드라이버 확인 (Windows)
# 장치 관리자에서 "Android Device" 확인

# 4. USB 케이블/포트 교체
```

### unauthorized 상태
```bash
# 1. 기기에서 "USB 디버깅 허용" 팝업 확인
# 2. "항상 허용" 체크박스 선택

# RSA 키 초기화 (필요 시)
adb shell rm /data/misc/adb/adb_keys
adb kill-server
adb start-server
```

### 명령이 느림
```bash
# ADB over WiFi 대신 USB 사용
adb usb

# 불필요한 ADB 서버 프로세스 종료
adb kill-server
adb start-server
```

## 참고 자료

- [Android Debug Bridge 공식 문서](https://developer.android.com/studio/command-line/adb)
- [ADB Shell Commands](https://adbshell.com/)
- [KeyEvent Reference](https://developer.android.com/reference/android/view/KeyEvent)
