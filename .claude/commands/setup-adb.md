---
description: ADB 연결 및 기기 상태 확인
model: claude-3-5-haiku-20241022
allowed-tools: Bash(adb:*), Write
---

Android Debug Bridge (ADB) 환경 설정을 검증하고 기기를 테스트에 사용할 수 있는 상태로 만듭니다.

## 검증 단계

### 1. ADB 설치 확인
!`adb --version`

예상 출력:
```
Android Debug Bridge version 1.0.41
```

### 2. 연결된 기기 목록
!`adb devices`

예상 출력:
```
List of devices attached
RF8M12345XY    device
```

**주의**: "unauthorized" 또는 "offline" 상태인 경우:
- 기기에서 "USB 디버깅 허용" 팝업 확인
- USB 케이블 재연결
- 개발자 옵션에서 "USB 디버깅 취소" 후 재활성화

### 3. 기기 정보 확인
!`adb shell getprop ro.product.model`
!`adb shell getprop ro.build.version.release`
!`adb shell wm size`

### 4. 네트워크 상태 확인
!`adb shell dumpsys connectivity | grep "NetworkAgentInfo"`

WiFi 또는 Mobile Data가 연결되어 있는지 확인합니다.

### 5. Chrome 브라우저 확인
!`adb shell pm list packages | grep chrome`

예상 출력:
```
package:com.android.chrome
```

### 6. 비행기모드 토글 테스트

**비행기모드 ON**:
!`adb shell cmd connectivity airplane-mode enable`

**3초 대기**

**비행기모드 OFF**:
!`adb shell cmd connectivity airplane-mode disable`

**네트워크 재연결 대기 (최대 10초)**

네트워크가 정상적으로 재연결되는지 확인:
!`adb shell dumpsys connectivity | grep "NetworkAgentInfo"`

## 환경 변수 설정

검증이 완료되면 `.env` 파일을 자동으로 생성/업데이트합니다:

```bash
# 기기 ID 가져오기
DEVICE_ID=$(adb devices | grep "device$" | awk '{print $1}')

# .env 파일 업데이트
cat >> .env << EOF
ADB_DEVICE_ID=$DEVICE_ID
ADB_VERIFIED=true
ADB_VERIFIED_AT=$(date '+%Y-%m-%d %H:%M:%S')
EOF
```

## 추가 권장 설정

### 화면 꺼짐 방지 (테스트 중 화면 유지)
!`adb shell settings put global stay_on_while_plugged_in 7`

### 화면 밝기 고정 (배터리 절약)
!`adb shell settings put system screen_brightness 50`

### 알림 음소거 (테스트 중단 방지)
!`adb shell settings put global heads_up_notifications_enabled 0`

## 검증 결과

모든 단계가 성공하면 다음과 같이 출력:

```
✅ ADB 설치 확인 완료
✅ 기기 연결 확인 완료 (RF8M12345XY)
✅ 네트워크 상태 정상
✅ Chrome 브라우저 설치 확인
✅ 비행기모드 토글 테스트 성공
✅ 환경 변수 설정 완료

=== 기기 정보 ===
모델: Samsung Galaxy S21
Android 버전: 13
화면 해상도: 1080x2400

테스트를 시작할 수 있습니다!
명령어: /test-product [product-id] [iterations] [test-type]
```

## 문제 해결

**기기가 인식되지 않는 경우**:
1. USB 디버깅 활성화 확인
2. USB 케이블 교체
3. 드라이버 재설치 (Windows)
4. 기기 재부팅

**비행기모드 토글 실패**:
1. 권한 확인: `adb shell pm grant ...`
2. Android 버전 확인 (11 이상 필요)
3. 수동으로 비행기모드 토글 테스트

**네트워크 재연결 느림**:
1. WiFi 대신 Mobile Data 사용 고려
2. 네트워크 설정 초기화
3. 재연결 대기 시간 늘리기 (10초 → 20초)
