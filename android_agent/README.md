# Turafic Android Agent

**완전 독립형 봇 에이전트** - 안드로이드 기기에서 PC 없이 독립적으로 동작하는 트래픽 생성 봇

## 주요 기능

### 1. 서버 통신
- C&C 서버와 HTTP 통신 (Retrofit 사용)
- 봇 등록 → 작업 요청 → 결과 보고 사이클

### 2. 루팅 기반 제어
- `su` 명령어로 루트 권한 획득
- `input tap`, `input text` 등 저수준 제어
- Appium 없이 직접 화면 제어

### 3. 비행기 모드 IP 변경
- 1 트래픽당 1회 IP 변경
- `settings put global airplane_mode_on 1/0`
- `am broadcast --action android.intent.action.AIRPLANE_MODE`

### 4. 백그라운드 서비스
- 부팅 시 자동 시작 (`BOOT_COMPLETED`)
- 24시간 지속 동작
- 주기적 작업 요청 (5분 간격)

## 프로젝트 구조

```
android_agent/
├── app/
│   ├── src/
│   │   └── main/
│   │       ├── java/com/turafic/agent/
│   │       │   ├── MainActivity.java          # 메인 액티비티
│   │       │   ├── service/
│   │       │   │   ├── BotService.java        # 백그라운드 서비스
│   │       │   │   └── BootReceiver.java      # 부팅 시 자동 시작
│   │       │   ├── network/
│   │       │   │   ├── ApiClient.java         # Retrofit 클라이언트
│   │       │   │   ├── ServerApi.java         # API 인터페이스
│   │       │   │   └── models/                # 요청/응답 모델
│   │       │   ├── executor/
│   │       │   │   ├── TaskExecutor.java      # 작업 실행 엔진
│   │       │   │   └── RootController.java    # 루팅 기반 제어
│   │       │   └── utils/
│   │       │       ├── AirplaneModeManager.java # 비행기 모드 제어
│   │       │       └── DeviceInfo.java          # 기기 정보 수집
│   │       ├── AndroidManifest.xml
│   │       └── res/
│   └── build.gradle
├── gradle/
├── build.gradle
└── README.md
```

## 빌드 및 설치

### 1. 사전 요구사항
- Android Studio Arctic Fox 이상
- Android SDK 28 이상
- 루팅된 안드로이드 기기 (Android 9 이상)

### 2. 빌드
```bash
# Android Studio에서 프로젝트 열기
# Build > Build Bundle(s) / APK(s) > Build APK(s)

# 또는 명령줄에서
./gradlew assembleRelease
```

### 3. 설치
```bash
adb install app/build/outputs/apk/release/app-release.apk
```

### 4. 루트 권한 부여
```bash
adb shell
su
pm grant com.turafic.agent android.permission.WRITE_SECURE_SETTINGS
```

## 설정

### 서버 URL 설정
`app/src/main/java/com/turafic/agent/network/ApiClient.java`에서 서버 URL 변경:

```java
private static final String BASE_URL = "http://your-server-ip:8000/api/v1/";
```

## 사용 방법

### 1. 앱 실행
- 앱 설치 후 실행
- 서버 URL 입력 (설정 화면)
- "서비스 시작" 버튼 클릭

### 2. 자동 동작
- 부팅 시 자동 시작
- 5분 간격으로 서버에 작업 요청
- 작업 수행 후 결과 보고
- 비행기 모드로 IP 변경 후 다음 작업

## 주요 클래스 설명

### BotService.java
백그라운드에서 지속적으로 동작하는 서비스. 주기적으로 서버에 작업을 요청하고 실행합니다.

```java
public class BotService extends Service {
    // 5분 간격으로 작업 요청
    private static final long TASK_REQUEST_INTERVAL = 5 * 60 * 1000;
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // 주기적 작업 요청 시작
        startTaskRequestLoop();
        return START_STICKY;  // 서비스 종료 시 자동 재시작
    }
}
```

### TaskExecutor.java
서버로부터 받은 JSON 작업 패턴을 실행하는 엔진입니다.

```java
public class TaskExecutor {
    public void executePattern(List<TaskStep> pattern) {
        for (TaskStep step : pattern) {
            switch (step.action) {
                case "tap":
                    RootController.tap(step.x, step.y);
                    break;
                case "text":
                    RootController.inputText(step.value);
                    break;
                // ...
            }
        }
    }
}
```

### RootController.java
루팅 기반 저수준 제어를 담당합니다.

```java
public class RootController {
    public static void tap(int x, int y) {
        executeRootCommand("input tap " + x + " " + y);
    }
    
    private static void executeRootCommand(String command) {
        Process process = Runtime.getRuntime().exec("su -c " + command);
        process.waitFor();
    }
}
```

### AirplaneModeManager.java
비행기 모드를 제어하여 IP를 변경합니다.

```java
public class AirplaneModeManager {
    public static void toggleAirplaneMode() {
        // 비행기 모드 ON
        Settings.Global.putInt(context.getContentResolver(), 
            Settings.Global.AIRPLANE_MODE_ON, 1);
        
        // 브로드캐스트
        Intent intent = new Intent(Intent.ACTION_AIRPLANE_MODE_CHANGED);
        context.sendBroadcast(intent);
        
        // 2초 대기
        Thread.sleep(2000);
        
        // 비행기 모드 OFF
        Settings.Global.putInt(context.getContentResolver(), 
            Settings.Global.AIRPLANE_MODE_ON, 0);
        context.sendBroadcast(intent);
    }
}
```

## 보안 및 주의사항

⚠️ **이 앱은 연구 및 교육 목적으로만 사용해야 합니다.**

- 루팅된 기기 필요
- 타사 서비스 약관 위반 가능성
- 법적 책임은 사용자에게 있음

## 라이선스

MIT License
