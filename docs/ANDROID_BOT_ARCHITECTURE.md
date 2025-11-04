# Turafic Android 봇 아키텍처 설계

## 📋 목차
1. [기존 APK 벤치마킹](#기존-apk-벤치마킹)
2. [Turafic 요구사항 매핑](#turafic-요구사항-매핑)
3. [확장 가능한 아키텍처 설계](#확장-가능한-아키텍처-설계)
4. [구현 로드맵](#구현-로드맵)
5. [마이그레이션 전략](#마이그레이션-전략)

---

## 🔍 기존 APK 벤치마킹

### 분석 대상 APK (3개)

| APK | 역할 | 패키지명 | 핵심 기능 |
|-----|------|---------|----------|
| **zu12.apk** | 대장 봇 | `com.zero.updater.zero` | 핫스팟 제공, 자동 업데이트 |
| **zcu12.apk** | 쫄병 봇 | `com.zero.updater.zero` | 핫스팟 연결, 작업 실행 |
| **zru12.apk** | 순위 체크 | `com.zero.updater.rank` | 범용 순위 체크 엔진 |

### 추출된 핵심 패턴

#### 1. 자동 업데이트 메커니즘 ⭐
```java
// CheckUpdateTask.java
private static final String url = "http://54.180.205.28/zero/api/v1/mobile/version?app=3&version_code=";

// 5초마다 버전 체크
handler.sendEmptyMessageDelayed(0, 5000);

// 새 버전 발견 시 자동 다운로드 및 설치
UpdateChecker.checkForBackground(context, handler);
```

**장점**:
- ✅ 봇 업데이트를 위해 수동 APK 배포 불필요
- ✅ 서버에서 버전 관리 및 배포 제어
- ✅ 긴급 패치 즉시 적용 가능

**Turafic 적용**:
```
Railway C&C 서버 → APK 버전 관리
/api/v1/bot/version?bot_id=Bot-1&version_code=12
→ 새 버전 있으면 APK URL 반환
→ 봇이 자동 다운로드 및 설치
```

---

#### 2. Root 권한 기반 제어 ⭐
```java
// SuCommander.java
public static boolean execute(String cmd) throws IOException, InterruptedException {
    Process process = Runtime.getRuntime().exec("su");
    DataOutputStream os = new DataOutputStream(process.getOutputStream());
    os.writeBytes(cmd + "\n");
    os.writeBytes("exit\n");
    os.flush();
    process.waitFor();
    return process.exitValue() == 0;
}

// 사용 예시
SuCommander.execute("/system/bin/am force-stop com.sec.android.app.sbrowser");
SuCommander.execute("input tap 500 1000");
SuCommander.execute("input text 'Samsung Galaxy S24'");
```

**장점**:
- ✅ 앱 강제 종료 (브라우저 캐시 초기화)
- ✅ UI 자동화 (좌표 기반 탭/텍스트 입력)
- ✅ 시스템 설정 변경 (비행기 모드, 핫스팟)

**Turafic 적용**:
```
Root 필수 기능:
1. 브라우저 제어 (force-stop, cache clear)
2. UI 자동화 (input tap, input text, input swipe)
3. 네트워크 제어 (비행기 모드 토글)
4. 핫스팟 제어 (대장 봇만)
```

---

#### 3. 백그라운드 서비스 (24/7 실행) ⭐
```java
// UpdateHandlerThread.java
public class UpdateHandlerThread extends HandlerThread {
    @Override
    protected void onLooperPrepared() {
        // 5초 후 첫 업데이트 체크
        handler.sendEmptyMessageDelayed(0, 5000);
    }
    
    @Override
    public void onHandleMessage(Handler handler, Message msg) {
        switch (msg.what) {
            case 0: // 업데이트 체크
                versionCheck();
                break;
            case 1: // 작업 실행
                executeTask();
                break;
            case 2: // 업데이트 중
                handler.sendEmptyMessageDelayed(0, 300000); // 5분 대기
                break;
        }
    }
}
```

**장점**:
- ✅ 앱 종료 없이 24/7 실행
- ✅ 메시지 큐 기반 비동기 처리
- ✅ 배터리 최적화 (Doze 모드 대응)

**Turafic 적용**:
```
ForegroundService + HandlerThread:
1. 서버 폴링 (30초마다 작업 요청)
2. 작업 실행 (JSON 패턴 기반)
3. 결과 보고 (순위 변동, 에러)
4. 자동 재시도 (네트워크 에러)
```

---

#### 4. C&C 서버 통신 패턴 ⭐
```java
// CheckUpdateTask.java
String url = "http://54.180.205.28/zero/api/v1/mobile/version?app=3&version_code=12";
String response = HttpUtils.get(url);
JSONObject json = new JSONObject(response);

if (json.getBoolean("has_update")) {
    String apkUrl = json.getString("apk_url");
    int newVersion = json.getInt("version_code");
    // 다운로드 및 설치
}
```

**장점**:
- ✅ 단순한 HTTP GET/POST
- ✅ JSON 기반 명령 전달
- ✅ 서버 중심 제어 (봇은 단순 실행기)

**Turafic 적용**:
```
Railway C&C 서버 API:
1. GET /api/v1/bot/task?bot_id=Bot-1
   → 작업 JSON 반환 (UI 좌표, 액션 시퀀스)
2. POST /api/v1/bot/report
   → 작업 결과 전송 (성공/실패, 스크린샷)
3. GET /api/v1/bot/version?bot_id=Bot-1
   → 버전 체크 및 업데이트
```

---

#### 5. 타겟 앱 제어 (Samsung Internet Browser) ⭐
```java
// MainActivity.java
public static final String TARGET_PACKAGE_NAME = "com.sec.android.app.sbrowser";

// 브라우저 강제 종료
killApp(TARGET_PACKAGE_NAME);

// 캐시 삭제
String cmd = "rm -rf /data/data/" + TARGET_PACKAGE_NAME + "/cache/*.apk";
SuCommander.execute(cmd);
```

**장점**:
- ✅ 브라우저 상태 초기화 (쿠키, 캐시)
- ✅ 깨끗한 세션 시작
- ✅ 탐지 회피 (브라우저 지문 초기화)

**Turafic 적용**:
```
타겟 브라우저: Samsung Internet Browser
작업 전 초기화:
1. force-stop (앱 종료)
2. cache clear (캐시 삭제)
3. 5초 대기
4. 브라우저 실행 (am start)
```

---

## 🎯 Turafic 요구사항 매핑

### 기존 APK vs Turafic 비교

| 기능 | 기존 APK | Turafic 요구사항 | 변경 필요성 |
|------|---------|-----------------|-----------|
| **자동 업데이트** | ✅ 구현됨 | ✅ 필수 | 🟢 재사용 가능 |
| **Root 제어** | ✅ 구현됨 | ✅ 필수 | 🟢 재사용 가능 |
| **백그라운드 서비스** | ✅ 구현됨 | ✅ 필수 | 🟢 재사용 가능 |
| **C&C 통신** | ✅ 구현됨 | ✅ 필수 | 🟡 URL 변경 필요 |
| **브라우저 제어** | ✅ 구현됨 | ✅ 필수 | 🟢 재사용 가능 |
| **핫스팟 제어** | ❌ 없음 | ✅ 필수 | 🔴 신규 구현 필요 |
| **UI 자동화** | ❌ 없음 | ✅ 필수 | 🔴 신규 구현 필요 |
| **JSON 패턴 실행** | ❌ 없음 | ✅ 필수 | 🔴 신규 구현 필요 |
| **스크린샷** | ❌ 없음 | ✅ 필수 | 🔴 신규 구현 필요 |
| **순위 체크** | ✅ 구현됨 (zru12) | ✅ 필수 | 🟢 재사용 가능 |

---

## 🏗️ 확장 가능한 아키텍처 설계

### 1. 모듈화 설계 (재사용성 극대화)

```
turafic-bot/
├── core/                          # 핵심 모듈 (기존 APK 재사용)
│   ├── AutoUpdateManager.java    # 자동 업데이트 (zu12 재사용)
│   ├── RootCommander.java         # Root 명령 실행 (zu12 재사용)
│   ├── BackgroundService.java    # 백그라운드 서비스 (zu12 재사용)
│   ├── C2CClient.java             # C&C 서버 통신 (zu12 재사용)
│   └── BrowserController.java    # 브라우저 제어 (zu12 재사용)
│
├── hotspot/                       # 핫스팟 모듈 (신규 구현)
│   ├── HotspotManager.java       # 핫스팟 ON/OFF
│   ├── AirplaneModeToggler.java  # 비행기 모드 토글 (IP 변경)
│   └── WifiConnector.java        # 쫄병 봇용 Wi-Fi 연결
│
├── automation/                    # UI 자동화 모듈 (신규 구현)
│   ├── ActionExecutor.java       # JSON 패턴 실행 엔진
│   ├── UICoordinateMapper.java   # UI 좌표 맵 관리
│   ├── ScreenshotCapture.java    # 스크린샷 촬영
│   └── actions/                  # 액션 구현
│       ├── TapAction.java
│       ├── TextInputAction.java
│       ├── SwipeAction.java
│       ├── WaitAction.java
│       └── ScrollAction.java
│
├── ranking/                       # 순위 체크 모듈 (zru12 재사용)
│   ├── RankChecker.java          # 순위 체크 엔진
│   ├── AdFilter.java             # 광고 필터링 (8가지 패턴)
│   └── ResultParser.java         # HTML 파싱
│
├── network/                       # 네트워크 모듈
│   ├── RetrofitClient.java       # HTTP 클라이언트
│   ├── WebSocketClient.java      # 실시간 통신 (선택)
│   └── NetworkMonitor.java       # 네트워크 상태 감지
│
└── utils/                         # 유틸리티
    ├── Logger.java               # 로그 관리
    ├── Config.java               # 설정 관리
    └── DeviceInfo.java           # 디바이스 정보
```

---

### 2. 봇 타입별 구현 전략

#### A. 대장 봇 (Leader Bot) - zu12.apk 기반

**패키지명**: `com.turafic.bot.leader`

**핵심 기능**:
1. ✅ 자동 업데이트 (zu12 재사용)
2. ✅ 백그라운드 서비스 (zu12 재사용)
3. ✅ C&C 통신 (zu12 재사용)
4. 🆕 핫스팟 제공 (신규 구현)
5. 🆕 비행기 모드 토글 (5분마다 IP 변경)
6. 🆕 UI 자동화 (JSON 패턴 실행)

**추가 구현 필요**:
```java
// HotspotManager.java
public class HotspotManager {
    // 핫스팟 ON
    public void enableHotspot() {
        String cmd = "svc wifi enable && " +
                     "settings put global wifi_ap_ssid 'Turafic-Leader-1' && " +
                     "settings put global wifi_ap_passwd 'turafic123' && " +
                     "cmd connectivity tether wifi on";
        RootCommander.execute(cmd);
    }
    
    // 비행기 모드 토글 (IP 변경)
    public void toggleAirplaneMode() {
        RootCommander.execute("settings put global airplane_mode_on 1");
        RootCommander.execute("am broadcast -a android.intent.action.AIRPLANE_MODE");
        Thread.sleep(5000);
        RootCommander.execute("settings put global airplane_mode_on 0");
        RootCommander.execute("am broadcast -a android.intent.action.AIRPLANE_MODE");
    }
}
```

---

#### B. 쫄병 봇 (Follower Bot) - zcu12.apk 기반

**패키지명**: `com.turafic.bot.follower`

**핵심 기능**:
1. ✅ 자동 업데이트 (zcu12 재사용)
2. ✅ 백그라운드 서비스 (zcu12 재사용)
3. ✅ C&C 통신 (zcu12 재사용)
4. 🆕 대장 핫스팟 연결 (신규 구현)
5. 🆕 UI 자동화 (JSON 패턴 실행)

**추가 구현 필요**:
```java
// WifiConnector.java
public class WifiConnector {
    // 대장 핫스팟 연결
    public void connectToLeader(String ssid, String password) {
        String cmd = "svc wifi enable && " +
                     "wpa_cli -i wlan0 add_network && " +
                     "wpa_cli -i wlan0 set_network 0 ssid '\"" + ssid + "\"' && " +
                     "wpa_cli -i wlan0 set_network 0 psk '\"" + password + "\"' && " +
                     "wpa_cli -i wlan0 enable_network 0";
        RootCommander.execute(cmd);
    }
}
```

---

#### C. 순위 체크 봇 (Rank Checker Bot) - zru12.apk 재사용

**패키지명**: `com.turafic.bot.rank`

**핵심 기능**:
1. ✅ 자동 업데이트 (zru12 재사용)
2. ✅ 백그라운드 서비스 (zru12 재사용)
3. ✅ C&C 통신 (zru12 재사용)
4. ✅ 순위 체크 엔진 (zru12 재사용)
5. 🆕 광고 필터링 강화 (8가지 패턴)

**거의 재사용 가능!** (URL만 변경)

---

### 3. JSON 패턴 실행 엔진 (핵심 신규 기능)

#### 서버에서 전달하는 JSON 패턴 예시

```json
{
  "task_id": "TASK-2024-001",
  "bot_id": "Bot-1",
  "test_case_id": "TC#1",
  "actions": [
    {
      "type": "force_stop",
      "package": "com.sec.android.app.sbrowser"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "start_app",
      "package": "com.sec.android.app.sbrowser"
    },
    {
      "type": "wait",
      "duration": 3000
    },
    {
      "type": "tap",
      "x": 540,
      "y": 200,
      "description": "검색창 탭"
    },
    {
      "type": "text",
      "value": "삼성 갤럭시 S24",
      "description": "키워드 입력"
    },
    {
      "type": "tap",
      "x": 540,
      "y": 1800,
      "description": "검색 버튼 탭"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "scroll",
      "direction": "down",
      "distance": 500,
      "description": "스크롤 다운"
    },
    {
      "type": "tap",
      "x": 540,
      "y": 800,
      "description": "상품 탭"
    },
    {
      "type": "wait",
      "duration": 30000,
      "description": "상품 페이지 체류"
    },
    {
      "type": "screenshot",
      "path": "/sdcard/turafic/Bot-1-TC1-001.png"
    }
  ]
}
```

#### ActionExecutor 구현

```java
// ActionExecutor.java
public class ActionExecutor {
    private RootCommander rootCommander;
    private BrowserController browserController;
    
    public boolean execute(JSONObject pattern) {
        try {
            JSONArray actions = pattern.getJSONArray("actions");
            
            for (int i = 0; i < actions.length(); i++) {
                JSONObject action = actions.getJSONObject(i);
                String type = action.getString("type");
                
                switch (type) {
                    case "force_stop":
                        String pkg = action.getString("package");
                        browserController.forceStop(pkg);
                        break;
                        
                    case "start_app":
                        String startPkg = action.getString("package");
                        browserController.startApp(startPkg);
                        break;
                        
                    case "tap":
                        int x = action.getInt("x");
                        int y = action.getInt("y");
                        rootCommander.tap(x, y);
                        break;
                        
                    case "text":
                        String text = action.getString("value");
                        rootCommander.inputText(text);
                        break;
                        
                    case "scroll":
                        String direction = action.getString("direction");
                        int distance = action.getInt("distance");
                        rootCommander.scroll(direction, distance);
                        break;
                        
                    case "wait":
                        int duration = action.getInt("duration");
                        Thread.sleep(duration);
                        break;
                        
                    case "screenshot":
                        String path = action.getString("path");
                        ScreenshotCapture.capture(path);
                        break;
                        
                    default:
                        Log.w("ActionExecutor", "Unknown action type: " + type);
                }
            }
            
            return true;
        } catch (Exception e) {
            Log.e("ActionExecutor", "Failed to execute pattern", e);
            return false;
        }
    }
}
```

---

### 4. 확장 가능한 API 설계

#### Railway C&C 서버 API

```
1. 봇 등록
POST /api/v1/bot/register
{
  "bot_id": "Bot-1",
  "bot_type": "leader",
  "group_id": "G1",
  "device_info": {
    "model": "Samsung Galaxy S21",
    "android_version": "12",
    "screen_resolution": "1080x2400"
  }
}

2. 작업 요청 (30초마다 폴링)
GET /api/v1/bot/task?bot_id=Bot-1
→ JSON 패턴 반환 (위 예시 참고)

3. 작업 결과 보고
POST /api/v1/bot/report
{
  "task_id": "TASK-2024-001",
  "bot_id": "Bot-1",
  "status": "success",
  "duration": 45000,
  "screenshot": "base64_encoded_image",
  "error": null
}

4. 버전 체크
GET /api/v1/bot/version?bot_id=Bot-1&version_code=12
{
  "has_update": true,
  "version_code": 13,
  "apk_url": "https://turafic-server.railway.app/downloads/bot-leader-v13.apk",
  "changelog": "Added hotspot auto-reconnect"
}

5. 순위 체크 (순위 체크 봇 전용)
GET /api/v1/rank/check?bot_id=Bot-RC1
{
  "product_id": "87654321",
  "keyword": "삼성 갤럭시 S24",
  "url": "https://search.shopping.naver.com/search/all?query=..."
}

6. 순위 결과 보고
POST /api/v1/rank/report
{
  "bot_id": "Bot-RC1",
  "product_id": "87654321",
  "keyword": "삼성 갤럭시 S24",
  "rank": 43,
  "page": 2,
  "position": 3,
  "screenshot": "base64_encoded_image"
}
```

---

## 🚀 구현 로드맵

### Phase 1: MVP (최소 기능 제품) - 3일

**목표**: 서버 API 호출 + Root 탭 기능만 구현

**구현 항목**:
1. ✅ 자동 업데이트 (zu12 재사용)
2. ✅ 백그라운드 서비스 (zu12 재사용)
3. ✅ C&C 통신 (zu12 재사용, URL만 변경)
4. ✅ Root 탭 (zu12 재사용)
5. 🆕 JSON 패턴 파싱 (신규)
6. 🆕 간단한 ActionExecutor (tap, wait만)

**테스트**:
- 서버에서 JSON 패턴 전달
- 봇이 패턴 실행 (탭 2회 + 대기)
- 결과 보고

**예상 소요 시간**: 3일

---

### Phase 2: 기본 액션 구현 - 2일

**목표**: 9가지 기본 액션 모두 구현

**구현 항목**:
1. 🆕 `force_stop` - 앱 강제 종료
2. 🆕 `start_app` - 앱 실행
3. 🆕 `tap` - 좌표 탭
4. 🆕 `text` - 텍스트 입력
5. 🆕 `scroll` - 스크롤
6. 🆕 `swipe` - 스와이프
7. 🆕 `wait` - 대기
8. 🆕 `screenshot` - 스크린샷
9. 🆕 `back` - 뒤로가기

**테스트**:
- 네이버 쇼핑 검색 → 상품 클릭 → 체류 → 스크린샷

**예상 소요 시간**: 2일

---

### Phase 3: 핫스팟 기능 구현 - 2일

**목표**: 대장 봇 핫스팟 + 쫄병 봇 연결

**구현 항목**:
1. 🆕 `HotspotManager` - 핫스팟 ON/OFF
2. 🆕 `AirplaneModeToggler` - 비행기 모드 토글
3. 🆕 `WifiConnector` - Wi-Fi 연결
4. 🆕 IP 변경 로직 (5분마다)

**테스트**:
- 대장 봇: 핫스팟 ON → 5분마다 IP 변경
- 쫄병 봇: 대장 핫스팟 연결 → 자동 IP 변경

**예상 소요 시간**: 2일

---

### Phase 4: 순위 체크 봇 통합 - 1일

**목표**: zru12.apk를 Turafic 서버와 통합

**구현 항목**:
1. ✅ zru12.apk URL 변경 (54.180.205.28 → Railway URL)
2. 🆕 광고 필터링 강화 (8가지 패턴)
3. 🆕 스크린샷 전송

**테스트**:
- 순위 체크 봇: 네이버 쇼핑 순위 체크 → 결과 보고

**예상 소요 시간**: 1일

---

### Phase 5: 통합 테스트 및 최적화 - 2일

**목표**: 22개 봇 동시 실행 테스트

**테스트 항목**:
1. 6개 트래픽 그룹 동시 실행
2. 1개 순위 체크 그룹 동시 실행
3. IP 변경 동작 확인
4. 에러 핸들링 확인
5. 배터리 소모 최적화

**예상 소요 시간**: 2일

---

**총 소요 시간**: 10일 (약 2주)

---

## 🔄 마이그레이션 전략

### 1. 기존 APK 재사용 전략

#### A. 100% 재사용 가능 (코드 복사)

```
zu12.apk → Turafic Leader Bot
├── AutoUpdateManager.java       ✅ 100% 재사용
├── RootCommander.java            ✅ 100% 재사용
├── BackgroundService.java        ✅ 100% 재사용
├── UpdateHandlerThread.java      ✅ 100% 재사용
└── BrowserController.java        ✅ 100% 재사용

zcu12.apk → Turafic Follower Bot
├── AutoUpdateManager.java       ✅ 100% 재사용
├── RootCommander.java            ✅ 100% 재사용
├── BackgroundService.java        ✅ 100% 재사용
└── UpdateHandlerThread.java      ✅ 100% 재사용

zru12.apk → Turafic Rank Checker Bot
├── RankChecker.java             ✅ 100% 재사용
├── AdFilter.java                 ✅ 100% 재사용
└── ResultParser.java             ✅ 100% 재사용
```

#### B. 50% 재사용 가능 (URL 변경 필요)

```
CheckUpdateTask.java
- 기존: http://54.180.205.28/zero/api/v1/mobile/version?app=3
- 변경: https://turafic-server.railway.app/api/v1/bot/version?bot_id=Bot-1
```

#### C. 신규 구현 필요

```
1. HotspotManager.java           🆕 신규 (2시간)
2. AirplaneModeToggler.java      🆕 신규 (1시간)
3. WifiConnector.java            🆕 신규 (1시간)
4. ActionExecutor.java           🆕 신규 (4시간)
5. ScreenshotCapture.java        🆕 신규 (1시간)
```

**총 신규 구현 시간**: 9시간 (약 1일)

---

### 2. 단계별 마이그레이션

#### Step 1: 기존 APK 디컴파일 및 Java 변환 (1일)

```bash
# zu12.apk 디컴파일
apktool d zu12.apk -o zu12_decoded

# smali → Java 변환 (jadx 사용)
jadx zu12.apk -d zu12_java

# 핵심 클래스 복사
cp zu12_java/com/loveplusplus/update/*.java turafic-bot/core/
```

#### Step 2: 패키지명 변경 및 리팩토링 (1일)

```java
// 기존
package com.loveplusplus.update;

// 변경
package com.turafic.bot.core;
```

#### Step 3: Railway 서버 API 연동 (1일)

```java
// 기존 URL
private static final String url = "http://54.180.205.28/zero/api/v1/mobile/version?app=3";

// 변경 URL
private static final String BASE_URL = "https://turafic-server.railway.app";
private String getVersionUrl() {
    return BASE_URL + "/api/v1/bot/version?bot_id=" + botId + "&version_code=" + versionCode;
}
```

#### Step 4: 신규 기능 구현 (3일)

1. **HotspotManager** (2시간)
2. **ActionExecutor** (4시간)
3. **WifiConnector** (1시간)
4. **ScreenshotCapture** (1시간)
5. **통합 테스트** (나머지 시간)

#### Step 5: APK 빌드 및 배포 (1일)

```bash
# Android Studio에서 빌드
./gradlew assembleRelease

# APK 서명
jarsigner -keystore turafic.keystore bot-leader-v1.apk turafic

# Railway 서버에 업로드
curl -X POST https://turafic-server.railway.app/api/v1/admin/upload-apk \
  -F "file=@bot-leader-v1.apk" \
  -F "bot_type=leader" \
  -F "version_code=1"
```

---

### 3. 코드 재사용률 분석

| 모듈 | 재사용률 | 소요 시간 |
|------|---------|----------|
| **자동 업데이트** | 90% | 1시간 (URL 변경) |
| **Root 제어** | 100% | 0시간 |
| **백그라운드 서비스** | 100% | 0시간 |
| **C&C 통신** | 80% | 2시간 (API 변경) |
| **브라우저 제어** | 100% | 0시간 |
| **핫스팟 제어** | 0% | 3시간 (신규) |
| **UI 자동화** | 0% | 4시간 (신규) |
| **스크린샷** | 0% | 1시간 (신규) |
| **순위 체크** | 100% | 0시간 |

**총 재사용률**: **약 70%**  
**총 신규 구현 시간**: **11시간 (약 1.5일)**

---

## 🎯 최종 요약

### 벤치마킹 결과

1. ✅ **기존 APK의 70%를 재사용 가능**
2. ✅ **자동 업데이트, Root 제어, 백그라운드 서비스는 100% 재사용**
3. ✅ **순위 체크 봇(zru12)은 거의 그대로 사용 가능**
4. 🆕 **핫스팟 제어, UI 자동화만 신규 구현 필요 (1.5일)**

### 확장 전략

1. **모듈화 설계**: 핵심 기능을 독립 모듈로 분리
2. **JSON 패턴 실행**: 서버에서 동적으로 작업 패턴 전달
3. **3가지 봇 타입**: Leader, Follower, Rank Checker
4. **Railway API 통합**: RESTful API로 중앙 제어

### 구현 로드맵

- **Phase 1 (MVP)**: 3일 - 서버 API + Root 탭
- **Phase 2 (기본 액션)**: 2일 - 9가지 액션 구현
- **Phase 3 (핫스팟)**: 2일 - IP 변경 로직
- **Phase 4 (순위 체크)**: 1일 - zru12 통합
- **Phase 5 (테스트)**: 2일 - 통합 테스트

**총 소요 시간**: **10일 (약 2주)**

---

**다음 단계**: Phase 1 (MVP) 구현 시작!
