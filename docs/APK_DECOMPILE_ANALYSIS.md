# APK 디컴파일 결과 분석 (정확한 사실)

## 📋 목차
1. [디컴파일 결과 요약](#디컴파일-결과-요약)
2. [UI 제어 방식 (좌표 기반)](#ui-제어-방식-좌표-기반)
3. [실제 구현 코드](#실제-구현-코드)
4. [좌표 출처 분석](#좌표-출처-분석)
5. [Turafic 구현 전략 (수정)](#turafic-구현-전략-수정)

---

## 🔍 디컴파일 결과 요약

### 분석 대상
- **zu12.apk** (대장 봇)
- **zcu12.apk** (쫄병 봇)
- **zru12.apk** (순위 체크 봇)

### 핵심 발견

| 항목 | 결과 |
|------|------|
| **UI 제어 방식** | ✅ **좌표 기반** (`input tap x y`) |
| **Root 권한** | ✅ 필수 (`su` 명령어 사용) |
| **텍스트/ID 기반** | ❌ 발견되지 않음 |
| **UI Automator** | ❌ 발견되지 않음 |
| **Accessibility Service** | ❌ 발견되지 않음 |

---

## 🎯 UI 제어 방식 (좌표 기반)

### 1. TouchInjector 클래스

**파일 경로**: `/home/ubuntu/zu12_decoded/smali/com/loveplusplus/update/TouchInjector.smali`

**핵심 메서드**:

```java
// Java 역컴파일 결과 (추정)
public class TouchInjector {
    
    public void touchScreen(int x, int y) {
        String xy = String.format("%s %s", x, y);
        
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String cmd = "input tap " + xy + "\n";
                    executeCommand(cmd);
                    Log.d(TAG, "터치: " + xy);
                } catch (IOException | InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }
    
    private boolean executeCommand(String command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec("su");
        DataOutputStream os = new DataOutputStream(process.getOutputStream());
        os.writeBytes(command);
        os.writeBytes("exit\n");
        os.flush();
        os.close();
        return process.waitFor() == 0;
    }
}
```

---

### 2. 실제 사용 예시 (DownloadService)

**파일 경로**: `/home/ubuntu/zu12_decoded/smali/com/loveplusplus/update/DownloadService.smali`

**Smali 코드**:

```smali
.line 164
const/16 v2, 0x71c    # v2 = 1820 (y 좌표)
const/16 v3, 0x3b6    # v3 = 950 (x 좌표)
invoke-virtual {v1, v3, v2}, Lcom/loveplusplus/update/TouchInjector;->touchScreen(II)V

.line 167
const-wide/32 v5, 0xea60    # 60000ms = 60초 대기
invoke-static {v5, v6}, Landroid/os/SystemClock;->sleep(J)V

.line 173
invoke-virtual {v1, v3, v2}, Lcom/loveplusplus/update/TouchInjector;->touchScreen(II)V
```

**Java 역컴파일 (추정)**:

```java
private void runAutoTouch() {
    Log.d("DownloadService", "설치 버튼 자동 터치 시작.");
    TouchInjector injector = new TouchInjector();
    
    // 10초 대기
    SystemClock.sleep(10000);
    
    // 설치 버튼 터치 (x=950, y=1820)
    injector.touchScreen(950, 1820);
    
    // 60초 대기
    SystemClock.sleep(60000);
    
    // 실행 버튼 터치 (x=950, y=1820)
    injector.touchScreen(950, 1820);
}
```

---

### 3. 실행되는 명령어

```bash
# Root 권한으로 실행
su

# 화면 터치 (x=950, y=1820)
input tap 950 1820
```

---

## 🔍 좌표 출처 분석

### Q: 서버에서 좌표를 어떻게 아는가?

**A: APK에 하드코딩되어 있음**

#### 증거 1: DownloadService.smali

```smali
const/16 v2, 0x71c    # 1820 (하드코딩)
const/16 v3, 0x3b6    # 950 (하드코딩)
```

#### 증거 2: 서버 API 응답

```json
{
  "version_code": 524,
  "url": "http://kimfinal77.ipdisk.co.kr/publist/HDD1/Updates/zero_524.apk",
  "update_message": ""
}
```

**서버는 APK URL만 제공, 좌표는 제공하지 않음!**

---

### 좌표 하드코딩 방식

#### 방법 1: APK 내부에 하드코딩 (현재 방식)

```java
// 설치 버튼 좌표 (FHD 1080x2340 기준)
private static final int INSTALL_BUTTON_X = 950;
private static final int INSTALL_BUTTON_Y = 1820;

// 실행 버튼 좌표
private static final int RUN_BUTTON_X = 950;
private static final int RUN_BUTTON_Y = 1820;
```

**장점**:
- ✅ 빠르고 단순함
- ✅ 서버 통신 불필요

**단점**:
- ❌ 해상도 변경 시 APK 재배포 필요
- ❌ UI 변경 시 APK 재배포 필요
- ❌ 유연성 없음

---

#### 방법 2: 서버에서 좌표 제공 (Turafic 방식)

```json
{
  "task_id": "TASK-001",
  "actions": [
    {
      "type": "tap",
      "x": 950,
      "y": 1820,
      "description": "설치 버튼 클릭"
    },
    {
      "type": "wait",
      "duration": 60000
    },
    {
      "type": "tap",
      "x": 950,
      "y": 1820,
      "description": "실행 버튼 클릭"
    }
  ]
}
```

**장점**:
- ✅ 서버에서 동적으로 좌표 변경 가능
- ✅ APK 재배포 불필요
- ✅ 유연성 높음

**단점**:
- ❌ 서버 통신 필요
- ❌ 구현 복잡도 증가

---

## 🛠️ 실제 구현 코드

### 1. TouchInjector.java (역컴파일 결과)

```java
package com.loveplusplus.update;

import android.util.Log;
import java.io.DataOutputStream;
import java.io.IOException;

public class TouchInjector {
    
    private static final String TAG = TouchInjector.class.getSimpleName();
    private Thread _thread;
    
    public void touchScreen(final int x, final int y) {
        final String xy = String.format("%s %s", x, y);
        
        _thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String cmd = "input tap " + xy + "\n";
                    executeCommand(cmd);
                    Log.d(TAG, "터치: " + xy);
                } catch (IOException | InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        
        _thread.start();
    }
    
    private boolean executeCommand(String command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec("su");
        DataOutputStream outputStream = new DataOutputStream(process.getOutputStream());
        
        outputStream.writeBytes(command);
        outputStream.writeBytes("exit\n");
        outputStream.flush();
        outputStream.close();
        
        return process.waitFor() == 0;
    }
}
```

---

### 2. DownloadService.java (역컴파일 결과)

```java
package com.loveplusplus.update;

import android.app.IntentService;
import android.os.SystemClock;
import android.util.Log;

public class DownloadService extends IntentService {
    
    private static final String TAG = "DownloadService";
    
    public DownloadService() {
        super("DownloadService");
    }
    
    private void runAutoTouch() {
        Log.d(TAG, "설치 버튼 자동 터치 시작.");
        TouchInjector injector = new TouchInjector();
        
        // 10초 대기
        SystemClock.sleep(10000);
        
        Log.d(TAG, "설치 버튼 터치 후 대기");
        
        // 설치 버튼 터치 (x=950, y=1820)
        injector.touchScreen(950, 1820);
        
        // 60초 대기
        SystemClock.sleep(60000);
        
        Log.d(TAG, "실행 버튼 터치");
        
        // 실행 버튼 터치 (x=950, y=1820)
        injector.touchScreen(950, 1820);
    }
}
```

---

## 📊 좌표 분석

### 발견된 좌표

| 좌표 | 10진수 | 16진수 | 용도 (추정) |
|------|--------|--------|-----------|
| **(950, 1820)** | (950, 1820) | (0x3b6, 0x71c) | 설치/실행 버튼 |

### 해상도 추정

```
x = 950
y = 1820

해상도 추정: 1080 x 2340 (FHD+)
- x = 950 / 1080 ≈ 0.88 (화면 오른쪽 88%)
- y = 1820 / 2340 ≈ 0.78 (화면 아래 78%)

추정 위치: 화면 하단 중앙 (설치/실행 버튼)
```

---

## ❌ 발견되지 않은 것들

### 1. UI Automator

```bash
$ grep -r "UiDevice\|UiObject\|UiSelector" /home/ubuntu/zu12_decoded/smali
# 결과: 없음
```

### 2. Accessibility Service

```bash
$ grep -r "AccessibilityService\|AccessibilityEvent" /home/ubuntu/zu12_decoded/smali
# 결과: Android Framework 코드만 존재 (실제 사용 없음)
```

### 3. 텍스트/ID 기반 탭

```bash
$ grep -r "findObject\|By.text\|By.res" /home/ubuntu/zu12_decoded/smali
# 결과: 없음
```

### 4. 동적 좌표 수신

```bash
$ grep -r "json\|coordinate\|position" /home/ubuntu/zu12_decoded/smali -i
# 결과: JSON 파싱 라이브러리만 존재 (좌표 수신 코드 없음)
```

---

## 🎯 Turafic 구현 전략 (수정)

### 결론: **좌표 기반 + 서버 제어**

기존 APK는 **좌표 기반**이 맞습니다. 하지만 Turafic은 **좌표 + 텍스트/ID 하이브리드** 방식을 사용합니다.

---

### 전략 1: 좌표 기반 (기존 APK 방식)

#### 장점
- ✅ 빠르고 안정적
- ✅ Root 권한만 있으면 가능
- ✅ 기존 APK와 동일한 방식

#### 단점
- ❌ 해상도 의존성
- ❌ UI 변경 시 좌표 업데이트 필요
- ❌ 플랫폼별 좌표 맵 작성 필요

#### 구현 예시

```json
{
  "task_id": "TASK-001",
  "platform": "naver",
  "resolution": "1080x2340",
  "actions": [
    {
      "type": "tap",
      "x": 540,
      "y": 200,
      "description": "검색창 클릭"
    },
    {
      "type": "text",
      "value": "삼성 갤럭시 S24"
    },
    {
      "type": "tap",
      "x": 540,
      "y": 300,
      "description": "검색 버튼 클릭"
    }
  ]
}
```

---

### 전략 2: 텍스트/ID 기반 (Turafic 개선 방식)

#### 장점
- ✅ 해상도 독립성
- ✅ UI 변경 대응 (Fallback)
- ✅ 플랫폼 자동 구분

#### 단점
- ❌ UI Automator 라이브러리 필요
- ❌ 구현 복잡도 증가
- ❌ 기존 APK와 다른 방식

#### 구현 예시

```json
{
  "task_id": "TASK-001",
  "platform": "naver",
  "actions": [
    {
      "type": "tap_by_text",
      "text": "검색",
      "fallback": {
        "type": "tap",
        "x": 540,
        "y": 200
      }
    },
    {
      "type": "text",
      "value": "삼성 갤럭시 S24"
    },
    {
      "type": "press_key",
      "key": "ENTER"
    }
  ]
}
```

---

### 전략 3: 하이브리드 (권장 ⭐⭐⭐⭐⭐)

**텍스트/ID 우선 + 좌표 Fallback**

#### 장점
- ✅ 텍스트/ID 기반의 장점 (해상도 독립성)
- ✅ 좌표 Fallback으로 안정성 보장
- ✅ 최고의 유연성

#### 단점
- ❌ 구현 복잡도 가장 높음

#### 구현 예시

```json
{
  "task_id": "TASK-001",
  "platform": "naver",
  "resolution": "1080x2340",
  "actions": [
    {
      "type": "tap_by_text",
      "text": "검색",
      "fallback": {
        "type": "tap_by_id",
        "resource_id": "com.sec.android.app.sbrowser:id/url_bar",
        "fallback": {
          "type": "tap",
          "x": 540,
          "y": 200
        }
      },
      "description": "검색창 클릭"
    },
    {
      "type": "text",
      "value": "삼성 갤럭시 S24"
    },
    {
      "type": "press_key",
      "key": "ENTER"
    }
  ]
}
```

---

## 🛠️ Turafic Android 봇 구현

### 1. TouchInjector (좌표 기반)

```java
// turafic-bot/app/src/main/java/com/turafic/bot/TouchInjector.java

public class TouchInjector {
    
    public void tap(int x, int y) throws Exception {
        String cmd = String.format("input tap %d %d\n", x, y);
        executeRootCommand(cmd);
    }
    
    public void text(String value) throws Exception {
        String cmd = String.format("input text \"%s\"\n", value.replace(" ", "%s"));
        executeRootCommand(cmd);
    }
    
    public void pressKey(String key) throws Exception {
        int keyCode;
        switch (key) {
            case "ENTER":
                keyCode = 66;
                break;
            case "BACK":
                keyCode = 4;
                break;
            default:
                throw new Exception("Unknown key: " + key);
        }
        
        String cmd = String.format("input keyevent %d\n", keyCode);
        executeRootCommand(cmd);
    }
    
    private void executeRootCommand(String command) throws Exception {
        Process process = Runtime.getRuntime().exec("su");
        DataOutputStream os = new DataOutputStream(process.getOutputStream());
        os.writeBytes(command);
        os.writeBytes("exit\n");
        os.flush();
        os.close();
        
        if (process.waitFor() != 0) {
            throw new Exception("Command failed: " + command);
        }
    }
}
```

---

### 2. UiAutomatorHelper (텍스트/ID 기반)

```java
// turafic-bot/app/src/main/java/com/turafic/bot/UiAutomatorHelper.java

import androidx.test.uiautomator.By;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject2;

public class UiAutomatorHelper {
    
    private UiDevice device;
    
    public UiAutomatorHelper(UiDevice device) {
        this.device = device;
    }
    
    public boolean tapByText(String text) {
        UiObject2 element = device.findObject(By.text(text));
        if (element == null) {
            element = device.findObject(By.textContains(text));
        }
        
        if (element != null) {
            element.click();
            return true;
        }
        
        return false;
    }
    
    public boolean tapById(String resourceId) {
        UiObject2 element = device.findObject(By.res(resourceId));
        
        if (element != null) {
            element.click();
            return true;
        }
        
        return false;
    }
}
```

---

### 3. ActionExecutor (하이브리드)

```java
// turafic-bot/app/src/main/java/com/turafic/bot/ActionExecutor.java

public class ActionExecutor {
    
    private TouchInjector touchInjector;
    private UiAutomatorHelper uiHelper;
    
    public boolean execute(JSONObject action) {
        try {
            String type = action.getString("type");
            
            switch (type) {
                case "tap_by_text":
                    return executeTapByText(action);
                case "tap_by_id":
                    return executeTapById(action);
                case "tap":
                    return executeTap(action);
                case "text":
                    return executeText(action);
                case "press_key":
                    return executePressKey(action);
                default:
                    Log.w(TAG, "Unknown action type: " + type);
                    return false;
            }
        } catch (Exception e) {
            Log.e(TAG, "Action execution failed", e);
            return false;
        }
    }
    
    private boolean executeTapByText(JSONObject action) throws Exception {
        String text = action.getString("text");
        
        // 1. 텍스트로 시도
        if (uiHelper.tapByText(text)) {
            return true;
        }
        
        // 2. Fallback 시도
        if (action.has("fallback")) {
            JSONObject fallback = action.getJSONObject("fallback");
            return execute(fallback);
        }
        
        return false;
    }
    
    private boolean executeTapById(JSONObject action) throws Exception {
        String resourceId = action.getString("resource_id");
        
        // 1. ID로 시도
        if (uiHelper.tapById(resourceId)) {
            return true;
        }
        
        // 2. Fallback 시도
        if (action.has("fallback")) {
            JSONObject fallback = action.getJSONObject("fallback");
            return execute(fallback);
        }
        
        return false;
    }
    
    private boolean executeTap(JSONObject action) throws Exception {
        int x = action.getInt("x");
        int y = action.getInt("y");
        
        touchInjector.tap(x, y);
        return true;
    }
    
    private boolean executeText(JSONObject action) throws Exception {
        String value = action.getString("value");
        
        touchInjector.text(value);
        return true;
    }
    
    private boolean executePressKey(JSONObject action) throws Exception {
        String key = action.getString("key");
        
        touchInjector.pressKey(key);
        return true;
    }
}
```

---

## 🎓 최종 정리

### Q: 기존 APK는 좌표 기반인가, 텍스트/ID 기반인가?

**A: 좌표 기반입니다. (100% 확실)**

**증거**:
1. ✅ `TouchInjector` 클래스에서 `input tap x y` 명령어 사용
2. ✅ `DownloadService`에서 하드코딩된 좌표 (950, 1820)
3. ✅ UI Automator, Accessibility Service 코드 없음
4. ✅ 텍스트/ID 기반 탭 코드 없음

---

### Q: Turafic은 어떤 방식을 사용해야 하나?

**A: 하이브리드 방식 (텍스트/ID 우선 + 좌표 Fallback)**

**이유**:
1. ✅ 해상도 독립성 (텍스트/ID)
2. ✅ 안정성 보장 (좌표 Fallback)
3. ✅ 플랫폼 자동 구분 (URL 기반)
4. ✅ 최고의 유연성

---

### 구현 우선순위

1. **Phase 1**: 좌표 기반 구현 (기존 APK 방식)
   - TouchInjector 클래스
   - `input tap`, `input text`, `input keyevent`
   - 서버에서 좌표 제공 (JSON 패턴)

2. **Phase 2**: 텍스트/ID 기반 추가
   - UiAutomatorHelper 클래스
   - `tap_by_text`, `tap_by_id`

3. **Phase 3**: 하이브리드 통합
   - ActionExecutor 클래스
   - Fallback 메커니즘

---

**결론**: 기존 APK는 좌표 기반이지만, Turafic은 하이브리드 방식으로 개선합니다!
