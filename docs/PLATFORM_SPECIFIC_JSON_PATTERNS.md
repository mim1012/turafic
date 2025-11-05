# 플랫폼별 JSON 패턴 전략 (네이버 vs 쿠팡)

## 📋 목차
1. [문제 정의](#문제-정의)
2. [해결 전략](#해결-전략)
3. [플랫폼 식별 시스템](#플랫폼-식별-시스템)
4. [텍스트/컨텍스트 기반 액션](#텍스트컨텍스트-기반-액션)
5. [플랫폼별 JSON 패턴](#플랫폼별-json-패턴)
6. [구현 예시](#구현-예시)

---

## 🔴 문제 정의

### 네이버와 쿠팡의 UI가 완전히 다름

```
네이버 쇼핑:
- 검색창 위치: 상단 중앙
- 상품 카드 레이아웃: 2열 그리드
- 상품 클릭 영역: 이미지 + 제목
- 필터 위치: 상단 (정렬, 가격)
- 광고 표시: "AD" 배지

쿠팡:
- 검색창 위치: 상단 좌측
- 상품 카드 레이아웃: 1열 리스트
- 상품 클릭 영역: 전체 카드
- 필터 위치: 좌측 사이드바
- 광고 표시: "광고" 텍스트
```

### 좌표 기반 접근의 한계

```
문제 1: 해상도 의존성
- 1080x1920 (FHD): 검색창 (540, 200)
- 1440x2560 (QHD): 검색창 (720, 267)
- 좌표가 기기마다 다름

문제 2: UI 업데이트
- 네이버/쿠팡이 UI 변경 시 좌표 무효화
- 모든 봇의 JSON 패턴 재작성 필요

문제 3: 플랫폼 구분 불가
- 동일한 좌표로 네이버와 쿠팡 제어 불가
- 플랫폼별로 완전히 다른 패턴 필요
```

---

## ✅ 해결 전략

### 1. 플랫폼 식별 시스템

**제품 URL로 플랫폼 자동 식별**

```python
# server/core/platform_detector.py

def detect_platform(product_url: str) -> str:
    """제품 URL로 플랫폼 식별"""
    
    if "shopping.naver.com" in product_url:
        return "naver"
    elif "coupang.com" in product_url:
        return "coupang"
    elif "11st.co.kr" in product_url:
        return "11st"
    else:
        raise ValueError(f"Unknown platform: {product_url}")
```

---

### 2. 텍스트/컨텍스트 기반 액션

**좌표 대신 텍스트, UI 요소, 컨텍스트로 제어**

#### A. 텍스트 기반 탭

```json
{
  "type": "tap_by_text",
  "text": "검색",
  "description": "검색 버튼 탭"
}
```

**Android 구현**:
```java
// UiAutomator2 사용
UiObject2 searchButton = device.findObject(By.text("검색"));
if (searchButton != null) {
    searchButton.click();
}
```

#### B. 리소스 ID 기반 탭

```json
{
  "type": "tap_by_id",
  "resource_id": "com.sec.android.app.sbrowser:id/url_bar",
  "description": "주소창 탭"
}
```

**Android 구현**:
```java
UiObject2 urlBar = device.findObject(By.res("com.sec.android.app.sbrowser:id/url_bar"));
if (urlBar != null) {
    urlBar.click();
}
```

#### C. 컨텍스트 기반 탭 (상대 위치)

```json
{
  "type": "tap_relative",
  "anchor_text": "삼성 갤럭시 S24",
  "direction": "below",
  "distance": 100,
  "description": "상품명 아래 100px 탭"
}
```

**Android 구현**:
```java
UiObject2 anchor = device.findObject(By.textContains("삼성 갤럭시 S24"));
if (anchor != null) {
    Rect bounds = anchor.getVisibleBounds();
    int x = bounds.centerX();
    int y = bounds.bottom + 100;  // 아래 100px
    device.click(x, y);
}
```

#### D. 스크롤 후 탭

```json
{
  "type": "scroll_and_tap",
  "scroll_to_text": "삼성 갤럭시 S24",
  "tap_text": "삼성 갤럭시 S24",
  "description": "스크롤해서 상품 찾고 탭"
}
```

**Android 구현**:
```java
// 스크롤해서 찾기
UiScrollable scrollable = new UiScrollable(new UiSelector().scrollable(true));
UiObject product = scrollable.getChildByText(
    new UiSelector().className("android.widget.TextView"),
    "삼성 갤럭시 S24",
    true
);
if (product != null) {
    product.click();
}
```

---

### 3. 플랫폼별 JSON 패턴 템플릿

**서버에서 플랫폼별로 다른 템플릿 생성**

```python
# server/agents/traffic_agent.py

class TrafficAgent:
    
    def generate_json_pattern(self, test_case: dict) -> dict:
        """테스트 케이스 → JSON 패턴 변환"""
        
        # 1. 플랫폼 식별
        platform = detect_platform(test_case["product_url"])
        
        # 2. 플랫폼별 템플릿 선택
        if platform == "naver":
            return self.generate_naver_pattern(test_case)
        elif platform == "coupang":
            return self.generate_coupang_pattern(test_case)
        else:
            raise ValueError(f"Unsupported platform: {platform}")
```

---

## 🔵 플랫폼별 JSON 패턴

### 네이버 쇼핑 패턴

#### 1. 네이버 검색 → 쇼핑 탭 (Entry Path: Naver Search)

```json
{
  "task_id": "TASK-NAVER-001",
  "platform": "naver",
  "product_url": "https://shopping.naver.com/catalog/12345678",
  "keyword": "삼성 갤럭시 S24",
  "actions": [
    {
      "type": "force_stop",
      "package": "com.sec.android.app.sbrowser",
      "description": "브라우저 강제 종료"
    },
    {
      "type": "wait",
      "duration": 3000
    },
    {
      "type": "start_app",
      "package": "com.sec.android.app.sbrowser",
      "description": "브라우저 시작"
    },
    {
      "type": "wait",
      "duration": 3000
    },
    {
      "type": "tap_by_id",
      "resource_id": "com.sec.android.app.sbrowser:id/url_bar",
      "fallback": {
        "type": "tap_by_text",
        "text": "검색 또는 웹 주소 입력"
      },
      "description": "주소창 탭"
    },
    {
      "type": "text",
      "value": "https://www.naver.com",
      "description": "네이버 URL 입력"
    },
    {
      "type": "press_key",
      "key": "ENTER",
      "description": "엔터 키"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "tap_by_text",
      "text": "검색",
      "fallback": {
        "type": "tap_by_id",
        "resource_id": "query"
      },
      "description": "네이버 검색창 탭"
    },
    {
      "type": "text",
      "value": "삼성 갤럭시 S24",
      "description": "키워드 입력"
    },
    {
      "type": "press_key",
      "key": "ENTER",
      "description": "검색 실행"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "tap_by_text",
      "text": "쇼핑",
      "description": "쇼핑 탭 클릭"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "scroll_and_tap",
      "scroll_to_text": "삼성 갤럭시 S24",
      "tap_text": "삼성 갤럭시 S24",
      "max_scrolls": 10,
      "description": "상품 찾아서 클릭"
    },
    {
      "type": "wait",
      "duration": 30000,
      "description": "상품 상세 페이지 체류 (High Engagement)"
    },
    {
      "type": "scroll",
      "direction": "down",
      "distance": 1000,
      "description": "상세 페이지 스크롤"
    },
    {
      "type": "wait",
      "duration": 10000
    },
    {
      "type": "screenshot",
      "path": "/sdcard/turafic/TASK-NAVER-001.png",
      "description": "스크린샷 저장"
    }
  ]
}
```

---

#### 2. 네이버 쇼핑 직접 접속 (Entry Path: Shopping Direct)

```json
{
  "task_id": "TASK-NAVER-002",
  "platform": "naver",
  "product_url": "https://shopping.naver.com/catalog/12345678",
  "keyword": "삼성 갤럭시 S24",
  "actions": [
    {
      "type": "force_stop",
      "package": "com.sec.android.app.sbrowser"
    },
    {
      "type": "wait",
      "duration": 3000
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
      "type": "tap_by_id",
      "resource_id": "com.sec.android.app.sbrowser:id/url_bar",
      "fallback": {
        "type": "tap_by_text",
        "text": "검색 또는 웹 주소 입력"
      }
    },
    {
      "type": "text",
      "value": "https://shopping.naver.com"
    },
    {
      "type": "press_key",
      "key": "ENTER"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "tap_by_text",
      "text": "검색",
      "fallback": {
        "type": "tap_by_class",
        "class_name": "android.widget.EditText"
      },
      "description": "네이버 쇼핑 검색창 탭"
    },
    {
      "type": "text",
      "value": "삼성 갤럭시 S24"
    },
    {
      "type": "press_key",
      "key": "ENTER"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "scroll_and_tap",
      "scroll_to_text": "삼성 갤럭시 S24",
      "tap_text": "삼성 갤럭시 S24",
      "max_scrolls": 10,
      "filter_ads": true,
      "ad_patterns": ["AD", "광고", "스폰서"],
      "description": "광고 제외하고 상품 클릭"
    },
    {
      "type": "wait",
      "duration": 30000
    },
    {
      "type": "scroll",
      "direction": "down",
      "distance": 1000
    },
    {
      "type": "wait",
      "duration": 10000
    },
    {
      "type": "screenshot",
      "path": "/sdcard/turafic/TASK-NAVER-002.png"
    }
  ]
}
```

---

### 쿠팡 패턴

#### 1. 쿠팡 직접 접속 → 검색

```json
{
  "task_id": "TASK-COUPANG-001",
  "platform": "coupang",
  "product_url": "https://www.coupang.com/vp/products/12345678",
  "keyword": "삼성 갤럭시 S24",
  "actions": [
    {
      "type": "force_stop",
      "package": "com.sec.android.app.sbrowser"
    },
    {
      "type": "wait",
      "duration": 3000
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
      "type": "tap_by_id",
      "resource_id": "com.sec.android.app.sbrowser:id/url_bar",
      "fallback": {
        "type": "tap_by_text",
        "text": "검색 또는 웹 주소 입력"
      }
    },
    {
      "type": "text",
      "value": "https://www.coupang.com"
    },
    {
      "type": "press_key",
      "key": "ENTER"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "tap_by_class",
      "class_name": "android.widget.EditText",
      "contains_text": "검색",
      "description": "쿠팡 검색창 탭"
    },
    {
      "type": "text",
      "value": "삼성 갤럭시 S24"
    },
    {
      "type": "press_key",
      "key": "ENTER"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "scroll_and_tap",
      "scroll_to_text": "삼성 갤럭시 S24",
      "tap_text": "삼성 갤럭시 S24",
      "max_scrolls": 10,
      "filter_ads": true,
      "ad_patterns": ["광고", "AD", "스폰서"],
      "description": "광고 제외하고 상품 클릭"
    },
    {
      "type": "wait",
      "duration": 30000,
      "description": "상품 상세 페이지 체류"
    },
    {
      "type": "scroll",
      "direction": "down",
      "distance": 1000
    },
    {
      "type": "wait",
      "duration": 10000
    },
    {
      "type": "tap_by_text",
      "text": "장바구니",
      "optional": true,
      "description": "장바구니 버튼 (있으면 클릭)"
    },
    {
      "type": "wait",
      "duration": 5000
    },
    {
      "type": "screenshot",
      "path": "/sdcard/turafic/TASK-COUPANG-001.png"
    }
  ]
}
```

---

#### 2. 쿠팡 URL 직접 접속 (제품 상세 페이지)

```json
{
  "task_id": "TASK-COUPANG-002",
  "platform": "coupang",
  "product_url": "https://www.coupang.com/vp/products/12345678",
  "keyword": "삼성 갤럭시 S24",
  "actions": [
    {
      "type": "force_stop",
      "package": "com.sec.android.app.sbrowser"
    },
    {
      "type": "wait",
      "duration": 3000
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
      "type": "tap_by_id",
      "resource_id": "com.sec.android.app.sbrowser:id/url_bar"
    },
    {
      "type": "text",
      "value": "https://www.coupang.com/vp/products/12345678"
    },
    {
      "type": "press_key",
      "key": "ENTER"
    },
    {
      "type": "wait",
      "duration": 10000,
      "description": "상품 페이지 로딩 대기"
    },
    {
      "type": "scroll",
      "direction": "down",
      "distance": 500
    },
    {
      "type": "wait",
      "duration": 15000
    },
    {
      "type": "scroll",
      "direction": "down",
      "distance": 1000
    },
    {
      "type": "wait",
      "duration": 10000
    },
    {
      "type": "tap_by_text",
      "text": "리뷰",
      "optional": true,
      "description": "리뷰 탭 (있으면 클릭)"
    },
    {
      "type": "wait",
      "duration": 10000
    },
    {
      "type": "screenshot",
      "path": "/sdcard/turafic/TASK-COUPANG-002.png"
    }
  ]
}
```

---

## 🛠️ 구현 예시

### 1. 서버: 플랫폼별 패턴 생성

```python
# server/agents/traffic_agent.py

class TrafficAgent:
    
    def generate_naver_pattern(self, test_case: dict) -> dict:
        """네이버 쇼핑 JSON 패턴 생성"""
        
        variables = test_case["variables"]
        actions = []
        
        # 기본 액션 (브라우저 재시작)
        actions.extend([
            {"type": "force_stop", "package": "com.sec.android.app.sbrowser"},
            {"type": "wait", "duration": 3000},
            {"type": "start_app", "package": "com.sec.android.app.sbrowser"},
            {"type": "wait", "duration": 3000}
        ])
        
        # Entry Path에 따라 분기
        if variables["entry_path"] == "Naver Search":
            # 네이버 검색 → 쇼핑 탭
            actions.extend([
                {
                    "type": "tap_by_id",
                    "resource_id": "com.sec.android.app.sbrowser:id/url_bar",
                    "fallback": {"type": "tap_by_text", "text": "검색 또는 웹 주소 입력"}
                },
                {"type": "text", "value": "https://www.naver.com"},
                {"type": "press_key", "key": "ENTER"},
                {"type": "wait", "duration": 5000},
                {"type": "tap_by_text", "text": "검색"},
                {"type": "text", "value": test_case["keyword"]},
                {"type": "press_key", "key": "ENTER"},
                {"type": "wait", "duration": 5000},
                {"type": "tap_by_text", "text": "쇼핑"},
                {"type": "wait", "duration": 5000}
            ])
        else:  # Shopping Direct
            # 네이버 쇼핑 직접 접속
            actions.extend([
                {
                    "type": "tap_by_id",
                    "resource_id": "com.sec.android.app.sbrowser:id/url_bar"
                },
                {"type": "text", "value": "https://shopping.naver.com"},
                {"type": "press_key", "key": "ENTER"},
                {"type": "wait", "duration": 5000},
                {"type": "tap_by_text", "text": "검색"},
                {"type": "text", "value": test_case["keyword"]},
                {"type": "press_key", "key": "ENTER"},
                {"type": "wait", "duration": 5000}
            ])
        
        # 상품 찾기 및 클릭
        actions.append({
            "type": "scroll_and_tap",
            "scroll_to_text": test_case["keyword"],
            "tap_text": test_case["keyword"],
            "max_scrolls": 10,
            "filter_ads": True,
            "ad_patterns": ["AD", "광고", "스폰서"]
        })
        
        # Engagement에 따라 액션 추가
        if variables["engagement"] == "High":
            actions.extend([
                {"type": "wait", "duration": 30000},
                {"type": "scroll", "direction": "down", "distance": 1000},
                {"type": "wait", "duration": 10000},
                {"type": "tap_by_text", "text": "장바구니", "optional": True},
                {"type": "wait", "duration": 5000}
            ])
        elif variables["engagement"] == "Medium":
            actions.extend([
                {"type": "wait", "duration": 15000},
                {"type": "scroll", "direction": "down", "distance": 500},
                {"type": "wait", "duration": 5000}
            ])
        else:  # Low
            actions.extend([
                {"type": "wait", "duration": 5000}
            ])
        
        # 스크린샷
        actions.append({
            "type": "screenshot",
            "path": f"/sdcard/turafic/{test_case['test_case_id']}.png"
        })
        
        return {
            "task_id": test_case["test_case_id"],
            "platform": "naver",
            "product_url": test_case["product_url"],
            "keyword": test_case["keyword"],
            "actions": actions
        }
    
    def generate_coupang_pattern(self, test_case: dict) -> dict:
        """쿠팡 JSON 패턴 생성"""
        
        variables = test_case["variables"]
        actions = []
        
        # 기본 액션
        actions.extend([
            {"type": "force_stop", "package": "com.sec.android.app.sbrowser"},
            {"type": "wait", "duration": 3000},
            {"type": "start_app", "package": "com.sec.android.app.sbrowser"},
            {"type": "wait", "duration": 3000}
        ])
        
        # Entry Path에 따라 분기
        if variables["entry_path"] == "Search":
            # 쿠팡 검색
            actions.extend([
                {"type": "tap_by_id", "resource_id": "com.sec.android.app.sbrowser:id/url_bar"},
                {"type": "text", "value": "https://www.coupang.com"},
                {"type": "press_key", "key": "ENTER"},
                {"type": "wait", "duration": 5000},
                {"type": "tap_by_class", "class_name": "android.widget.EditText", "contains_text": "검색"},
                {"type": "text", "value": test_case["keyword"]},
                {"type": "press_key", "key": "ENTER"},
                {"type": "wait", "duration": 5000}
            ])
        else:  # Direct
            # 쿠팡 URL 직접 접속
            actions.extend([
                {"type": "tap_by_id", "resource_id": "com.sec.android.app.sbrowser:id/url_bar"},
                {"type": "text", "value": test_case["product_url"]},
                {"type": "press_key", "key": "ENTER"},
                {"type": "wait", "duration": 10000}
            ])
        
        # 상품 찾기 및 클릭 (검색 경로만)
        if variables["entry_path"] == "Search":
            actions.append({
                "type": "scroll_and_tap",
                "scroll_to_text": test_case["keyword"],
                "tap_text": test_case["keyword"],
                "max_scrolls": 10,
                "filter_ads": True,
                "ad_patterns": ["광고", "AD", "스폰서"]
            })
        
        # Engagement
        if variables["engagement"] == "High":
            actions.extend([
                {"type": "wait", "duration": 30000},
                {"type": "scroll", "direction": "down", "distance": 1000},
                {"type": "wait", "duration": 10000},
                {"type": "tap_by_text", "text": "장바구니", "optional": True},
                {"type": "wait", "duration": 5000}
            ])
        elif variables["engagement"] == "Medium":
            actions.extend([
                {"type": "wait", "duration": 15000},
                {"type": "scroll", "direction": "down", "distance": 500}
            ])
        else:
            actions.extend([
                {"type": "wait", "duration": 5000}
            ])
        
        # 스크린샷
        actions.append({
            "type": "screenshot",
            "path": f"/sdcard/turafic/{test_case['test_case_id']}.png"
        })
        
        return {
            "task_id": test_case["test_case_id"],
            "platform": "coupang",
            "product_url": test_case["product_url"],
            "keyword": test_case["keyword"],
            "actions": actions
        }
```

---

### 2. Android: 액션 실행 엔진

```java
// turafic-bot/app/src/main/java/com/turafic/bot/ActionExecutor.java

public class ActionExecutor {
    
    private UiDevice device;
    
    public boolean execute(JSONObject pattern) {
        try {
            JSONArray actions = pattern.getJSONArray("actions");
            
            for (int i = 0; i < actions.length(); i++) {
                JSONObject action = actions.getJSONObject(i);
                String type = action.getString("type");
                
                switch (type) {
                    case "tap_by_text":
                        tapByText(action);
                        break;
                    case "tap_by_id":
                        tapById(action);
                        break;
                    case "tap_by_class":
                        tapByClass(action);
                        break;
                    case "scroll_and_tap":
                        scrollAndTap(action);
                        break;
                    case "text":
                        inputText(action);
                        break;
                    case "press_key":
                        pressKey(action);
                        break;
                    case "scroll":
                        scroll(action);
                        break;
                    case "wait":
                        wait(action);
                        break;
                    case "screenshot":
                        screenshot(action);
                        break;
                    case "force_stop":
                        forceStop(action);
                        break;
                    case "start_app":
                        startApp(action);
                        break;
                    default:
                        Log.w(TAG, "Unknown action type: " + type);
                }
            }
            
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Action execution failed", e);
            return false;
        }
    }
    
    private void tapByText(JSONObject action) throws Exception {
        String text = action.getString("text");
        
        UiObject2 element = device.findObject(By.text(text));
        if (element == null) {
            element = device.findObject(By.textContains(text));
        }
        
        if (element != null) {
            element.click();
            Log.i(TAG, "Tapped by text: " + text);
        } else {
            // Fallback 시도
            if (action.has("fallback")) {
                JSONObject fallback = action.getJSONObject("fallback");
                execute(new JSONObject().put("actions", new JSONArray().put(fallback)));
            } else {
                throw new Exception("Element not found: " + text);
            }
        }
    }
    
    private void tapById(JSONObject action) throws Exception {
        String resourceId = action.getString("resource_id");
        
        UiObject2 element = device.findObject(By.res(resourceId));
        
        if (element != null) {
            element.click();
            Log.i(TAG, "Tapped by ID: " + resourceId);
        } else {
            // Fallback
            if (action.has("fallback")) {
                JSONObject fallback = action.getJSONObject("fallback");
                execute(new JSONObject().put("actions", new JSONArray().put(fallback)));
            } else {
                throw new Exception("Element not found: " + resourceId);
            }
        }
    }
    
    private void scrollAndTap(JSONObject action) throws Exception {
        String scrollToText = action.getString("scroll_to_text");
        String tapText = action.getString("tap_text");
        int maxScrolls = action.optInt("max_scrolls", 10);
        boolean filterAds = action.optBoolean("filter_ads", false);
        JSONArray adPatterns = action.optJSONArray("ad_patterns");
        
        for (int i = 0; i < maxScrolls; i++) {
            // 화면에서 텍스트 찾기
            List<UiObject2> elements = device.findObjects(By.textContains(scrollToText));
            
            if (!elements.isEmpty()) {
                // 광고 필터링
                if (filterAds && adPatterns != null) {
                    for (UiObject2 element : elements) {
                        boolean isAd = false;
                        
                        // 광고 패턴 체크
                        for (int j = 0; j < adPatterns.length(); j++) {
                            String adPattern = adPatterns.getString(j);
                            UiObject2 parent = element.getParent();
                            
                            if (parent != null) {
                                List<UiObject2> siblings = parent.getChildren();
                                for (UiObject2 sibling : siblings) {
                                    if (sibling.getText() != null && 
                                        sibling.getText().contains(adPattern)) {
                                        isAd = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (isAd) break;
                        }
                        
                        // 광고가 아니면 클릭
                        if (!isAd) {
                            element.click();
                            Log.i(TAG, "Tapped non-ad element: " + scrollToText);
                            return;
                        }
                    }
                } else {
                    // 광고 필터링 없으면 첫 번째 요소 클릭
                    elements.get(0).click();
                    Log.i(TAG, "Tapped first element: " + scrollToText);
                    return;
                }
            }
            
            // 스크롤
            device.swipe(
                device.getDisplayWidth() / 2,
                device.getDisplayHeight() * 3 / 4,
                device.getDisplayWidth() / 2,
                device.getDisplayHeight() / 4,
                10
            );
            
            Thread.sleep(1000);
        }
        
        throw new Exception("Element not found after " + maxScrolls + " scrolls: " + scrollToText);
    }
    
    private void inputText(JSONObject action) throws Exception {
        String value = action.getString("value");
        
        // 현재 포커스된 요소에 텍스트 입력
        device.pressKeyCode(KeyEvent.KEYCODE_DEL, 0);  // 기존 텍스트 삭제
        Thread.sleep(500);
        
        // Root 권한으로 텍스트 입력
        Runtime.getRuntime().exec(new String[]{
            "su", "-c", "input text \"" + value.replace(" ", "%s") + "\""
        }).waitFor();
        
        Log.i(TAG, "Input text: " + value);
    }
    
    private void pressKey(JSONObject action) throws Exception {
        String key = action.getString("key");
        
        int keyCode;
        switch (key) {
            case "ENTER":
                keyCode = KeyEvent.KEYCODE_ENTER;
                break;
            case "BACK":
                keyCode = KeyEvent.KEYCODE_BACK;
                break;
            case "HOME":
                keyCode = KeyEvent.KEYCODE_HOME;
                break;
            default:
                throw new Exception("Unknown key: " + key);
        }
        
        device.pressKeyCode(keyCode);
        Log.i(TAG, "Pressed key: " + key);
    }
    
    private void forceStop(JSONObject action) throws Exception {
        String packageName = action.getString("package");
        
        Runtime.getRuntime().exec(new String[]{
            "su", "-c", "am force-stop " + packageName
        }).waitFor();
        
        Log.i(TAG, "Force stopped: " + packageName);
    }
    
    private void startApp(JSONObject action) throws Exception {
        String packageName = action.getString("package");
        
        Intent intent = getPackageManager().getLaunchIntentForPackage(packageName);
        if (intent != null) {
            startActivity(intent);
            Log.i(TAG, "Started app: " + packageName);
        } else {
            throw new Exception("App not found: " + packageName);
        }
    }
}
```

---

## 🎯 핵심 요약

### 1. 플랫폼 식별
- ✅ 제품 URL로 자동 식별 (네이버 vs 쿠팡)
- ✅ 서버에서 플랫폼별 템플릿 선택

### 2. 텍스트/컨텍스트 기반 액션
- ✅ `tap_by_text`: 텍스트로 탭
- ✅ `tap_by_id`: 리소스 ID로 탭
- ✅ `tap_by_class`: 클래스명으로 탭
- ✅ `scroll_and_tap`: 스크롤해서 찾고 탭
- ✅ `fallback`: 실패 시 대체 액션

### 3. 광고 필터링
- ✅ 8가지 광고 패턴 ("AD", "광고", "스폰서", ...)
- ✅ 광고 제외하고 실제 상품 클릭

### 4. 플랫폼별 패턴
- ✅ 네이버: 검색 → 쇼핑 탭 or 쇼핑 직접 접속
- ✅ 쿠팡: 검색 or URL 직접 접속

---

**다음 단계**: Android 봇 구현 시작!
