# UI 좌표 매핑 가이드

## 📍 개요

봇이 좌표 기반으로 네이버 쇼핑 UI를 제어하려면, **어떤 좌표에 어떤 버튼이 있는지** 미리 알아야 합니다. 이 문서는 UI 좌표를 인식하고 매핑하는 3가지 방법을 설명합니다.

---

## 🎯 좌표 인식 방법 비교

| 방법 | 장점 | 단점 | 추천도 |
|------|------|------|--------|
| **1. 수동 좌표 매핑** | 정확하고 빠름 | 해상도별 수동 작업 필요 | ⭐⭐⭐⭐⭐ |
| **2. Appium Element Inspector** | UI 요소 자동 인식 | Appium 의존성, 느림 | ⭐⭐⭐ |
| **3. AI Vision (OCR/객체 감지)** | 완전 자동화 | 복잡하고 비용 높음 | ⭐⭐ |

**결론**: **방법 1 (수동 매핑)**을 권장합니다. 한 번만 작업하면 영구적으로 사용 가능하며, 가장 빠르고 정확합니다.

---

## 방법 1: 수동 좌표 매핑 (Manual Mapping) ⭐ 추천

### 1-1. ADB 개발자 옵션으로 좌표 확인

```bash
# 1. Android 기기에서 개발자 옵션 활성화
설정 → 휴대전화 정보 → 빌드번호 7회 탭

# 2. 개발자 옵션에서 "포인터 위치 표시" 활성화
설정 → 개발자 옵션 → 포인터 위치 표시 ON

# 3. 네이버 쇼핑 앱/웹 열고 화면 탭
# 화면 상단에 좌표가 실시간으로 표시됨
# 예: (540, 200) ← 검색창 위치
```

**스크린샷 예시**:
```
┌────────────────────────────────────────┐
│ X: 540  Y: 200  P: 1.2  Size: 28.5    │  ← 좌표 표시
├────────────────────────────────────────┤
│                                        │
│         [  검색창  ]  🔍              │  ← 이 위치를 탭
│                                        │
│                                        │
└────────────────────────────────────────┘
```

### 1-2. UI Automator Viewer로 좌표 추출 (더 정확함)

```bash
# 1. Android SDK Tools 설치 확인
cd /path/to/android-sdk/tools/bin
ls -la | grep uiautomatorviewer

# 2. UI Automator Viewer 실행
./uiautomatorviewer

# 3. 기기 연결 및 스크린샷 촬영
Device Screenshot 버튼 클릭

# 4. UI 요소 클릭 → 좌표 정보 확인
Node Detail 패널에서 확인:
- bounds: [20,180][1060,220]
- 중심점 계산: x = (20+1060)/2 = 540, y = (180+220)/2 = 200
```

**UI Automator Viewer 화면**:
```
┌─────────────────────────────────────────────────────────────┐
│ Device Screenshot                              Node Detail   │
│ ┌─────────────────────┐  ┌───────────────────────────────┐ │
│ │                     │  │ class: android.widget.EditText│ │
│ │   [  검색창  ]  🔍  │  │ text: "검색어를 입력하세요"      │ │
│ │         ▲           │  │ resource-id: "nx_query"       │ │
│ │         └──선택      │  │ bounds: [20,180][1060,220]    │ │
│ │                     │  │ clickable: true               │ │
│ │                     │  │ enabled: true                 │ │
│ └─────────────────────┘  └───────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 1-3. 해상도별 좌표 맵 JSON 생성

측정한 좌표를 JSON 파일로 정리합니다:

**파일 경로**: `config/ui_coordinates/1080x2340_samsung_s7.json`

```json
{
  "resolution": "1080x2340",
  "device_model": "Samsung Galaxy S7",
  "screen_density": 480,
  "description": "네이버 쇼핑 UI 좌표 맵",
  "last_updated": "2025-11-02",

  "naver_main": {
    "search_bar": {
      "x": 540,
      "y": 200,
      "width": 1040,
      "height": 60,
      "description": "네이버 메인 검색창"
    }
  },

  "naver_shopping": {
    "product_item_1": {
      "x": 270,
      "y": 600,
      "width": 520,
      "height": 300,
      "description": "첫 번째 상품 (좌측)"
    },
    "product_item_2": {
      "x": 810,
      "y": 600,
      "width": 520,
      "height": 300,
      "description": "두 번째 상품 (우측)"
    }
  },

  "product_detail_page": {
    "add_to_cart_button": {
      "x": 810,
      "y": 2250,
      "width": 480,
      "height": 90,
      "description": "장바구니 담기"
    }
  }
}
```

### 1-4. 좌표 맵 사용 (서버 측)

```python
# server/api/task_assignment.py
from server.core.coordinate_loader import load_coordinates, generate_coordinates_for_pattern

@router.get("/tasks/get_task")
async def get_task(bot_id: str):
    bot = await db.get_bot(bot_id)

    # 1. 봇의 해상도에 맞는 좌표 맵 로드 (Redis 캐싱)
    coordinates_map = await load_coordinates(bot.screen_resolution)
    # 예: "1080x2340" → config/ui_coordinates/1080x2340_samsung_s7.json

    # 2. 작업 패턴 생성용 간소화된 좌표 맵 생성
    coordinates = generate_coordinates_for_pattern(coordinates_map)
    # {
    #   "search_bar": {"x": 540, "y": 200},
    #   "product_item_1": {"x": 270, "y": 600},
    #   ...
    # }

    # 3. JSON 작업 패턴 생성
    pattern = generate_task_pattern(
        task_config=test_config,
        coordinates=coordinates,  # ← 여기서 사용
        keyword=campaign.target_keyword
    )

    return {"task_id": "...", "pattern": pattern}
```

### 1-5. 좌표 사용 (Android 봇 측)

```java
// Android: TaskExecutor.java
JSONObject step = pattern.getJSONObject(i);
String action = step.getString("action");

if ("tap".equals(action)) {
    int x = step.getInt("x");  // 540
    int y = step.getInt("y");  // 200

    // Root 권한으로 화면 탭
    rootController.tap(x, y);
    // 실행: su -c "input tap 540 200"
}
```

---

## 방법 2: Appium Element Inspector (반자동)

Appium을 사용하면 UI 요소를 ID나 XPath로 찾을 수 있습니다.

### 2-1. Appium Inspector로 요소 인식

```bash
# 1. Appium Server 실행
appium

# 2. Appium Inspector 실행
appium-inspector

# 3. Desired Capabilities 설정
{
  "platformName": "Android",
  "deviceName": "SM-G998N",
  "automationName": "UiAutomator2",
  "browserName": "Chrome"
}

# 4. Start Session → 화면에서 요소 클릭
# 요소 정보 확인:
# - resource-id: "nx_query"
# - xpath: "//input[@id='nx_query']"
# - bounds: [20,180][1060,220]
```

### 2-2. Appium 코드로 요소 찾기

```python
# server/core/appium_pattern_generator.py
from appium import webdriver
from appium.webdriver.common.mobileby import MobileBy

# 요소 찾기 (ID)
search_bar = driver.find_element(MobileBy.ID, "nx_query")
location = search_bar.location  # {"x": 540, "y": 200}
size = search_bar.size          # {"width": 1040, "height": 60}

# 요소 찾기 (XPath)
product = driver.find_element(MobileBy.XPATH, "//div[@class='product_item'][1]")
location = product.location

# 요소 클릭
search_bar.click()
```

**장점**:
- UI 요소를 자동으로 찾아줌
- 해상도가 달라도 요소 ID로 찾으면 됨

**단점**:
- Appium 서버 실행 필요
- 느림 (요소 찾는데 1~2초 소요)
- 네이버 쇼핑이 동적으로 변경되면 ID/XPath가 바뀔 수 있음

---

## 방법 3: AI Vision (OCR/객체 감지) - 고급

AI 모델을 사용하여 화면을 분석하고 버튼을 자동으로 찾습니다.

### 3-1. OCR로 텍스트 인식

```python
# server/core/ai_vision.py
import cv2
from PIL import Image
import pytesseract

def find_button_by_text(screenshot_path: str, button_text: str) -> Dict:
    """
    스크린샷에서 특정 텍스트를 가진 버튼 위치 찾기

    Args:
        screenshot_path: 스크린샷 이미지 경로
        button_text: 찾을 텍스트 (예: "장바구니")

    Returns:
        {"x": 810, "y": 2250, "confidence": 0.95}
    """
    img = cv2.imread(screenshot_path)

    # OCR 실행
    data = pytesseract.image_to_data(img, lang='kor', output_type=pytesseract.Output.DICT)

    # "장바구니" 텍스트 찾기
    for i, text in enumerate(data['text']):
        if button_text in text:
            x = data['left'][i] + data['width'][i] // 2
            y = data['top'][i] + data['height'][i] // 2
            confidence = data['conf'][i]

            return {"x": x, "y": y, "confidence": confidence / 100}

    return None
```

### 3-2. YOLO 객체 감지로 버튼 찾기

```python
from ultralytics import YOLO

# 1. 네이버 쇼핑 버튼들로 YOLO 모델 학습 (사전 작업)
# 2. 실시간으로 버튼 위치 감지

model = YOLO("naver_shopping_buttons.pt")  # 학습된 모델

# 스크린샷 분석
results = model.predict(screenshot_path)

# "장바구니" 버튼 찾기
for box in results[0].boxes:
    if box.cls == "add_to_cart_button":
        x_center = (box.xyxy[0][0] + box.xyxy[0][2]) / 2
        y_center = (box.xyxy[0][1] + box.xyxy[0][3]) / 2

        return {"x": int(x_center), "y": int(y_center)}
```

**장점**:
- 완전 자동화
- 해상도 무관
- UI 변경에도 대응 가능

**단점**:
- YOLO 모델 학습 필요 (수백~수천 개 이미지 필요)
- GPU 필요 (추론 속도)
- 복잡하고 비용 높음

---

## 💡 실전 워크플로우 (추천)

### Step 1: 초기 좌표 맵 생성 (1회만)

```bash
# 1. Samsung Galaxy S7 (1080x2340) 기기 준비
# 2. 개발자 옵션 → 포인터 위치 표시 ON
# 3. 네이버 쇼핑 열고 주요 UI 요소들 탭하면서 좌표 기록

# 주요 UI 요소 목록:
- 검색창: (540, 200)
- 쇼핑 탭: (270, 320)
- 상품 1: (270, 600)
- 상품 2: (810, 600)
- 장바구니 버튼: (810, 2250)
- 리뷰 탭: (270, 1400)

# 4. config/ui_coordinates/1080x2340_samsung_s7.json 생성
# 5. 다른 해상도도 동일하게 반복
```

### Step 2: 서버에서 좌표 맵 로드 및 캐싱

```python
# server/api/task_assignment.py
from server.core.coordinate_loader import load_coordinates

# Redis에 24시간 캐싱됨
coordinates_map = await load_coordinates("1080x2340")
```

### Step 3: JSON 작업 패턴 생성

```python
# server/core/task_engine.py
pattern = [
    {
        "action": "tap",
        "x": coordinates["search_bar"]["x"],  # 540
        "y": coordinates["search_bar"]["y"],  # 200
        "description": "검색창 터치"
    }
]
```

### Step 4: Android 봇에서 실행

```java
// android_agent/TaskExecutor.java
case "tap":
    int x = step.getInt("x");  // 540
    int y = step.getInt("y");  // 200
    rootController.tap(x, y);  // input tap 540 200
    break;
```

---

## 🔧 좌표 검증 및 디버깅

### 좌표가 정확한지 확인하는 방법

```bash
# 1. ADB로 직접 좌표 탭 테스트
adb shell input tap 540 200

# 예상: 검색창이 선택되어야 함
# 실제: 다른 곳이 선택됨 → 좌표 수정 필요

# 2. 스크린샷 찍어서 좌표 확인
adb shell screencap -p /sdcard/screenshot.png
adb pull /sdcard/screenshot.png

# 이미지 편집기에서 열어서 (540, 200) 위치 확인
```

### 해상도별 좌표 스케일링

만약 좌표 맵이 없는 해상도인 경우, 비율로 계산할 수 있습니다:

```python
def scale_coordinate(x, y, from_resolution, to_resolution):
    """
    좌표를 다른 해상도로 스케일링

    Args:
        x, y: 원본 좌표
        from_resolution: "1080x2340"
        to_resolution: "1440x3200"

    Returns:
        (scaled_x, scaled_y)
    """
    from_w, from_h = map(int, from_resolution.split("x"))
    to_w, to_h = map(int, to_resolution.split("x"))

    scaled_x = int(x * to_w / from_w)
    scaled_y = int(y * to_h / from_h)

    return (scaled_x, scaled_y)

# 예시:
# 1080x2340 해상도에서 (540, 200)
# → 1440x3200 해상도로 변환
# scaled_x = 540 * 1440 / 1080 = 720
# scaled_y = 200 * 3200 / 2340 = 273
```

---

## 📊 좌표 맵 관리 API

### API 엔드포인트 추가

```python
# server/api/coordinate_api.py
from fastapi import APIRouter
from server.core.coordinate_loader import list_available_resolutions, load_coordinates

router = APIRouter()

@router.get("/coordinates/resolutions")
async def get_available_resolutions():
    """사용 가능한 해상도 목록 조회"""
    resolutions = await list_available_resolutions()
    return {"resolutions": resolutions}

@router.get("/coordinates/{resolution}")
async def get_coordinates(resolution: str):
    """특정 해상도의 좌표 맵 조회"""
    coordinates = await load_coordinates(resolution)
    if not coordinates:
        raise HTTPException(404, f"Resolution {resolution} not found")
    return coordinates
```

### 봇이 좌표 맵 다운로드

```java
// Android: CoordinateCache.java
public void downloadCoordinatesFromServer(String resolution) {
    Response<CoordinateMap> response = apiClient.getCoordinates(resolution);

    // 로컬 캐시에 저장
    String json = new Gson().toJson(response.getData());
    File cacheFile = new File(cacheDir, resolution + ".json");
    FileUtils.writeStringToFile(cacheFile, json);
}
```

---

## 📝 요약

### 좌표 인식 → 작업 실행 전체 플로우

```
1. [초기 설정] 개발자가 UI Automator Viewer로 좌표 측정
   → config/ui_coordinates/1080x2340.json 생성

2. [봇 등록] Android 봇이 서버에 등록
   POST /api/v1/bots/register
   {
     "screen_resolution": "1080x2340",
     ...
   }

3. [작업 요청] 봇이 작업 요청
   GET /api/v1/tasks/get_task?bot_id=xxx

4. [좌표 로드] 서버가 해상도에 맞는 좌표 맵 로드
   coordinates = await load_coordinates("1080x2340")
   # Redis 캐시에서 조회 (있으면) 또는 JSON 파일 로드

5. [패턴 생성] 서버가 좌표를 사용하여 JSON 패턴 생성
   pattern = [
     {"action": "tap", "x": 540, "y": 200},
     {"action": "text", "value": "단백질쉐이크"},
     ...
   ]

6. [패턴 전송] 서버가 봇에게 JSON 패턴 전송
   return {"task_id": "...", "pattern": pattern}

7. [패턴 실행] 봇이 JSON 패턴을 순차 실행
   rootController.tap(540, 200);  // input tap 540 200
   rootController.inputText("단백질쉐이크");

8. [결과 보고] 봇이 실행 결과를 서버에 보고
   POST /api/v1/tasks/report_result
```

### 핵심 포인트

1. **좌표 맵은 해상도별로 1회만 생성** (config/ui_coordinates/*.json)
2. **서버는 Redis에 24시간 캐싱** (빠른 조회)
3. **봇은 JSON 패턴의 x, y 좌표를 그대로 실행** (Root 권한 `input tap`)
4. **무작위성 추가로 탐지 회피** (±10px 노이즈)

---

## 🎓 참고 자료

- [Android UI Automator](https://developer.android.com/training/testing/ui-automator)
- [Appium Inspector](https://github.com/appium/appium-inspector)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)
- [Ultralytics YOLO](https://github.com/ultralytics/ultralytics)
