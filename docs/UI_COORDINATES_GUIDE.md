# UI 좌표 맵 작성 가이드

## 📋 개요

Turafic 프로젝트는 **좌표 기반 UI 제어 방식**을 사용합니다. 서버가 해상도별 UI 좌표 맵을 기반으로 JSON 패턴을 생성하고, Android 봇이 Root 권한으로 `input tap` 명령어를 실행합니다.

---

## 🎯 지원 해상도

| 해상도 | 비율 | 대표 기기 | 우선순위 |
|--------|------|----------|---------|
| 1080x2340 | 18.5:9 | Galaxy S20, S21, S22 | ⭐⭐⭐⭐⭐ |
| 1440x3200 | 20:9 | Galaxy S23 Ultra, S24 Ultra | ⭐⭐⭐⭐ |
| 720x1560 | 19.5:9 | Galaxy A 시리즈 | ⭐⭐⭐ |

---

## 📐 좌표 측정 방법

### 방법 1: 개발자 옵션 (권장)

1. **개발자 옵션 활성화**
   - 설정 → 휴대전화 정보 → 소프트웨어 정보
   - 빌드 번호를 7번 탭

2. **포인터 위치 활성화**
   - 설정 → 개발자 옵션 → 포인터 위치 ON

3. **좌표 측정**
   - 네이버 쇼핑 앱 실행
   - 각 UI 요소를 터치
   - 화면 상단에 표시되는 좌표 기록

### 방법 2: UI Automator Viewer

1. **Android SDK 설치**
   ```bash
   # macOS/Linux
   export ANDROID_HOME=/path/to/android-sdk
   export PATH=$PATH:$ANDROID_HOME/tools/bin
   ```

2. **UI Automator Viewer 실행**
   ```bash
   uiautomatorviewer
   ```

3. **화면 캡처 및 좌표 확인**
   - Device Screenshot 버튼 클릭
   - UI 요소 클릭하여 bounds 확인
   - 중심 좌표 계산: `(x1 + x2) / 2`, `(y1 + y2) / 2`

### 방법 3: ADB 스크립트 (자동화)

```bash
#!/bin/bash

# UI 덤프 생성
adb shell uiautomator dump /sdcard/ui.xml
adb pull /sdcard/ui.xml

# XML 파싱하여 좌표 추출
python3 parse_ui_xml.py ui.xml
```

---

## 📝 좌표 맵 파일 구조

### 파일 위치
```
server/data/ui_coordinates.json
```

### JSON 구조
```json
{
  "1080x2340": {
    "naver_search": {
      "search_bar": {"x": 540, "y": 200, "description": "검색창"},
      "search_button": {"x": 1000, "y": 200, "description": "검색 버튼"}
    },
    "naver_shopping": {
      "search_bar": {"x": 540, "y": 150, "description": "쇼핑 검색창"},
      "filter_button": {"x": 100, "y": 300, "description": "필터 버튼"},
      "sort_button": {"x": 980, "y": 300, "description": "정렬 버튼"},
      "product_list_item_1": {"x": 540, "y": 600, "description": "첫 번째 상품"},
      "product_list_item_2": {"x": 540, "y": 1000, "description": "두 번째 상품"},
      "product_list_item_3": {"x": 540, "y": 1400, "description": "세 번째 상품"},
      "scroll_start": {"x": 540, "y": 1200, "description": "스크롤 시작점"},
      "scroll_end": {"x": 540, "y": 400, "description": "스크롤 끝점"}
    },
    "product_detail": {
      "product_image": {"x": 540, "y": 600, "description": "상품 이미지"},
      "product_name": {"x": 540, "y": 900, "description": "상품명"},
      "price": {"x": 540, "y": 1000, "description": "가격"},
      "add_to_cart": {"x": 270, "y": 2200, "description": "장바구니 담기"},
      "buy_now": {"x": 810, "y": 2200, "description": "바로 구매"},
      "review_tab": {"x": 270, "y": 1100, "description": "리뷰 탭"},
      "detail_tab": {"x": 540, "y": 1100, "description": "상세정보 탭"},
      "inquiry_tab": {"x": 810, "y": 1100, "description": "문의 탭"},
      "scroll_start": {"x": 540, "y": 1500, "description": "스크롤 시작점"},
      "scroll_end": {"x": 540, "y": 500, "description": "스크롤 끝점"}
    }
  },
  "1440x3200": {
    "naver_search": {
      "search_bar": {"x": 720, "y": 267, "description": "검색창"},
      "search_button": {"x": 1333, "y": 267, "description": "검색 버튼"}
    },
    "naver_shopping": {
      "search_bar": {"x": 720, "y": 200, "description": "쇼핑 검색창"},
      "filter_button": {"x": 133, "y": 400, "description": "필터 버튼"},
      "sort_button": {"x": 1307, "y": 400, "description": "정렬 버튼"},
      "product_list_item_1": {"x": 720, "y": 800, "description": "첫 번째 상품"},
      "product_list_item_2": {"x": 720, "y": 1333, "description": "두 번째 상품"},
      "product_list_item_3": {"x": 720, "y": 1867, "description": "세 번째 상품"},
      "scroll_start": {"x": 720, "y": 1600, "description": "스크롤 시작점"},
      "scroll_end": {"x": 720, "y": 533, "description": "스크롤 끝점"}
    },
    "product_detail": {
      "product_image": {"x": 720, "y": 800, "description": "상품 이미지"},
      "product_name": {"x": 720, "y": 1200, "description": "상품명"},
      "price": {"x": 720, "y": 1333, "description": "가격"},
      "add_to_cart": {"x": 360, "y": 2933, "description": "장바구니 담기"},
      "buy_now": {"x": 1080, "y": 2933, "description": "바로 구매"},
      "review_tab": {"x": 360, "y": 1467, "description": "리뷰 탭"},
      "detail_tab": {"x": 720, "y": 1467, "description": "상세정보 탭"},
      "inquiry_tab": {"x": 1080, "y": 1467, "description": "문의 탭"},
      "scroll_start": {"x": 720, "y": 2000, "description": "스크롤 시작점"},
      "scroll_end": {"x": 720, "y": 667, "description": "스크롤 끝점"}
    }
  }
}
```

---

## 🔧 좌표 변환 공식

### 해상도 변환
```python
def convert_coordinates(base_resolution, target_resolution, x, y):
    """
    기준 해상도의 좌표를 목표 해상도로 변환
    
    Args:
        base_resolution: (width, height) 튜플 (예: (1080, 2340))
        target_resolution: (width, height) 튜플 (예: (1440, 3200))
        x: 기준 해상도의 x 좌표
        y: 기준 해상도의 y 좌표
    
    Returns:
        (new_x, new_y) 튜플
    """
    base_width, base_height = base_resolution
    target_width, target_height = target_resolution
    
    new_x = int(x * target_width / base_width)
    new_y = int(y * target_height / base_height)
    
    return (new_x, new_y)

# 예시
base = (1080, 2340)
target = (1440, 3200)
x, y = 540, 1200

new_x, new_y = convert_coordinates(base, target, x, y)
print(f"변환된 좌표: ({new_x}, {new_y})")  # (720, 1641)
```

---

## 📊 좌표 검증 방법

### 1. ADB 명령어로 직접 테스트

```bash
# 좌표 (540, 1200)을 터치
adb shell input tap 540 1200

# 스크롤 테스트
adb shell input swipe 540 1200 540 400 500

# 텍스트 입력 테스트
adb shell input text "삼성 갤럭시 S24"
```

### 2. Python 스크립트로 자동 검증

```python
import subprocess
import json

def test_coordinates(resolution, ui_coords):
    """좌표가 올바른지 ADB로 테스트"""
    
    print(f"Testing coordinates for {resolution}")
    
    for screen, elements in ui_coords.items():
        print(f"\n[{screen}]")
        
        for element, coord in elements.items():
            x, y = coord["x"], coord["y"]
            desc = coord["description"]
            
            # ADB로 터치 테스트
            cmd = f"adb shell input tap {x} {y}"
            subprocess.run(cmd, shell=True)
            
            # 사용자 확인
            result = input(f"  {desc} ({x}, {y}) - 정확한가요? (y/n): ")
            
            if result.lower() != 'y':
                print(f"  ❌ {element} 좌표 수정 필요")
            else:
                print(f"  ✅ {element} 좌표 정확")

# 좌표 맵 로드
with open("ui_coordinates.json") as f:
    coords = json.load(f)

# 테스트 실행
test_coordinates("1080x2340", coords["1080x2340"])
```

---

## 🎨 좌표 시각화

### 스크린샷에 좌표 표시

```python
from PIL import Image, ImageDraw, ImageFont

def visualize_coordinates(screenshot_path, ui_coords, output_path):
    """스크린샷에 좌표를 표시하여 시각화"""
    
    img = Image.open(screenshot_path)
    draw = ImageDraw.Draw(img)
    
    for element, coord in ui_coords.items():
        x, y = coord["x"], coord["y"]
        desc = coord["description"]
        
        # 빨간 점 그리기
        draw.ellipse((x-10, y-10, x+10, y+10), fill='red', outline='red')
        
        # 설명 텍스트
        draw.text((x+15, y-10), f"{desc} ({x},{y})", fill='red')
    
    img.save(output_path)
    print(f"Saved: {output_path}")

# 예시
visualize_coordinates(
    "screenshots/1080x2340_shopping.png",
    coords["1080x2340"]["naver_shopping"],
    "screenshots/1080x2340_shopping_annotated.png"
)
```

---

## 🚀 서버 API 구현

### 좌표 맵 로드 및 제공

```python
from fastapi import APIRouter, HTTPException
import json

router = APIRouter()

# 좌표 맵 로드
with open("data/ui_coordinates.json") as f:
    UI_COORDS = json.load(f)

@router.get("/api/v1/ui/coordinates")
async def get_ui_coordinates(resolution: str = "1080x2340"):
    """해상도별 UI 좌표 맵 반환"""
    
    if resolution not in UI_COORDS:
        raise HTTPException(status_code=404, detail="Resolution not supported")
    
    return UI_COORDS[resolution]

@router.get("/api/v1/ui/coordinates/{screen}/{element}")
async def get_element_coordinate(
    screen: str,
    element: str,
    resolution: str = "1080x2340"
):
    """특정 UI 요소의 좌표 반환"""
    
    if resolution not in UI_COORDS:
        raise HTTPException(status_code=404, detail="Resolution not supported")
    
    if screen not in UI_COORDS[resolution]:
        raise HTTPException(status_code=404, detail="Screen not found")
    
    if element not in UI_COORDS[resolution][screen]:
        raise HTTPException(status_code=404, detail="Element not found")
    
    return UI_COORDS[resolution][screen][element]
```

---

## 📋 체크리스트

### 좌표 맵 작성 시 확인 사항

- [ ] 3가지 해상도 모두 작성 (1080x2340, 1440x3200, 720x1560)
- [ ] 각 화면별 필수 요소 좌표 포함
  - [ ] 네이버 검색: 검색창, 검색 버튼
  - [ ] 네이버 쇼핑: 검색창, 필터, 정렬, 상품 리스트, 스크롤
  - [ ] 상품 상세: 이미지, 가격, 장바구니, 구매, 탭, 스크롤
- [ ] 좌표 검증 완료 (ADB 테스트)
- [ ] 좌표 시각화 완료 (스크린샷에 표시)
- [ ] 서버 API 테스트 완료
- [ ] Redis 캐시 설정 완료

---

## 🔄 좌표 업데이트 프로세스

1. **네이버 앱 UI 변경 감지**
   - 봇 실행 중 에러 발생
   - 좌표가 맞지 않음

2. **새로운 좌표 측정**
   - 개발자 옵션 또는 UI Automator Viewer 사용
   - 변경된 UI 요소의 새 좌표 기록

3. **좌표 맵 업데이트**
   - `ui_coordinates.json` 파일 수정
   - Git 커밋 및 푸시

4. **서버 재시작**
   - Railway에서 자동 배포
   - Redis 캐시 초기화

5. **검증**
   - 봇 테스트 실행
   - 정상 동작 확인

---

## 📚 참고 자료

- [Android Input 명령어 문서](https://developer.android.com/reference/android/view/InputDevice)
- [UI Automator Viewer 가이드](https://developer.android.com/training/testing/other-components/ui-automator)
- [ADB 명령어 레퍼런스](https://developer.android.com/studio/command-line/adb)

---

**핵심 요약**:
- ✅ 해상도별 UI 좌표 맵 작성 (JSON 파일)
- ✅ 서버가 JSON 패턴으로 좌표 전송
- ✅ APK가 Root 권한으로 `input tap` 실행
- ✅ 좌표 검증 및 시각화 도구 활용
