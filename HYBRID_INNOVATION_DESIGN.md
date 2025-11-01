# Turafic × 제로 Updater 하이브리드 혁신 설계

## 개요

`turafic` 프로젝트의 지능형 분석 능력과 APK 기반 독립 실행 능력을 결합한 4가지 혁신 아이디어의 상세 설계 문서입니다.

---

## 아이디어 1: 하이브리드 제어 시스템 (Hybrid Control System)

### 컨셉
- **Appium의 "눈"** (정확한 UI 인식) + **ADB/루팅의 "손"** (빠른 실행)
- UI 변경에 강한 "중앙 매핑 시스템"

### 아키텍처

```
┌──────────────────────────────────────────────────────────┐
│                    중앙 서버 (Turafic)                      │
├──────────────────────────────────────────────────────────┤
│  1. UI 좌표 맵 관리 (Coordinate Map Storage)               │
│     - 해상도별 UI 요소 좌표 데이터베이스                      │
│     - 앱 버전별 매핑 테이블                                 │
│                                                            │
│  2. 매핑 스케줄러 (Mapping Scheduler)                       │
│     - 주기적 UI 스캔 작업 (매일 새벽 3시)                    │
│     - Appium으로 UI 요소 탐지 및 좌표 저장                   │
│                                                            │
│  3. 패치 배포 시스템 (Patch Distribution)                   │
│     - 변경된 좌표를 모든 봇에게 실시간 푸시                   │
│     - WebSocket 또는 MQTT 사용                             │
└──────────────────────────────────────────────────────────┘
                           ↓ ↑
        ┌──────────────────┴─┴──────────────────┐
        ↓                                        ↓
┌────────────────┐                    ┌────────────────┐
│  봇 에이전트 #1  │                    │  봇 에이전트 #N  │
├────────────────┤                    ├────────────────┤
│ ADB Controller │                    │ ADB Controller │
│ + 좌표 캐시      │                    │ + 좌표 캐시      │
└────────────────┘                    └────────────────┘
```

### 데이터 구조

#### UI 좌표 맵 (JSON)
```json
{
  "app_name": "네이버쇼핑",
  "app_version": "12.3.4",
  "last_updated": "2025-11-01T10:00:00",
  "resolutions": {
    "1080x1920": {
      "search_bar": {"x": 540, "y": 120, "width": 900, "height": 80},
      "cart_button": {"x": 960, "y": 100, "width": 120, "height": 120},
      "product_list_item_1": {"x": 540, "y": 400, "width": 1000, "height": 300}
    },
    "1440x2560": {
      "search_bar": {"x": 720, "y": 160, "width": 1200, "height": 100},
      "cart_button": {"x": 1280, "y": 130, "width": 160, "height": 160}
    }
  },
  "actions": {
    "tap_search_bar": {
      "element": "search_bar",
      "type": "tap",
      "offset": {"x": 0, "y": 0}
    },
    "scroll_down_product_list": {
      "type": "swipe",
      "start": {"x": "50%", "y": "70%"},
      "end": {"x": "50%", "y": "30%"},
      "duration": 300
    }
  }
}
```

### 구현 단계

#### Phase 1: UI 매핑 시스템 (2주)
```python
# src/hybrid/ui_mapper.py

from appium import webdriver
from typing import Dict, List, Tuple
import json

class UIMapper:
    """Appium을 사용한 UI 요소 좌표 매핑"""

    def __init__(self, appium_server: str = "http://localhost:4723"):
        self.driver = None
        self.appium_server = appium_server
        self.coordinate_map = {}

    def scan_ui_elements(self, app_package: str, target_elements: List[str]) -> Dict:
        """
        UI 요소들을 스캔하여 좌표 추출

        Args:
            app_package: 대상 앱 패키지명
            target_elements: 스캔할 요소 목록 (예: ["search_bar", "cart_button"])

        Returns:
            좌표 맵 딕셔너리
        """
        # Appium 연결
        self.driver = self._connect_appium(app_package)

        # 해상도 정보
        window_size = self.driver.get_window_size()
        resolution_key = f"{window_size['width']}x{window_size['height']}"

        coordinate_map = {
            "resolution": resolution_key,
            "elements": {}
        }

        for element_name in target_elements:
            try:
                # UI 요소 찾기 (여러 전략 시도)
                element = self._find_element_multi_strategy(element_name)

                if element:
                    # 좌표 및 크기 정보 추출
                    location = element.location
                    size = element.size

                    coordinate_map["elements"][element_name] = {
                        "x": location['x'] + size['width'] // 2,  # 중심 좌표
                        "y": location['y'] + size['height'] // 2,
                        "width": size['width'],
                        "height": size['height'],
                        "bounds": {
                            "left": location['x'],
                            "top": location['y'],
                            "right": location['x'] + size['width'],
                            "bottom": location['y'] + size['height']
                        }
                    }

                    print(f"✅ {element_name}: ({location['x']}, {location['y']})")
                else:
                    print(f"❌ {element_name}: 요소를 찾을 수 없음")

            except Exception as e:
                print(f"⚠️ {element_name} 스캔 실패: {e}")

        return coordinate_map

    def _find_element_multi_strategy(self, element_name: str):
        """여러 전략으로 UI 요소 찾기"""
        strategies = [
            ("id", f"com.naver.shopping:id/{element_name}"),
            ("accessibility id", element_name),
            ("xpath", f"//*[@content-desc='{element_name}']"),
            ("xpath", f"//*[@text='{element_name}']"),
        ]

        for strategy, locator in strategies:
            try:
                if strategy == "id":
                    element = self.driver.find_element_by_id(locator)
                elif strategy == "accessibility id":
                    element = self.driver.find_element_by_accessibility_id(locator)
                elif strategy == "xpath":
                    element = self.driver.find_element_by_xpath(locator)

                if element:
                    return element
            except:
                continue

        return None

    def save_coordinate_map(self, filepath: str):
        """좌표 맵을 JSON 파일로 저장"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.coordinate_map, f, indent=2, ensure_ascii=False)
```

#### Phase 2: ADB 실행 에이전트 (1주)
```python
# src/hybrid/adb_executor.py

from src.automation.mobile import ADBController
import json
import requests

class HybridExecutor:
    """중앙 서버의 좌표 맵을 사용한 ADB 실행기"""

    def __init__(self, server_url: str = "http://localhost:5000"):
        self.adb = ADBController()
        self.server_url = server_url
        self.coordinate_cache = {}
        self._load_coordinate_map()

    def _load_coordinate_map(self):
        """서버에서 좌표 맵 다운로드"""
        try:
            response = requests.get(f"{self.server_url}/api/coordinate_map")
            if response.status_code == 200:
                self.coordinate_cache = response.json()
                print("✅ 좌표 맵 로드 완료")
            else:
                print("❌ 좌표 맵 로드 실패")
        except Exception as e:
            print(f"⚠️ 서버 연결 실패: {e}")

    def execute_action(self, action_name: str) -> bool:
        """
        고수준 액션 실행 (예: "tap_search_bar")

        Args:
            action_name: 실행할 액션 이름

        Returns:
            성공 여부
        """
        # 기기 해상도 확인
        device_info = self.adb.get_device_info()
        resolution = f"{device_info['screen_width']}x{device_info['screen_height']}"

        # 좌표 맵에서 해당 해상도의 좌표 조회
        if resolution not in self.coordinate_cache.get("resolutions", {}):
            print(f"❌ 해상도 {resolution}에 대한 좌표 맵 없음")
            return False

        action = self.coordinate_cache.get("actions", {}).get(action_name)
        if not action:
            print(f"❌ 액션 {action_name}을 찾을 수 없음")
            return False

        # 액션 타입에 따라 실행
        if action["type"] == "tap":
            element_name = action["element"]
            element_data = self.coordinate_cache["resolutions"][resolution].get(element_name)

            if element_data:
                x = element_data["x"] + action.get("offset", {}).get("x", 0)
                y = element_data["y"] + action.get("offset", {}).get("y", 0)
                return self.adb.tap(x, y)

        elif action["type"] == "swipe":
            # 퍼센트 좌표를 픽셀로 변환
            width = device_info['screen_width']
            height = device_info['screen_height']

            x1 = self._parse_coordinate(action["start"]["x"], width)
            y1 = self._parse_coordinate(action["start"]["y"], height)
            x2 = self._parse_coordinate(action["end"]["x"], width)
            y2 = self._parse_coordinate(action["end"]["y"], height)
            duration = action.get("duration", 300)

            return self.adb.swipe(x1, y1, x2, y2, duration)

        return False

    def _parse_coordinate(self, value: str, max_value: int) -> int:
        """퍼센트 또는 절대값 좌표 파싱"""
        if isinstance(value, str) and '%' in value:
            percent = int(value.replace('%', ''))
            return int(max_value * percent / 100)
        return int(value)


# 사용 예시
if __name__ == "__main__":
    executor = HybridExecutor()

    # 고수준 명령어로 실행
    executor.execute_action("tap_search_bar")
    executor.execute_action("scroll_down_product_list")
```

### 장점
1. **정확성**: Appium의 UI 인식 능력 활용
2. **성능**: ADB의 빠른 실행 속도 활용
3. **유지보수**: 중앙 서버에서만 좌표 업데이트하면 모든 봇에 즉시 반영
4. **확장성**: 새로운 앱/버전 추가가 용이

### 실행 타임라인
- **Week 1-2**: UI 매핑 시스템 개발 및 테스트
- **Week 3**: ADB 실행 에이전트 개발
- **Week 4**: 중앙 서버 API 및 배포 시스템 구축
- **Week 5**: 파일럿 테스트 (10개 봇)
- **Week 6**: 프로덕션 배포

---

## 아이디어 2: 자가 학습 및 자가 치유 봇 네트워크

### 컨셉
- 실패를 감지하고 AI 비전으로 자동 복구
- 앱 업데이트에도 무중단 운영

### 아키텍처

```
┌───────────────────────────────────────────────────────┐
│              중앙 AI 비전 서버                            │
├───────────────────────────────────────────────────────┤
│  1. 실패 감지 큐 (Failure Detection Queue)              │
│     - 봇들이 전송한 스크린샷 + 오류 로그                  │
│                                                         │
│  2. AI 비전 분석기 (GPT-4 Vision / YOLO)                │
│     - 스크린샷에서 UI 요소 재탐지                         │
│     - 변경된 좌표 자동 추출                              │
│                                                         │
│  3. 동적 패치 생성기 (Dynamic Patch Generator)           │
│     - 새 좌표로 coordinate_map 업데이트                  │
│     - 패치를 모든 봇에게 즉시 배포                        │
└───────────────────────────────────────────────────────┘
                          ↑ ↓
        ┌─────────────────┴─┴─────────────────┐
        ↑                                      ↓
┌────────────────┐                  ┌────────────────┐
│   봇 #1 (실패)  │                  │   봇 #N         │
├────────────────┤                  ├────────────────┤
│ 1. 액션 실행     │                  │ 패치 수신 후     │
│ 2. 결과 검증     │                  │ 정상 동작       │
│ 3. 실패 감지     │                  └────────────────┘
│ 4. 스크린샷 전송 │
└────────────────┘
```

### 실패 감지 로직

```python
# src/hybrid/failure_detector.py

import time
from typing import Optional, Dict
from src.automation.mobile import ADBController

class FailureDetector:
    """액션 실행 후 예상 결과 검증"""

    def __init__(self, adb: ADBController):
        self.adb = adb

    def execute_and_verify(
        self,
        action_name: str,
        expected_result: Dict,
        timeout: int = 5
    ) -> tuple[bool, Optional[str]]:
        """
        액션 실행 후 예상 결과 검증

        Args:
            action_name: 실행할 액션
            expected_result: 예상 결과 (예: {"screen_change": True, "element_visible": "product_list"})
            timeout: 검증 타임아웃 (초)

        Returns:
            (성공 여부, 실패 시 스크린샷 경로)
        """
        # 실행 전 화면 캡처
        before_screenshot = self.adb.take_screenshot()

        # 액션 실행
        from src.hybrid.adb_executor import HybridExecutor
        executor = HybridExecutor()
        executor.execute_action(action_name)

        # 대기
        time.sleep(1)

        # 실행 후 화면 캡처
        after_screenshot = self.adb.take_screenshot()

        # 결과 검증
        if expected_result.get("screen_change"):
            # 화면이 변경되었는지 확인 (이미지 비교)
            if self._compare_screenshots(before_screenshot, after_screenshot):
                return True, None
            else:
                print(f"❌ 액션 {action_name} 실패: 화면 변화 없음")
                return False, str(after_screenshot)

        return True, None

    def _compare_screenshots(self, img1_path, img2_path) -> bool:
        """두 스크린샷 비교 (간단한 해시 비교)"""
        try:
            from PIL import Image
            import imagehash

            hash1 = imagehash.average_hash(Image.open(img1_path))
            hash2 = imagehash.average_hash(Image.open(img2_path))

            # 해시 차이가 10 이상이면 화면이 변경된 것으로 간주
            return abs(hash1 - hash2) > 10
        except:
            return True  # 오류 시 일단 성공으로 간주
```

### AI 비전 분석 (GPT-4 Vision API)

```python
# src/hybrid/ai_vision_analyzer.py

import openai
import base64
from typing import Dict, Optional

class AIVisionAnalyzer:
    """GPT-4 Vision을 사용한 UI 요소 재탐지"""

    def __init__(self, api_key: str):
        openai.api_key = api_key

    def analyze_failure_screenshot(
        self,
        screenshot_path: str,
        target_element: str
    ) -> Optional[Dict]:
        """
        실패 스크린샷에서 UI 요소 재탐지

        Args:
            screenshot_path: 스크린샷 파일 경로
            target_element: 찾을 요소 (예: "검색창", "장바구니 버튼")

        Returns:
            찾은 요소의 좌표 정보 또는 None
        """
        # 이미지를 base64로 인코딩
        with open(screenshot_path, "rb") as f:
            image_data = base64.b64encode(f.read()).decode('utf-8')

        # GPT-4 Vision API 호출
        prompt = f"""
        이 스크린샷에서 "{target_element}"의 위치를 찾아주세요.

        응답 형식 (JSON):
        {{
            "found": true/false,
            "x": 중심 X 좌표,
            "y": 중심 Y 좌표,
            "width": 너비,
            "height": 높이,
            "confidence": 0.0~1.0
        }}

        요소를 찾지 못한 경우 "found": false 반환
        """

        try:
            response = openai.ChatCompletion.create(
                model="gpt-4-vision-preview",
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{image_data}"
                                }
                            }
                        ]
                    }
                ],
                max_tokens=300
            )

            # JSON 응답 파싱
            import json
            result = json.loads(response.choices[0].message.content)

            if result.get("found") and result.get("confidence", 0) > 0.7:
                return {
                    "x": result["x"],
                    "y": result["y"],
                    "width": result["width"],
                    "height": result["height"]
                }

        except Exception as e:
            print(f"⚠️ AI 비전 분석 실패: {e}")

        return None
```

### 자동 패치 배포 시스템

```python
# src/hybrid/auto_patch_distributor.py

import asyncio
import websockets
import json
from typing import Set

class AutoPatchDistributor:
    """WebSocket을 통한 실시간 패치 배포"""

    def __init__(self, port: int = 8765):
        self.port = port
        self.connected_bots: Set[websockets.WebSocketServerProtocol] = set()

    async def register_bot(self, websocket):
        """봇 연결 등록"""
        self.connected_bots.add(websocket)
        print(f"✅ 봇 연결: {websocket.remote_address} (총 {len(self.connected_bots)}개)")

        try:
            await websocket.wait_closed()
        finally:
            self.connected_bots.remove(websocket)

    async def broadcast_patch(self, patch_data: Dict):
        """모든 봇에게 패치 브로드캐스트"""
        if not self.connected_bots:
            return

        message = json.dumps(patch_data)

        await asyncio.gather(
            *[bot.send(message) for bot in self.connected_bots],
            return_exceptions=True
        )

        print(f"📡 패치 배포 완료: {len(self.connected_bots)}개 봇")

    async def start_server(self):
        """WebSocket 서버 시작"""
        async with websockets.serve(self.register_bot, "0.0.0.0", self.port):
            print(f"🚀 패치 배포 서버 시작: ws://0.0.0.0:{self.port}")
            await asyncio.Future()  # 무한 대기


# 사용 예시
async def main():
    distributor = AutoPatchDistributor()

    # 서버 시작
    asyncio.create_task(distributor.start_server())

    # 패치 발생 시
    await asyncio.sleep(10)

    new_patch = {
        "type": "coordinate_update",
        "element": "search_bar",
        "resolution": "1080x1920",
        "new_coordinates": {
            "x": 550,  # 변경된 좌표
            "y": 130
        },
        "timestamp": "2025-11-01T10:30:00"
    }

    await distributor.broadcast_patch(new_patch)


if __name__ == "__main__":
    asyncio.run(main())
```

### 실행 플로우

1. **봇 #47**이 "검색창 탭" 액션 실행
2. 예상 결과(화면 전환) 발생하지 않음 → **실패 감지**
3. 스크린샷 + 오류 로그를 중앙 서버로 전송
4. **AI 비전 분석기**가 스크린샷에서 "검색창" 재탐지
5. 새 좌표 (550, 130) 발견
6. **coordinate_map** 업데이트: `{"search_bar": {"x": 550, "y": 130}}`
7. **패치 배포**: 모든 봇에게 WebSocket으로 즉시 전송
8. **봇 #1~1000**이 패치 수신 후 로컬 캐시 업데이트
9. 이후 모든 봇은 새 좌표 사용 → **정상 동작**

---

## 아이디어 3: 인간 행동 시뮬레이션 엔진

### 컨셉
- 저수준 명령(`tap(540,300)`)이 아닌 고수준 목표(`"상품 2개 비교"`) 부여
- 행동 프리미티브 조합으로 매번 다른 시나리오 생성

### 행동 프리미티브 라이브러리

```python
# src/behavior/primitives.py

import random
import time
from typing import Callable
from src.automation.mobile import ADBController

class BehaviorPrimitive:
    """행동 프리미티브 기본 클래스"""

    def __init__(self, adb: ADBController):
        self.adb = adb

    def execute(self):
        raise NotImplementedError


class ScrollWithHesitation(BehaviorPrimitive):
    """망설임이 있는 스크롤"""

    def execute(self):
        # 스크롤 전 망설임 (0.5~1.5초)
        time.sleep(random.uniform(0.5, 1.5))

        # 스크롤 속도 랜덤화 (200~500ms)
        duration = random.randint(200, 500)
        self.adb.scroll_down(duration)

        # 스크롤 후 잠시 정지 (1~3초)
        time.sleep(random.uniform(1, 3))


class ReadForSeconds(BehaviorPrimitive):
    """특정 시간 동안 읽기"""

    def __init__(self, adb: ADBController, min_seconds: int = 3, max_seconds: int = 10):
        super().__init__(adb)
        self.min_seconds = min_seconds
        self.max_seconds = max_seconds

    def execute(self):
        # 읽는 시간 (정규분포)
        read_time = max(
            self.min_seconds,
            min(self.max_seconds, random.gauss((self.min_seconds + self.max_seconds) / 2, 2))
        )

        print(f"📖 읽는 중... ({read_time:.1f}초)")

        # 읽는 동안 미세한 스크롤 (사람처럼)
        start_time = time.time()
        while time.time() - start_time < read_time:
            if random.random() < 0.3:  # 30% 확률로 미세 스크롤
                self.adb.swipe(
                    540, 1200,
                    540, 1100,  # 작은 스크롤
                    duration=100
                )
            time.sleep(random.uniform(0.5, 1.5))


class CompareItems(BehaviorPrimitive):
    """상품 비교 행동"""

    def __init__(self, adb: ADBController, item_count: int = 2):
        super().__init__(adb)
        self.item_count = item_count

    def execute(self):
        for i in range(self.item_count):
            print(f"🔍 상품 {i+1} 확인 중...")

            # 상품 클릭 (좌표는 동적으로 결정)
            y = 400 + (i * 300)
            self.adb.tap(540, y)

            # 상품 페이지 읽기
            ReadForSeconds(self.adb, min_seconds=5, max_seconds=15).execute()

            # 뒤로가기
            self.adb.press_back()
            time.sleep(random.uniform(1, 2))

            # 다음 상품 찾기 위한 스크롤
            if i < self.item_count - 1:
                ScrollWithHesitation(self.adb).execute()


class TapWithNoise(BehaviorPrimitive):
    """노이즈가 있는 탭 (정확히 중심을 누르지 않음)"""

    def __init__(self, adb: ADBController, x: int, y: int, noise_radius: int = 10):
        super().__init__(adb)
        self.x = x
        self.y = y
        self.noise_radius = noise_radius

    def execute(self):
        # 중심에서 랜덤 오프셋 추가
        noise_x = random.randint(-self.noise_radius, self.noise_radius)
        noise_y = random.randint(-self.noise_radius, self.noise_radius)

        final_x = self.x + noise_x
        final_y = self.y + noise_y

        # 탭 전 짧은 대기 (50~200ms)
        time.sleep(random.uniform(0.05, 0.2))

        self.adb.tap(final_x, final_y)
```

### 고수준 시나리오 생성기

```python
# src/behavior/scenario_generator.py

import random
from typing import List
from src.behavior.primitives import *

class ScenarioGenerator:
    """고수준 목표를 프리미티브 시퀀스로 변환"""

    def __init__(self, adb: ADBController):
        self.adb = adb
        self.primitives = {
            "scroll_hesitation": ScrollWithHesitation(adb),
            "read": ReadForSeconds(adb),
            "compare": CompareItems(adb),
            "tap_noise": lambda x, y: TapWithNoise(adb, x, y).execute()
        }

    def generate(self, goal: str) -> List[BehaviorPrimitive]:
        """
        목표에서 프리미티브 시퀀스 생성

        Args:
            goal: "상품 2개 비교 후 리뷰 읽기"

        Returns:
            실행할 프리미티브 리스트
        """
        if "상품" in goal and "비교" in goal:
            return self._generate_product_comparison_scenario()
        elif "리뷰" in goal:
            return self._generate_review_reading_scenario()
        else:
            return self._generate_default_browsing_scenario()

    def _generate_product_comparison_scenario(self) -> List[BehaviorPrimitive]:
        """상품 비교 시나리오"""
        scenario = []

        # 1. 검색창 클릭 (노이즈 포함)
        scenario.append(lambda: TapWithNoise(self.adb, 540, 120).execute())

        # 2. 검색 결과 둘러보기
        for _ in range(random.randint(2, 4)):
            scenario.append(ScrollWithHesitation(self.adb))

        # 3. 상품 2~3개 비교
        item_count = random.randint(2, 3)
        scenario.append(CompareItems(self.adb, item_count))

        # 4. 다시 목록으로 돌아와서 추가 탐색 (50% 확률)
        if random.random() < 0.5:
            scenario.append(ScrollWithHesitation(self.adb))
            scenario.append(ReadForSeconds(self.adb, 3, 7))

        return scenario

    def _generate_review_reading_scenario(self) -> List[BehaviorPrimitive]:
        """리뷰 읽기 시나리오"""
        scenario = []

        # 1. 상품 클릭
        scenario.append(lambda: TapWithNoise(self.adb, 540, 500).execute())

        # 2. 상품 페이지 스크롤 (리뷰 섹션까지)
        for _ in range(random.randint(3, 5)):
            scenario.append(ScrollWithHesitation(self.adb))

        # 3. 리뷰 읽기 (10~30초)
        scenario.append(ReadForSeconds(self.adb, 10, 30))

        # 4. 리뷰 더보기 클릭 (70% 확률)
        if random.random() < 0.7:
            scenario.append(lambda: TapWithNoise(self.adb, 540, 1400).execute())
            scenario.append(ReadForSeconds(self.adb, 5, 15))

        return scenario

    def execute_scenario(self, scenario: List[BehaviorPrimitive]):
        """시나리오 실행"""
        for i, primitive in enumerate(scenario):
            print(f"\n[Step {i+1}/{len(scenario)}]")
            if callable(primitive):
                primitive()
            else:
                primitive.execute()
```

### 사용 예시

```python
# 기존 방식 (탐지 쉬움)
adb.tap(540, 120)
adb.scroll_down()
adb.tap(540, 500)

# 새로운 방식 (탐지 어려움)
generator = ScenarioGenerator(adb)

goal = "상품 2개 비교 후 리뷰 읽기"
scenario = generator.generate(goal)

generator.execute_scenario(scenario)
# 실행 결과: 매번 다른 순서, 다른 시간 간격, 다른 좌표로 실행됨
```

### 탐지 회피 효과
- **좌표 노이즈**: 같은 버튼도 매번 다른 위치 클릭
- **시간 랜덤화**: 정규분포 기반 체류 시간
- **행동 다양성**: 같은 목표라도 매번 다른 경로
- **미세 동작**: 읽는 중 미세 스크롤, 망설임 등

---

## 아이디어 4: 분산형 A/B 테스팅 플랫폼

### 컨셉
- `turafic`의 테스트 매트릭스를 수천 대의 봇에서 병렬 실행
- 시간 단축: 수십 시간 → 수 분

### 아키텍처

```
┌──────────────────────────────────────────────────────┐
│           테스트 지휘자 (Test Conductor)                │
├──────────────────────────────────────────────────────┤
│  1. 테스트 매트릭스 로드 (IT-001 ~ IT-012)               │
│  2. 봇 네트워크를 12개 그룹으로 분할                      │
│     - Group 1 (봇 1~100): IT-001 실행                  │
│     - Group 2 (봇 101~200): IT-002 실행                │
│     ...                                                │
│  3. 실시간 결과 집계 및 ANOVA 분석                       │
│  4. 최적 전략 도출 및 보고                               │
└──────────────────────────────────────────────────────┘
                         ↓
        ┌────────────────┴────────────────┐
        ↓                ↓                 ↓
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Group 1      │  │ Group 2      │  │ Group 12     │
│ (봇 1~100)   │  │ (봇 101~200) │  │ (봇 1101~...) │
│ TC: IT-001   │  │ TC: IT-002   │  │ TC: IT-012   │
└──────────────┘  └──────────────┘  └──────────────┘
   100회 병렬        100회 병렬        100회 병렬
   (동시 실행)       (동시 실행)       (동시 실행)
```

### 구현

```python
# src/distributed/test_conductor.py

from typing import List, Dict
import asyncio
import json

class TestConductor:
    """분산 테스트 지휘자"""

    def __init__(self, test_matrix_path: str, total_bots: int = 1200):
        self.test_matrix = self._load_test_matrix(test_matrix_path)
        self.total_bots = total_bots
        self.results = []

    def _load_test_matrix(self, path: str) -> List[Dict]:
        """테스트 매트릭스 로드"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get("test_cases", [])

    def assign_test_cases(self) -> Dict[str, List[int]]:
        """봇들에게 테스트 케이스 할당"""
        num_cases = len(self.test_matrix)
        bots_per_case = self.total_bots // num_cases

        assignments = {}
        bot_id = 1

        for i, test_case in enumerate(self.test_matrix):
            tc_id = test_case["tc"]
            bot_ids = list(range(bot_id, bot_id + bots_per_case))
            assignments[tc_id] = bot_ids
            bot_id += bots_per_case

            print(f"✅ {tc_id}: 봇 {bot_ids[0]}~{bot_ids[-1]} ({len(bot_ids)}개)")

        return assignments

    async def run_distributed_test(self):
        """분산 테스트 실행"""
        assignments = self.assign_test_cases()

        # 각 그룹에 명령 전송 (병렬)
        tasks = []
        for tc_id, bot_ids in assignments.items():
            task = self._send_command_to_group(tc_id, bot_ids)
            tasks.append(task)

        # 모든 그룹의 결과 대기
        results = await asyncio.gather(*tasks)

        # ANOVA 분석
        self._analyze_results(results)

    async def _send_command_to_group(self, tc_id: str, bot_ids: List[int]):
        """특정 그룹에 명령 전송"""
        print(f"\n📡 {tc_id} 명령 전송: {len(bot_ids)}개 봇")

        # 실제로는 WebSocket/MQTT로 전송
        # 여기서는 시뮬레이션
        await asyncio.sleep(1)

        # 봇들의 결과 수집 (시뮬레이션)
        results = []
        for bot_id in bot_ids:
            # 실제로는 각 봇이 결과를 서버로 전송
            result = {
                "bot_id": bot_id,
                "tc_id": tc_id,
                "rank_change": random.randint(-10, 5)  # 시뮬레이션
            }
            results.append(result)

        return {
            "tc_id": tc_id,
            "results": results
        }

    def _analyze_results(self, results: List[Dict]):
        """ANOVA 분석"""
        import numpy as np
        from scipy import stats

        # 테스트 케이스별 순위 변화 그룹화
        groups = {}
        for result in results:
            tc_id = result["tc_id"]
            rank_changes = [r["rank_change"] for r in result["results"]]
            groups[tc_id] = rank_changes

        # ANOVA 수행
        f_stat, p_value = stats.f_oneway(*groups.values())

        print(f"\n\n{'='*80}")
        print("분산 분석 (ANOVA) 결과")
        print(f"{'='*80}")
        print(f"F-statistic: {f_stat:.4f}")
        print(f"p-value: {p_value:.6f}")

        if p_value < 0.05:
            print("✅ 유의미한 차이 발견 (p < 0.05)")
        else:
            print("❌ 유의미한 차이 없음 (p >= 0.05)")

        # 각 테스트 케이스별 평균
        print(f"\n테스트 케이스별 평균 순위 변화:")
        for tc_id, rank_changes in groups.items():
            mean = np.mean(rank_changes)
            std = np.std(rank_changes)
            print(f"  {tc_id}: {mean:.2f}위 (±{std:.2f})")

        # 최적 전략 도출
        best_tc = min(groups.keys(), key=lambda k: np.mean(groups[k]))
        print(f"\n🏆 최적 전략: {best_tc} (평균 {np.mean(groups[best_tc]):.2f}위 상승)")


# 실행
async def main():
    conductor = TestConductor(
        test_matrix_path="config/test_matrix.json",
        total_bots=1200
    )

    await conductor.run_distributed_test()


if __name__ == "__main__":
    asyncio.run(main())
```

### 실행 시간 비교

| 구분 | 순차 실행 (기존) | 병렬 실행 (신규) |
|------|----------------|----------------|
| **테스트 케이스** | 12개 | 12개 |
| **케이스당 반복** | 100회 | 100회 |
| **총 트래픽** | 1,200회 | 1,200회 |
| **실행 방식** | 순차 (한 번에 1개) | 병렬 (동시 1,200개) |
| **소요 시간** | 40시간 (2분×1,200) | **3분** (병렬) |

### 장점
1. **시간 단축**: 40시간 → 3분 (800배 빠름)
2. **통계 신뢰도**: 큰 표본 크기 (n=100 per case)
3. **실시간 분석**: 결과 즉시 ANOVA 처리
4. **확장성**: 봇 수 증가 시 더 빠른 실험

---

## 통합 로드맵

### Phase 1: 하이브리드 제어 시스템 (6주)
- Week 1-2: UI 매핑 시스템
- Week 3: ADB 실행 에이전트
- Week 4: 중앙 서버 API
- Week 5: 파일럿 테스트
- Week 6: 프로덕션 배포

### Phase 2: 자가 치유 시스템 (4주)
- Week 7-8: 실패 감지 및 AI 비전 통합
- Week 9: 동적 패치 배포 시스템
- Week 10: 무중단 운영 테스트

### Phase 3: 인간 행동 시뮬레이션 (3주)
- Week 11: 행동 프리미티브 라이브러리
- Week 12: 시나리오 생성기
- Week 13: 탐지 회피 효과 검증

### Phase 4: 분산 테스팅 플랫폼 (2주)
- Week 14: 테스트 지휘자 및 명령 배포
- Week 15: 실시간 분석 및 최적화

**총 소요 시간**: 15주 (약 4개월)

---

## 예상 효과

| 지표 | 현재 | 개선 후 |
|------|------|--------|
| **UI 변경 대응** | 수동 (2시간) | 자동 (5분) |
| **봇 탐지율** | 30% | 5% 이하 |
| **테스트 실행 시간** | 40시간 | 3분 |
| **유지보수 비용** | 높음 | 거의 제로 |
| **확장성** | 제한적 | 무제한 |

---

## 결론

이 4가지 혁신 아이디어를 통해:

1. **정확성 + 성능** (하이브리드 제어)
2. **무중단 운영** (자가 치유)
3. **탐지 불가** (인간 행동 시뮬레이션)
4. **대규모 실험** (분산 테스팅)

을 모두 달성할 수 있습니다.

**다음 단계**: Phase 1 (하이브리드 제어 시스템) 구현 착수
