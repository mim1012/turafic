---
name: mobile-automation
description: ADB와 Appium을 사용한 Android 모바일 자동화 전문 스킬. 모바일 기기 제어, 화면 조작, 앱 자동화, 비행기모드 토글, IP 변경이 필요할 때 사용. 키워드: ADB, Appium, Android, 모바일 테스트, 기기 제어, 비행기모드, IP 변경
allowed-tools: Bash(adb:*), Bash(python:*), Read, Write
---

# Mobile Automation Specialist

Android 모바일 기기 자동화 전문가입니다. ADB, Appium, Chrome DevTools Protocol을 활용한 모바일 자동화를 수행합니다.

## 전문 분야

### 1. ADB (Android Debug Bridge) 제어
- 기기 연결 및 상태 확인
- 화면 조작 (탭, 스와이프, 텍스트 입력)
- 앱 실행 및 종료
- 비행기모드 토글
- 네트워크 상태 모니터링

### 2. Appium 기반 자동화
- 웹뷰 및 네이티브 앱 제어
- 요소 선택 및 조작
- 스크린샷 및 페이지 소스 추출
- 세션 관리

### 3. Chrome DevTools Protocol
- 모바일 Chrome 원격 디버깅
- JavaScript 실행
- 네트워크 요청 모니터링
- 쿠키 및 로컬스토리지 관리

## 자동화 접근 방법

### Phase 1: Pure ADB Shell (프로토타입)

빠른 검증과 단순 동작 테스트에 적합합니다.

```python
import subprocess
import time

# 화면 탭
subprocess.run(['adb', 'shell', 'input', 'tap', '500', '1000'])

# 스크롤 (swipe)
# 형식: input swipe <x1> <y1> <x2> <y2> [duration_ms]
subprocess.run(['adb', 'shell', 'input', 'swipe', '500', '1500', '500', '500', '300'])

# 텍스트 입력 (한글은 인코딩 필요)
subprocess.run(['adb', 'shell', 'input', 'text', 'search_keyword'])

# URL 열기 (Chrome)
subprocess.run([
    'adb', 'shell', 'am', 'start',
    '-a', 'android.intent.action.VIEW',
    '-d', 'https://shopping.naver.com'
])

# 앱 실행
subprocess.run([
    'adb', 'shell', 'am', 'start',
    '-n', 'com.android.chrome/.Main'
])

# 뒤로 가기
subprocess.run(['adb', 'shell', 'input', 'keyevent', 'KEYCODE_BACK'])

# 홈 버튼
subprocess.run(['adb', 'shell', 'input', 'keyevent', 'KEYCODE_HOME'])
```

**장점**:
- 추가 의존성 없음
- 가볍고 빠름
- 리소스 사용 최소화

**단점**:
- 좌표 하드코딩 필요
- 화면 해상도별 대응 어려움
- DOM 요소 접근 불가

### Phase 2: Appium + uiautomator2 (안정성)

안정적이고 유지보수 가능한 코드에 적합합니다.

```python
from appium import webdriver
from appium.options.android import UiAutomator2Options
from appium.webdriver.common.appiumby import AppiumBy
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Appium 설정
options = UiAutomator2Options()
options.platform_name = "Android"
options.automation_name = "UiAutomator2"
options.device_name = "Android Device"
options.no_reset = True  # 앱 데이터 유지
options.browser_name = "Chrome"  # Chrome 브라우저 사용

# Appium 서버 연결 (기본 포트: 4723)
driver = webdriver.Remote('http://localhost:4723', options=options)

# 네이버 쇼핑 접속
driver.get('https://shopping.naver.com')

# 요소 대기 및 찾기
wait = WebDriverWait(driver, 10)
search_box = wait.until(
    EC.presence_of_element_located((AppiumBy.CSS_SELECTOR, 'input[type="text"]'))
)

# 텍스트 입력
search_box.send_keys('무선 이어폰')

# 검색 버튼 클릭
search_button = driver.find_element(AppiumBy.CSS_SELECTOR, 'button.search')
search_button.click()

# 스크롤 (JavaScript)
driver.execute_script('window.scrollBy(0, 500)')

# 스크린샷
driver.save_screenshot('screenshot.png')

# 세션 종료
driver.quit()
```

**장점**:
- 크로스 플랫폼 (iOS도 지원)
- Selenium과 유사한 API
- 웹뷰, 네이티브 앱 모두 제어 가능
- 요소 선택이 정확함

**단점**:
- Appium Server 설치 필요
- 초기 설정 복잡
- Pure ADB보다 느림

### Phase 3: Chrome DevTools Protocol (세밀한 제어)

웹 페이지 세밀한 제어에 적합합니다.

```python
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# 모바일 Chrome의 원격 디버깅 포트 포워딩
subprocess.run([
    'adb', 'forward',
    'tcp:9222', 'localabstract:chrome_devtools_remote'
])

# Selenium으로 연결
options = Options()
options.add_experimental_option("debuggerAddress", "127.0.0.1:9222")
driver = webdriver.Chrome(options=options)

# 현재 페이지 URL 확인
print(driver.current_url)

# JavaScript 실행
result = driver.execute_script('return document.title')

# 쿠키 관리
cookies = driver.get_cookies()
driver.add_cookie({'name': 'test', 'value': 'value'})

driver.quit()
```

**장점**:
- 웹 자동화에 최적화
- DOM 요소 접근 가능
- Selenium 코드 재사용
- 네트워크 요청 모니터링 가능

**단점**:
- Chrome 브라우저만 가능
- 모바일 Chrome에서 원격 디버깅 활성화 필요
- 포트 포워딩 설정 필요

## 비행기모드 토글 (IP 변경)

네이버 쇼핑 트래픽 테스트에서 IP를 변경하기 위해 비행기모드를 토글합니다.

```python
import subprocess
import time

def toggle_airplane_mode():
    """
    비행기모드를 토글하여 IP를 변경합니다.
    """
    # 비행기모드 ON
    result = subprocess.run(
        ['adb', 'shell', 'cmd', 'connectivity', 'airplane-mode', 'enable'],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise Exception(f"비행기모드 ON 실패: {result.stderr}")

    print("✈️  비행기모드 활성화")

    # 3초 대기
    time.sleep(3)

    # 비행기모드 OFF
    result = subprocess.run(
        ['adb', 'shell', 'cmd', 'connectivity', 'airplane-mode', 'disable'],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise Exception(f"비행기모드 OFF 실패: {result.stderr}")

    print("📶 비행기모드 비활성화")

    # 네트워크 재연결 대기
    wait_for_network(timeout=10)

def wait_for_network(timeout=10):
    """
    네트워크가 재연결될 때까지 대기합니다.
    """
    import time

    for i in range(timeout):
        result = subprocess.run(
            ['adb', 'shell', 'dumpsys', 'connectivity'],
            capture_output=True,
            text=True
        )

        if 'NetworkAgentInfo' in result.stdout and 'CONNECTED' in result.stdout:
            print(f"🌐 네트워크 재연결 완료 ({i+1}초)")
            return True

        time.sleep(1)

    raise Exception(f"네트워크 재연결 타임아웃 ({timeout}초)")

# 사용 예시
try:
    toggle_airplane_mode()
    print("✅ IP 변경 완료")
except Exception as e:
    print(f"❌ IP 변경 실패: {e}")
```

## 자연스러운 사용자 행동 시뮬레이션

봇 탐지를 회피하기 위해 사람처럼 자연스러운 행동을 시뮬레이션합니다.

### 1. 자연스러운 스크롤

```python
import random
import time

def human_like_scroll(duration_seconds=3):
    """
    사람처럼 불규칙한 속도로 스크롤합니다.
    """
    screen_height = get_screen_height()  # ADB로 화면 높이 가져오기
    start_y = int(screen_height * 0.7)
    end_y = int(screen_height * 0.3)

    # 여러 번 짧게 스크롤 (사람은 한 번에 끝까지 스크롤하지 않음)
    num_scrolls = random.randint(3, 6)

    for i in range(num_scrolls):
        # 스크롤 거리 랜덤화
        distance = random.randint(200, 500)
        this_end_y = start_y - distance

        # 스크롤 속도 랜덤화
        swipe_duration = random.randint(100, 300)

        subprocess.run([
            'adb', 'shell', 'input', 'swipe',
            '500', str(start_y), '500', str(this_end_y), str(swipe_duration)
        ])

        # 스크롤 사이 대기 (사람은 내용을 읽음)
        time.sleep(random.uniform(0.5, 1.5))

def get_screen_height():
    """
    ADB로 화면 높이를 가져옵니다.
    """
    result = subprocess.run(
        ['adb', 'shell', 'wm', 'size'],
        capture_output=True,
        text=True
    )
    # 출력: Physical size: 1080x2400
    height = int(result.stdout.split('x')[1].strip())
    return height
```

### 2. 체류 시간 (정규분포)

```python
import numpy as np

def get_stay_duration(mean=45, std=10, min_val=30, max_val=60):
    """
    정규분포 기반으로 체류 시간을 생성합니다.
    평균 45초, 표준편차 10초, 최소 30초, 최대 60초
    """
    duration = np.random.normal(mean, std)
    duration = max(min_val, min(max_val, int(duration)))
    return duration

# 사용 예시
stay_time = get_stay_duration()
print(f"체류 시간: {stay_time}초")
time.sleep(stay_time)
```

### 3. 랜덤 액션

```python
def perform_random_action():
    """
    랜덤하게 사용자 액션을 수행합니다.
    """
    actions = {
        'add_to_cart': 0.3,   # 30% - 장바구니 담기
        'click_review': 0.4,   # 40% - 리뷰 클릭
        'click_qna': 0.2,      # 20% - 1:1 문의 클릭
        'just_browse': 0.1,    # 10% - 그냥 둘러보기
    }

    # 확률 기반 선택
    chosen_action = random.choices(
        list(actions.keys()),
        weights=list(actions.values())
    )[0]

    if chosen_action == 'add_to_cart':
        # 장바구니 버튼 좌표 (화면 해상도에 따라 조정 필요)
        subprocess.run(['adb', 'shell', 'input', 'tap', '900', '1800'])
        print("🛒 장바구니 담기")
    elif chosen_action == 'click_review':
        # 리뷰 탭 클릭
        subprocess.run(['adb', 'shell', 'input', 'tap', '500', '1200'])
        print("⭐ 리뷰 클릭")
    elif chosen_action == 'click_qna':
        # 문의 탭 클릭
        subprocess.run(['adb', 'shell', 'input', 'tap', '700', '1200'])
        print("💬 문의 클릭")
    else:
        print("👀 그냥 둘러보기")
```

## 에러 핸들링

### 1. ADB 연결 끊김

```python
def check_adb_connection():
    """
    ADB 기기 연결 상태를 확인합니다.
    """
    result = subprocess.run(
        ['adb', 'devices'],
        capture_output=True,
        text=True
    )

    lines = result.stdout.strip().split('\n')
    if len(lines) < 2 or 'device' not in lines[1]:
        return False
    return True

def reconnect_adb(max_retries=3):
    """
    ADB 연결을 재시도합니다.
    """
    for i in range(max_retries):
        if check_adb_connection():
            print(f"✅ ADB 연결 확인 (재시도 {i+1})")
            return True

        print(f"🔄 ADB 재연결 시도 {i+1}/{max_retries}")

        # USB 케이블 재인식을 위한 대기
        time.sleep(2)

        # ADB 서버 재시작
        subprocess.run(['adb', 'kill-server'])
        time.sleep(1)
        subprocess.run(['adb', 'start-server'])
        time.sleep(2)

    raise Exception("ADB 연결 실패: 기기를 확인하세요")
```

### 2. 명령 실패 재시도

```python
def adb_command_with_retry(command, max_retries=3):
    """
    ADB 명령을 재시도합니다.
    """
    for i in range(max_retries):
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            return result

        print(f"⚠️  명령 실패, 재시도 {i+1}/{max_retries}")
        time.sleep(1)

    raise Exception(f"명령 실패: {' '.join(command)}")
```

### 3. 기기 재부팅

```python
def reboot_device():
    """
    기기를 재부팅합니다. (최후의 수단)
    """
    print("🔄 기기 재부팅 중...")

    subprocess.run(['adb', 'reboot'])

    # 재부팅 완료 대기 (약 30초)
    time.sleep(30)

    # ADB 재연결 대기
    for i in range(30):
        if check_adb_connection():
            print(f"✅ 재부팅 완료 및 ADB 재연결 ({i+1}초)")
            return True
        time.sleep(1)

    raise Exception("재부팅 후 ADB 재연결 실패")
```

## 사용 가이드

### 언제 이 Skill이 발동되는가?

사용자가 다음과 같은 요청을 하면 이 Skill이 자동으로 발동됩니다:
- "ADB로 기기 연결해줘"
- "모바일 기기에서 네이버 쇼핑 접속해줘"
- "비행기모드 토글해서 IP 변경해줘"
- "Appium으로 앱 자동화해줘"
- "모바일 Chrome 원격 디버깅 설정해줘"

### 참조 문서

상세한 ADB 명령어는 @adb-commands.md 를 참고하세요.

## 권장 구성

프로젝트 단계별 권장 자동화 방법:

```
Phase 1 (프로토타입): Pure ADB Shell
→ 빠른 검증, 단순 동작 테스트

Phase 2 (본 구현): Appium + uiautomator2
→ 안정적이고 유지보수 가능한 코드

Phase 3 (최적화): CDP 혼합
→ 웹 페이지 세밀한 제어
```

현재 Navertrafic 프로젝트는 Phase 1 (Pure ADB Shell)로 시작하여, 안정화 후 Phase 2로 전환하는 것을 권장합니다.
