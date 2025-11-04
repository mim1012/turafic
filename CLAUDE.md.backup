# Navertrafic - 네이버 쇼핑 순위 테스트 자동화

## 📋 프로젝트 개요

### 목적
네이버 쇼핑 상품의 트래픽 생성 및 순위 변동 추적을 자동화하여, 어떤 사용자 행동 패턴이 상품 순위에 영향을 미치는지 분석합니다.

### 핵심 기능
- 네이버/네이버쇼핑 검색을 통한 상품 페이지 자동 접근
- 자연스러운 사용자 행동 시뮬레이션 (스크롤, 클릭, 체류)
- ADB를 통한 모바일 기기 제어 및 IP 변경
- 상품 순위 추적 및 효과성 분석

### 기술 스택
```
언어: Python 3.10+
모바일 자동화: Appium + uiautomator2
모바일 제어: ADB (Android Debug Bridge)
브라우저 제어: Chrome DevTools Protocol (선택적)
데이터 분석: Pandas, Matplotlib
데이터 저장: JSON / CSV / SQLite
```

### 실행 환경
```
하드웨어 구성:
- PC (Windows/Mac/Linux) - 제어 서버
- Android 스마트폰 - USB/WiFi로 ADB 연결
- USB 케이블 또는 무선 ADB 설정

소프트웨어 요구사항:
- Android 기기: 개발자 옵션 활성화, USB 디버깅 ON
- PC: Python 3.10+, ADB 도구, Appium (선택)
- 네트워크: WiFi 또는 모바일 데이터
```

---

## 🎯 테스트 시나리오

### 1. 테스트 모드
- **Phase 1**: 비로그인 모드 (우선 구현)
- **Phase 2**: 로그인 모드 (추후 확장)

### 2. 테스트 상품 데이터 구조
```python
# 10개 테스트 케이스
test_products = [
    {
        "id": 1,
        "product_name": "상품명",
        "product_id": "12345678",  # 네이버 상품 ID
        "search_keyword": "검색 키워드",
        "category": "카테고리명",
        "initial_rank": {
            "page": 0,  # 초기 페이지 번호 (0이면 순위권 밖)
            "position": 0,  # 페이지 내 위치
            "checked_at": "2025-01-01 00:00:00"
        },
        "test_case_type": "A",  # A: 네이버 검색, B: 쇼핑 직접 검색
    },
    # ... 9개 더
]
```

### 3. 테스트 케이스 선정 기준
- [ ] 카테고리 분산: 다양한 카테고리에서 선정
- [ ] 초기 순위: 2~10페이지 범위 내 상품 선호
- [ ] 키워드 경쟁도: 중간~낮은 경쟁 키워드 우선
- [ ] 상품 가격대: 클릭 가능성이 높은 가격대

---

## 🔄 작업 프로세스

### 페이지 이동 경로

#### **케이스 A: 네이버 통합검색 경로**
```
1. 네이버 메인 (naver.com) 접속
2. 검색창에 키워드 입력
3. 쇼핑탭 클릭
4. 스크롤하여 상품 찾기
5. 상품 상세 페이지 진입
```

#### **케이스 B: 네이버쇼핑 직접 검색**
```
1. 네이버쇼핑 (shopping.naver.com) 접속
2. 검색창에 키워드 입력
3. 스크롤하여 상품 찾기
4. 상품 상세 페이지 진입
```

### 상품 페이지 액션

#### 스크롤 동작
```python
# 자연스러운 스크롤 패턴
scroll_actions = [
    "scroll_to_options",      # 옵션 영역까지 스크롤
    "scroll_to_reviews",      # 리뷰 영역까지 스크롤 (확률 70%)
    "scroll_to_qna",          # Q&A 영역까지 스크롤 (확률 40%)
]
# 스크롤 속도: 100~300ms 간격으로 200~500px씩
```

#### 랜덤 액션 (확률 분포)
```python
actions = {
    "add_to_cart": 0.3,        # 30% - 장바구니 담기
    "click_review": 0.4,       # 40% - 리뷰 클릭
    "click_qna": 0.2,          # 20% - 1:1 문의 클릭
    "just_browse": 0.1,        # 10% - 그냥 둘러보기
}
```

#### 체류 시간
```python
import random
import numpy as np

# 정규분포 기반 체류시간 (평균 45초, 표준편차 10초)
stay_duration = max(30, min(60, int(np.random.normal(45, 10))))
```

---

## 📱 ADB 연동 프로세스

### ADB 명령어 표준화

```python
# 기기 연결 확인
adb devices

# 비행기모드 ON
adb shell cmd connectivity airplane-mode enable

# 3초 대기
time.sleep(3)

# 비행기모드 OFF
adb shell cmd connectivity airplane-mode disable

# 네트워크 재연결 대기 (최대 10초)
# WiFi/LTE 연결 상태 체크
```

### IP 변경 확인
```python
def verify_ip_change(previous_ip):
    """
    IP가 실제로 변경되었는지 확인
    """
    max_retries = 5
    for i in range(max_retries):
        current_ip = get_current_ip()
        if current_ip != previous_ip:
            return True
        time.sleep(2)
    return False
```

### 에러 핸들링
- 기기 연결 끊김: 재연결 시도 (최대 3회)
- 비행기모드 토글 실패: 기기 재부팅 후 재시도
- 네트워크 재연결 타임아웃: 로그 기록 후 다음 케이스 진행

### 모바일 자동화 구현 방식

#### 방법 1: Appium + uiautomator2 (권장)
```python
from appium import webdriver
from appium.options.android import UiAutomator2Options

# Appium 설정
options = UiAutomator2Options()
options.platform_name = "Android"
options.automation_name = "UiAutomator2"
options.device_name = "Android Device"
options.no_reset = True  # 앱 데이터 유지

# Chrome 브라우저 사용
options.browser_name = "Chrome"

driver = webdriver.Remote('http://localhost:4723', options=options)

# 네이버 쇼핑 접속
driver.get('https://shopping.naver.com')
```

**장점**:
- 크로스 플랫폼 (iOS도 지원)
- Selenium과 유사한 API
- 웹뷰, 네이티브 앱 모두 제어 가능

**단점**:
- Appium Server 설치 필요
- 초기 설정 복잡

#### 방법 2: Pure ADB Shell 명령어 (경량)
```python
import subprocess

# 화면 탭
subprocess.run(['adb', 'shell', 'input', 'tap', '500', '1000'])

# 스크롤 (swipe)
subprocess.run(['adb', 'shell', 'input', 'swipe', '500', '1500', '500', '500', '300'])

# 텍스트 입력
subprocess.run(['adb', 'shell', 'input', 'text', '검색어'])

# URL 열기 (Chrome)
subprocess.run(['adb', 'shell', 'am', 'start', '-a', 'android.intent.action.VIEW',
                '-d', 'https://shopping.naver.com'])
```

**장점**:
- 추가 의존성 없음
- 가볍고 빠름
- 리소스 사용 최소화

**단점**:
- 좌표 하드코딩 필요
- 화면 해상도별 대응 어려움
- DOM 요소 접근 불가

#### 방법 3: Chrome DevTools Protocol (CDP)
```python
# 모바일 Chrome의 원격 디버깅 포트 포워딩
subprocess.run(['adb', 'forward', 'tcp:9222', 'localabstract:chrome_devtools_remote'])

# Selenium으로 연결
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

options = Options()
options.add_experimental_option("debuggerAddress", "127.0.0.1:9222")
driver = webdriver.Chrome(options=options)
```

**장점**:
- 웹 자동화에 최적화
- DOM 요소 접근 가능
- Selenium 코드 재사용

**단점**:
- Chrome 브라우저만 가능
- 모바일 Chrome에서 원격 디버깅 활성화 필요

#### 권장 구성
```
Phase 1 (프로토타입): Pure ADB Shell
→ 빠른 검증, 단순 동작 테스트

Phase 2 (본 구현): Appium + uiautomator2
→ 안정적이고 유지보수 가능한 코드

Phase 3 (최적화): CDP 혼합
→ 웹 페이지 세밀한 제어
```

---

## 📊 평가 지표 및 데이터 수집

### 순위 계산 방식
```python
# 네이버 쇼핑 검색 결과: 1페이지당 20개 상품
# 페이지 1: 1-20위
# 페이지 2: 21-40위
# 페이지 3: 41-60위
# 페이지 4: 61-80위

# 순위 계산 공식
def calculate_rank(page: int, position: int) -> int:
    """
    Args:
        page: 페이지 번호 (1부터 시작)
        position: 페이지 내 위치 (1-20)

    Returns:
        전체 순위 (1부터 시작)

    Examples:
        >>> calculate_rank(1, 1)   # 1페이지 1번째
        1
        >>> calculate_rank(4, 1)   # 4페이지 1번째
        61
        >>> calculate_rank(4, 20)  # 4페이지 20번째 (4페이지 끝)
        80
    """
    return (page - 1) * 20 + position

# 순위 변동 계산
def calculate_rank_change(before_rank: int, after_rank: int) -> int:
    """
    순위 변동 계산 (음수 = 상승, 양수 = 하락)

    Examples:
        >>> calculate_rank_change(52, 28)  # 52위 → 28위
        -24  # 24위 상승
        >>> calculate_rank_change(28, 52)  # 28위 → 52위
        24   # 24위 하락
    """
    return after_rank - before_rank
```

### 순위 추적 데이터
```python
ranking_data = {
    "product_id": "12345678",
    "test_case_id": 1,
    "iteration": 1,  # 1~100
    "before_rank": {
        "page": 3,
        "position": 12,
        "absolute_rank": 52  # (3-1)*20 + 12 = 52위
    },
    "after_rank": {
        "page": 2,
        "position": 8,
        "absolute_rank": 28  # (2-1)*20 + 8 = 28위
    },
    "rank_change": -24,  # 28 - 52 = -24 (24위 상승)
    "rank_improved": True,  # rank_change < 0
    "timestamp": "2025-01-01 00:00:00",
}
```

### 효과성 측정 기준
1. **순위 변동폭**: 평균 몇 위 상승/하락
2. **페이지 이동**: 페이지 간 이동 발생 여부
3. **안정성**: 순위 변동의 일관성
4. **케이스 비교**: A vs B 경로의 효과 차이

### 100회 반복 실행 프레임워크
```python
for iteration in range(1, 101):
    # 1. 순위 체크 (Before)
    current_rank = check_product_rank(product)

    # 2. 트래픽 생성 작업 수행
    perform_traffic_action(product, test_case)

    # 3. ADB 비행기모드 토글 (IP 변경)
    toggle_airplane_mode()
    wait_for_network_reconnect()

    # 4. 순위 체크 (After) - 30분 후
    time.sleep(1800)
    new_rank = check_product_rank(product)

    # 5. 결과 저장
    save_result(product, iteration, current_rank, new_rank)

    # 6. 다음 반복 전 대기 (3~5분 랜덤)
    time.sleep(random.randint(180, 300))
```

---

## 💻 코딩 규칙 및 제약사항

### 봇 탐지 회피 전략
```python
# 1. User-Agent 로테이션
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...",
    # ... 20개 이상 준비
]

# 2. 요청 간격 랜덤화
time.sleep(random.uniform(2.0, 5.0))  # 2~5초 랜덤 대기

# 3. 마우스 이동 시뮬레이션
def human_like_mouse_move(driver, element):
    """사람처럼 곡선으로 마우스 이동"""
    action = ActionChains(driver)
    # Bezier curve 기반 이동
    ...

# 4. 쿠키/로컬스토리지 관리
# 매 세션마다 새로운 브라우저 프로필 생성

# 5. 화면 해상도 랜덤화
resolutions = [(1920, 1080), (1366, 768), (1440, 900)]
```

### 프로젝트 구조
```
Navertrafic/
├── CLAUDE.md                 # 이 파일
├── README.md                 # 프로젝트 설명
├── requirements.txt          # 의존성
├── config/
│   ├── settings.py          # 전역 설정
│   └── test_products.json   # 테스트 상품 목록
├── src/
│   ├── automation/
│   │   ├── browser.py       # 브라우저 제어
│   │   ├── actions.py       # 사용자 액션 시뮬레이션
│   │   └── mobile.py        # ADB 제어
│   ├── ranking/
│   │   ├── checker.py       # 순위 체크
│   │   └── tracker.py       # 순위 추적 데이터 관리
│   ├── analysis/
│   │   ├── stats.py         # 통계 분석
│   │   └── visualize.py     # 시각화
│   └── utils/
│       ├── logger.py        # 로깅
│       └── helpers.py       # 유틸리티 함수
├── data/
│   ├── rankings/            # 순위 데이터
│   └── results/             # 분석 결과
├── logs/                    # 로그 파일
└── tests/                   # 단위 테스트
```

---

## 🚀 구현 우선순위

### Phase 1: 기본 인프라 (1주차)
- [ ] 프로젝트 구조 생성
- [ ] 테스트 상품 10개 선정 및 데이터 입력
- [ ] 순위 체크 모듈 구현 (순위 크롤링)
- [ ] ADB 연동 및 비행기모드 토글 테스트

### Phase 2: 자동화 구현 (2주차)
- [ ] 브라우저 자동화 (Selenium/Playwright)
- [ ] 페이지 이동 경로 A, B 구현
- [ ] 사용자 액션 시뮬레이션 (스크롤, 클릭, 체류)
- [ ] 봇 탐지 회피 로직 적용

### Phase 3: 반복 실행 및 데이터 수집 (3주차)
- [ ] 100회 반복 실행 프레임워크
- [ ] 에러 핸들링 및 복구 로직
- [ ] 실시간 로깅 및 모니터링
- [ ] 데이터 저장 및 백업

### Phase 4: 분석 및 최적화 (4주차)
- [ ] 순위 변동 통계 분석
- [ ] 케이스별 효과성 비교
- [ ] 시각화 대시보드
- [ ] 보고서 자동 생성

---

## 🤖 Claude 작업 지침

### 파일 생성 규칙
- **절대 금지**: 불필요한 README.md, 문서 파일 자동 생성
- **우선순위**: 기존 파일 수정 > 새 파일 생성
- **필수 확인**: 파일 생성 전 사용자에게 확인 요청

### 코드 작성 원칙
1. **모듈화**: 각 기능을 독립적인 모듈로 분리
2. **재사용성**: 공통 로직은 utils에 작성
3. **에러 핸들링**: 모든 외부 API 호출에 try-except 적용
4. **로깅**: 중요한 이벤트는 반드시 로그 기록
5. **타입 힌팅**: Python 3.10+ 타입 힌트 적극 사용

### 봇 탐지 회피 중요 원칙
```python
# ❌ 나쁜 예
driver.get(url)
element.click()

# ✅ 좋은 예
time.sleep(random.uniform(1.5, 3.0))  # 랜덤 대기
driver.get(url)
wait_for_page_load()  # 페이지 로드 대기
human_like_scroll()  # 자연스러운 스크롤
time.sleep(random.uniform(0.5, 1.5))
element.click()
```

### 데이터 관리
- 모든 테스트 결과는 timestamp와 함께 저장
- JSON 형식으로 저장 (나중에 DB 마이그레이션 용이)
- 매일 자정 데이터 백업 자동화

### 성능 최적화
- **모바일 환경 최적화**
  - 백그라운드 앱 정리: 메모리 확보
  - 화면 밝기 자동 조절: 배터리 절약
  - 불필요한 알림 차단: 테스트 중단 방지
- **네트워크 최적화**
  - WiFi 고정 연결 권장 (안정성)
  - 모바일 데이터 사용 시 데이터 세이버 OFF
- **리소스 관리**
  - 장시간 실행 시 기기 발열 모니터링
  - 배터리 20% 이하 시 충전 대기
- **확장 시 고려사항**
  - 여러 기기 동시 제어 시 USB 허브 사용
  - 무선 ADB로 다중 기기 관리 가능

---

## 📝 논의 필요 사항

### 1. 테스트 상품 선정
- [ ] 10개 상품 리스트 확정
- [ ] 각 상품의 초기 순위 측정
- [ ] 카테고리별 분포 확인

### 2. 트래픽 분배 비율
- 네이버 검색 vs 쇼핑 검색: **50:50** or **30:70**?
- 장바구니/리뷰/문의 클릭 비율: **30:40:20:10** 유지?

### 3. 실행 환경 ✅ (확정)
- **PC + ADB 연결 Android 스마트폰** (확정)
- 클라우드 서버 사용 여부: 추후 논의
- 동시 실행 기기 수: 1대부터 시작, 추후 확장

### 4. 법적/윤리적 고려사항
- 네이버 서비스 약관 준수
- 트래픽 생성 속도 제한
- 테스트 목적 명확화

### 5. 데이터 저장 형식
- JSON (개발 단계) → SQLite (운영) 전환 시점?
- 클라우드 스토리지 연동 필요 여부?

---

## 🔧 필수 환경 설정

### 1. Python 가상환경
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. ADB 설치 및 설정
```bash
# Windows
choco install adb
# 또는 https://developer.android.com/tools/releases/platform-tools 에서 다운로드

# Mac
brew install android-platform-tools

# Linux (Ubuntu/Debian)
sudo apt-get install android-tools-adb android-tools-fastboot

# 연결 확인
adb devices

# 출력 예시:
# List of devices attached
# RF8M12345XY    device
```

### 3. Android 기기 설정
```
1. 개발자 옵션 활성화
   - 설정 > 휴대전화 정보 > 빌드번호 7회 탭

2. USB 디버깅 활성화
   - 설정 > 개발자 옵션 > USB 디버깅 ON

3. USB 연결 모드
   - 파일 전송(MTP) 또는 PTP 모드 선택
   - "USB 디버깅 허용" 팝업에서 항상 허용 체크

4. 화면 꺼짐 방지 (권장)
   - 개발자 옵션 > 화면 켜짐 상태 유지 ON

5. Chrome 원격 디버깅 (CDP 사용 시)
   - Chrome 브라우저 실행
   - chrome://inspect 접속 확인
```

### 4. Appium 설치 (Phase 2 구현 시)
```bash
# Node.js 설치 (Appium 실행 환경)
# Windows: https://nodejs.org 에서 다운로드
# Mac: brew install node

# Appium 설치
npm install -g appium

# Appium 드라이버 설치
appium driver install uiautomator2

# Appium 실행
appium

# Python Appium 클라이언트 설치
pip install Appium-Python-Client
```

### 5. 환경변수 설정
```bash
# .env 파일 생성
NAVER_URL=https://www.naver.com
NAVER_SHOPPING_URL=https://shopping.naver.com
ADB_DEVICE_ID=RF8M12345XY  # adb devices로 확인한 ID
APPIUM_SERVER=http://localhost:4723
LOG_LEVEL=INFO
AUTOMATION_MODE=adb  # adb, appium, cdp 중 선택
```

---

## 📖 참고 자료

### 모바일 자동화
- [Appium 공식 문서](https://appium.io/docs/en/latest/)
- [Appium Python Client](https://github.com/appium/python-client)
- [UiAutomator2 Driver](https://github.com/appium/appium-uiautomator2-driver)

### ADB 명령어 레퍼런스
- [ADB Shell Commands](https://adbshell.com/)
- [Android Debug Bridge Guide](https://developer.android.com/studio/command-line/adb)
- [ADB Input Commands](https://developer.android.com/reference/android/view/KeyEvent)

### Chrome DevTools Protocol
- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [Remote Debugging Android](https://developer.chrome.com/docs/devtools/remote-debugging/)

### 봇 탐지 회피 전략 (모바일)
- 터치 이벤트 시뮬레이션 (탭, 스와이프)
- 실제 사용자처럼 불규칙한 스크롤
- 체류 시간 정규분포 랜덤화
- 기기 fingerprinting 최소화
- IP 로테이션 (비행기모드 활용)

---

## ⚠️ 주의사항

1. **테스트 속도 제한**: 네이버 서버에 과부하를 주지 않도록 적절한 간격 유지
2. **IP 밴 리스크**: 비행기모드 토글로 IP 변경하지만, 기기 fingerprinting 주의
3. **법적 책임**: 본 프로젝트는 학습/연구 목적이며, 상업적 남용 금지
4. **데이터 보안**: 테스트 결과 데이터의 외부 유출 방지

---

## 🎛️ Claude Code 커스텀 설정

### Slash Commands (커스텀 명령어)

프로젝트에 특화된 slash commands를 `.claude/commands/` 디렉토리에 생성하여 반복 작업을 자동화합니다.

#### 사용 가능한 커스텀 명령어

1. **`/check-rank [product-id] [keyword]`** - 상품 순위 체크
2. **`/test-product [product-id] [iterations] [test-type]`** - 트래픽 테스트 실행
3. **`/setup-adb`** - ADB 환경 검증
4. **`/analyze-results [start-date] [end-date]`** - 결과 분석
5. **`/generate-report [type] [format]`** - 보고서 생성

---

### Agent Skills (자동 발동 전문 기능)

Skills는 Claude가 자동으로 필요 시 발동하는 전문 기능입니다.

#### 사용 가능한 Skills

1. **`mobile-automation`** - ADB/Appium 모바일 자동화 전문가
2. **`ranking-analysis`** - 순위 분석 및 통계 전문가
3. **`test-orchestration`** - 테스트 워크플로우 관리 전문가

---

### 디렉토리 구조

```
Navertrafic/
├── .claude/
│   ├── commands/                    # Slash Commands
│   │   ├── check-rank.md
│   │   ├── test-product.md
│   │   ├── setup-adb.md
│   │   ├── analyze-results.md
│   │   └── generate-report.md
│   │
│   └── skills/                      # Agent Skills
│       ├── mobile-automation/
│       │   ├── SKILL.md
│       │   └── adb-commands.md
│       │
│       ├── ranking-analysis/
│       │   ├── SKILL.md
│       │   └── metrics-guide.md
│       │
│       └── test-orchestration/
│           ├── SKILL.md
│           └── error-recovery.md
```

---

### 설치 방법

**1단계**: 커스텀 명령어 생성
```bash
mkdir -p .claude/commands
mkdir -p .claude/skills
```

**2단계**: 공식 문서에서 명령어 템플릿 다운로드
- Slash Commands: https://docs.claude.com/en/docs/claude-code/slash-commands
- Skills: https://docs.claude.com/en/docs/claude-code/skills

**3단계**: 프로젝트에 맞게 커스터마이징

**4단계**: Claude Code 재시작 후 `/help` 명령으로 확인

---

### Skills vs Slash Commands 선택 가이드

| 특성 | Slash Commands | Agent Skills |
|------|----------------|--------------|
| **발동 방식** | 사용자가 명시적으로 `/명령어` 호출 | Claude가 자동 판단 발동 |
| **사용 시기** | 반복적인 단순 작업 | 복잡한 전문 지식 필요 작업 |
| **구조** | 단일 Markdown 파일 | 디렉토리 + 여러 파일 |
| **예시** | `/check-rank 12345678` | "순위 분석해줘" → 자동 발동 |

---

## 📞 문의 및 개선 제안

프로젝트 개선 아이디어나 버그 발견 시 이슈 등록 바랍니다.

**마지막 업데이트**: 2025-11-01
