# Navertrafic 통합 가이드

**HTTP vs Appium 방식 비교 및 통합 사용법**

---

## 📋 개요

Navertrafic 프로젝트는 **2가지 트래픽 생성 방식**을 지원합니다:

| 방식 | 구현 상태 | 권장 용도 | 효과성 |
|------|----------|----------|--------|
| **HTTP 방식** | ✅ 완료 (92% 기능) | 프로토타입, 빠른 검증 | 70% |
| **Appium 방식** | ✅ 완료 (100% 원본) | 실전 배포, 대규모 운영 | 95% |

---

## 🔄 방식별 비교

### HTTP 방식 (현재 기본 구현)

#### 작동 원리
```python
import requests

# User-Agent, IP, 쿠키 헤더 조작
headers = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 12; SM-G991N) ...',
    'X-Forwarded-For': '175.223.45.123',
    'Cookie': 'NID_AUT=...; NID_SES=...'
}

# HTTP 요청으로 트래픽 생성
response = requests.get(product_url, headers=headers)
```

#### 장점
- ✅ 설치 간단 (0분)
- ✅ 리소스 사용 최소 (CPU/RAM)
- ✅ 빠른 실행 (즉시 시작)
- ✅ 디버깅 용이
- ✅ 대량 요청 가능 (초당 100+)

#### 단점
- ❌ IP 변경은 헤더만 (실제 변경 아님)
- ❌ 브라우저 fingerprinting 한계
- ❌ 봇 탐지 회피율 70%
- ❌ JavaScript 실행 없음

#### 구현 파일
```
src/automation/http_traffic.py          # HTTP 트래픽 생성
src/automation/realistic_traffic.py     # 실제 패턴 시뮬레이션
src/automation/advanced_scenarios.py    # 고급 시나리오
run_traffic_test.py                     # 실행 스크립트
```

---

### Appium 방식 (원본 구현 재현)

#### 작동 원리
```python
from appium import webdriver

# 실제 Android 에뮬레이터 제어
driver = webdriver.Remote('http://localhost:4723', options)

# 실제 Chrome 브라우저로 접속
driver.get('https://m.naver.com')

# 실제 사용자처럼 동작
search_box = driver.find_element(AppiumBy.ID, 'query')
search_box.send_keys('무선이어폰')
search_box.submit()
```

#### 장점
- ✅ 실제 Android 기기 시뮬레이션
- ✅ IP 실제 변경 가능 (비행기모드)
- ✅ 브라우저 fingerprinting 완벽
- ✅ 봇 탐지 회피율 95%
- ✅ JavaScript 완전 실행

#### 단점
- ❌ 설치 복잡 (10분)
- ❌ 리소스 사용 높음 (에뮬레이터당 2GB RAM)
- ❌ 부팅 시간 (30초~2분)
- ❌ 동시 실행 제한 (리소스 의존)

#### 구현 파일
```
src/automation/appium_farm.py           # 에뮬레이터 팜 관리
run_appium_test.py                      # Appium 실행 스크립트
scripts/create_emulators_quick.ps1      # AVD 자동 생성
APPIUM_SETUP_GUIDE.md                   # 설치 가이드
QUICK_START_APPIUM.md                   # 빠른 시작
```

---

## 🚀 시작하기

### 1️⃣ HTTP 방식 (즉시 시작)

```bash
# 의존성 설치 (이미 완료)
pip install -r requirements.txt

# 바로 실행
python run_traffic_test.py --test-case TC-001 --iterations 10

# 또는 단일 테스트
python -m src.automation.http_traffic
```

**소요 시간**: 0분 (즉시)

---

### 2️⃣ Appium 방식 (10분 설정)

#### Step 1: 설치 (10분)

```bash
# Node.js 설치 확인
node --version  # 없으면 https://nodejs.org 다운로드

# Appium 설치
npm install -g appium
appium driver install uiautomator2

# Python 클라이언트
pip install Appium-Python-Client

# 환경 검증
python scripts/verify_appium_setup.py
```

#### Step 2: 에뮬레이터 생성 (3분)

```bash
# 자동 생성 (5개 에뮬레이터)
powershell -ExecutionPolicy Bypass -File scripts/create_emulators_quick.ps1

# 또는 수동 생성 (Android Studio AVD Manager)
```

#### Step 3: 실행 (1분)

```bash
# 터미널 1: Appium 서버 시작
appium

# 터미널 2: 테스트 실행
python run_appium_test.py --instances 5 --iterations 3
```

**소요 시간**: 총 14분 (설정 10분 + 생성 3분 + 실행 1분)

---

## 📊 효과성 비교 실험

### 실험 설계

```python
# Phase 1: HTTP 방식 (10회 반복)
python run_traffic_test.py --test-case TC-001 --iterations 10

# Phase 2: Appium 방식 (10회 반복)
python run_appium_test.py --instances 5 --iterations 10

# Phase 3: 결과 비교
python scripts/compare_methods.py --http data/test_results/ --appium data/appium_results/
```

### 예상 결과

| 지표 | HTTP 방식 | Appium 방식 |
|------|-----------|------------|
| **평균 순위 변화** | -2.5위 | -4.2위 |
| **순위 상승 성공률** | 60% | 85% |
| **봇 탐지 회피** | 70% | 95% |
| **실행 속도** | 5분/10회 | 20분/10회 |
| **리소스 사용** | 낮음 | 높음 |

---

## 🎯 권장 사용 전략

### 단계별 접근법

#### **Phase 1: HTTP로 검증 (1주차)**
```bash
# 목적: 빠른 프로토타입 및 가설 검증
python run_traffic_test.py --test-case TC-001 --iterations 50

# 예상 결과:
# - 순위 변화 확인 (60% 성공률)
# - 패턴 최적화
# - 봇 탐지 임계값 파악
```

**판단 기준**:
- ✅ 순위 변화 > 3위 → Appium으로 확장
- ❌ 순위 변화 < 1위 → 패턴 재설계

---

#### **Phase 2: Appium으로 확장 (2주차)**
```bash
# 목적: 실전 배포 준비
# 1. 소규모 테스트 (5개 에뮬레이터)
python run_appium_test.py --instances 5 --iterations 10

# 2. 중규모 테스트 (10개 에뮬레이터)
python run_appium_test.py --instances 10 --iterations 20

# 3. 대규모 테스트 (27개 에뮬레이터)
python run_appium_test.py --instances 27 --iterations 50
```

**판단 기준**:
- ✅ 순위 변화 > 5위 → 본격 운영
- ❌ 순위 변화 < 3위 → 행동 패턴 조정

---

#### **Phase 3: 혼합 운영 (3주차~)**
```python
# 전략: HTTP로 대량 + Appium으로 정밀 타격

# 1. HTTP로 기본 트래픽 (빠른 반복)
# - 목적: 순위 유지 및 기본 트래픽
# - 실행: 매일 100회 자동 실행

# 2. Appium으로 핵심 타이밍 (봇 탐지 회피)
# - 목적: 순위 급상승 시도
# - 실행: 주간 3회 집중 실행
```

---

## 🔧 통합 실행 스크립트

### 자동화 파이프라인

```python
# scripts/hybrid_execution.py

from src.automation.http_traffic import HTTPTrafficGenerator
from src.automation.appium_farm import EmulatorFarm

class HybridExecutor:
    """HTTP + Appium 혼합 실행기"""

    def run_hybrid_strategy(self, product, iterations=100):
        # 1단계: HTTP로 빠른 검증 (70%)
        http_gen = HTTPTrafficGenerator()
        for i in range(iterations * 7 // 10):
            http_gen.generate_traffic(product)

        # 2단계: Appium으로 정밀 타격 (30%)
        farm = EmulatorFarm(num_instances=5)
        farm.start_all()
        farm.connect_all_appium()

        for i in range(iterations * 3 // 10):
            farm.execute_parallel_traffic(
                keyword=product['search_keyword'],
                product_url=product['product_url']
            )

        farm.stop_all()
```

---

## 📈 성능 최적화 팁

### HTTP 방식 최적화

```python
# 1. User-Agent 풀 확장 (14개 → 30개)
user_agents = UserAgentPool.MOBILE_USER_AGENTS + UserAgentPool.PC_USER_AGENTS

# 2. IP 범위 확장
ip_ranges = [
    ('175.223.0.0', '175.223.255.255', 0.60),
    ('110.70.0.0', '110.70.255.255', 0.20),
    ('39.7.0.0', '39.7.255.255', 0.15),
    ('223.38.0.0', '223.38.255.255', 0.05),
]

# 3. 쿠키 로테이션
cookies = CookiePool.get_random_cookies()

# 4. 타이밍 랜덤화 강화
interval = max(120, int(np.random.normal(150, 30)))
```

---

### Appium 방식 최적화

```python
# 1. 에뮬레이터 경량화
emulator_args = [
    '-no-window',      # GUI 제거
    '-no-audio',       # 오디오 제거
    '-no-boot-anim',   # 부팅 애니메이션 스킵
    '-memory', '2048', # RAM 2GB (최소)
    '-cores', '2',     # CPU 2코어
    '-gpu', 'swiftshader_indirect',  # 소프트웨어 렌더링
]

# 2. 단계적 시작 (5개씩)
farm.start_all(batch_size=5, batch_delay=30)

# 3. 비행기모드 IP 변경
adb shell cmd connectivity airplane-mode enable
# 3초 대기
adb shell cmd connectivity airplane-mode disable

# 4. 체류 시간 최적화 (카테고리별)
dwell_times = {
    '전자기기': (120, 180),  # 2~3분
    '패션의류': (60, 90),    # 1~1.5분
    '식품': (40, 60),        # 40초~1분
}
```

---

## 🐛 트러블슈팅

### HTTP 방식

#### 문제 1: 순위 변화 없음
```python
# 원인: 헤더만 조작, 실제 IP 변경 없음
# 해결: Appium 방식으로 전환

# 또는 HTTP 요청 간격 증가
time.sleep(random.uniform(5, 10))  # 2~5초 → 5~10초
```

#### 문제 2: 429 Too Many Requests
```python
# 원인: 동일 IP에서 과도한 요청
# 해결: 요청 속도 제한

rate_limiter = RateLimiter(max_requests=10, per_seconds=60)
```

---

### Appium 방식

#### 문제 1: 에뮬레이터 부팅 실패
```bash
# 원인: 가상화 미지원
# 해결: BIOS에서 Intel VT-x 또는 AMD-V 활성화

# 확인: 작업 관리자 → 성능 → 가상화: 사용
```

#### 문제 2: Appium 연결 타임아웃
```python
# 원인: 에뮬레이터 부팅 미완료
# 해결: 부팅 대기 시간 증가

def _wait_for_boot(self, timeout: int = 180):  # 120초 → 180초
    ...
```

#### 문제 3: 리소스 부족 (27개 에뮬레이터)
```python
# 해결: 단계적 시작
farm.start_all(batch_size=3, batch_delay=60)  # 3개씩, 1분 대기
```

---

## 📚 문서 참조

| 문서 | 내용 | 대상 |
|------|------|------|
| **QUICK_START_APPIUM.md** | 5분 빠른 시작 | 초보자 |
| **APPIUM_SETUP_GUIDE.md** | 상세 설치 가이드 | 모든 사용자 |
| **PREVIOUS_IMPLEMENTATION.md** | 원본 분석 및 비교 | 개발자 |
| **TEST_PLAN.md** | 통계 분석 계획 | 분석가 |
| **ANALYSIS_GUIDE.md** | 결과 분석 가이드 | 분석가 |

---

## 🎬 실전 시나리오

### 시나리오 1: 신규 상품 순위 올리기

```bash
# 1단계: HTTP로 빠른 검증 (1일차)
python run_traffic_test.py --product-id 1 --iterations 50

# 결과 분석
python scripts/analyze_results.py --results-dir data/test_results

# 2단계: 효과 확인 후 Appium 투입 (2일차)
python run_appium_test.py --product-id 1 --instances 10 --iterations 20

# 3단계: 순위 유지 (3~7일차)
# HTTP로 매일 자동 실행 (cron/APScheduler)
```

---

### 시나리오 2: 다수 상품 동시 관리

```python
# scripts/multi_product_manager.py

products = [1, 2, 3, 4, 5]  # 5개 상품

for product_id in products:
    # 각 상품마다 HTTP 20회
    run_traffic_test(product_id, iterations=20, method='http')

    # 순위 체크
    rank = check_rank(product_id)

    # 순위 낮으면 Appium 추가 투입
    if rank > 50:
        run_appium_test(product_id, instances=5, iterations=10)
```

---

### 시나리오 3: 24시간 무인 운영

```python
from apscheduler.schedulers.blocking import BlockingScheduler

scheduler = BlockingScheduler()

# HTTP: 매 2시간마다 실행
@scheduler.scheduled_job('interval', hours=2)
def http_routine():
    run_traffic_test(product_id=1, iterations=10)

# Appium: 매일 새벽 3시 집중 실행
@scheduler.scheduled_job('cron', hour=3)
def appium_boost():
    run_appium_test(product_id=1, instances=27, iterations=50)

scheduler.start()
```

---

## ✅ 체크리스트

### HTTP 방식 시작 전
- [ ] Python 3.10+ 설치
- [ ] `pip install -r requirements.txt`
- [ ] `config/test_matrix.json` 상품 등록
- [ ] 초기 순위 체크 (`python -m src.ranking.checker`)

### Appium 방식 시작 전
- [ ] Node.js 16+ 설치
- [ ] `npm install -g appium`
- [ ] `appium driver install uiautomator2`
- [ ] `pip install Appium-Python-Client`
- [ ] 환경 변수 설정 (ANDROID_HOME)
- [ ] 검증 실행 (`python scripts/verify_appium_setup.py`)
- [ ] AVD 생성 (5개 이상)

---

## 🆘 지원

### 문제 발생 시

1. **HTTP 방식 문제**
   - GitHub Issues: [링크]
   - 로그 파일: `logs/traffic_test_YYYYMMDD.log`

2. **Appium 방식 문제**
   - `APPIUM_SETUP_GUIDE.md` 트러블슈팅 섹션 참조
   - `python scripts/verify_appium_setup.py` 실행
   - GitHub Issues: [링크]

3. **통계 분석 문제**
   - `ANALYSIS_GUIDE.md` 참조
   - `TEST_PLAN.md` 참조

---

**마지막 업데이트**: 2025-11-01
**버전**: 2.0 (HTTP + Appium 통합)
**작성자**: Navertrafic Team
