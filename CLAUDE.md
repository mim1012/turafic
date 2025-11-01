# Turafic - 네이버 쇼핑 트래픽 최적화 분산 봇 네트워크

## 📋 프로젝트 개요

### 목적
C&C 서버 기반 분산 봇 네트워크를 통해 네이버 쇼핑 상품의 트래픽 생성 및 순위 변동을 자동화하고, **과학적 실험 설계(L18 직교배열)**를 통해 어떤 사용자 행동 패턴이 상품 순위에 영향을 미치는지 분석합니다.

### 핵심 기능
- **C&C 서버**: 수천 대의 Android 봇을 중앙에서 제어
- **분산 봇 네트워크**: 독립적으로 동작하는 Android APK 에이전트
- **작업 할당 엔진**: "1봇 = 1캠페인 전담" 모델로 순수한 테스트 결과 보장
- **L18 테스트 매트릭스**: 7차원 변수를 18개 테스트 케이스로 압축
- **안티 탐지 시스템**: Identity Profiles, IP 로테이션, 브라우저 지문 다양화
- **실시간 모니터링**: 관리자 대시보드를 통한 봇 상태 및 캠페인 진행률 추적

### 기술 스택
```
서버:
- 언어: Python 3.10+
- 프레임워크: FastAPI
- 데이터베이스: PostgreSQL
- 캐시: Redis
- 배포: Oracle Cloud (무료 티어)

Android 봇:
- 언어: Java/Kotlin
- 제어 방식: Root (su + input tap/text) + Appium
- 백그라운드 서비스: 24/7 실행
- 네트워크: HTTP API (Retrofit)

데이터 분석:
- Python: Pandas, Matplotlib, SciPy (ANOVA)
- 실시간 시각화: Chart.js
```

### 시스템 아키텍처
```
┌─────────────────────────────────────────────────────────────┐
│                    관리자 대시보드 (Web UI)                    │
│                  실시간 모니터링 및 제어                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    C&C 서버 (FastAPI)                        │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐  │
│  │ Bot Mgmt    │ Task Assign │ Admin API   │ AI Vision   │  │
│  │ API         │ API         │             │ (자가 치유)  │  │
│  └─────────────┴─────────────┴─────────────┴─────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐│
│  │         작업 할당 엔진 (Task Engine)                      ││
│  │  - "1봇 = 1캠페인 전담" 모델                             ││
│  │  - JSON 작업 패턴 생성                                   ││
│  │  - 무작위성 추가 (탐지 회피)                              ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
         │                                          │
         │ PostgreSQL                               │ Redis
         ▼                                          ▼
┌─────────────────┐                        ┌─────────────────┐
│  Bot DB         │                        │ UI 좌표 맵       │
│  Task DB        │                        │ (캐시)          │
│  Campaign DB    │                        └─────────────────┘
└─────────────────┘
         │
         │ HTTP API (봇 등록, 작업 요청, 결과 보고)
         ▼
┌─────────────────────────────────────────────────────────────┐
│                       봇 네트워크 (N대)                        │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐       ┌─────────┐  │
│  │ 봇 #1   │  │ 봇 #2   │  │ 봇 #3   │  ...  │ 봇 #N   │  │
│  │ (APK)   │  │ (APK)   │  │ (APK)   │       │ (APK)   │  │
│  │ TC#1    │  │ TC#2    │  │ TC#3    │       │ TC#N    │  │
│  └─────────┘  └─────────┘  └─────────┘       └─────────┘  │
└─────────────────────────────────────────────────────────────┘
         │
         │ Root 기반 UI 제어 (su + input tap/text)
         │ 비행기 모드 IP 변경 (1 트래픽당 1회)
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    네이버 쇼핑                                │
│              (트래픽 생성 대상 서비스)                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 테스트 시나리오

### 1. L18 직교배열 테스트 매트릭스

**7차원 변수**를 **18개 테스트 케이스**로 압축하여 효율적인 실험 설계를 구현합니다.

#### 변수 정의

| 변수 | 수준 | 설명 |
|------|------|------|
| **플랫폼** | PC / Mobile | 접속 기기 유형 |
| **참여도** | High / Medium / Low | 체류 시간, 클릭 횟수 |
| **트래픽량** | 100 / 200 / 500 | 반복 실행 횟수 |
| **지문 다양성** | Diverse / Fixed | User-Agent, 쿠키 변경 여부 |
| **IP 전략** | Per Traffic / Per Session | IP 변경 빈도 |
| **진입 경로** | Naver Search / Shopping Direct | 검색 경로 |
| **카테고리** | Electronics / Fashion / Beauty | 상품 카테고리 |

#### L18 테스트 케이스 예시

```python
test_matrix = [
    {
        "tc": "TC#1",
        "platform": "mobile",
        "engagement": "high",
        "traffic_volume": 100,
        "fingerprint": "diverse",
        "ip_strategy": "per_traffic",
        "entry_path": "naver_search",
        "category": "electronics"
    },
    {
        "tc": "TC#2",
        "platform": "mobile",
        "engagement": "medium",
        "traffic_volume": 200,
        "fingerprint": "diverse",
        "ip_strategy": "per_session",
        "entry_path": "shopping_direct",
        "category": "fashion"
    },
    # ... TC#3 ~ TC#18
]
```

### 2. 캠페인 정의

하나의 **캠페인(Campaign)**은 다음을 의미합니다:

- **1개 상품** (target_keyword)
- **1개 테스트 케이스** (L18 매트릭스의 특정 행)
- **정확히 100회 실행** (traffic_volume)
- **1개 봇 전담** (assigned_bot_id)

```python
campaign = {
    "campaign_id": "uuid-1234",
    "name": "삼성 갤럭시 - TC#1",
    "target_keyword": "삼성 갤럭시 S24",
    "target_traffic": 100,
    "test_case": "TC#1",
    "execution_mode": "appium",  # or "http"
    "identity_profile_group": "samsung_mobile_default",
    "status": "active",
    "assigned_bot_id": "bot-5678"
}
```

### 3. 작업 할당 모델: "1봇 = 1캠페인 전담"

각 봇은 **하나의 캠페인(테스트 케이스)**에만 전담 할당되어, 해당 테스트 케이스를 100회 반복 실행합니다.

**예시**:
- Bot-1 → TC#1 (100회 전담)
- Bot-2 → TC#2 (100회 전담)
- Bot-3 → TC#3 (100회 전담)
- ...
- Bot-18 → TC#18 (100회 전담)

**장점**:
- 테스트 케이스별 순수한 결과 측정 가능
- 봇 간 경쟁 조건 없음
- 병렬 실행으로 전체 테스트 시간 단축

---

## 🔄 작업 프로세스

### 1. 봇 등록 프로세스

```
1. Android APK 설치 및 실행
2. 기기 정보 수집 (android_id, 모델명, 해상도 등)
3. C&C 서버에 등록 요청 (POST /api/v1/bots/register)
4. 서버에서 bot_id 및 그룹 할당
5. 봇이 bot_id 저장 및 백그라운드 서비스 시작
```

**API 요청 예시**:
```python
POST /api/v1/bots/register
{
    "android_id": "abc123def456",
    "device_model": "SM-G998N",
    "android_version": "13",
    "screen_resolution": "1440x3200"
}

# 응답
{
    "bot_id": "uuid-bot-1234",
    "group": 1,
    "status": "active"
}
```

### 2. 작업 할당 프로세스

```
1. 봇이 작업 요청 (GET /api/v1/tasks/get_task?bot_id=xxx)
2. 서버가 봇에게 캠페인 할당 (첫 요청 시)
   - 미할당 캠페인 중 하나를 선택
   - campaign.assigned_bot_id = bot_id 설정
3. 서버가 JSON 작업 패턴 생성 및 반환
4. 봇이 JSON 패턴 실행
5. 봇이 결과 보고 (POST /api/v1/tasks/report_result)
6. 반복 (100회 완료 시까지)
```

**작업 패턴 예시 (Appium 모드)**:
```json
{
    "task_id": "task-uuid-5678",
    "pattern": [
        {
            "action": "open_url",
            "url": "https://m.naver.com",
            "wait": 2000
        },
        {
            "action": "tap",
            "element_id": "search_box",
            "coordinates": {"x": 540, "y": 200}
        },
        {
            "action": "input_text",
            "text": "삼성 갤럭시 S24"
        },
        {
            "action": "tap",
            "element_id": "search_button"
        },
        {
            "action": "scroll",
            "direction": "down",
            "distance": 500,
            "duration": 300
        },
        {
            "action": "tap",
            "element_id": "product_item",
            "index": 3
        },
        {
            "action": "wait",
            "duration": 45000,
            "description": "상품 페이지 체류"
        },
        {
            "action": "airplane_mode_toggle",
            "description": "IP 변경"
        }
    ]
}
```

### 3. 페이지 이동 경로

#### **경로 A: 네이버 통합검색**
```
1. 네이버 메인 (m.naver.com) 접속
2. 검색창에 키워드 입력
3. 쇼핑탭 클릭
4. 스크롤하여 상품 찾기
5. 상품 상세 페이지 진입
6. 자연스러운 행동 (스크롤, 클릭)
7. 체류 (30~60초)
```

#### **경로 B: 네이버쇼핑 직접 검색**
```
1. 네이버쇼핑 (m.shopping.naver.com) 접속
2. 검색창에 키워드 입력
3. 스크롤하여 상품 찾기
4. 상품 상세 페이지 진입
5. 자연스러운 행동 (스크롤, 클릭)
6. 체류 (30~60초)
```

### 4. 상품 페이지 액션

#### 스크롤 동작
```python
scroll_actions = [
    "scroll_to_options",      # 옵션 영역까지 스크롤 (100%)
    "scroll_to_reviews",      # 리뷰 영역까지 스크롤 (70%)
    "scroll_to_qna",          # Q&A 영역까지 스크롤 (40%)
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

#### 체류 시간 (참여도별)
```python
import numpy as np

# High: 평균 60초, 표준편차 15초
stay_high = max(45, min(90, int(np.random.normal(60, 15))))

# Medium: 평균 45초, 표준편차 10초
stay_medium = max(30, min(60, int(np.random.normal(45, 10))))

# Low: 평균 30초, 표준편차 8초
stay_low = max(20, min(40, int(np.random.normal(30, 8))))
```

---

## 📱 Android 봇 에이전트 아키텍처

### 1. 백그라운드 서비스 구조

```java
public class BotService extends Service {
    private String botId;
    private ApiClient apiClient;
    private TaskExecutor taskExecutor;
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // 24/7 백그라운드 실행
        startForeground(NOTIFICATION_ID, createNotification());
        
        // 작업 루프 시작
        new Thread(() -> {
            while (true) {
                try {
                    // 1. 서버에서 작업 요청
                    TaskResponse task = apiClient.getTask(botId);
                    
                    if ("wait".equals(task.getTaskId())) {
                        // 대기 명령
                        Thread.sleep(task.getWaitDuration());
                        continue;
                    }
                    
                    // 2. JSON 패턴 실행
                    boolean success = taskExecutor.execute(task.getPattern());
                    
                    // 3. 결과 보고
                    apiClient.reportResult(botId, task.getTaskId(), 
                        success ? "success" : "failed");
                    
                    // 4. 다음 작업 전 대기 (3~5분)
                    Thread.sleep(randomInt(180000, 300000));
                    
                } catch (Exception e) {
                    Log.e(TAG, "Task execution error", e);
                    Thread.sleep(60000); // 1분 대기 후 재시도
                }
            }
        }).start();
        
        return START_STICKY;
    }
}
```

### 2. JSON 작업 패턴 실행 엔진

```java
public class TaskExecutor {
    private RootController rootController;
    
    public boolean execute(List<ActionStep> pattern) {
        for (ActionStep step : pattern) {
            try {
                switch (step.getAction()) {
                    case "open_url":
                        openUrl(step.getUrl());
                        break;
                    case "tap":
                        rootController.tap(step.getX(), step.getY());
                        break;
                    case "input_text":
                        rootController.inputText(step.getText());
                        break;
                    case "scroll":
                        rootController.scroll(step.getDirection(), 
                            step.getDistance(), step.getDuration());
                        break;
                    case "wait":
                        Thread.sleep(step.getDuration());
                        break;
                    case "airplane_mode_toggle":
                        toggleAirplaneMode();
                        break;
                }
                
                // 액션 간 랜덤 대기
                Thread.sleep(randomInt(500, 1500));
                
            } catch (Exception e) {
                Log.e(TAG, "Action failed: " + step.getAction(), e);
                return false;
            }
        }
        return true;
    }
}
```

### 3. Root 기반 UI 제어

```java
public class RootController {
    /**
     * Root 권한으로 화면 탭
     */
    public void tap(int x, int y) {
        executeRootCommand("input tap " + x + " " + y);
    }
    
    /**
     * Root 권한으로 텍스트 입력
     */
    public void inputText(String text) {
        // 한글 입력을 위해 URL 인코딩
        String encoded = URLEncoder.encode(text, "UTF-8");
        executeRootCommand("input text " + encoded);
    }
    
    /**
     * Root 권한으로 스크롤 (swipe)
     */
    public void scroll(String direction, int distance, int duration) {
        int startX = 540, startY = 1500;
        int endX = startX, endY = startY - distance;
        
        executeRootCommand(String.format(
            "input swipe %d %d %d %d %d",
            startX, startY, endX, endY, duration
        ));
    }
    
    /**
     * Root 명령어 실행
     */
    private void executeRootCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(command + "\n");
            os.writeBytes("exit\n");
            os.flush();
            process.waitFor();
        } catch (Exception e) {
            Log.e(TAG, "Root command failed: " + command, e);
        }
    }
}
```

### 4. 비행기 모드 IP 변경

```java
public void toggleAirplaneMode() throws InterruptedException {
    // 1. 비행기 모드 ON
    executeRootCommand("cmd connectivity airplane-mode enable");
    Thread.sleep(3000);
    
    // 2. 비행기 모드 OFF
    executeRootCommand("cmd connectivity airplane-mode disable");
    
    // 3. 네트워크 재연결 대기 (최대 10초)
    for (int i = 0; i < 10; i++) {
        if (isNetworkConnected()) {
            Log.i(TAG, "Network reconnected");
            return;
        }
        Thread.sleep(1000);
    }
    
    throw new NetworkException("Network reconnection timeout");
}
```

### 5. UI 좌표 맵 캐싱

```java
public class CoordinateCache {
    private Map<String, Coordinate> coordinateMap;
    
    /**
     * 서버에서 해상도별 UI 좌표 맵 다운로드
     */
    public void loadFromServer(String resolution) {
        Response<CoordinateMap> response = apiClient.getCoordinates(resolution);
        this.coordinateMap = response.getData().getCoordinates();
    }
    
    /**
     * 좌표 조회
     */
    public Coordinate get(String elementId) {
        return coordinateMap.get(elementId);
    }
}
```

---

## 📊 평가 지표 및 데이터 수집

### 1. 순위 계산 방식

```python
# 네이버 쇼핑 검색 결과: 1페이지당 20개 상품
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
    """
    return (page - 1) * 20 + position

# 순위 변동 계산
def calculate_rank_change(before_rank: int, after_rank: int) -> int:
    """
    순위 변동 계산 (음수 = 상승, 양수 = 하락)
    
    Examples:
        >>> calculate_rank_change(52, 28)  # 52위 → 28위
        -24  # 24위 상승
    """
    return after_rank - before_rank
```

### 2. 데이터베이스 구조

#### Bots 테이블
```sql
CREATE TABLE bots (
    bot_id VARCHAR(36) PRIMARY KEY,
    android_id VARCHAR(64) UNIQUE NOT NULL,
    device_model VARCHAR(50) NOT NULL,
    android_version VARCHAR(20) NOT NULL,
    screen_resolution VARCHAR(20) NOT NULL,
    "group" INTEGER,
    assigned_campaign_id VARCHAR(36),
    status VARCHAR(20) DEFAULT 'active',
    registered_at TIMESTAMP DEFAULT NOW(),
    last_task_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    success_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0,
    total_traffic_generated INTEGER DEFAULT 0
);
```

#### Campaigns 테이블
```sql
CREATE TABLE campaigns (
    campaign_id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    target_keyword VARCHAR(100) NOT NULL,
    target_traffic INTEGER NOT NULL,
    test_case VARCHAR(20) NOT NULL,
    execution_mode VARCHAR(20) DEFAULT 'appium',
    identity_profile_group VARCHAR(50),
    assigned_bot_id VARCHAR(36),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    current_traffic_count INTEGER DEFAULT 0,
    success_tasks INTEGER DEFAULT 0,
    fail_tasks INTEGER DEFAULT 0
);
```

#### Tasks 테이블
```sql
CREATE TABLE tasks (
    task_id VARCHAR(36) PRIMARY KEY,
    bot_id VARCHAR(36) NOT NULL,
    campaign_id VARCHAR(36),
    "group" INTEGER NOT NULL,
    pattern JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'assigned',
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    log TEXT,
    error_message TEXT
);
```

### 3. 효과성 측정 기준

1. **순위 변동폭**: 평균 몇 위 상승/하락
2. **페이지 이동**: 페이지 간 이동 발생 여부
3. **안정성**: 순위 변동의 일관성
4. **테스트 케이스 비교**: ANOVA 분석을 통한 최적 조합 도출

### 4. ANOVA 분석

```python
from scipy import stats

# 7차원 변수별 순위 변동 데이터
data_by_platform = {
    'mobile': [rank_changes...],
    'pc': [rank_changes...]
}

# F-검정
f_stat, p_value = stats.f_oneway(
    data_by_platform['mobile'],
    data_by_platform['pc']
)

if p_value < 0.05:
    print("플랫폼 변수가 순위 변동에 유의미한 영향을 미침")
```

---

## 🛡️ 안티 탐지 시스템

### 1. Identity Profiles

15개의 Samsung 기기 프로필을 사전 정의하여 다양한 브라우저 지문을 생성합니다.

```python
identity_profiles = [
    {
        "profile_id": "samsung_s24_ultra_1",
        "user_agent": "Mozilla/5.0 (Linux; Android 14; SM-S928N) AppleWebKit/537.36...",
        "device_model": "SM-S928N",
        "screen_resolution": "1440x3088",
        "cookies": {...},
        "headers": {
            "Accept-Language": "ko-KR,ko;q=0.9",
            "Accept-Encoding": "gzip, deflate, br"
        },
        "fingerprint": {
            "canvas": "hash_value_1",
            "webgl": "hash_value_2",
            "fonts": ["NanumGothic", "Roboto", ...]
        }
    },
    # ... 14개 더
]
```

### 2. IP 로테이션 전략

- **Per Traffic**: 1회 트래픽당 1회 IP 변경 (비행기 모드 토글)
- **Per Session**: 1회 세션당 1회 IP 변경 (여러 트래픽 공유)

### 3. 행동 패턴 무작위화

```python
# 좌표 무작위화 (±10px)
def randomize_coordinate(x, y):
    return (
        x + random.randint(-10, 10),
        y + random.randint(-10, 10)
    )

# 체류 시간 무작위화 (정규분포)
def randomize_stay_duration(mean, std):
    return max(mean - 2*std, min(mean + 2*std, 
        int(np.random.normal(mean, std))))

# 스크롤 속도 무작위화
def randomize_scroll_speed():
    return random.randint(100, 300)  # ms
```

---

## 💻 프로젝트 구조

```
turafic/
├── CLAUDE.md                      # 이 파일
├── README.md                      # 프로젝트 설명
├── ARCHITECTURE.md                # 시스템 아키텍처
├── TASK_ALLOCATION_MODEL.md       # 작업 할당 모델 상세
├── requirements.txt               # Python 의존성
│
├── server/                        # C&C 서버
│   ├── main.py                    # FastAPI 앱 진입점
│   ├── api/
│   │   ├── bot_management.py      # 봇 관리 API
│   │   ├── task_assignment.py     # 작업 할당 API
│   │   └── admin.py               # 관리자 대시보드 API
│   ├── core/
│   │   ├── database.py            # DB 연결 및 모델
│   │   ├── cache.py               # Redis 캐시
│   │   ├── task_engine.py         # 작업 할당 로직
│   │   ├── identity_profiles.py   # Identity Profiles
│   │   ├── http_pattern_generator.py  # HTTP 모드 패턴
│   │   └── appium_pattern_generator.py  # Appium 모드 패턴
│   ├── migrations/                # DB 마이그레이션
│   │   └── add_bot_campaign_assignment.sql
│   └── config/
│       └── server_settings.py     # 서버 설정
│
├── android_agent/                 # Android 봇 에이전트
│   ├── app/
│   │   ├── src/main/java/com/turafic/
│   │   │   ├── service/
│   │   │   │   └── BotService.java        # 백그라운드 서비스
│   │   │   ├── executor/
│   │   │   │   ├── TaskExecutor.java      # JSON 패턴 실행
│   │   │   │   └── RootController.java    # Root 제어
│   │   │   ├── network/
│   │   │   │   └── ApiClient.java         # HTTP 클라이언트
│   │   │   └── models/
│   │   │       ├── TaskResponse.java
│   │   │       └── ActionStep.java
│   │   └── AndroidManifest.xml
│   └── build.gradle
│
├── config/
│   ├── test_matrix.json           # L18 테스트 매트릭스
│   ├── identity_profiles.json     # Identity Profiles
│   └── ui_coordinates/            # 해상도별 UI 좌표 맵
│       ├── 1080x2340.json
│       └── 1440x3200.json
│
├── data/
│   ├── rankings/                  # 순위 데이터 (백업)
│   └── results/                   # 분석 결과
│
├── logs/                          # 로그 파일
│
└── tests/                         # 단위 테스트
    ├── test_task_engine.py
    └── test_identity_profiles.py
```

---

## 🚀 구현 우선순위

### Phase 1: C&C 서버 구축 (1주차)
- [x] FastAPI 서버 구현
- [x] PostgreSQL 데이터베이스 설계
- [x] 봇 관리 API 구현
- [x] 작업 할당 엔진 구현 ("1봇 = 1캠페인 전담")
- [x] Identity Profiles 시스템

### Phase 2: Android 봇 에이전트 개발 (2주차)
- [ ] 백그라운드 서비스 구현
- [ ] JSON 작업 패턴 실행 엔진
- [ ] Root 기반 UI 제어 (su + input)
- [ ] 비행기 모드 IP 변경 자동화
- [ ] HTTP API 클라이언트 (Retrofit)

### Phase 3: 테스트 매트릭스 설계 (3주차)
- [x] L18 직교배열 설계
- [x] 7차원 변수 정의
- [x] Identity Profiles 생성 (15개 Samsung 기기)
- [ ] UI 좌표 맵 생성 (해상도별)

### Phase 4: 분산 실행 및 데이터 수집 (4주차)
- [ ] 9개 봇 × 18개 테스트 케이스 실행
- [ ] 실시간 모니터링 대시보드
- [ ] ANOVA 분석 및 최적 조합 도출
- [ ] 보고서 자동 생성

---

## 🔧 필수 환경 설정

### 1. 서버 환경 (Oracle Cloud 무료 티어)

#### 인스턴스 생성
```bash
# Oracle Cloud 무료 티어
- Shape: VM.Standard.A1.Flex (ARM, 4 OCPU, 24GB RAM)
- OS: Ubuntu 22.04 LTS
- Storage: 200GB Block Volume
```

#### 서버 소프트웨어 설치
```bash
# Python 3.10+
sudo apt update
sudo apt install python3.10 python3-pip

# PostgreSQL
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Redis
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis

# Nginx (리버스 프록시)
sudo apt install nginx
```

#### Python 가상환경
```bash
cd /home/ubuntu/turafic/server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 데이터베이스 초기화
```bash
# PostgreSQL 사용자 및 데이터베이스 생성
sudo -u postgres psql
CREATE DATABASE turafic;
CREATE USER turafic_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE turafic TO turafic_user;
\q

# 마이그레이션 실행
psql -U turafic_user -d turafic -f server/migrations/add_bot_campaign_assignment.sql
```

#### 서버 실행
```bash
cd /home/ubuntu/turafic/server
source venv/bin/activate
python main.py

# 또는 Uvicorn으로 실행
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Android 기기 설정

#### Root 권한 획득
```
1. 기기 Bootloader 언락
2. Magisk 설치 (https://github.com/topjohnwu/Magisk)
3. Root 권한 확인: `su` 명령어 실행
```

#### 개발자 옵션 활성화
```
1. 설정 > 휴대전화 정보 > 빌드번호 7회 탭
2. 설정 > 개발자 옵션 > USB 디버깅 ON
3. 설정 > 개발자 옵션 > 화면 켜짐 상태 유지 ON
```

#### APK 빌드 및 설치
```bash
# Android Studio에서 빌드
cd /home/ubuntu/turafic/android_agent
./gradlew assembleRelease

# APK 설치
adb install app/build/outputs/apk/release/app-release.apk

# 또는 기기에서 직접 설치
```

### 3. 환경변수 설정

#### 서버 (.env)
```bash
# 데이터베이스
DATABASE_URL=postgresql+asyncpg://turafic_user:your_password@localhost/turafic

# Redis
REDIS_URL=redis://localhost:6379/0

# 서버 설정
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
LOG_LEVEL=INFO

# 보안
API_KEY=your_api_key_here
```

#### Android (config.properties)
```properties
# C&C 서버 URL
server_url=https://your-server-ip:8000

# API 키
api_key=your_api_key_here

# 로그 레벨
log_level=INFO
```

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

### 작업 할당 모델 준수
- **"1봇 = 1캠페인 전담"** 원칙 절대 준수
- 봇이 여러 캠페인을 섞어서 실행하지 않도록 주의
- 캠페인 완료 시 `assigned_bot_id` 해제 필수

### 데이터베이스 우선
- 모든 데이터는 PostgreSQL에 저장
- JSON/CSV는 백업 용도로만 사용
- 실시간 데이터는 Redis 캐시 활용

### API 우선
- 봇과 서버 간 통신은 REST API만 사용
- WebSocket은 실시간 모니터링에만 사용
- gRPC는 고성능 필요 시에만 고려

### 안티 탐지 필수
- Identity Profiles 필수 사용
- IP 로테이션 전략 준수
- 행동 패턴 무작위화 적용

---

## 📖 참고 자료

### C&C 서버
- [FastAPI 공식 문서](https://fastapi.tiangolo.com/)
- [PostgreSQL 공식 문서](https://www.postgresql.org/docs/)
- [Redis 공식 문서](https://redis.io/documentation)

### Android 개발
- [Android Background Services](https://developer.android.com/guide/components/services)
- [Retrofit HTTP Client](https://square.github.io/retrofit/)
- [Magisk Root](https://github.com/topjohnwu/Magisk)

### 실험 설계
- [직교배열 (Orthogonal Array)](https://en.wikipedia.org/wiki/Orthogonal_array)
- [ANOVA 분석](https://en.wikipedia.org/wiki/Analysis_of_variance)

### 봇 탐지 회피
- 터치 이벤트 시뮬레이션
- 실제 사용자처럼 불규칙한 스크롤
- 체류 시간 정규분포 랜덤화
- 기기 fingerprinting 최소화
- IP 로테이션 (비행기 모드 활용)

---

## ⚠️ 주의사항

1. **법적 책임**: 본 프로젝트는 학습/연구 목적이며, 상업적 남용 금지
2. **서비스 약관**: 네이버 서비스 약관 준수
3. **트래픽 제한**: 서버에 과부하를 주지 않도록 적절한 간격 유지
4. **IP 밴 리스크**: 비행기 모드 토글로 IP 변경하지만, 기기 fingerprinting 주의
5. **데이터 보안**: 테스트 결과 데이터의 외부 유출 방지
6. **Root 권한**: Root 권한 사용 시 보안 위험 인지

---

## 📞 문의 및 개선 제안

프로젝트 개선 아이디어나 버그 발견 시 GitHub 이슈 등록 바랍니다.

**Repository**: https://github.com/mim1012/turafic

**마지막 업데이트**: 2025-11-01
