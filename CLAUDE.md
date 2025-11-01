# CLAUDE.md

## 📋 프로젝트 개요

### 목적
C&C 서버 기반 분산 봇 네트워크를 통해 네이버 쇼핑 상품의 트래픽 생성 및 순위 변동을 자동화하고, **과학적 실험 설계(L18 직교배열)**를 통해 어떤 사용자 행동 패턴이 상품 순위에 영향을 미치는지 분석합니다.

### 핵심 기능
- **C&C 서버**: Railway 기반 FastAPI 서버로 수십 대의 Android 봇을 중앙 제어
- **분산 봇 네트워크**: 트래픽 작업 봇(18개) + 순위 체크 봇(4개)
- **작업 할당 엔진**: "1봇 = 1캠페인 전담" 모델로 순수한 테스트 결과 보장
- **L18 테스트 매트릭스**: 7차원 변수(User-Agent, 쿠키, HTTP 헤더 등)를 18개 테스트 케이스로 압축
- **핫스팟 기반 IP 전략**: 대장 봇(핫스팟 제공) + 쫄병 봇(핫스팟 연결) 그룹 구조
- **안티 탐지 시스템**: Identity Profiles, IP 로테이션, 브라우저 지문 다양화
- **실시간 모니터링**: 관리자 대시보드를 통한 봇 상태 및 캠페인 진행률 추적

### 기술 스택
```
서버:
- 언어: Python 3.10+
- 프레임워크: FastAPI
- 데이터베이스: PostgreSQL (Railway 제공)
- 캐시: Redis (Railway 제공)
- 배포: Railway (무료 티어, GitHub 연동, 자동 HTTPS)

Android 봇:
- 언어: Java/Kotlin
- 최소 버전: Android 7.0 (API 24)
- 제어 방식: Root (su + input tap/text)
- 백그라운드 서비스: 24/7 실행 (ForegroundService)
- 네트워크: HTTP API (Retrofit)
- 핫스팟 제어: 대장 봇만 비행기 모드 토글

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
│                C&C 서버 (FastAPI on Railway)                 │
│  ┌──────────────────┬──────────────────┬─────────────────┐  │
│  │ Traffic Bot API  │ Rank Checker API │ Admin API       │  │
│  └──────────────────┴──────────────────┴─────────────────┘  │
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
│  Ranking DB     │
└─────────────────┘
         │
         │ HTTP API (봇 등록, 작업 요청, 결과 보고)
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    트래픽 작업 봇 (18개)                       │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │ 그룹 1 (대장+쫄병) │  │ 그룹 2 (대장+쫄병) │  ...          │
│  │  대장 Bot-1      │  │  대장 Bot-5      │                 │
│  │  (핫스팟 ON)     │  │  (핫스팟 ON)     │                 │
│  │  ├─ 쫄병 Bot-2   │  │  ├─ 쫄병 Bot-6   │                 │
│  │  ├─ 쫄병 Bot-3   │  │  └─ 쫄병 Bot-7   │                 │
│  │  └─ 쫄병 Bot-4   │  │                  │                 │
│  │                  │  │                  │                 │
│  │ 역할: TC#1~18    │  │ 역할: TC#1~18    │                 │
│  │ 전담 (100회)     │  │ 전담 (100회)     │                 │
│  └──────────────────┘  └──────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
         │                                          │
         │ 트래픽 생성                               │ 순위 조회
         ▼                                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    순위 체크 봇 (4개)                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 그룹 RC (대장+쫄병)                                   │   │
│  │  대장 Bot-RC1 (핫스팟 ON)                            │   │
│  │  ├─ 쫄병 Bot-RC2 (핫스팟 연결)                       │   │
│  │  ├─ 쫄병 Bot-RC3 (핫스팟 연결)                       │   │
│  │  └─ 쫄병 Bot-RC4 (핫스팟 연결)                       │   │
│  │                                                       │   │
│  │ 역할:                                                 │   │
│  │ - 18개 제품 순위 체크 (병렬 처리)                     │   │
│  │ - Before/During/After 순위 측정                      │   │
│  │ - 대장 봇이 주기적으로 IP 변경                        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │
         │ 순위 조회
         ▼
┌──────────────────────┐
│    네이버 쇼핑        │
│  (트래픽 생성 대상)   │
└──────────────────────┘
```

---

## 🎯 테스트 시나리오

### 1. L18 직교배열 테스트 매트릭스

**7차원 변수**를 **18개 테스트 케이스**로 압축하여 효율적인 실험 설계를 구현합니다.

#### 변수 정의

**트래픽량**: 모든 테스트 케이스에서 **100회로 고정** (변수 아님)

**상품 정보**: 사용자가 직접 제품 ID 및 URL 제공 (카테고리 분류 불필요)

| 변수 | 수준 | 설명 |
|------|------|------|
| **플랫폼** | Mobile / PC | 접속 기기 유형 (Android APK / PC 에뮬레이터) |
| **참여도** | High / Medium / Low | 체류 시간, 스크롤 깊이, 액션 확률 |
| **User-Agent** | Real Device / Randomized / Fixed | User-Agent 전략 (실제 기기 / 랜덤 / 고정) |
| **쿠키 전략** | Fresh / Persistent / Partial | 쿠키 관리 방식 (신규 / 유지 / 일부 유지) |
| **IP 전략** | Per Traffic / Per Session | 대장 봇의 IP 변경 빈도 (핫스팟 기반) |
| **진입 경로** | Naver Search / Shopping Direct | 검색 경로 (통합검색 / 쇼핑 직접) |
| **HTTP 헤더** | Standard / Enhanced / Minimal | HTTP 헤더 조작 수준 |

#### 참여도 정의 (상세)

| 참여도 | 체류 시간 | 스크롤 깊이 | 액션 확률 | 설명 |
|--------|-----------|-------------|-----------|------|
| **High** | 60초 (±15초) | 100% (Q&A까지) | 장바구니 50%, 리뷰 40%, 문의 10% | 적극적 관심, 구매 의도 높음 |
| **Medium** | 45초 (±10초) | 70% (리뷰까지) | 장바구니 30%, 리뷰 50%, 문의 20% | 보통 관심, 비교 검토 중 |
| **Low** | 30초 (±8초) | 40% (옵션까지) | 장바구니 10%, 리뷰 30%, 그냥 보기 60% | 낮은 관심, 가볍게 둘러봄 |

#### User-Agent 전략 상세

| 전략 | 설명 | 예시 |
|------|------|------|
| **Real Device** | 실제 Samsung 기기 User-Agent 사용 | `Mozilla/5.0 (Linux; Android 14; SM-S928N) ...` |
| **Randomized** | 매 트래픽마다 랜덤 User-Agent | 15개 풀에서 무작위 선택 |
| **Fixed** | 고정 User-Agent (탐지 테스트용) | `Mozilla/5.0 (Linux; Android 10; SM-G973N) ...` |

#### 쿠키 전략 상세

| 전략 | 설명 | 구현 |
|------|------|------|
| **Fresh** | 매 트래픽마다 쿠키 삭제 (신규 사용자) | `driver.delete_all_cookies()` |
| **Persistent** | 쿠키 유지 (재방문 사용자) | 세션 간 쿠키 공유 |
| **Partial** | 일부 쿠키만 유지 (혼합) | 필수 쿠키만 유지, 나머지 삭제 |

#### HTTP 헤더 조작 상세

| 수준 | 포함 헤더 | 설명 |
|------|----------|------|
| **Standard** | User-Agent, Accept, Accept-Encoding | 표준 헤더만 사용 |
| **Enhanced** | + Accept-Language, Referer, DNT, Upgrade-Insecure-Requests | 상세 헤더 추가 (실제 브라우저 모방) |
| **Minimal** | User-Agent, Accept: */* | 최소 헤더만 사용 (탐지 테스트용) |

#### IP 전략 (핫스팟 기반)

| 전략 | 설명 | 구현 |
|------|------|------|
| **Per Traffic** | 대장 봇이 1회 트래픽마다 비행기 모드 토글 | 쫄병 봇들도 자동 IP 변경 |
| **Per Session** | 대장 봇이 1회 세션(여러 트래픽)마다 비행기 모드 토글 | 세션 내 IP 고정 |

**핫스팟 그룹 구조**:
```
그룹 1:
  대장 Bot-1 (핫스팟 ON) → 비행기 모드 토글 → IP 변경
    ├─ 쫄병 Bot-2 (핫스팟 연결) → 자동 IP 변경
    ├─ 쫄병 Bot-3 (핫스팟 연결) → 자동 IP 변경
    └─ 쫄병 Bot-4 (핫스팟 연결) → 자동 IP 변경

그룹 2:
  대장 Bot-5 (핫스팟 ON) → 비행기 모드 토글 → IP 변경
    ├─ 쫄병 Bot-6 (핫스팟 연결) → 자동 IP 변경
    └─ 쫄병 Bot-7 (핫스팟 연결) → 자동 IP 변경
```

#### L18 테스트 케이스 전체 표

| TC | 플랫폼 | 참여도 | User-Agent | 쿠키 | IP전략 | 진입경로 | HTTP헤더 |
|----|--------|--------|------------|------|--------|----------|----------|
| TC#1 | Mobile | High | Real Device | Fresh | Per Traffic | Naver Search | Standard |
| TC#2 | Mobile | High | Randomized | Fresh | Per Session | Shopping Direct | Enhanced |
| TC#3 | Mobile | High | Fixed | Persistent | Per Traffic | Shopping Direct | Minimal |
| TC#4 | Mobile | Medium | Real Device | Persistent | Per Traffic | Shopping Direct | Enhanced |
| TC#5 | Mobile | Medium | Randomized | Partial | Per Session | Naver Search | Minimal |
| TC#6 | Mobile | Medium | Fixed | Fresh | Per Session | Shopping Direct | Standard |
| TC#7 | Mobile | Low | Real Device | Partial | Per Session | Shopping Direct | Minimal |
| TC#8 | Mobile | Low | Randomized | Fresh | Per Traffic | Shopping Direct | Standard |
| TC#9 | Mobile | Low | Fixed | Persistent | Per Session | Naver Search | Enhanced |
| TC#10 | PC | High | Real Device | Partial | Per Session | Naver Search | Enhanced |
| TC#11 | PC | High | Randomized | Fresh | Per Traffic | Naver Search | Minimal |
| TC#12 | PC | High | Fixed | Persistent | Per Session | Shopping Direct | Standard |
| TC#13 | PC | Medium | Real Device | Fresh | Per Session | Shopping Direct | Minimal |
| TC#14 | PC | Medium | Randomized | Persistent | Per Traffic | Shopping Direct | Standard |
| TC#15 | PC | Medium | Fixed | Partial | Per Traffic | Naver Search | Enhanced |
| TC#16 | PC | Low | Real Device | Fresh | Per Traffic | Shopping Direct | Standard |
| TC#17 | PC | Low | Randomized | Partial | Per Session | Shopping Direct | Enhanced |
| TC#18 | PC | Low | Fixed | Persistent | Per Traffic | Naver Search | Minimal |

### 2. 캠페인 정의

하나의 **캠페인(Campaign)**은 다음을 의미합니다:

- **1개 상품** (사용자 제공 product_id, product_url)
- **1개 테스트 케이스** (L18 매트릭스의 특정 행)
- **정확히 100회 실행** (모든 케이스 고정)
- **1개 봇 전담** (assigned_bot_id)

```python
campaign = {
    "campaign_id": "uuid-1234",
    "name": "제품A - TC#1",
    "target_product_id": "12345678",  # 사용자 제공
    "target_product_url": "https://shopping.naver.com/catalog/12345678",  # 사용자 제공
    "target_keyword": "삼성 갤럭시 S24",  # 검색용
    "target_traffic": 100,  # 고정
    "test_case": "TC#1",
    "execution_mode": "root",  # Root 기반 UI 제어
    "identity_profile_group": "samsung_mobile_default",
    "status": "active",
    "assigned_bot_id": "bot-5678"
}
```

### 3. 작업 할당 모델: "1봇 = 1캠페인 전담"

#### 원칙
- 각 봇은 **정확히 1개의 캠페인**만 할당받음
- 캠페인 완료(100회) 전까지 다른 캠페인 할당 불가
- 완료 후 10초 대기 → 새로운 캠페인 요청 가능

#### 예시: 9개 봇 + 18개 테스트 케이스

**1차 할당**:
- Bot-1 → TC#1 (100회 전담)
- Bot-2 → TC#2 (100회 전담)
- ...
- Bot-9 → TC#9 (100회 전담)

**1차 완료 후**:
- Bot-1 → TC#10 (100회 전담)
- Bot-2 → TC#11 (100회 전담)
- ...
- Bot-9 → TC#18 (100회 전담)

**최종 결과**: 18개 테스트 케이스 × 100회 = 1,800회 트래픽

---

## 🤖 봇 타입 및 역할

### 1. 트래픽 작업 봇 (Traffic Bot)

**역할**:
- 상품 페이지 방문
- 자연스러운 행동 시뮬레이션 (스크롤, 클릭, 체류)
- 100회 반복 실행
- IP 로테이션 (핫스팟 기반)

**그룹 구조**:
- **대장 봇**: 핫스팟 제공, 비행기 모드 토글로 IP 변경
- **쫄병 봇**: 대장 핫스팟 연결, 작업 실행

**데이터베이스 스키마**:
```sql
CREATE TABLE traffic_bots (
    bot_id VARCHAR(36) PRIMARY KEY,
    bot_type VARCHAR(20) DEFAULT 'traffic',
    android_id VARCHAR(64) UNIQUE NOT NULL,
    device_model VARCHAR(50) NOT NULL,
    
    -- 그룹 정보
    is_leader BOOLEAN DEFAULT FALSE,
    leader_bot_id VARCHAR(36),
    group_id INTEGER,
    
    -- 작업 정보
    assigned_campaign_id VARCHAR(36),
    status VARCHAR(20) DEFAULT 'active',
    
    -- 통계
    registered_at TIMESTAMP DEFAULT NOW(),
    last_task_at TIMESTAMP,
    success_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0
);
```

### 2. 순위 체크 봇 (Rank Checker Bot)

**역할**:
- 주기적 순위 체크 (캠페인 연동)
- 검색 결과 크롤링
- 순위 계산 및 DB 저장
- 순위 변동 알림

**특징**:
- **4개 봇으로 병렬 처리** (대장 1 + 쫄병 3)
- 대장-쫄병 그룹 구조 (핫스팟 기반 IP 전략)
- 트래픽 작업 봇과 독립적으로 동작
- IP 다양성으로 탐지 회피

**그룹 구성**:
```
순위 체크 그룹 RC:
  대장 Bot-RC1 (핫스팟 ON) → 비행기 모드 토글 → IP 변경
    ├─ 쫄병 Bot-RC2 (핫스팟 연결) → 자동 IP 변경
    ├─ 쫄병 Bot-RC3 (핫스팟 연결) → 자동 IP 변경
    └─ 쫄병 Bot-RC4 (핫스팟 연결) → 자동 IP 변경
```

**작업 분배**:
- Bot-RC1 (대장): 제품 1~5 순위 체크
- Bot-RC2 (쫄병): 제품 6~10 순위 체크
- Bot-RC3 (쫄병): 제품 11~15 순위 체크
- Bot-RC4 (쫄병): 제품 16~18 순위 체크

**데이터베이스 스키마**:
```sql
CREATE TABLE rank_checker_bots (
    bot_id VARCHAR(36) PRIMARY KEY,
    bot_type VARCHAR(20) DEFAULT 'rank_checker',
    
    -- 그룹 정보
    is_leader BOOLEAN DEFAULT FALSE,
    leader_bot_id VARCHAR(36),
    group_id INTEGER DEFAULT 1,  -- 모두 그룹 RC(1)
    
    -- 할당된 제품 목록
    assigned_products TEXT,  -- JSON 배열: ["12345678", "87654321", ...]
    
    -- 기기 정보
    android_id VARCHAR(64) UNIQUE NOT NULL,
    device_model VARCHAR(50) NOT NULL,
    
    -- 상태
    status VARCHAR(20) DEFAULT 'active',
    last_check_at TIMESTAMP,
    total_checks INTEGER DEFAULT 0,
    
    registered_at TIMESTAMP DEFAULT NOW()
);
```

### 3. 순위 체크 주기

**캠페인 연동 방식** (권장):

1. **캠페인 시작 전**: Before 순위 체크
2. **캠페인 진행 중**: 30분마다 체크 (진행률 모니터링)
3. **캠페인 완료 후**: 30분 대기 → After 순위 체크

```python
# 캠페인 시작 시
1. 순위 체크 봇에게 "product_id" 순위 체크 요청
2. Before 순위 저장
3. 트래픽 작업 봇에게 작업 할당

# 캠페인 진행 중
1. 30분마다 순위 체크 (진행률 모니터링)

# 캠페인 완료 후
1. 30분 대기 (네이버 순위 반영 시간)
2. 순위 체크 봇에게 "product_id" 순위 체크 요청
3. After 순위 저장
4. Before/After 비교 → 순위 변동 계산
```

---

## 🔧 Android 봇 에이전트 아키텍처

### 시스템 요구사항
- **최소 Android 버전**: Android 7.0 (API 24)
- **Root 권한**: 필수 (`su` 명령어 사용)
- **권장 기기**: Samsung Galaxy 시리즈 (S21, S22, S23, S24)

### 핵심 컴포넌트

#### 1. BotService.java (백그라운드 서비스)
```java
public class BotService extends Service {
    // 24/7 실행되는 ForegroundService
    // 서버와 HTTP 통신으로 작업 요청 및 결과 보고
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID, notification);
        startTaskLoop();  // 무한 루프로 작업 요청
        return START_STICKY;  // 시스템이 종료해도 자동 재시작
    }
}
```

#### 2. TaskExecutor.java (JSON 패턴 실행 엔진)
```java
public class TaskExecutor {
    // 서버에서 받은 JSON 작업 패턴을 순차 실행
    
    public void executePattern(JSONArray pattern) {
        for (int i = 0; i < pattern.length(); i++) {
            JSONObject action = pattern.getJSONObject(i);
            String actionType = action.getString("action");
            
            switch (actionType) {
                case "open_url":
                    openUrl(action.getString("url"));
                    break;
                case "tap":
                    tap(action.getInt("x"), action.getInt("y"));
                    break;
                case "scroll":
                    scroll(action.getInt("distance"));
                    break;
                case "wait":
                    Thread.sleep(action.getInt("duration"));
                    break;
            }
        }
    }
}
```

#### 3. RootController.java (Root 기반 UI 제어)
```java
public class RootController {
    // Root 권한으로 UI 제어 (ADB 불필요)
    // 좌표는 서버에서 JSON 패턴으로 전달받음
    
    public void tap(int x, int y) {
        try {
            Process process = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(process.getOutputStream());
            os.writeBytes("input tap " + x + " " + y + "\n");
            os.writeBytes("exit\n");
            os.flush();
            process.waitFor();
        } catch (Exception e) {
            Log.e("RootController", "Failed to tap", e);
        }
    }
    
    public void inputText(String text) {
        executeRootCommand("input text \"" + text + "\"");
    }
    
    public void scroll(int distance) {
        executeRootCommand("input swipe 540 1500 540 " + (1500 - distance) + " 300");
    }
    
    public void toggleAirplaneMode() {
        // 대장 봇만 실행
        executeRootCommand("cmd connectivity airplane-mode enable");
        Thread.sleep(2000);
        executeRootCommand("cmd connectivity airplane-mode disable");
    }
}
```

#### 4. ApiClient.java (HTTP API 클라이언트)
```java
public class ApiClient {
    private static final String BASE_URL = "https://your-railway-app.railway.app";
    
    // 작업 요청
    public Task getTask(String botId) {
        Response response = retrofit.get("/api/v1/traffic/get_task?bot_id=" + botId);
        return response.body();
    }
    
    // 결과 보고
    public void reportResult(String botId, String taskId, String status) {
        retrofit.post("/api/v1/traffic/report_result", new ReportRequest(botId, taskId, status));
    }
    
    // 순위 체크 요청 (순위 체크 봇 전용)
    public List<Product> getProductsToCheck() {
        Response response = retrofit.get("/api/v1/rank/check_products");
        return response.body();
    }
    
    // 순위 결과 보고 (순위 체크 봇 전용)
    public void reportRank(String botId, String productId, int rank) {
        retrofit.post("/api/v1/rank/report_rank", new RankReport(botId, productId, rank));
    }
}
```

### 작업 프로세스 (트래픽 작업 봇)

```
1. 봇 등록
   ├─ POST /api/v1/traffic/register
   ├─ { "android_id": "xxx", "device_model": "SM-S928N", "is_leader": true }
   └─ 서버가 bot_id 발급

2. 작업 요청 (무한 루프)
   ├─ GET /api/v1/traffic/get_task?bot_id=xxx
   ├─ 서버가 캠페인 할당 (첫 요청 시)
   └─ JSON 작업 패턴 수신

3. 작업 실행
   ├─ TaskExecutor가 JSON 패턴 순차 실행
   ├─ open_url → tap → scroll → wait → ...
   └─ 실행 시간 측정

4. 결과 보고
   ├─ POST /api/v1/traffic/report_result
   ├─ { "bot_id": "xxx", "task_id": "yyy", "status": "success" }
   └─ 서버가 진행률 업데이트

5. 반복
   ├─ 100회 완료까지 2~4 반복
   └─ 완료 후 10초 대기 → 새로운 캠페인 요청
```

### 작업 프로세스 (순위 체크 봇)

```
1. 봇 등록
   ├─ POST /api/v1/rank/register
   ├─ { "android_id": "xxx", "device_model": "SM-S928N" }
   └─ 서버가 bot_id 발급

2. 순위 체크 요청
   ├─ GET /api/v1/rank/check_products
   └─ 서버가 체크할 제품 목록 반환

3. 순위 체크 실행
   ├─ 네이버 쇼핑 검색
   ├─ 검색 결과 크롤링
   └─ 순위 계산 (페이지, 위치)

4. 결과 보고
   ├─ POST /api/v1/rank/report_rank
   ├─ { "bot_id": "xxx", "product_id": "12345678", "rank": 28 }
   └─ 서버가 Rankings 테이블에 저장

5. 대기
   ├─ 30분 대기
   └─ 2~4 반복
```

---

## 📊 데이터베이스 구조

### Bots 테이블 (통합)
```sql
CREATE TABLE bots (
    bot_id VARCHAR(36) PRIMARY KEY,
    bot_type VARCHAR(20) NOT NULL,  -- 'traffic' or 'rank_checker'
    android_id VARCHAR(64) UNIQUE NOT NULL,
    device_model VARCHAR(50) NOT NULL,
    
    -- 트래픽 봇 전용 필드
    is_leader BOOLEAN DEFAULT FALSE,
    leader_bot_id VARCHAR(36),
    group_id INTEGER,
    assigned_campaign_id VARCHAR(36),
    
    -- 공통 필드
    status VARCHAR(20) DEFAULT 'active',
    registered_at TIMESTAMP DEFAULT NOW(),
    last_task_at TIMESTAMP,
    success_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0
);

CREATE INDEX idx_bots_type ON bots(bot_type);
CREATE INDEX idx_bots_status ON bots(status);
CREATE INDEX idx_bots_assigned_campaign ON bots(assigned_campaign_id);
```

### Campaigns 테이블
```sql
CREATE TABLE campaigns (
    campaign_id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    target_product_id VARCHAR(64) NOT NULL,
    target_product_url TEXT NOT NULL,
    target_keyword VARCHAR(100) NOT NULL,
    target_traffic INTEGER DEFAULT 100,
    test_case VARCHAR(10) NOT NULL,
    execution_mode VARCHAR(20) DEFAULT 'root',
    identity_profile_group VARCHAR(50),
    status VARCHAR(20) DEFAULT 'pending',
    assigned_bot_id VARCHAR(36),
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_campaigns_status ON campaigns(status);
CREATE INDEX idx_campaigns_assigned_bot ON campaigns(assigned_bot_id);
```

### Tasks 테이블
```sql
CREATE TABLE tasks (
    task_id VARCHAR(36) PRIMARY KEY,
    campaign_id VARCHAR(36) NOT NULL,
    bot_id VARCHAR(36) NOT NULL,
    pattern JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    execution_time FLOAT,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id),
    FOREIGN KEY (bot_id) REFERENCES bots(bot_id)
);

CREATE INDEX idx_tasks_campaign ON tasks(campaign_id);
CREATE INDEX idx_tasks_bot ON tasks(bot_id);
CREATE INDEX idx_tasks_status ON tasks(status);
```

### Rankings 테이블
```sql
CREATE TABLE rankings (
    ranking_id VARCHAR(36) PRIMARY KEY,
    product_id VARCHAR(64) NOT NULL,
    campaign_id VARCHAR(36),
    rank INTEGER NOT NULL,
    page INTEGER NOT NULL,
    position INTEGER NOT NULL,
    checked_at TIMESTAMP DEFAULT NOW(),
    checked_by VARCHAR(36),
    rank_type VARCHAR(20),  -- 'before', 'during', 'after', 'periodic'
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id),
    FOREIGN KEY (checked_by) REFERENCES bots(bot_id)
);

CREATE INDEX idx_rankings_product ON rankings(product_id);
CREATE INDEX idx_rankings_campaign ON rankings(campaign_id);
CREATE INDEX idx_rankings_checked_at ON rankings(checked_at);
```

---

## 🚀 서버 환경 설정 (Railway)

### Railway 배포 가이드

#### 1. Railway 프로젝트 생성
```bash
# Railway CLI 설치
npm install -g @railway/cli

# 로그인
railway login

# 프로젝트 생성
railway init
```

#### 2. PostgreSQL 추가
```bash
# Railway 대시보드에서 "New" → "Database" → "PostgreSQL" 선택
# 자동으로 DATABASE_URL 환경변수 생성됨
```

#### 3. Redis 추가
```bash
# Railway 대시보드에서 "New" → "Database" → "Redis" 선택
# 자동으로 REDIS_URL 환경변수 생성됨
```

#### 4. 환경변수 설정
```bash
# Railway 대시보드 → Variables 탭
PORT=8000
DATABASE_URL=postgresql://...  # 자동 생성
REDIS_URL=redis://...  # 자동 생성
ADMIN_PASSWORD=your_secure_password
```

#### 5. GitHub 연동 배포
```bash
# Railway 대시보드 → Settings → "Connect Repo"
# GitHub 저장소 선택 (mim1012/turafic)
# 자동으로 main 브랜치 배포
```

#### 6. 도메인 설정
```bash
# Railway 대시보드 → Settings → "Generate Domain"
# 자동 HTTPS 도메인 생성: https://your-app.railway.app
```

### Railway 무료 티어 제한
- **실행 시간**: 500시간/월
- **메모리**: 512MB
- **CPU**: 공유 vCPU
- **네트워크**: 100GB/월
- **PostgreSQL**: 1GB 스토리지
- **Redis**: 100MB 메모리

### 서버 실행
```bash
# 로컬 개발
cd server
pip install -r requirements.txt
python main.py

# Railway 배포 (자동)
git push origin main  # Railway가 자동으로 감지하여 배포
```

---

## 🎨 안티 탐지 시스템

### 1. Identity Profiles (15개 Samsung 기기)

```python
identity_profiles = [
    {
        "device_model": "SM-S928N",  # Galaxy S24 Ultra
        "user_agent": "Mozilla/5.0 (Linux; Android 14; SM-S928N) AppleWebKit/537.36...",
        "screen_resolution": "1440x3200",
        "android_version": "14"
    },
    {
        "device_model": "SM-G998N",  # Galaxy S21 Ultra
        "user_agent": "Mozilla/5.0 (Linux; Android 13; SM-G998N) AppleWebKit/537.36...",
        "screen_resolution": "1440x3200",
        "android_version": "13"
    },
    # ... 13개 더
]
```

### 2. IP 로테이션 (핫스팟 기반)

#### IP 변경 주기: **5분**

**실제 트래픽 로그 분석 결과**:
- 대장 봇이 **5분마다** 비행기 모드 토글 → IP 변경
- 쫄병 봇들은 대장 핫스팟에 연결되어 **자동으로 IP 변경**
- 관찰된 IP 범위: `175.223.x.x`, `110.70.x.x`, `39.7.x.x`, `211.246.x.x`

#### 대장 봇 구현

```java
public class LeaderBotService extends Service {
    private static final int IP_CHANGE_INTERVAL = 5 * 60 * 1000; // 5분
    private Handler handler = new Handler();
    
    @Override
    public void onCreate() {
        super.onCreate();
        startIPRotation();
    }
    
    private void startIPRotation() {
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                changeIP();
                handler.postDelayed(this, IP_CHANGE_INTERVAL);
            }
        }, IP_CHANGE_INTERVAL);
    }
    
    private void changeIP() {
        try {
            // 방법 1: 비행기 모드 토글 (권장)
            toggleAirplaneMode();
            
            // 또는 방법 2: 모바일 데이터 토글
            // toggleMobileData();
            
            Log.d("LeaderBot", "IP changed successfully");
        } catch (Exception e) {
            Log.e("LeaderBot", "Failed to change IP", e);
        }
    }
    
    private void toggleAirplaneMode() throws Exception {
        // Root 권한으로 비행기 모드 켜기
        executeRootCommand("settings put global airplane_mode_on 1");
        executeRootCommand("am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true");
        
        // 3초 대기
        Thread.sleep(3000);
        
        // Root 권한으로 비행기 모드 끄기
        executeRootCommand("settings put global airplane_mode_on 0");
        executeRootCommand("am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false");
        
        // IP 재할당 대기 (5초)
        Thread.sleep(5000);
    }
    
    private void toggleMobileData() throws Exception {
        // Root 권한으로 모바일 데이터 끄기
        executeRootCommand("svc data disable");
        Thread.sleep(3000);
        
        // Root 권한으로 모바일 데이터 켜기
        executeRootCommand("svc data enable");
        Thread.sleep(5000);
    }
    
    private void executeRootCommand(String command) throws Exception {
        Process process = Runtime.getRuntime().exec("su");
        DataOutputStream os = new DataOutputStream(process.getOutputStream());
        os.writeBytes(command + "\n");
        os.writeBytes("exit\n");
        os.flush();
        process.waitFor();
    }
}
```

#### 쫄병 봇 구현

```java
public class FollowerBotService extends Service {
    private String leaderHotspotSSID = "Leader_Hotspot";
    private String currentIP = "";
    
    @Override
    public void onCreate() {
        super.onCreate();
        connectToLeaderHotspot();
        monitorIPChange();
    }
    
    private void connectToLeaderHotspot() {
        // 대장 봇의 핫스팟에 연결
        WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        
        WifiConfiguration config = new WifiConfiguration();
        config.SSID = "\"" + leaderHotspotSSID + "\"";
        config.preSharedKey = "\"password\"";
        
        int netId = wifiManager.addNetwork(config);
        wifiManager.enableNetwork(netId, true);
        
        Log.d("FollowerBot", "Connected to leader hotspot");
    }
    
    private void monitorIPChange() {
        currentIP = getCurrentIP();
        
        new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(10000); // 10초마다 체크
                    
                    String newIP = getCurrentIP();
                    if (!newIP.equals(currentIP)) {
                        Log.d("FollowerBot", "IP changed: " + currentIP + " -> " + newIP);
                        currentIP = newIP;
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        }).start();
    }
    
    private String getCurrentIP() {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (!addr.isLoopbackAddress() && addr instanceof Inet4Address) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            Log.e("FollowerBot", "Failed to get IP", e);
        }
        return "Unknown";
    }
}
```

#### IP 변경 시나리오 (5분 주기)

```
그룹 1 (대장 Bot-1 + 쫄병 Bot-2, Bot-3, Bot-4):
  00:00 → IP: 175.223.19.211
  00:05 → IP: 110.70.54.172   (5분 후)
  00:10 → IP: 39.7.54.15      (5분 후)
  00:15 → IP: 175.223.26.144  (5분 후)
  00:20 → IP: 110.70.47.241   (5분 후)
  ...

예상 IP 로테이션:
- 100회 트래픽 ÷ 5분 = 약 20회 IP 변경
- 18개 봇 × 20회 = 약 360개 고유 IP
- 탐지 회피: 매우 높음
```

### 3. 행동 패턴 무작위화

```python
# 체류 시간 무작위화
dwell_time = base_time + random.randint(-variation, variation)

# 스크롤 속도 무작위화
scroll_speed = random.randint(200, 500)  # ms

# 좌표 무작위화 (±10px)
tap_x = base_x + random.randint(-10, 10)
tap_y = base_y + random.randint(-10, 10)
```

---

## 📈 데이터 분석

### ANOVA (분산 분석)

```python
import pandas as pd
from scipy import stats

# 데이터 수집
df = pd.read_sql("SELECT * FROM rankings WHERE rank_type='after'", conn)

# ANOVA 분석
f_stat, p_value = stats.f_oneway(
    df[df['test_case']=='TC#1']['rank'],
    df[df['test_case']=='TC#2']['rank'],
    # ... TC#18까지
)

# 결과 해석
if p_value < 0.05:
    print("테스트 케이스 간 유의미한 차이 존재")
else:
    print("테스트 케이스 간 유의미한 차이 없음")
```

### 최적 조합 도출

```python
# 순위 변동이 가장 큰 테스트 케이스 찾기
best_tc = df.groupby('test_case')['rank_change'].mean().idxmin()
print(f"최적 테스트 케이스: {best_tc}")

# 변수별 영향도 분석
for var in ['platform', 'engagement', 'user_agent', ...]:
    print(f"{var}: {df.groupby(var)['rank_change'].mean()}")
```

---

## 🛠️ 프로젝트 구조

```
turafic/
├── server/                      # C&C 서버 (FastAPI)
│   ├── main.py                  # 서버 진입점
│   ├── core/
│   │   ├── database.py          # PostgreSQL 연결
│   │   └── redis_client.py      # Redis 연결
│   ├── api/
│   │   ├── traffic_bot.py       # 트래픽 봇 API
│   │   ├── rank_checker.py      # 순위 체크 봇 API
│   │   ├── admin.py             # 관리자 API
│   │   └── task_assignment.py   # 작업 할당 엔진
│   ├── models/
│   │   ├── bot.py               # Bot 모델
│   │   ├── campaign.py          # Campaign 모델
│   │   ├── task.py              # Task 모델
│   │   └── ranking.py           # Ranking 모델
│   ├── migrations/              # DB 마이그레이션
│   │   └── add_bot_campaign_assignment.sql
│   └── requirements.txt
├── android_agent/               # Android 봇 에이전트 (APK)
│   ├── app/
│   │   ├── src/main/java/
│   │   │   ├── BotService.java
│   │   │   ├── TaskExecutor.java
│   │   │   ├── RootController.java
│   │   │   └── ApiClient.java
│   │   └── AndroidManifest.xml
│   └── build.gradle
├── CLAUDE.md                    # 이 파일
├── ARCHITECTURE.md              # 아키텍처 설명
└── TASK_ALLOCATION_MODEL.md     # 작업 할당 모델 설명
```

---

## 📝 개발 가이드

### 서버 개발

```bash
# 가상환경 생성
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
cd server
pip install -r requirements.txt

# 데이터베이스 마이그레이션
psql $DATABASE_URL < migrations/add_bot_campaign_assignment.sql

# 서버 실행
python main.py
```

### Android 개발

```bash
# Android Studio에서 android_agent 프로젝트 열기
# Build → Build APK(s)
# APK 위치: android_agent/app/build/outputs/apk/debug/app-debug.apk

# ADB로 설치
adb install app-debug.apk

# 로그 확인
adb logcat -s BotService TaskExecutor
```

---

## 🔍 테스트 시나리오 예시

### 1개 제품 × 18개 테스트 케이스

```python
# 사용자가 제공하는 제품 정보
product = {
    "product_id": "12345678",
    "product_name": "삼성 갤럭시 S24 울트라",
    "product_url": "https://shopping.naver.com/catalog/12345678",
    "search_keyword": "삼성 갤럭시 S24"
}

# 18개 캠페인 생성
for tc in range(1, 19):
    campaign = create_campaign(
        product_id=product["product_id"],
        product_url=product["product_url"],
        search_keyword=product["search_keyword"],
        test_case=f"TC#{tc}",
        target_traffic=100  # 고정
    )
```

### 실행 결과

| 테스트 케이스 | Before 순위 | After 순위 | 순위 변동 | 실행 시간 |
|--------------|------------|-----------|----------|----------|
| TC#1 | 45 | 28 | +17 | 2.5시간 |
| TC#2 | 45 | 32 | +13 | 3.1시간 |
| TC#3 | 45 | 41 | +4 | 2.8시간 |
| ... | ... | ... | ... | ... |
| TC#18 | 45 | 38 | +7 | 2.9시간 |

**최적 조합**: TC#1 (Mobile, High, Real Device, Fresh, Per Traffic, Naver Search, Standard)

---

## 🚨 주의사항

### 법적 리스크
- 이 프로젝트는 **교육 목적**으로만 사용해야 합니다.
- 실제 상업적 목적으로 사용 시 네이버 이용약관 위반 가능
- 봇 탐지 시 계정 차단 또는 법적 조치 가능

### 윤리적 고려사항
- 공정한 경쟁 환경 훼손
- 다른 판매자에게 불이익
- 소비자 기만 가능성

### 기술적 제한사항
- 네이버의 봇 탐지 알고리즘은 지속적으로 진화
- IP 차단, CAPTCHA, 행동 패턴 분석 등으로 탐지 가능
- 대규모 트래픽 생성 시 서버 부하 및 비용 증가

---

## 📚 참고 자료

- [L18 직교배열 설계](https://en.wikipedia.org/wiki/Orthogonal_array)
- [ANOVA 분산 분석](https://en.wikipedia.org/wiki/Analysis_of_variance)
- [Railway 배포 가이드](https://docs.railway.app/)
- [Android Root 권한 사용](https://developer.android.com/guide/topics/security/permissions)
- [FastAPI 공식 문서](https://fastapi.tiangolo.com/)

---

## 📞 문의

- GitHub Issues: https://github.com/mim1012/turafic/issues
- Email: your-email@example.com

---

**마지막 업데이트**: 2025-11-01  
**버전**: 2.0 (C&C 서버 + 분산 봇 네트워크)
