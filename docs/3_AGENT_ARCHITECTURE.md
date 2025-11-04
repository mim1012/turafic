# Turafic 3-Agent 아키텍처

## 🎯 개요

Turafic 시스템을 **3개의 독립적인 에이전트**로 분리하여 각각의 책임을 명확히 하고, 확장성과 유지보수성을 향상시킵니다.

---

## 📊 3-Agent 구조

```
┌─────────────────────────────────────────────────────────────┐
│                     Turafic System                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────┐  │
│  │  Campaign Agent  │→ │   Bot Agent      │→ │Analytics │  │
│  │  (캠페인 생성)    │  │   (작업 실행)     │  │ Agent    │  │
│  │                  │  │                  │  │(통계분석)│  │
│  └──────────────────┘  └──────────────────┘  └──────────┘  │
│         ↓                      ↓                    ↓       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              PostgreSQL Database                     │  │
│  │  - campaigns                                         │  │
│  │  - bots                                              │  │
│  │  - tasks                                             │  │
│  │  - rankings                                          │  │
│  │  - analytics                                         │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🤖 Agent 1: Campaign Agent (캠페인 생성 에이전트)

### 역할
- ✅ 사용자로부터 캠페인 요청 받기
- ✅ L18 테스트 케이스 생성
- ✅ JSON 패턴 생성 (UI 좌표 맵 기반)
- ✅ 캠페인 DB에 저장
- ✅ 봇 할당 준비

### 입력
```json
{
  "product_id": "prod-001",
  "product_url": "https://shopping.naver.com/products/87654321",
  "naver_product_id": "87654321",
  "keyword": "삼성 갤럭시 S24",
  "traffic_count": 100,
  "test_cases": "L18"  // 또는 "custom"
}
```

### 출력
```json
{
  "campaign_id": "camp-001",
  "test_cases": [
    {
      "test_case_id": "TC#1",
      "variables": {
        "platform": "Mobile",
        "engagement": "High",
        "user_agent": "Samsung",
        // ... 7개 변수
      },
      "pattern": [
        {"action": "kill", "target": "com.naver.search"},
        {"action": "start", "target": "com.naver.search"},
        {"action": "tap", "x": 540, "y": 150},
        // ... JSON 패턴
      ]
    },
    // ... 18개 테스트 케이스
  ],
  "status": "ready"
}
```

### API 엔드포인트

#### 1. 캠페인 생성
```http
POST /api/v1/campaigns/create
Content-Type: application/json

{
  "product_id": "prod-001",
  "product_url": "https://shopping.naver.com/products/87654321",
  "naver_product_id": "87654321",
  "keyword": "삼성 갤럭시 S24",
  "traffic_count": 100
}

Response:
{
  "campaign_id": "camp-001",
  "test_cases_count": 18,
  "status": "ready",
  "created_at": "2025-11-01T12:00:00Z"
}
```

#### 2. 캠페인 목록 조회
```http
GET /api/v1/campaigns/list?status=ready

Response:
{
  "campaigns": [
    {
      "campaign_id": "camp-001",
      "product_id": "prod-001",
      "keyword": "삼성 갤럭시 S24",
      "test_cases_count": 18,
      "status": "ready",
      "created_at": "2025-11-01T12:00:00Z"
    }
  ]
}
```

#### 3. 캠페인 상세 조회
```http
GET /api/v1/campaigns/{campaign_id}

Response:
{
  "campaign_id": "camp-001",
  "product_id": "prod-001",
  "product_url": "https://shopping.naver.com/products/87654321",
  "naver_product_id": "87654321",
  "keyword": "삼성 갤럭시 S24",
  "traffic_count": 100,
  "test_cases": [
    {
      "test_case_id": "TC#1",
      "variables": {...},
      "pattern": [...]
    },
    // ... 18개
  ],
  "status": "ready"
}
```

#### 4. 캠페인 시작
```http
POST /api/v1/campaigns/{campaign_id}/start

Response:
{
  "campaign_id": "camp-001",
  "status": "running",
  "started_at": "2025-11-01T12:05:00Z"
}
```

### 내부 로직

**1. L18 테스트 케이스 생성**:
```python
def generate_l18_test_cases(product_id: str, keyword: str) -> List[TestCase]:
    """L18 직교배열 기반 18개 테스트 케이스 생성"""
    
    l18_matrix = [
        # TC#1
        {"platform": "Mobile", "engagement": "High", "user_agent": "Samsung", ...},
        # TC#2
        {"platform": "Mobile", "engagement": "Medium", "user_agent": "LG", ...},
        # ... TC#18
    ]
    
    test_cases = []
    for i, variables in enumerate(l18_matrix):
        test_case = TestCase(
            test_case_id=f"TC#{i+1}",
            product_id=product_id,
            keyword=keyword,
            variables=variables,
            pattern=generate_json_pattern(variables, product_id, keyword)
        )
        test_cases.append(test_case)
    
    return test_cases
```

**2. JSON 패턴 생성**:
```python
def generate_json_pattern(variables: dict, product_id: str, keyword: str) -> List[dict]:
    """변수 기반 JSON 패턴 생성"""
    
    # UI 좌표 맵 로드
    coords = load_ui_coordinates(variables["platform"])
    
    pattern = [
        # 1. 네이버 앱 종료
        {"action": "kill", "target": "com.naver.search"},
        
        # 2. 네이버 앱 실행
        {"action": "start", "target": "com.naver.search"},
        {"action": "wait", "duration": 3000},
        
        # 3. 검색창 클릭
        {"action": "tap", "x": coords["search_bar"]["x"], "y": coords["search_bar"]["y"]},
        {"action": "wait", "duration": 1000},
        
        # 4. 키워드 입력
        {"action": "text", "value": keyword},
        {"action": "wait", "duration": 500},
        
        # 5. 검색 실행 (Enter)
        {"action": "keyevent", "code": "KEYCODE_ENTER"},
        {"action": "wait", "duration": 3000},
        
        # 6. 상품 찾기
        {"action": "find_product_by_id", "naver_product_id": product_id, "max_scroll_attempts": 10},
        
        # 7. 상품 클릭
        {"action": "tap_found_product"},
        {"action": "wait", "duration": 3000},
        
        # 8. 참여도에 따른 액션
        *generate_engagement_actions(variables["engagement"]),
        
        # 9. 뒤로 가기
        {"action": "back"},
        {"action": "wait", "duration": 1000},
    ]
    
    return pattern
```

**3. 참여도별 액션 생성**:
```python
def generate_engagement_actions(engagement: str) -> List[dict]:
    """참여도에 따른 액션 생성"""
    
    if engagement == "High":
        return [
            {"action": "scroll", "direction": "down", "distance": 500, "duration": 300},
            {"action": "wait", "duration": 2000},
            {"action": "scroll", "direction": "down", "distance": 500, "duration": 300},
            {"action": "wait", "duration": 2000},
            {"action": "scroll", "direction": "down", "distance": 500, "duration": 300},
            {"action": "wait", "duration": 60000},  # 60초 체류
            {"action": "random_action", "probability": 0.5, "actions": ["tap_cart", "tap_review"]},
        ]
    elif engagement == "Medium":
        return [
            {"action": "scroll", "direction": "down", "distance": 500, "duration": 300},
            {"action": "wait", "duration": 1500},
            {"action": "scroll", "direction": "down", "distance": 500, "duration": 300},
            {"action": "wait", "duration": 45000},  # 45초 체류
        ]
    else:  # Low
        return [
            {"action": "scroll", "direction": "down", "distance": 300, "duration": 300},
            {"action": "wait", "duration": 30000},  # 30초 체류
        ]
```

---

## 🤖 Agent 2: Bot Agent (봇 에이전트)

### 역할
- ✅ 봇 등록 및 관리
- ✅ 작업 할당 ("1봇 = 1캠페인 전담")
- ✅ JSON 패턴 전송
- ✅ 작업 결과 수집
- ✅ IP 변경 스케줄링 (대장 봇)

### 입력 (봇 등록)
```json
{
  "android_id": "abc123def456",
  "device_model": "Samsung Galaxy S21",
  "role": "follower",  // "leader", "follower", "rank_checker"
  "is_leader": false,
  "group_id": "group-1"
}
```

### 출력 (봇 등록)
```json
{
  "bot_id": "bot-001",
  "role": "follower",
  "group_id": "group-1",
  "status": "idle"
}
```

### API 엔드포인트

#### 1. 봇 등록
```http
POST /api/v1/bots/register
Content-Type: application/json

{
  "android_id": "abc123def456",
  "device_model": "Samsung Galaxy S21",
  "role": "follower",
  "is_leader": false,
  "group_id": "group-1"
}

Response:
{
  "bot_id": "bot-001",
  "role": "follower",
  "group_id": "group-1",
  "status": "idle",
  "registered_at": "2025-11-01T12:00:00Z"
}
```

#### 2. 작업 요청 (봇이 호출)
```http
GET /api/v1/tasks/get_task?bot_id=bot-001

Response (작업 있음):
{
  "task_id": "task-001",
  "campaign_id": "camp-001",
  "test_case_id": "TC#1",
  "pattern": [
    {"action": "kill", "target": "com.naver.search"},
    {"action": "start", "target": "com.naver.search"},
    // ... JSON 패턴
  ],
  "repeat_count": 100,
  "current_iteration": 1
}

Response (작업 없음):
{
  "task_id": "wait",
  "message": "No task available. Wait 5 minutes."
}
```

#### 3. 작업 결과 보고 (봇이 호출)
```http
POST /api/v1/tasks/report_result
Content-Type: application/json

{
  "bot_id": "bot-001",
  "task_id": "task-001",
  "status": "success",  // "success", "failed"
  "completed_at": "2025-11-01T12:10:00Z",
  "error_message": null
}

Response:
{
  "message": "Result recorded",
  "next_iteration": 2,
  "total_iterations": 100
}
```

#### 4. 봇 상태 조회
```http
GET /api/v1/bots/{bot_id}/status

Response:
{
  "bot_id": "bot-001",
  "status": "working",  // "idle", "working", "offline"
  "current_campaign_id": "camp-001",
  "current_test_case_id": "TC#1",
  "completed_iterations": 45,
  "total_iterations": 100,
  "last_active_at": "2025-11-01T12:10:00Z"
}
```

#### 5. 봇 목록 조회
```http
GET /api/v1/bots/list?status=working

Response:
{
  "bots": [
    {
      "bot_id": "bot-001",
      "device_model": "Samsung Galaxy S21",
      "role": "follower",
      "status": "working",
      "current_campaign_id": "camp-001",
      "last_active_at": "2025-11-01T12:10:00Z"
    }
  ]
}
```

### 내부 로직

**1. 작업 할당 ("1봇 = 1캠페인 전담")**:
```python
def assign_task(bot_id: str) -> Task:
    """봇에게 작업 할당"""
    
    # 1. 봇 정보 조회
    bot = db.query(Bot).filter(Bot.bot_id == bot_id).first()
    
    # 2. 이미 할당된 캠페인이 있는지 확인
    if bot.assigned_campaign_id:
        campaign = db.query(Campaign).filter(
            Campaign.campaign_id == bot.assigned_campaign_id
        ).first()
        
        # 캠페인이 완료되었는지 확인
        if campaign.status == "completed":
            # 봇 할당 해제
            bot.assigned_campaign_id = None
            db.commit()
            
            # 10초 대기 후 새 작업 요청
            return Task(task_id="wait", message="Campaign completed. Wait 10 seconds.")
        
        # 진행 중인 캠페인의 다음 작업 반환
        return get_next_task(bot, campaign)
    
    # 3. 새로운 캠페인 할당
    available_campaign = db.query(Campaign).filter(
        Campaign.status == "running",
        Campaign.assigned_bot_id == None
    ).first()
    
    if not available_campaign:
        return Task(task_id="wait", message="No campaign available. Wait 5 minutes.")
    
    # 캠페인 할당
    available_campaign.assigned_bot_id = bot_id
    bot.assigned_campaign_id = available_campaign.campaign_id
    db.commit()
    
    # 첫 번째 작업 반환
    return get_next_task(bot, available_campaign)
```

**2. 다음 작업 가져오기**:
```python
def get_next_task(bot: Bot, campaign: Campaign) -> Task:
    """캠페인의 다음 작업 가져오기"""
    
    # 현재 진행 상황 조회
    completed_tasks = db.query(Task).filter(
        Task.campaign_id == campaign.campaign_id,
        Task.bot_id == bot.bot_id,
        Task.status == "completed"
    ).count()
    
    total_tasks = len(campaign.test_cases) * campaign.traffic_count  # 18 * 100 = 1800
    
    if completed_tasks >= total_tasks:
        # 캠페인 완료
        campaign.status = "completed"
        campaign.completed_at = datetime.now()
        bot.assigned_campaign_id = None
        db.commit()
        
        return Task(task_id="wait", message="Campaign completed. Wait 10 seconds.")
    
    # 다음 작업 생성
    current_test_case_index = completed_tasks // campaign.traffic_count
    current_iteration = (completed_tasks % campaign.traffic_count) + 1
    
    test_case = campaign.test_cases[current_test_case_index]
    
    task = Task(
        task_id=f"task-{uuid.uuid4()}",
        campaign_id=campaign.campaign_id,
        bot_id=bot.bot_id,
        test_case_id=test_case["test_case_id"],
        pattern=test_case["pattern"],
        repeat_count=campaign.traffic_count,
        current_iteration=current_iteration,
        status="assigned"
    )
    
    db.add(task)
    db.commit()
    
    return task
```

**3. IP 변경 스케줄링 (대장 봇)**:
```python
def schedule_ip_rotation():
    """대장 봇의 IP 변경 스케줄링 (5분 주기)"""
    
    while True:
        # 5분 대기
        time.sleep(300)
        
        # 모든 대장 봇 조회
        leader_bots = db.query(Bot).filter(Bot.is_leader == True).all()
        
        for leader_bot in leader_bots:
            # 쫄병 봇들이 작업 완료할 때까지 대기
            subordinates = db.query(Bot).filter(
                Bot.group_id == leader_bot.group_id,
                Bot.is_leader == False
            ).all()
            
            # 모든 쫄병 봇이 idle 상태인지 확인
            all_idle = all(bot.status == "idle" for bot in subordinates)
            
            if all_idle or time_exceeded(leader_bot.last_ip_change, max_wait=180):
                # IP 변경 명령 전송
                send_ip_change_command(leader_bot.bot_id)
                leader_bot.last_ip_change = datetime.now()
                db.commit()
```

---

## 🤖 Agent 3: Analytics Agent (통계 및 결과 에이전트)

### 역할
- ✅ 순위 데이터 수집 (순위 체크 봇으로부터)
- ✅ 캠페인 결과 분석
- ✅ ANOVA 통계 분석
- ✅ 최적 조합 도출
- ✅ 리포트 생성

### 입력 (순위 보고)
```json
{
  "bot_id": "bot-rc-001",
  "product_id": "prod-001",
  "naver_product_id": "87654321",
  "keyword": "삼성 갤럭시 S24",
  "rank": 28,
  "page": 2,
  "position": 8,
  "checked_at": "2025-11-01T12:00:00Z"
}
```

### 출력 (캠페인 분석 결과)
```json
{
  "campaign_id": "camp-001",
  "product_id": "prod-001",
  "keyword": "삼성 갤럭시 S24",
  "before_rank": 45,
  "after_rank": 28,
  "rank_improvement": 17,
  "best_test_case": {
    "test_case_id": "TC#7",
    "variables": {
      "platform": "Mobile",
      "engagement": "High",
      "user_agent": "Samsung",
      // ...
    },
    "rank_improvement": 22
  },
  "anova_results": {
    "significant_factors": ["engagement", "user_agent"],
    "f_values": {
      "engagement": 12.34,
      "user_agent": 8.56,
      // ...
    },
    "p_values": {
      "engagement": 0.001,
      "user_agent": 0.005,
      // ...
    }
  },
  "recommendations": [
    "Use High engagement for maximum rank improvement",
    "Samsung User-Agent performs better than others",
    // ...
  ]
}
```

### API 엔드포인트

#### 1. 순위 보고 (순위 체크 봇이 호출)
```http
POST /api/v1/analytics/report_ranking
Content-Type: application/json

{
  "bot_id": "bot-rc-001",
  "product_id": "prod-001",
  "naver_product_id": "87654321",
  "keyword": "삼성 갤럭시 S24",
  "rank": 28,
  "page": 2,
  "position": 8,
  "checked_at": "2025-11-01T12:00:00Z"
}

Response:
{
  "message": "Ranking recorded",
  "rank_id": "rank-001"
}
```

#### 2. 캠페인 분석 결과 조회
```http
GET /api/v1/analytics/campaigns/{campaign_id}/results

Response:
{
  "campaign_id": "camp-001",
  "product_id": "prod-001",
  "keyword": "삼성 갤럭시 S24",
  "before_rank": 45,
  "after_rank": 28,
  "rank_improvement": 17,
  "best_test_case": {...},
  "anova_results": {...},
  "recommendations": [...]
}
```

#### 3. ANOVA 분석 실행
```http
POST /api/v1/analytics/campaigns/{campaign_id}/anova

Response:
{
  "campaign_id": "camp-001",
  "anova_results": {
    "significant_factors": ["engagement", "user_agent"],
    "f_values": {...},
    "p_values": {...}
  },
  "analysis_completed_at": "2025-11-01T18:00:00Z"
}
```

#### 4. 리포트 생성
```http
POST /api/v1/analytics/campaigns/{campaign_id}/generate_report

Response:
{
  "campaign_id": "camp-001",
  "report_url": "https://turafic.railway.app/reports/camp-001.pdf",
  "generated_at": "2025-11-01T18:05:00Z"
}
```

#### 5. 순위 이력 조회
```http
GET /api/v1/analytics/products/{product_id}/ranking_history?from=2025-11-01&to=2025-11-05

Response:
{
  "product_id": "prod-001",
  "keyword": "삼성 갤럭시 S24",
  "history": [
    {
      "checked_at": "2025-11-01T00:00:00Z",
      "rank": 45,
      "page": 3,
      "position": 5
    },
    {
      "checked_at": "2025-11-01T12:00:00Z",
      "rank": 28,
      "page": 2,
      "position": 8
    },
    // ...
  ]
}
```

### 내부 로직

**1. ANOVA 분석**:
```python
import pandas as pd
from scipy import stats

def perform_anova(campaign_id: str) -> dict:
    """L18 테스트 케이스 결과에 대한 ANOVA 분석"""
    
    # 1. 캠페인 데이터 로드
    campaign = db.query(Campaign).filter(Campaign.campaign_id == campaign_id).first()
    
    # 2. 순위 데이터 수집
    rankings = db.query(Ranking).filter(
        Ranking.product_id == campaign.product_id,
        Ranking.checked_at >= campaign.started_at,
        Ranking.checked_at <= campaign.completed_at
    ).all()
    
    # 3. 데이터프레임 생성
    data = []
    for test_case in campaign.test_cases:
        # 각 테스트 케이스의 순위 변화 계산
        before_rank = get_rank_before_campaign(campaign.product_id, campaign.started_at)
        after_rank = get_rank_after_test_case(campaign.product_id, test_case["test_case_id"])
        
        rank_improvement = before_rank - after_rank
        
        data.append({
            "test_case_id": test_case["test_case_id"],
            "platform": test_case["variables"]["platform"],
            "engagement": test_case["variables"]["engagement"],
            "user_agent": test_case["variables"]["user_agent"],
            "cookie_manipulation": test_case["variables"]["cookie_manipulation"],
            "http_headers": test_case["variables"]["http_headers"],
            "entry_path": test_case["variables"]["entry_path"],
            "ip_strategy": test_case["variables"]["ip_strategy"],
            "rank_improvement": rank_improvement
        })
    
    df = pd.DataFrame(data)
    
    # 4. ANOVA 분석 (각 변수별)
    factors = ["platform", "engagement", "user_agent", "cookie_manipulation", 
               "http_headers", "entry_path", "ip_strategy"]
    
    anova_results = {
        "significant_factors": [],
        "f_values": {},
        "p_values": {}
    }
    
    for factor in factors:
        groups = [df[df[factor] == level]["rank_improvement"].values 
                  for level in df[factor].unique()]
        
        f_value, p_value = stats.f_oneway(*groups)
        
        anova_results["f_values"][factor] = f_value
        anova_results["p_values"][factor] = p_value
        
        # p < 0.05이면 유의미한 요인
        if p_value < 0.05:
            anova_results["significant_factors"].append(factor)
    
    return anova_results
```

**2. 최적 조합 도출**:
```python
def find_best_combination(campaign_id: str) -> dict:
    """ANOVA 결과 기반 최적 조합 도출"""
    
    # 1. ANOVA 분석 실행
    anova_results = perform_anova(campaign_id)
    
    # 2. 각 변수의 최적 레벨 찾기
    campaign = db.query(Campaign).filter(Campaign.campaign_id == campaign_id).first()
    
    data = []
    for test_case in campaign.test_cases:
        before_rank = get_rank_before_campaign(campaign.product_id, campaign.started_at)
        after_rank = get_rank_after_test_case(campaign.product_id, test_case["test_case_id"])
        rank_improvement = before_rank - after_rank
        
        data.append({
            **test_case["variables"],
            "rank_improvement": rank_improvement
        })
    
    df = pd.DataFrame(data)
    
    # 3. 유의미한 요인의 최적 레벨 찾기
    best_combination = {}
    
    for factor in anova_results["significant_factors"]:
        # 각 레벨의 평균 순위 개선 계산
        level_means = df.groupby(factor)["rank_improvement"].mean()
        
        # 가장 높은 평균을 가진 레벨 선택
        best_level = level_means.idxmax()
        best_combination[factor] = best_level
    
    # 4. 유의미하지 않은 요인은 기본값 사용
    for factor in ["platform", "engagement", "user_agent", "cookie_manipulation", 
                   "http_headers", "entry_path", "ip_strategy"]:
        if factor not in best_combination:
            # 가장 흔한 레벨 사용
            best_combination[factor] = df[factor].mode()[0]
    
    return {
        "best_combination": best_combination,
        "expected_improvement": df[
            (df[list(best_combination.keys())] == pd.Series(best_combination)).all(axis=1)
        ]["rank_improvement"].mean() if len(best_combination) > 0 else df["rank_improvement"].mean()
    }
```

**3. 리포트 생성**:
```python
from fpdf import FPDF

def generate_report(campaign_id: str) -> str:
    """캠페인 분석 리포트 PDF 생성"""
    
    campaign = db.query(Campaign).filter(Campaign.campaign_id == campaign_id).first()
    anova_results = perform_anova(campaign_id)
    best_combo = find_best_combination(campaign_id)
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    
    # 제목
    pdf.cell(0, 10, f"Campaign Analysis Report: {campaign.campaign_id}", ln=True)
    
    # 기본 정보
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Product: {campaign.product_id}", ln=True)
    pdf.cell(0, 10, f"Keyword: {campaign.keyword}", ln=True)
    pdf.cell(0, 10, f"Traffic Count: {campaign.traffic_count}", ln=True)
    
    # 순위 변화
    before_rank = get_rank_before_campaign(campaign.product_id, campaign.started_at)
    after_rank = get_rank_after_campaign(campaign.product_id, campaign.completed_at)
    
    pdf.cell(0, 10, f"Before Rank: {before_rank}", ln=True)
    pdf.cell(0, 10, f"After Rank: {after_rank}", ln=True)
    pdf.cell(0, 10, f"Improvement: {before_rank - after_rank}", ln=True)
    
    # ANOVA 결과
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "ANOVA Results:", ln=True)
    
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Significant Factors: {', '.join(anova_results['significant_factors'])}", ln=True)
    
    # 최적 조합
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Best Combination:", ln=True)
    
    pdf.set_font("Arial", "", 12)
    for factor, level in best_combo["best_combination"].items():
        pdf.cell(0, 10, f"  {factor}: {level}", ln=True)
    
    pdf.cell(0, 10, f"Expected Improvement: {best_combo['expected_improvement']:.2f}", ln=True)
    
    # PDF 저장
    report_path = f"/tmp/reports/{campaign_id}.pdf"
    pdf.output(report_path)
    
    return report_path
```

---

## 🔄 3-Agent 워크플로우

### 전체 프로세스

```
1. Campaign Agent: 캠페인 생성
   ↓
   사용자 요청 → L18 테스트 케이스 생성 → JSON 패턴 생성 → DB 저장
   
2. Bot Agent: 작업 할당 및 실행
   ↓
   봇 등록 → 캠페인 할당 → JSON 패턴 전송 → 봇이 작업 실행 → 결과 수집
   
3. Analytics Agent: 결과 분석
   ↓
   순위 데이터 수집 → ANOVA 분석 → 최적 조합 도출 → 리포트 생성
```

### 상세 워크플로우

**Day 1 00:00 - 캠페인 시작**:
```
1. Campaign Agent:
   - 사용자가 캠페인 생성 요청
   - L18 테스트 케이스 18개 생성
   - 각 테스트 케이스의 JSON 패턴 생성
   - DB에 저장, status = "ready"
   
2. Analytics Agent:
   - Before 순위 체크 (순위 체크 봇 4개 동원)
   - 순위: 45위 (기준선)
   
3. Campaign Agent:
   - 캠페인 시작 (status = "running")
```

**Day 1 00:05 - 작업 할당 시작**:
```
1. Bot Agent:
   - 18개 트래픽 봇 등록 완료
   - Bot-1 → TC#1 할당 (100회 전담)
   - Bot-2 → TC#2 할당 (100회 전담)
   - ...
   - Bot-18 → TC#18 할당 (100회 전담)
   
2. Bot Agent:
   - 각 봇에게 JSON 패턴 전송
   - 봇들이 작업 시작
```

**Day 1 00:05 ~ Day 1 12:00 - 작업 실행**:
```
1. Bot Agent:
   - 18개 봇이 병렬로 작업 실행
   - 각 봇이 100회 반복
   - 5분마다 대장 봇 IP 변경
   - 작업 결과 수집
   
2. Analytics Agent:
   - 30분마다 순위 체크 (모니터링)
```

**Day 1 12:00 - 첫 번째 배치 완료**:
```
1. Bot Agent:
   - 18개 봇 모두 100회 완료
   - 캠페인 완료 (status = "completed")
   
2. Analytics Agent:
   - After 순위 체크 (30분 대기 후)
   - 순위: 28위 (17위 상승!)
   - ANOVA 분석 실행
   - 최적 조합 도출
   - 리포트 생성
```

---

## 📊 데이터베이스 스키마

### campaigns 테이블
```sql
CREATE TABLE campaigns (
    campaign_id VARCHAR(50) PRIMARY KEY,
    product_id VARCHAR(50) NOT NULL,
    product_url TEXT NOT NULL,
    naver_product_id VARCHAR(50) NOT NULL,
    keyword VARCHAR(255) NOT NULL,
    traffic_count INTEGER DEFAULT 100,
    test_cases JSON NOT NULL,  -- 18개 테스트 케이스
    status VARCHAR(20) DEFAULT 'ready',  -- ready, running, completed
    assigned_bot_id VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);
```

### bots 테이블
```sql
CREATE TABLE bots (
    bot_id VARCHAR(50) PRIMARY KEY,
    android_id VARCHAR(255) UNIQUE NOT NULL,
    device_model VARCHAR(100),
    role VARCHAR(20) NOT NULL,  -- leader, follower, rank_checker
    is_leader BOOLEAN DEFAULT FALSE,
    group_id VARCHAR(50),
    status VARCHAR(20) DEFAULT 'idle',  -- idle, working, offline
    assigned_campaign_id VARCHAR(50),
    last_active_at TIMESTAMP,
    last_ip_change TIMESTAMP,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### tasks 테이블
```sql
CREATE TABLE tasks (
    task_id VARCHAR(50) PRIMARY KEY,
    campaign_id VARCHAR(50) NOT NULL,
    bot_id VARCHAR(50) NOT NULL,
    test_case_id VARCHAR(10) NOT NULL,  -- TC#1 ~ TC#18
    pattern JSON NOT NULL,
    repeat_count INTEGER DEFAULT 100,
    current_iteration INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'assigned',  -- assigned, in_progress, completed, failed
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT
);
```

### rankings 테이블
```sql
CREATE TABLE rankings (
    rank_id VARCHAR(50) PRIMARY KEY,
    product_id VARCHAR(50) NOT NULL,
    naver_product_id VARCHAR(50) NOT NULL,
    keyword VARCHAR(255) NOT NULL,
    rank INTEGER,
    page INTEGER,
    position INTEGER,
    checked_at TIMESTAMP NOT NULL,
    bot_id VARCHAR(50)
);
```

### analytics 테이블
```sql
CREATE TABLE analytics (
    analysis_id VARCHAR(50) PRIMARY KEY,
    campaign_id VARCHAR(50) NOT NULL,
    before_rank INTEGER,
    after_rank INTEGER,
    rank_improvement INTEGER,
    best_test_case_id VARCHAR(10),
    anova_results JSON,
    best_combination JSON,
    report_url TEXT,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 🎯 장점

### 1. 책임 분리
- ✅ 각 에이전트가 명확한 역할 수행
- ✅ 독립적으로 개발 및 테스트 가능
- ✅ 유지보수 용이

### 2. 확장성
- ✅ 각 에이전트를 독립적으로 스케일 가능
- ✅ 새로운 기능 추가 용이

### 3. 재사용성
- ✅ Analytics Agent는 다른 캠페인에도 재사용 가능
- ✅ Bot Agent는 다른 작업에도 활용 가능

### 4. 테스트 용이성
- ✅ 각 에이전트를 독립적으로 테스트
- ✅ Mock 데이터로 단위 테스트 가능

---

## 🚀 구현 순서

### Phase 1: Campaign Agent (2일)
1. ✅ L18 테스트 케이스 생성 로직
2. ✅ JSON 패턴 생성 로직
3. ✅ 캠페인 CRUD API
4. ✅ UI 좌표 맵 로드

### Phase 2: Bot Agent (3일)
1. ✅ 봇 등록 API
2. ✅ 작업 할당 로직 ("1봇 = 1캠페인 전담")
3. ✅ 작업 결과 수집 API
4. ✅ IP 변경 스케줄링

### Phase 3: Analytics Agent (3일)
1. ✅ 순위 데이터 수집 API
2. ✅ ANOVA 분석 로직
3. ✅ 최적 조합 도출 로직
4. ✅ 리포트 생성 기능

### Phase 4: 통합 테스트 (2일)
1. ✅ 3개 에이전트 통합 테스트
2. ✅ 전체 워크플로우 테스트
3. ✅ 버그 수정

**총 소요 시간: 약 10일**

---

## 🎓 결론

**3-Agent 아키텍처의 핵심**:
- ✅ **Campaign Agent**: 캠페인 생성 및 JSON 패턴 생성
- ✅ **Bot Agent**: 작업 할당 및 실행 관리
- ✅ **Analytics Agent**: 결과 분석 및 리포트 생성

**장점**:
- ✅ 명확한 책임 분리
- ✅ 독립적인 개발 및 테스트
- ✅ 확장성 및 재사용성
- ✅ 유지보수 용이

**다음 단계**:
1. Campaign Agent 구현
2. Bot Agent 구현
3. Analytics Agent 구현
4. 통합 테스트
