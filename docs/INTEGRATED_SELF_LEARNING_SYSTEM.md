# 4-Agent + 자기학습 피드백 루프 통합 시스템 설계

## 📋 목차
1. [시스템 개요](#시스템-개요)
2. [4-Agent 아키텍처](#4-agent-아키텍처)
3. [자기학습 피드백 루프](#자기학습-피드백-루프)
4. [Android 봇 통합](#android-봇-통합)
5. [LLM 통합](#llm-통합)
6. [전체 워크플로우](#전체-워크플로우)
7. [구현 로드맵](#구현-로드맵)

---

## 🎯 시스템 개요

**Turafic 자기학습 시스템**은 4-Agent 아키텍처, Android 봇 네트워크, LLM을 유기적으로 연동하여 **완전 자동화된 순위 최적화 시스템**을 구축합니다.

### 핵심 특징

1. ✅ **완전 자동화**: 사용자는 제품 URL만 입력
2. ✅ **자기학습**: 실패 원인 분석 → 새로운 조합 생성 → 재시도
3. ✅ **LLM 기반 의사결정**: ChatGPT-5 + Claude API
4. ✅ **실시간 모니터링**: WebSocket 기반 대시보드
5. ✅ **분산 봇 네트워크**: 22개 Android 봇 (18개 트래픽 + 4개 순위 체크)

---

## 🤖 4-Agent 아키텍처

### 전체 구조

```
┌─────────────────────────────────────────────────────────────────┐
│                   Control Tower Agent                            │
│                   (컨트롤 타워 - 두뇌)                            │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  핵심 역할:                                               │   │
│  │  1. 캠페인 생성 (L18 테스트 케이스)                       │   │
│  │  2. 에러 분석 및 복구                                     │   │
│  │  3. 자동 의사결정                                         │   │
│  │  4. LLM 통합 (ChatGPT-5 + Claude)                        │   │
│  │  5. 자기학습 피드백 루프 제어                             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  LLM 통합:                                                │   │
│  │  - ChatGPT-5: 실패 원인 분석, 새로운 조합 생성           │   │
│  │  - Claude: 코드 디버깅, 전략 수립                        │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Traffic    │    │  Monitoring  │    │  Analytics   │
│    Agent     │    │    Agent     │    │    Agent     │
│              │    │              │    │              │
│ - 봇 관리    │    │ - 순위 체크  │    │ - ANOVA      │
│ - 작업 할당  │    │ - 이상 탐지  │    │ - 최적 조합  │
│ - IP 변경    │    │ - 대시보드   │    │ - 리포트     │
│ - JSON 패턴  │    │ - WebSocket  │    │ - 피드백     │
└──────────────┘    └──────────────┘    └──────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
                ┌───────────────────────┐
                │  PostgreSQL Database  │
                │                       │
                │  - Bots               │
                │  - Campaigns          │
                │  - Tasks              │
                │  - Rankings           │
                │  - Feedback           │
                │  - LLM_Insights       │
                └───────────────────────┘
```

---

### 1. Control Tower Agent (컨트롤 타워)

**역할**: 전체 시스템의 두뇌, 핵심 의사결정 담당

#### 주요 기능

##### A. 캠페인 생성
```python
# server/agents/control_tower.py

class ControlTowerAgent:
    """컨트롤 타워 에이전트"""
    
    def __init__(self):
        self.chatgpt = ChatGPT5Client()
        self.claude = ClaudeClient()
        self.db = Database()
    
    def create_campaign(self, product_url: str) -> dict:
        """캠페인 생성 (L18 테스트 케이스)"""
        
        # 1. 제품 정보 추출
        product_info = self.extract_product_info(product_url)
        
        # 2. L18 테스트 케이스 생성
        test_cases = self.generate_l18_test_cases()
        
        # 3. 데이터베이스에 저장
        campaign = self.db.create_campaign({
            "product_id": product_info["product_id"],
            "product_url": product_url,
            "test_cases": test_cases,
            "status": "pending"
        })
        
        # 4. Traffic Agent에게 작업 할당 요청
        self.assign_tasks_to_bots(campaign)
        
        return campaign
```

##### B. 에러 분석 및 복구
```python
def handle_bot_error(self, bot_id: str, error: dict) -> None:
    """봇 에러 처리 (LLM 디버깅)"""
    
    # 1. 에러 로그 수집
    error_log = {
        "bot_id": bot_id,
        "error_type": error["type"],
        "error_message": error["message"],
        "screenshot": error.get("screenshot"),
        "timestamp": datetime.now()
    }
    
    # 2. Claude API로 디버깅
    debug_result = self.claude.debug_error(error_log)
    
    # 3. 자동 수정 시도
    if debug_result["auto_fixable"]:
        fix_action = debug_result["fix_action"]
        
        if fix_action["type"] == "restart_bot":
            self.restart_bot(bot_id)
        
        elif fix_action["type"] == "update_json_pattern":
            new_pattern = fix_action["new_pattern"]
            self.update_bot_task(bot_id, new_pattern)
        
        elif fix_action["type"] == "change_ip":
            self.trigger_ip_change(bot_id)
    
    # 4. 수동 개입 필요 시 알림
    else:
        self.notify_admin({
            "bot_id": bot_id,
            "error": error_log,
            "debug_result": debug_result
        })
```

##### C. 자동 의사결정
```python
def make_decision(self, campaign_id: str) -> dict:
    """캠페인 진행 중 의사결정"""
    
    # 1. 현재 상태 조회
    campaign = self.db.get_campaign(campaign_id)
    current_rank = self.get_current_rank(campaign["product_id"])
    before_rank = campaign["before_rank"]
    
    # 2. 순위 개선 여부 판단
    rank_improvement = before_rank - current_rank
    
    if rank_improvement >= 10:
        # 순위 크게 개선 → 계속 진행
        decision = {
            "action": "continue",
            "reason": f"순위 {rank_improvement}위 개선 중"
        }
    
    elif rank_improvement >= 5:
        # 순위 약간 개선 → 트래픽 증가
        decision = {
            "action": "increase_traffic",
            "reason": "순위 개선 중이지만 속도 느림",
            "new_traffic_count": campaign["traffic_count"] * 1.5
        }
    
    elif rank_improvement < 0:
        # 순위 하락 → 즉시 중단 및 분석
        decision = {
            "action": "stop_and_analyze",
            "reason": "순위 하락 감지",
            "trigger_feedback_loop": True
        }
    
    else:
        # 순위 변화 없음 → 대기 후 재판단
        decision = {
            "action": "wait",
            "reason": "순위 변화 없음, 30분 후 재판단",
            "wait_time": 1800
        }
    
    return decision
```

---

### 2. Traffic Agent (트래픽 에이전트)

**역할**: Android 봇 관리 및 작업 할당

#### 주요 기능

##### A. 봇 관리
```python
# server/agents/traffic_agent.py

class TrafficAgent:
    """트래픽 에이전트"""
    
    def __init__(self):
        self.db = Database()
        self.bots = {}  # bot_id -> Bot 객체
    
    def register_bot(self, bot_info: dict) -> dict:
        """봇 등록"""
        
        bot = Bot(
            bot_id=bot_info["bot_id"],
            bot_type=bot_info["bot_type"],  # leader, follower, rank_checker
            group_id=bot_info["group_id"],
            device_info=bot_info["device_info"],
            status="idle"
        )
        
        self.bots[bot.bot_id] = bot
        self.db.save_bot(bot)
        
        return {"status": "registered", "bot_id": bot.bot_id}
    
    def assign_task(self, bot_id: str, test_case: dict) -> dict:
        """봇에게 작업 할당"""
        
        bot = self.bots[bot_id]
        
        # 1. JSON 패턴 생성
        json_pattern = self.generate_json_pattern(test_case)
        
        # 2. 봇 상태 업데이트
        bot.status = "working"
        bot.current_task = test_case["test_case_id"]
        
        # 3. 데이터베이스 저장
        self.db.update_bot(bot)
        
        return {
            "task_id": test_case["test_case_id"],
            "json_pattern": json_pattern
        }
```

##### B. JSON 패턴 생성
```python
def generate_json_pattern(self, test_case: dict) -> dict:
    """테스트 케이스 → JSON 패턴 변환"""
    
    variables = test_case["variables"]
    
    # 기본 액션 시퀀스
    actions = [
        {"type": "force_stop", "package": "com.sec.android.app.sbrowser"},
        {"type": "wait", "duration": 5000},
        {"type": "start_app", "package": "com.sec.android.app.sbrowser"},
        {"type": "wait", "duration": 3000}
    ]
    
    # Entry Path에 따라 분기
    if variables["entry_path"] == "Naver Search":
        actions.extend([
            {"type": "tap", "x": 540, "y": 200, "description": "네이버 검색창 탭"},
            {"type": "text", "value": test_case["keyword"]},
            {"type": "tap", "x": 540, "y": 1800, "description": "검색 버튼 탭"},
            {"type": "wait", "duration": 5000},
            {"type": "tap", "x": 200, "y": 400, "description": "쇼핑 탭 클릭"}
        ])
    else:  # Shopping Direct
        actions.extend([
            {"type": "tap", "x": 540, "y": 200, "description": "주소창 탭"},
            {"type": "text", "value": "https://shopping.naver.com"},
            {"type": "tap", "x": 540, "y": 1800, "description": "이동"},
            {"type": "wait", "duration": 3000},
            {"type": "tap", "x": 540, "y": 300, "description": "검색창 탭"},
            {"type": "text", "value": test_case["keyword"]}
        ])
    
    # Engagement에 따라 액션 추가
    if variables["engagement"] == "High":
        actions.extend([
            {"type": "scroll", "direction": "down", "distance": 500},
            {"type": "wait", "duration": 3000},
            {"type": "tap", "x": 540, "y": 800, "description": "상품 클릭"},
            {"type": "wait", "duration": 30000},
            {"type": "scroll", "direction": "down", "distance": 1000},
            {"type": "wait", "duration": 10000},
            {"type": "tap", "x": 540, "y": 1500, "description": "장바구니"},
            {"type": "wait", "duration": 5000}
        ])
    elif variables["engagement"] == "Medium":
        actions.extend([
            {"type": "scroll", "direction": "down", "distance": 300},
            {"type": "wait", "duration": 2000},
            {"type": "tap", "x": 540, "y": 800, "description": "상품 클릭"},
            {"type": "wait", "duration": 15000}
        ])
    else:  # Low
        actions.extend([
            {"type": "tap", "x": 540, "y": 800, "description": "상품 클릭"},
            {"type": "wait", "duration": 5000}
        ])
    
    # 스크린샷
    actions.append({
        "type": "screenshot",
        "path": f"/sdcard/turafic/{test_case['test_case_id']}.png"
    })
    
    return {
        "task_id": test_case["test_case_id"],
        "bot_id": test_case["bot_id"],
        "test_case_id": test_case["test_case_id"],
        "actions": actions
    }
```

##### C. IP 변경 제어
```python
def trigger_ip_change(self, group_id: str) -> None:
    """그룹 전체 IP 변경 (대장 봇 비행기 모드 토글)"""
    
    # 1. 대장 봇 찾기
    leader_bot = self.find_leader_bot(group_id)
    
    # 2. 비행기 모드 토글 명령 전송
    self.send_command(leader_bot.bot_id, {
        "command": "toggle_airplane_mode",
        "duration": 5000  # 5초간 비행기 모드
    })
    
    # 3. 쫄병 봇들은 자동으로 IP 변경됨 (핫스팟 재연결)
    follower_bots = self.find_follower_bots(group_id)
    for bot in follower_bots:
        bot.ip_changed = True
        self.db.update_bot(bot)
```

---

### 3. Monitoring Agent (모니터링 에이전트)

**역할**: 순위 체크 및 이상 탐지

#### 주요 기능

##### A. 순위 체크
```python
# server/agents/monitoring_agent.py

class MonitoringAgent:
    """모니터링 에이전트"""
    
    def __init__(self):
        self.db = Database()
        self.rank_checker_bots = []
    
    def check_rank(self, product_id: str, keyword: str) -> dict:
        """순위 체크 (순위 체크 봇 활용)"""
        
        # 1. 순위 체크 봇 선택 (라운드 로빈)
        bot = self.select_rank_checker_bot()
        
        # 2. 순위 체크 요청
        rank_result = self.request_rank_check(bot.bot_id, {
            "product_id": product_id,
            "keyword": keyword,
            "url": f"https://search.shopping.naver.com/search/all?query={keyword}"
        })
        
        # 3. 결과 저장
        self.db.save_ranking({
            "product_id": product_id,
            "keyword": keyword,
            "rank": rank_result["rank"],
            "page": rank_result["page"],
            "position": rank_result["position"],
            "timestamp": datetime.now()
        })
        
        return rank_result
```

##### B. 이상 탐지
```python
def detect_anomaly(self, campaign_id: str) -> dict:
    """이상 탐지 (순위 급락, 봇 탐지 등)"""
    
    # 1. 최근 순위 변동 조회
    rankings = self.db.get_recent_rankings(campaign_id, limit=10)
    
    # 2. 순위 급락 감지
    if len(rankings) >= 2:
        latest_rank = rankings[0]["rank"]
        previous_rank = rankings[1]["rank"]
        
        if latest_rank - previous_rank > 10:
            # 순위 10위 이상 급락
            return {
                "anomaly_type": "rank_drop",
                "severity": "high",
                "message": f"순위 급락 감지: {previous_rank}위 → {latest_rank}위",
                "action": "stop_campaign"
            }
    
    # 3. 봇 탐지 감지 (순위가 계속 하락)
    if len(rankings) >= 5:
        is_declining = all(
            rankings[i]["rank"] > rankings[i+1]["rank"]
            for i in range(4)
        )
        
        if is_declining:
            return {
                "anomaly_type": "bot_detection",
                "severity": "critical",
                "message": "봇 탐지 의심 (순위 지속 하락)",
                "action": "change_ip_and_pause"
            }
    
    return {"anomaly_type": "none"}
```

##### C. WebSocket 실시간 업데이트
```python
async def broadcast_update(self, update_type: str, data: dict) -> None:
    """WebSocket으로 대시보드에 실시간 업데이트 전송"""
    
    message = {
        "type": update_type,
        "data": data,
        "timestamp": datetime.now().isoformat()
    }
    
    # 모든 연결된 클라이언트에게 전송
    await self.websocket_manager.broadcast(json.dumps(message))
```

---

### 4. Analytics Agent (분석 에이전트)

**역할**: ANOVA 분석 및 최적 조합 도출

#### 주요 기능

##### A. ANOVA 분석
```python
# server/agents/analytics_agent.py

class AnalyticsAgent:
    """분석 에이전트"""
    
    def __init__(self):
        self.db = Database()
        self.chatgpt = ChatGPT5Client()
    
    def analyze_campaign(self, campaign_id: str) -> dict:
        """캠페인 ANOVA 분석"""
        
        # 1. 18개 테스트 케이스 결과 조회
        test_cases = self.db.get_test_cases(campaign_id)
        
        # 2. 데이터프레임 생성
        data = []
        for tc in test_cases:
            before_rank = self.db.get_rank_before(tc["test_case_id"])
            after_rank = self.db.get_rank_after(tc["test_case_id"])
            improvement = before_rank - after_rank
            
            data.append({
                "test_case_id": tc["test_case_id"],
                "platform": tc["variables"]["platform"],
                "engagement": tc["variables"]["engagement"],
                "user_agent": tc["variables"]["user_agent"],
                "cookie": tc["variables"]["cookie"],
                "http_headers": tc["variables"]["http_headers"],
                "entry_path": tc["variables"]["entry_path"],
                "ip_strategy": tc["variables"]["ip_strategy"],
                "improvement": improvement
            })
        
        df = pd.DataFrame(data)
        
        # 3. ANOVA 분석
        anova_results = {}
        
        for var in ["platform", "engagement", "user_agent", "cookie", 
                    "http_headers", "entry_path", "ip_strategy"]:
            groups = df.groupby(var)["improvement"].apply(list)
            f_stat, p_value = stats.f_oneway(*groups)
            
            anova_results[var] = {
                "f_statistic": f_stat,
                "p_value": p_value,
                "significant": p_value < 0.05
            }
        
        # 4. 최적 조합 도출
        best_combination = {}
        for var in anova_results.keys():
            if anova_results[var]["significant"]:
                # 유의미한 변수 → 평균 개선도가 가장 높은 레벨 선택
                best_level = df.groupby(var)["improvement"].mean().idxmax()
                best_combination[var] = best_level
            else:
                # 유의미하지 않은 변수 → 기본값
                best_combination[var] = df[var].mode()[0]
        
        return {
            "anova_results": anova_results,
            "best_combination": best_combination
        }
```

##### B. 실패 원인 분석 (LLM 활용)
```python
def analyze_failure(self, campaign_id: str) -> dict:
    """실패 원인 분석 (ChatGPT-5 활용)"""
    
    # 1. 캠페인 데이터 수집
    campaign = self.db.get_campaign(campaign_id)
    test_cases = self.db.get_test_cases(campaign_id)
    
    campaign_data = {
        "product_id": campaign["product_id"],
        "before_rank": campaign["before_rank"],
        "after_rank": campaign["after_rank"],
        "rank_improvement": campaign["before_rank"] - campaign["after_rank"],
        "test_case_results": []
    }
    
    for tc in test_cases:
        before_rank = self.db.get_rank_before(tc["test_case_id"])
        after_rank = self.db.get_rank_after(tc["test_case_id"])
        
        campaign_data["test_case_results"].append({
            "test_case_id": tc["test_case_id"],
            "variables": tc["variables"],
            "before_rank": before_rank,
            "after_rank": after_rank,
            "improvement": before_rank - after_rank
        })
    
    # 2. ChatGPT-5로 분석
    llm_analysis = self.chatgpt.analyze_failure(campaign_data)
    
    # 3. 결과 저장
    self.db.save_llm_insight({
        "campaign_id": campaign_id,
        "analysis_type": "failure_analysis",
        "llm_provider": "chatgpt-5",
        "result": llm_analysis,
        "timestamp": datetime.now()
    })
    
    return llm_analysis
```

---

## 🔄 자기학습 피드백 루프

### 전체 워크플로우

```
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: 캠페인 실행                                             │
│  - Control Tower: L18 테스트 케이스 생성                         │
│  - Traffic Agent: 18개 봇에게 작업 할당                          │
│  - Android 봇: JSON 패턴 실행 (100회 반복)                       │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: 순위 모니터링                                           │
│  - Monitoring Agent: 30분마다 순위 체크                          │
│  - Rank Checker 봇: 순위 조회 및 보고                            │
│  - 실시간 대시보드 업데이트 (WebSocket)                          │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 3: 결과 분석                                               │
│  - Analytics Agent: ANOVA 분석                                  │
│  - 순위 개선 여부 판단                                           │
│  - 실패 판정 기준:                                               │
│    • 순위 개선 < 5위                                             │
│    • 순위 하락                                                   │
│    • 비용 대비 효율 낮음                                         │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
                    순위 개선 충분?
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
            ✅ YES                   ❌ NO
                │                       │
                ▼                       ▼
┌───────────────────────┐   ┌───────────────────────────────────┐
│  Step 4-A: 성공       │   │  Step 4-B: 실패 분석 (피드백)     │
│  - 리포트 생성        │   │  - ChatGPT-5: 실패 원인 분석      │
│  - 최적 조합 저장     │   │  - 어떤 변수가 문제인지 파악      │
│  - 사용자에게 전송    │   │  - 변수별 영향도 계산             │
└───────────────────────┘   └─────────────┬─────────────────────┘
                                          ▼
                            ┌─────────────────────────────────────┐
                            │  Step 5: 새로운 조합 생성           │
                            │  - ChatGPT-5: 새로운 L18 생성       │
                            │  - 실패 원인 개선한 조합 우선       │
                            │  - 이미 테스트한 조합 제외          │
                            └─────────────┬─────────────────────┘
                                          ▼
                            ┌─────────────────────────────────────┐
                            │  Step 6: 재시도                     │
                            │  - Control Tower: 새 캠페인 생성    │
                            │  - Traffic Agent: 작업 재할당       │
                            │  - Android 봇: 새 패턴 실행         │
                            └─────────────┬─────────────────────┘
                                          │
                                          └──────┐
                                                 │
                            ┌────────────────────┘
                            │
                            └─→ Step 2로 돌아가기 (최대 5회 반복)
```

---

### 구현 예시

#### 1. 피드백 루프 트리거

```python
# server/agents/control_tower.py

class ControlTowerAgent:
    
    def trigger_feedback_loop(self, campaign_id: str) -> None:
        """자기학습 피드백 루프 시작"""
        
        logger.info(f"🔄 피드백 루프 시작: {campaign_id}")
        
        # 1. 실패 원인 분석 (Analytics Agent)
        failure_analysis = self.analytics_agent.analyze_failure(campaign_id)
        
        logger.info(f"📊 실패 원인 분석 완료:")
        logger.info(f"  - 주요 원인: {failure_analysis['failure_causes'][0]['variable']}")
        logger.info(f"  - 권장 사항: {failure_analysis['failure_causes'][0]['recommendation']}")
        
        # 2. 이미 테스트한 조합 조회
        tested_combinations = self.db.get_tested_combinations(
            product_id=self.db.get_campaign(campaign_id)["product_id"]
        )
        
        # 3. 새로운 조합 생성 (ChatGPT-5)
        new_combinations = self.chatgpt.generate_new_combinations(
            failure_analysis=failure_analysis,
            tested_combinations=tested_combinations
        )
        
        logger.info(f"🆕 새로운 조합 {len(new_combinations)}개 생성")
        
        # 4. 새 캠페인 생성
        new_campaign = self.create_campaign_from_combinations(
            product_id=self.db.get_campaign(campaign_id)["product_id"],
            combinations=new_combinations
        )
        
        logger.info(f"✅ 새 캠페인 생성: {new_campaign['campaign_id']}")
        
        # 5. 피드백 이력 저장
        self.db.save_feedback({
            "original_campaign_id": campaign_id,
            "new_campaign_id": new_campaign["campaign_id"],
            "failure_analysis": failure_analysis,
            "new_combinations": new_combinations,
            "iteration": self.get_iteration_count(campaign_id) + 1,
            "timestamp": datetime.now()
        })
```

#### 2. 반복 횟수 제한

```python
def should_continue_feedback_loop(self, campaign_id: str) -> bool:
    """피드백 루프 계속 진행 여부 판단"""
    
    iteration = self.get_iteration_count(campaign_id)
    
    # 최대 5회 반복
    if iteration >= 5:
        logger.warning(f"⚠️ 최대 반복 횟수 도달 ({iteration}회)")
        return False
    
    # 순위 개선이 전혀 없으면 중단
    all_campaigns = self.get_all_related_campaigns(campaign_id)
    improvements = [c["rank_improvement"] for c in all_campaigns]
    
    if all(imp <= 0 for imp in improvements):
        logger.warning("⚠️ 모든 시도에서 순위 개선 없음")
        return False
    
    return True
```

---

## 📱 Android 봇 통합

### 봇 네트워크 구성

```
트래픽 작업 봇 (18개, 6개 그룹)
├─ 그룹 1: Leader Bot-1 + Follower Bot-2,3,4
│   └─ zu12.apk 기반 (Leader) + zcu12.apk 기반 (Follower)
│
├─ 그룹 2: Leader Bot-5 + Follower Bot-6,7
├─ 그룹 3: Leader Bot-8 + Follower Bot-9,10
├─ 그룹 4: Leader Bot-11 + Follower Bot-12,13
├─ 그룹 5: Leader Bot-14 + Follower Bot-15,16
└─ 그룹 6: Leader Bot-17 + Follower Bot-18

순위 체크 봇 (4개, 1개 그룹)
└─ 그룹 RC: Leader Bot-RC1 + Follower Bot-RC2,3,4
    └─ zru12.apk 기반 (범용 순위 체크 엔진)
```

### 봇 ↔ 서버 통신

#### A. 작업 요청 (30초마다 폴링)

```python
# Android 봇 코드 (Java)

public class TaskPoller extends HandlerThread {
    private static final String API_URL = "https://turafic-server.railway.app/api/v1/bot/task";
    private String botId;
    
    @Override
    public void onHandleMessage(Handler handler, Message msg) {
        // 1. 서버에 작업 요청
        String url = API_URL + "?bot_id=" + botId;
        String response = HttpUtils.get(url);
        
        if (response != null) {
            JSONObject task = new JSONObject(response);
            
            if (task.has("json_pattern")) {
                // 2. JSON 패턴 실행
                JSONObject pattern = task.getJSONObject("json_pattern");
                boolean success = ActionExecutor.execute(pattern);
                
                // 3. 결과 보고
                reportResult(task.getString("task_id"), success);
            }
        }
        
        // 4. 30초 후 다시 폴링
        handler.sendEmptyMessageDelayed(0, 30000);
    }
}
```

#### B. 결과 보고

```python
# Android 봇 코드 (Java)

public void reportResult(String taskId, boolean success) {
    String url = "https://turafic-server.railway.app/api/v1/bot/report";
    
    JSONObject report = new JSONObject();
    report.put("task_id", taskId);
    report.put("bot_id", botId);
    report.put("status", success ? "success" : "failed");
    report.put("duration", executionTime);
    
    // 스크린샷 Base64 인코딩
    if (screenshotPath != null) {
        byte[] imageBytes = Files.readAllBytes(Paths.get(screenshotPath));
        String base64 = Base64.getEncoder().encodeToString(imageBytes);
        report.put("screenshot", base64);
    }
    
    HttpUtils.post(url, report.toString());
}
```

---

## 🤖 LLM 통합

### ChatGPT-5 API 활용

#### 1. 실패 원인 분석

```python
# server/core/llm_clients.py

class ChatGPT5Client:
    
    def analyze_failure(self, campaign_data: dict) -> dict:
        """실패 원인 분석"""
        
        prompt = f"""
당신은 네이버 쇼핑 순위 최적화 전문가입니다.

다음 캠페인이 실패했습니다:
- 제품 ID: {campaign_data['product_id']}
- Before 순위: {campaign_data['before_rank']}위
- After 순위: {campaign_data['after_rank']}위
- 순위 개선: {campaign_data['rank_improvement']}위

18개 테스트 케이스 결과:
{json.dumps(campaign_data['test_case_results'], indent=2, ensure_ascii=False)}

**분석 요청:**
1. 어떤 변수가 순위 하락의 주요 원인인가?
2. 각 변수의 영향도는 얼마나 되는가? (0-10점)
3. 어떤 변수 조합이 가장 효과적일 것으로 예상되는가?

JSON 형식으로 답변해주세요:
{{
  "failure_causes": [
    {{
      "variable": "변수명",
      "reason": "실패 이유",
      "recommendation": "권장 사항",
      "impact_score": 0-10
    }}
  ],
  "best_combination_prediction": {{
    "platform": "...",
    "engagement": "...",
    ...
  }},
  "confidence": 0.0-1.0
}}
"""
        
        response = self.client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert in Naver Shopping ranking optimization."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        return json.loads(response.choices[0].message.content)
```

#### 2. 새로운 조합 생성

```python
def generate_new_combinations(
    self,
    failure_analysis: dict,
    tested_combinations: list
) -> list:
    """새로운 변수 조합 생성"""
    
    prompt = f"""
당신은 네이버 쇼핑 순위 최적화 전문가입니다.

**실패 분석 결과:**
{json.dumps(failure_analysis, indent=2, ensure_ascii=False)}

**이미 테스트한 조합:**
{json.dumps(tested_combinations, indent=2, ensure_ascii=False)}

**요청:**
실패 분석 결과를 바탕으로 새로운 변수 조합 18개를 생성해주세요.
- 이미 테스트한 조합은 제외
- 실패 원인을 개선한 조합 우선
- 창의적인 조합 포함

**변수 및 가능한 레벨:**
- platform: PC, Mobile
- engagement: High, Medium, Low
- user_agent: Samsung, LG, Generic
- cookie: Enabled, Disabled
- http_headers: Real, Fake
- entry_path: Naver Search, Shopping Direct
- ip_strategy: Per Traffic, Per Session

JSON 형식으로 답변해주세요:
{{
  "combinations": [
    {{
      "platform": "...",
      "engagement": "...",
      "user_agent": "...",
      "cookie": "...",
      "http_headers": "...",
      "entry_path": "...",
      "ip_strategy": "...",
      "rationale": "이 조합을 선택한 이유"
    }}
  ]
}}
"""
    
    response = self.client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role": "system", "content": "You are an expert in Naver Shopping ranking optimization."},
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"},
        temperature=0.7  # 창의성을 위해 temperature 높임
    )
    
    result = json.loads(response.choices[0].message.content)
    return result["combinations"]
```

### Claude API 활용

#### 1. 코드 디버깅

```python
# server/core/llm_clients.py

class ClaudeClient:
    
    def debug_error(self, error_log: dict) -> dict:
        """봇 에러 디버깅"""
        
        prompt = f"""
당신은 Android 봇 디버깅 전문가입니다.

다음 봇에서 에러가 발생했습니다:
- Bot ID: {error_log['bot_id']}
- Error Type: {error_log['error_type']}
- Error Message: {error_log['error_message']}
- Timestamp: {error_log['timestamp']}

**스크린샷:**
{error_log.get('screenshot', 'N/A')}

**분석 요청:**
1. 에러 원인은 무엇인가?
2. 자동으로 수정 가능한가?
3. 수정 방법은 무엇인가?

JSON 형식으로 답변해주세요:
{{
  "error_cause": "에러 원인",
  "auto_fixable": true/false,
  "fix_action": {{
    "type": "restart_bot | update_json_pattern | change_ip | manual_intervention",
    "new_pattern": {{...}} (if type == update_json_pattern)
  }},
  "explanation": "상세 설명"
}}
"""
        
        response = self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=2048,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return json.loads(response.content[0].text)
```

---

## 🚀 구현 로드맵

### Phase 1: 서버 에이전트 구현 (7일)

| 에이전트 | 소요 시간 | 상태 |
|---------|----------|------|
| **Control Tower Agent** | 2일 | ⏳ 대기 |
| **Traffic Agent** | 2일 | ⏳ 대기 |
| **Monitoring Agent** | 2일 | ⏳ 대기 |
| **Analytics Agent** | 1일 | ⏳ 대기 |

### Phase 2: LLM 통합 (2일)

| 작업 | 소요 시간 | 상태 |
|------|----------|------|
| **ChatGPT-5 클라이언트** | 1일 | ⏳ 대기 |
| **Claude 클라이언트** | 1일 | ⏳ 대기 |

### Phase 3: Android 봇 구현 (10일)

| 작업 | 소요 시간 | 상태 |
|------|----------|------|
| **MVP (서버 API + Root 탭)** | 3일 | ⏳ 대기 |
| **9가지 기본 액션** | 2일 | ⏳ 대기 |
| **핫스팟 기능** | 2일 | ⏳ 대기 |
| **순위 체크 봇 통합** | 1일 | ⏳ 대기 |
| **통합 테스트** | 2일 | ⏳ 대기 |

### Phase 4: 피드백 루프 통합 (3일)

| 작업 | 소요 시간 | 상태 |
|------|----------|------|
| **피드백 트리거 로직** | 1일 | ⏳ 대기 |
| **새 조합 생성 및 재시도** | 1일 | ⏳ 대기 |
| **반복 횟수 제한 및 안전장치** | 1일 | ⏳ 대기 |

### Phase 5: 대시보드 연동 (2일)

| 작업 | 소요 시간 | 상태 |
|------|----------|------|
| **WebSocket 실시간 업데이트** | 1일 | ⏳ 대기 |
| **LLM 인사이트 표시** | 1일 | ⏳ 대기 |

---

**총 소요 시간: 24일 (약 1개월)**

---

## 🎯 핵심 요약

### 1. 4-Agent 아키텍처
- **Control Tower**: 두뇌 (캠페인 생성, 에러 분석, 의사결정, LLM 통합)
- **Traffic Agent**: 봇 관리 (작업 할당, IP 변경, JSON 패턴 생성)
- **Monitoring Agent**: 순위 체크 (이상 탐지, WebSocket 업데이트)
- **Analytics Agent**: 분석 (ANOVA, 실패 원인 분석, 최적 조합)

### 2. 자기학습 피드백 루프
1. 캠페인 실행 (L18 테스트 케이스)
2. 순위 모니터링 (30분마다)
3. 결과 분석 (ANOVA)
4. 실패 시 → ChatGPT-5로 원인 분석
5. 새로운 조합 생성 (ChatGPT-5)
6. 재시도 (최대 5회)

### 3. Android 봇 통합
- **70% 재사용**: 기존 APK (zu12, zcu12, zru12)
- **30% 신규**: 핫스팟 제어, JSON 패턴 실행
- **3가지 봇 타입**: Leader, Follower, Rank Checker

### 4. LLM 통합
- **ChatGPT-5**: 실패 원인 분석, 새 조합 생성, 리포트
- **Claude**: 코드 디버깅, 전략 수립, 데이터 검증

---

**다음 단계**: Phase 1 (서버 에이전트 구현) 시작!
