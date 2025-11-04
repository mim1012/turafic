# Turafic 4-Agent 자동화 아키텍처

## 🎯 개요

**컨트롤 타워**를 중심으로 4개의 전문 에이전트가 협력하여 완전 자동화된 트래픽 캠페인 시스템을 구축합니다.

---

## 📊 4-Agent 구조

```
                    ┌─────────────────────────────────┐
                    │   Control Tower Agent           │
                    │   (캠페인 및 원인 분석 디버깅)    │
                    │   - 캠페인 생성 및 관리          │
                    │   - 전체 시스템 조율             │
                    │   - 에러 분석 및 디버깅          │
                    │   - 의사결정                    │
                    └──────────┬──────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Traffic Agent    │  │ Monitoring Agent │  │ Analytics Agent  │
│ (트래픽 담당)     │  │ (모니터링 담당)   │  │ (통계분석 담당)   │
│                  │  │                  │  │                  │
│ - 봇 관리        │  │ - 순위 체크      │  │ - ANOVA 분석     │
│ - 작업 할당      │  │ - 실시간 모니터링│  │ - 최적 조합 도출 │
│ - IP 변경        │  │ - 이상 탐지      │  │ - 리포트 생성    │
└──────────────────┘  └──────────────────┘  └──────────────────┘
          │                    │                    │
          └────────────────────┼────────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │  PostgreSQL + Redis │
                    └─────────────────────┘
```

---

## 🏢 Agent 1: Control Tower Agent (핵심 컨트롤 타워)

### 역할
- ✅ **캠페인 생성 및 관리**: L18 테스트 케이스 생성, JSON 패턴 생성
- ✅ **전체 시스템 조율**: 다른 3개 에이전트 조율 및 명령
- ✅ **에러 분석 및 디버깅**: 실패 원인 분석, 자동 복구
- ✅ **의사결정**: 캠페인 중단/재시작 결정

### 자동화 기능

#### 1. 캠페인 자동 생성
```python
# 사용자가 제품 URL만 입력하면 자동으로 캠페인 생성
def auto_create_campaign(product_url: str) -> Campaign:
    """제품 URL로부터 자동으로 캠페인 생성"""
    
    # 1. 네이버 상품 ID 추출
    naver_product_id = extract_product_id(product_url)
    
    # 2. 상품 정보 크롤링
    product_info = crawl_product_info(naver_product_id)
    keyword = product_info["title"]  # 상품명을 키워드로 사용
    
    # 3. L18 테스트 케이스 생성
    test_cases = generate_l18_test_cases(naver_product_id, keyword)
    
    # 4. JSON 패턴 생성
    for test_case in test_cases:
        test_case["pattern"] = generate_json_pattern(
            test_case["variables"],
            naver_product_id,
            keyword
        )
    
    # 5. 캠페인 DB에 저장
    campaign = Campaign(
        campaign_id=f"camp-{uuid.uuid4()}",
        product_id=naver_product_id,
        product_url=product_url,
        keyword=keyword,
        test_cases=test_cases,
        status="ready"
    )
    db.add(campaign)
    db.commit()
    
    return campaign
```

#### 2. 자동 에러 분석 및 복구
```python
def auto_debug_and_recover():
    """실패한 작업 자동 분석 및 복구"""
    
    while True:
        # 1. 실패한 작업 조회
        failed_tasks = db.query(Task).filter(Task.status == "failed").all()
        
        for task in failed_tasks:
            # 2. 에러 원인 분석
            error_type = analyze_error(task.error_message)
            
            # 3. 자동 복구 시도
            if error_type == "network_timeout":
                # 네트워크 타임아웃 → 재시도
                task.status = "assigned"
                task.retry_count += 1
                db.commit()
                
                log.info(f"Task {task.task_id} auto-recovered (network timeout)")
                
            elif error_type == "root_permission_denied":
                # Root 권한 거부 → 봇 오프라인 처리
                bot = db.query(Bot).filter(Bot.bot_id == task.bot_id).first()
                bot.status = "offline"
                db.commit()
                
                # 다른 봇에게 재할당
                reassign_task_to_another_bot(task)
                
                log.warning(f"Bot {bot.bot_id} marked offline, task reassigned")
                
            elif error_type == "product_not_found":
                # 상품을 찾을 수 없음 → 캠페인 중단
                campaign = db.query(Campaign).filter(
                    Campaign.campaign_id == task.campaign_id
                ).first()
                campaign.status = "failed"
                campaign.error_message = "Product not found in search results"
                db.commit()
                
                log.error(f"Campaign {campaign.campaign_id} failed (product not found)")
                
            else:
                # 알 수 없는 에러 → 관리자에게 알림
                send_admin_notification(task, error_type)
        
        # 5분마다 체크
        time.sleep(300)
```

#### 3. 자동 의사결정
```python
def auto_decision_making():
    """실시간 데이터 기반 자동 의사결정"""
    
    while True:
        # 1. 진행 중인 캠페인 조회
        running_campaigns = db.query(Campaign).filter(
            Campaign.status == "running"
        ).all()
        
        for campaign in running_campaigns:
            # 2. 진행률 계산
            total_tasks = len(campaign.test_cases) * campaign.traffic_count
            completed_tasks = db.query(Task).filter(
                Task.campaign_id == campaign.campaign_id,
                Task.status == "completed"
            ).count()
            
            progress = (completed_tasks / total_tasks) * 100
            
            # 3. 실시간 순위 체크
            current_rank = get_current_rank(campaign.product_id, campaign.keyword)
            before_rank = get_rank_before_campaign(campaign.product_id, campaign.started_at)
            
            # 4. 의사결정
            if progress >= 50 and current_rank > before_rank:
                # 50% 진행했는데 순위가 오히려 하락 → 캠페인 중단
                campaign.status = "stopped"
                campaign.stop_reason = "Rank decreased despite 50% progress"
                db.commit()
                
                log.warning(f"Campaign {campaign.campaign_id} auto-stopped (rank decreased)")
                
            elif progress >= 30 and current_rank < before_rank - 10:
                # 30% 진행했는데 순위가 10위 이상 상승 → 트래픽 증가
                campaign.traffic_count = int(campaign.traffic_count * 1.5)
                db.commit()
                
                log.info(f"Campaign {campaign.campaign_id} traffic increased (good progress)")
        
        # 10분마다 체크
        time.sleep(600)
```

### API 엔드포인트

#### 1. 자동 캠페인 생성
```http
POST /api/v1/control/auto_create_campaign
Content-Type: application/json

{
  "product_url": "https://shopping.naver.com/products/87654321"
}

Response:
{
  "campaign_id": "camp-001",
  "product_id": "87654321",
  "keyword": "삼성 갤럭시 S24 256GB",
  "test_cases_count": 18,
  "status": "ready",
  "estimated_duration": "12 hours"
}
```

#### 2. 캠페인 자동 시작
```http
POST /api/v1/control/auto_start_campaign
Content-Type: application/json

{
  "campaign_id": "camp-001"
}

Response:
{
  "campaign_id": "camp-001",
  "status": "running",
  "assigned_bots": 18,
  "estimated_completion": "2025-11-01T24:00:00Z"
}
```

#### 3. 시스템 상태 조회
```http
GET /api/v1/control/system_status

Response:
{
  "total_campaigns": 5,
  "running_campaigns": 2,
  "completed_campaigns": 3,
  "total_bots": 22,
  "active_bots": 18,
  "offline_bots": 4,
  "system_health": "healthy",
  "last_error": null
}
```

---

## 🚀 Agent 2: Traffic Agent (트래픽 담당)

### 역할
- ✅ **봇 관리**: 봇 등록, 상태 관리, 그룹 관리
- ✅ **작업 할당**: "1봇 = 1캠페인 전담" 로직
- ✅ **IP 변경**: 5분 주기 IP 로테이션 (대장 봇)
- ✅ **작업 결과 수집**: 봇으로부터 결과 수집

### 자동화 기능

#### 1. 봇 자동 등록 및 그룹 할당
```python
def auto_register_bot(android_id: str, device_model: str) -> Bot:
    """봇 자동 등록 및 그룹 할당"""
    
    # 1. 기존 봇 확인
    existing_bot = db.query(Bot).filter(Bot.android_id == android_id).first()
    if existing_bot:
        return existing_bot
    
    # 2. 역할 자동 결정
    # 트래픽 봇 수 확인
    traffic_bots_count = db.query(Bot).filter(
        Bot.role.in_(["leader", "follower"])
    ).count()
    
    # 순위 체크 봇 수 확인
    rank_checker_bots_count = db.query(Bot).filter(
        Bot.role == "rank_checker"
    ).count()
    
    # 트래픽 봇 18개, 순위 체크 봇 4개 목표
    if traffic_bots_count < 18:
        # 트래픽 봇으로 등록
        group_id = f"group-{(traffic_bots_count // 3) + 1}"  # 3개씩 그룹
        is_leader = (traffic_bots_count % 3 == 0)  # 그룹의 첫 번째 봇은 대장
        role = "leader" if is_leader else "follower"
    else:
        # 순위 체크 봇으로 등록
        group_id = "group-rc"
        is_leader = (rank_checker_bots_count == 0)  # 첫 번째 봇은 대장
        role = "rank_checker"
    
    # 3. 봇 생성
    bot = Bot(
        bot_id=f"bot-{uuid.uuid4()}",
        android_id=android_id,
        device_model=device_model,
        role=role,
        is_leader=is_leader,
        group_id=group_id,
        status="idle"
    )
    
    db.add(bot)
    db.commit()
    
    log.info(f"Bot {bot.bot_id} auto-registered as {role} in {group_id}")
    
    return bot
```

#### 2. 작업 자동 할당
```python
def auto_assign_tasks():
    """Control Tower로부터 명령 받아 작업 자동 할당"""
    
    while True:
        # 1. 시작 대기 중인 캠페인 조회
        ready_campaigns = db.query(Campaign).filter(
            Campaign.status == "ready"
        ).all()
        
        for campaign in ready_campaigns:
            # 2. 사용 가능한 봇 조회 (idle 상태)
            available_bots = db.query(Bot).filter(
                Bot.status == "idle",
                Bot.role.in_(["leader", "follower"])
            ).limit(18).all()
            
            if len(available_bots) < 18:
                log.warning(f"Not enough bots for campaign {campaign.campaign_id}")
                continue
            
            # 3. 캠페인 시작
            campaign.status = "running"
            campaign.started_at = datetime.now()
            db.commit()
            
            # 4. 각 봇에게 테스트 케이스 할당
            for i, bot in enumerate(available_bots):
                test_case = campaign.test_cases[i]
                
                # 봇에게 캠페인 할당
                bot.status = "working"
                bot.assigned_campaign_id = campaign.campaign_id
                campaign.assigned_bot_id = bot.bot_id
                db.commit()
                
                log.info(f"Bot {bot.bot_id} assigned to {test_case['test_case_id']}")
        
        # 1분마다 체크
        time.sleep(60)
```

#### 3. IP 변경 자동 스케줄링
```python
def auto_ip_rotation():
    """대장 봇의 IP 변경 자동 스케줄링"""
    
    while True:
        # 5분 대기
        time.sleep(300)
        
        # 모든 대장 봇 조회
        leader_bots = db.query(Bot).filter(Bot.is_leader == True).all()
        
        for leader_bot in leader_bots:
            # 쫄병 봇들의 작업 상태 확인
            subordinates = db.query(Bot).filter(
                Bot.group_id == leader_bot.group_id,
                Bot.is_leader == False
            ).all()
            
            # 모든 쫄병 봇이 작업 완료했는지 확인
            all_completed = all(
                bot.status == "idle" or 
                (bot.last_task_completed and 
                 (datetime.now() - bot.last_task_completed).seconds < 60)
                for bot in subordinates
            )
            
            # 최대 대기 시간 초과 확인 (3분)
            time_exceeded = (
                leader_bot.last_ip_change and
                (datetime.now() - leader_bot.last_ip_change).seconds > 180
            )
            
            if all_completed or time_exceeded:
                # IP 변경 명령 생성
                ip_change_task = Task(
                    task_id=f"ip-change-{uuid.uuid4()}",
                    bot_id=leader_bot.bot_id,
                    pattern=[
                        {"action": "airplane_mode_toggle", "duration": 8000}
                    ],
                    status="assigned"
                )
                
                db.add(ip_change_task)
                leader_bot.last_ip_change = datetime.now()
                db.commit()
                
                log.info(f"IP change scheduled for {leader_bot.bot_id}")
```

### API 엔드포인트

#### 1. 봇 자동 등록
```http
POST /api/v1/traffic/auto_register_bot
Content-Type: application/json

{
  "android_id": "abc123def456",
  "device_model": "Samsung Galaxy S21"
}

Response:
{
  "bot_id": "bot-001",
  "role": "leader",
  "group_id": "group-1",
  "status": "idle"
}
```

#### 2. 작업 요청 (봇이 호출)
```http
GET /api/v1/traffic/get_task?bot_id=bot-001

Response:
{
  "task_id": "task-001",
  "campaign_id": "camp-001",
  "test_case_id": "TC#1",
  "pattern": [...],
  "repeat_count": 100,
  "current_iteration": 1
}
```

---

## 📊 Agent 3: Monitoring Agent (모니터링 담당)

### 역할
- ✅ **순위 체크**: 순위 체크 봇으로부터 데이터 수집
- ✅ **실시간 모니터링**: 캠페인 진행 상황 실시간 추적
- ✅ **이상 탐지**: 순위 급락, 봇 오프라인 등 이상 감지
- ✅ **알림**: Control Tower에게 이상 알림

### 자동화 기능

#### 1. 자동 순위 체크 스케줄링
```python
def auto_rank_checking():
    """순위 체크 봇에게 자동으로 순위 체크 명령"""
    
    while True:
        # 1. 진행 중인 캠페인 조회
        running_campaigns = db.query(Campaign).filter(
            Campaign.status == "running"
        ).all()
        
        for campaign in running_campaigns:
            # 2. 순위 체크 봇 조회
            rank_checker_bots = db.query(Bot).filter(
                Bot.role == "rank_checker",
                Bot.status == "idle"
            ).limit(4).all()
            
            if not rank_checker_bots:
                log.warning("No rank checker bots available")
                continue
            
            # 3. 각 봇에게 순위 체크 명령
            for bot in rank_checker_bots:
                rank_check_task = Task(
                    task_id=f"rank-check-{uuid.uuid4()}",
                    bot_id=bot.bot_id,
                    campaign_id=campaign.campaign_id,
                    pattern=[
                        {"action": "check_ranking", 
                         "naver_product_id": campaign.naver_product_id,
                         "keyword": campaign.keyword}
                    ],
                    status="assigned"
                )
                
                db.add(rank_check_task)
                bot.status = "working"
                db.commit()
                
                log.info(f"Rank check scheduled for {campaign.campaign_id}")
        
        # 30분마다 체크
        time.sleep(1800)
```

#### 2. 실시간 이상 탐지
```python
def auto_anomaly_detection():
    """실시간 이상 탐지 및 알림"""
    
    while True:
        # 1. 순위 급락 감지
        recent_rankings = db.query(Ranking).filter(
            Ranking.checked_at >= datetime.now() - timedelta(hours=1)
        ).all()
        
        for ranking in recent_rankings:
            # 1시간 전 순위와 비교
            previous_rank = get_rank_1hour_ago(ranking.product_id, ranking.keyword)
            
            if previous_rank and ranking.rank > previous_rank + 10:
                # 10위 이상 급락 → Control Tower에게 알림
                send_alert_to_control_tower(
                    alert_type="rank_drop",
                    product_id=ranking.product_id,
                    previous_rank=previous_rank,
                    current_rank=ranking.rank
                )
                
                log.warning(f"Rank drop detected: {ranking.product_id} ({previous_rank} → {ranking.rank})")
        
        # 2. 봇 오프라인 감지
        offline_bots = db.query(Bot).filter(
            Bot.status == "working",
            Bot.last_active_at < datetime.now() - timedelta(minutes=10)
        ).all()
        
        for bot in offline_bots:
            # 10분 이상 응답 없음 → 오프라인 처리
            bot.status = "offline"
            db.commit()
            
            # Control Tower에게 알림
            send_alert_to_control_tower(
                alert_type="bot_offline",
                bot_id=bot.bot_id,
                last_active=bot.last_active_at
            )
            
            log.error(f"Bot offline detected: {bot.bot_id}")
        
        # 3. 캠페인 지연 감지
        delayed_campaigns = db.query(Campaign).filter(
            Campaign.status == "running",
            Campaign.started_at < datetime.now() - timedelta(hours=24)
        ).all()
        
        for campaign in delayed_campaigns:
            # 24시간 이상 진행 중 → 이상
            send_alert_to_control_tower(
                alert_type="campaign_delayed",
                campaign_id=campaign.campaign_id,
                started_at=campaign.started_at
            )
            
            log.warning(f"Campaign delayed: {campaign.campaign_id}")
        
        # 5분마다 체크
        time.sleep(300)
```

#### 3. 실시간 대시보드 데이터 생성
```python
def auto_generate_dashboard_data():
    """실시간 대시보드 데이터 자동 생성 (Redis 캐시)"""
    
    while True:
        # 1. 시스템 전체 통계
        dashboard_data = {
            "timestamp": datetime.now().isoformat(),
            "campaigns": {
                "total": db.query(Campaign).count(),
                "running": db.query(Campaign).filter(Campaign.status == "running").count(),
                "completed": db.query(Campaign).filter(Campaign.status == "completed").count(),
                "failed": db.query(Campaign).filter(Campaign.status == "failed").count()
            },
            "bots": {
                "total": db.query(Bot).count(),
                "active": db.query(Bot).filter(Bot.status == "working").count(),
                "idle": db.query(Bot).filter(Bot.status == "idle").count(),
                "offline": db.query(Bot).filter(Bot.status == "offline").count()
            },
            "tasks": {
                "total": db.query(Task).count(),
                "completed": db.query(Task).filter(Task.status == "completed").count(),
                "failed": db.query(Task).filter(Task.status == "failed").count()
            }
        }
        
        # 2. 진행 중인 캠페인 상세
        running_campaigns = db.query(Campaign).filter(
            Campaign.status == "running"
        ).all()
        
        dashboard_data["running_campaigns_detail"] = []
        for campaign in running_campaigns:
            total_tasks = len(campaign.test_cases) * campaign.traffic_count
            completed_tasks = db.query(Task).filter(
                Task.campaign_id == campaign.campaign_id,
                Task.status == "completed"
            ).count()
            
            progress = (completed_tasks / total_tasks) * 100
            
            dashboard_data["running_campaigns_detail"].append({
                "campaign_id": campaign.campaign_id,
                "product_id": campaign.product_id,
                "keyword": campaign.keyword,
                "progress": progress,
                "completed_tasks": completed_tasks,
                "total_tasks": total_tasks,
                "started_at": campaign.started_at.isoformat()
            })
        
        # 3. Redis에 캐시 (1분 TTL)
        redis_client.setex(
            "dashboard_data",
            60,
            json.dumps(dashboard_data)
        )
        
        # 30초마다 업데이트
        time.sleep(30)
```

### API 엔드포인트

#### 1. 순위 보고 (순위 체크 봇이 호출)
```http
POST /api/v1/monitoring/report_ranking
Content-Type: application/json

{
  "bot_id": "bot-rc-001",
  "product_id": "87654321",
  "keyword": "삼성 갤럭시 S24",
  "rank": 28,
  "page": 2,
  "position": 8
}

Response:
{
  "message": "Ranking recorded",
  "rank_id": "rank-001"
}
```

#### 2. 실시간 대시보드 데이터 조회
```http
GET /api/v1/monitoring/dashboard

Response:
{
  "timestamp": "2025-11-01T12:00:00Z",
  "campaigns": {
    "total": 10,
    "running": 2,
    "completed": 7,
    "failed": 1
  },
  "bots": {
    "total": 22,
    "active": 18,
    "idle": 2,
    "offline": 2
  },
  "running_campaigns_detail": [...]
}
```

---

## 📈 Agent 4: Analytics Agent (통계분석 담당)

### 역할
- ✅ **ANOVA 분석**: L18 테스트 결과 통계 분석
- ✅ **최적 조합 도출**: 유의미한 변수 및 최적 레벨 찾기
- ✅ **리포트 생성**: PDF 리포트 자동 생성
- ✅ **예측**: 다음 캠페인 결과 예측

### 자동화 기능

#### 1. 캠페인 완료 시 자동 분석
```python
def auto_analyze_on_completion():
    """캠페인 완료 시 자동으로 ANOVA 분석 실행"""
    
    while True:
        # 1. 완료된 캠페인 중 분석 안 된 것 조회
        completed_campaigns = db.query(Campaign).filter(
            Campaign.status == "completed",
            Campaign.analyzed == False
        ).all()
        
        for campaign in completed_campaigns:
            try:
                # 2. ANOVA 분석 실행
                anova_results = perform_anova(campaign.campaign_id)
                
                # 3. 최적 조합 도출
                best_combo = find_best_combination(campaign.campaign_id)
                
                # 4. 리포트 생성
                report_path = generate_report(campaign.campaign_id)
                
                # 5. Analytics 테이블에 저장
                analysis = Analytics(
                    analysis_id=f"analysis-{uuid.uuid4()}",
                    campaign_id=campaign.campaign_id,
                    before_rank=get_rank_before_campaign(
                        campaign.product_id, campaign.started_at
                    ),
                    after_rank=get_rank_after_campaign(
                        campaign.product_id, campaign.completed_at
                    ),
                    anova_results=anova_results,
                    best_combination=best_combo,
                    report_url=report_path
                )
                
                db.add(analysis)
                campaign.analyzed = True
                db.commit()
                
                # 6. Control Tower에게 알림
                send_alert_to_control_tower(
                    alert_type="analysis_completed",
                    campaign_id=campaign.campaign_id,
                    report_url=report_path
                )
                
                log.info(f"Analysis completed for {campaign.campaign_id}")
                
            except Exception as e:
                log.error(f"Analysis failed for {campaign.campaign_id}: {e}")
        
        # 5분마다 체크
        time.sleep(300)
```

#### 2. 자동 예측
```python
def auto_predict_next_campaign():
    """과거 캠페인 데이터 기반 다음 캠페인 결과 예측"""
    
    # 1. 모든 분석 결과 조회
    all_analyses = db.query(Analytics).all()
    
    if len(all_analyses) < 3:
        log.warning("Not enough data for prediction")
        return None
    
    # 2. 데이터프레임 생성
    data = []
    for analysis in all_analyses:
        best_combo = analysis.best_combination
        rank_improvement = analysis.before_rank - analysis.after_rank
        
        data.append({
            **best_combo,
            "rank_improvement": rank_improvement
        })
    
    df = pd.DataFrame(data)
    
    # 3. 선형 회귀 모델 학습
    from sklearn.linear_model import LinearRegression
    from sklearn.preprocessing import LabelEncoder
    
    # 범주형 변수 인코딩
    encoders = {}
    for col in df.columns:
        if col != "rank_improvement":
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le
    
    X = df.drop("rank_improvement", axis=1)
    y = df["rank_improvement"]
    
    model = LinearRegression()
    model.fit(X, y)
    
    # 4. 예측 함수 반환
    def predict(variables: dict) -> float:
        """변수 조합으로 순위 개선 예측"""
        
        # 인코딩
        encoded_vars = {}
        for key, value in variables.items():
            if key in encoders:
                encoded_vars[key] = encoders[key].transform([value])[0]
        
        # 예측
        X_pred = pd.DataFrame([encoded_vars])
        predicted_improvement = model.predict(X_pred)[0]
        
        return predicted_improvement
    
    return predict
```

#### 3. 자동 리포트 생성 및 전송
```python
def auto_generate_and_send_report():
    """캠페인 완료 시 자동으로 리포트 생성 및 이메일 전송"""
    
    while True:
        # 1. 리포트 생성 안 된 분석 조회
        analyses = db.query(Analytics).filter(
            Analytics.report_sent == False
        ).all()
        
        for analysis in analyses:
            try:
                # 2. PDF 리포트 생성
                report_path = generate_report(analysis.campaign_id)
                
                # 3. S3에 업로드 (선택사항)
                report_url = upload_to_s3(report_path)
                
                # 4. 이메일 전송 (선택사항)
                campaign = db.query(Campaign).filter(
                    Campaign.campaign_id == analysis.campaign_id
                ).first()
                
                send_email(
                    to=campaign.user_email,
                    subject=f"Campaign {campaign.campaign_id} Analysis Report",
                    body=f"Your campaign analysis is complete. Report: {report_url}",
                    attachments=[report_path]
                )
                
                # 5. 상태 업데이트
                analysis.report_url = report_url
                analysis.report_sent = True
                db.commit()
                
                log.info(f"Report sent for {analysis.campaign_id}")
                
            except Exception as e:
                log.error(f"Report generation failed for {analysis.campaign_id}: {e}")
        
        # 10분마다 체크
        time.sleep(600)
```

### API 엔드포인트

#### 1. 자동 분석 트리거
```http
POST /api/v1/analytics/auto_analyze/{campaign_id}

Response:
{
  "campaign_id": "camp-001",
  "analysis_status": "in_progress",
  "estimated_completion": "2025-11-01T12:10:00Z"
}
```

#### 2. 예측
```http
POST /api/v1/analytics/predict
Content-Type: application/json

{
  "variables": {
    "platform": "Mobile",
    "engagement": "High",
    "user_agent": "Samsung",
    // ... 7개 변수
  }
}

Response:
{
  "predicted_rank_improvement": 18.5,
  "confidence": 0.85
}
```

---

## 🔄 4-Agent 자동화 워크플로우

### 전체 자동화 프로세스

```
사용자: 제품 URL 입력
   ↓
Control Tower: 자동 캠페인 생성 (L18 테스트 케이스, JSON 패턴)
   ↓
Monitoring: Before 순위 체크
   ↓
Control Tower: 캠페인 시작 명령
   ↓
Traffic: 18개 봇에게 자동 작업 할당
   ↓
Traffic: 5분마다 IP 변경 (대장 봇)
   ↓
Monitoring: 30분마다 순위 체크, 이상 탐지
   ↓
Control Tower: 실시간 의사결정 (중단/계속/트래픽 증가)
   ↓
Traffic: 작업 완료 시 결과 수집
   ↓
Monitoring: After 순위 체크
   ↓
Analytics: 자동 ANOVA 분석, 최적 조합 도출
   ↓
Analytics: 리포트 생성 및 이메일 전송
   ↓
Control Tower: 다음 캠페인 자동 생성 (최적 조합 적용)
```

---

## 🎯 완전 자동화 시나리오

### Day 1 00:00 - 사용자 요청
```
사용자: "https://shopping.naver.com/products/87654321" 입력
```

### Day 1 00:01 - Control Tower 자동 처리
```
Control Tower:
  1. 네이버 상품 ID 추출: 87654321
  2. 상품 정보 크롤링: "삼성 갤럭시 S24 256GB"
  3. L18 테스트 케이스 18개 생성
  4. JSON 패턴 18개 생성
  5. 캠페인 DB에 저장 (status = "ready")
```

### Day 1 00:02 - Monitoring 자동 순위 체크
```
Monitoring:
  1. 순위 체크 봇 4개에게 명령
  2. Before 순위: 45위 (기준선)
```

### Day 1 00:05 - Control Tower 캠페인 시작
```
Control Tower:
  1. 캠페인 시작 명령 (status = "running")
```

### Day 1 00:06 - Traffic 자동 작업 할당
```
Traffic:
  1. 18개 봇 자동 등록 확인
  2. Bot-1 → TC#1 할당
  3. Bot-2 → TC#2 할당
  ...
  4. Bot-18 → TC#18 할당
  5. JSON 패턴 전송
```

### Day 1 00:10 - Traffic IP 변경 시작
```
Traffic:
  1. 대장 봇 6개 (group-1 ~ group-6)
  2. 5분마다 비행기 모드 토글
  3. 쫄병 봇들 자동 IP 변경
```

### Day 1 06:00 - Monitoring 순위 체크
```
Monitoring:
  1. 30분마다 순위 체크
  2. 현재 순위: 38위 (7위 상승)
  3. Control Tower에게 보고: "Good progress"
```

### Day 1 12:00 - Control Tower 의사결정
```
Control Tower:
  1. 진행률: 50%
  2. 순위: 32위 (13위 상승)
  3. 의사결정: "Continue" (계속 진행)
```

### Day 1 18:00 - 작업 완료
```
Traffic:
  1. 18개 봇 모두 100회 완료
  2. 캠페인 완료 (status = "completed")
```

### Day 1 18:30 - Monitoring After 순위 체크
```
Monitoring:
  1. After 순위 체크
  2. 최종 순위: 28위 (17위 상승!)
```

### Day 1 18:35 - Analytics 자동 분석
```
Analytics:
  1. ANOVA 분석 실행
  2. 유의미한 변수: engagement, user_agent
  3. 최적 조합: High engagement + Samsung User-Agent
  4. 예상 개선: 22위
```

### Day 1 18:40 - Analytics 리포트 생성
```
Analytics:
  1. PDF 리포트 생성
  2. S3에 업로드
  3. 이메일 전송
```

### Day 1 18:45 - Control Tower 다음 캠페인 자동 생성
```
Control Tower:
  1. 최적 조합 적용한 새 캠페인 생성
  2. 사용자에게 알림: "Next campaign ready with optimized settings"
```

---

## 🚀 구현 우선순위

### Phase 1: Control Tower Agent (3일)
1. ✅ 자동 캠페인 생성
2. ✅ 자동 에러 분석 및 복구
3. ✅ 자동 의사결정
4. ✅ 시스템 상태 조회 API

### Phase 2: Traffic Agent (3일)
1. ✅ 봇 자동 등록 및 그룹 할당
2. ✅ 작업 자동 할당
3. ✅ IP 변경 자동 스케줄링
4. ✅ 작업 결과 자동 수집

### Phase 3: Monitoring Agent (2일)
1. ✅ 자동 순위 체크 스케줄링
2. ✅ 실시간 이상 탐지
3. ✅ 실시간 대시보드 데이터 생성

### Phase 4: Analytics Agent (2일)
1. ✅ 캠페인 완료 시 자동 분석
2. ✅ 자동 예측
3. ✅ 자동 리포트 생성 및 전송

### Phase 5: 통합 및 테스트 (2일)
1. ✅ 4개 에이전트 통합
2. ✅ 완전 자동화 테스트
3. ✅ 버그 수정

**총 소요 시간: 약 12일**

---

## 🎓 결론

### 4-Agent 자동화의 핵심

**완전 자동화**:
- ✅ 사용자는 제품 URL만 입력
- ✅ 나머지 모든 과정 자동 실행
- ✅ 결과 리포트 자동 생성 및 전송

**장점**:
1. ✅ **Control Tower**: 전체 시스템 조율 및 의사결정
2. ✅ **Traffic**: 봇 관리 및 작업 할당 자동화
3. ✅ **Monitoring**: 실시간 모니터링 및 이상 탐지
4. ✅ **Analytics**: 자동 분석 및 예측

**다음 단계**:
1. Control Tower Agent 구현
2. Traffic Agent 구현
3. Monitoring Agent 구현
4. Analytics Agent 구현
5. 통합 테스트 및 완전 자동화 검증
