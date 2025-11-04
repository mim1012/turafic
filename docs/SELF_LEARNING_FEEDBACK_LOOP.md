# Turafic 자가 학습 피드백 루프 시스템

## 🎯 개요

**자가 학습 피드백 루프**는 실패한 변수 조합을 자동으로 분석하고, 새로운 조합을 생성하여 지속적으로 최적화하는 시스템입니다.

---

## 🔄 피드백 루프 메커니즘

```
트래픽 봇 실행 (특정 변수 조합)
   ↓
통계분석 봇: 순위 트래킹 결과 분석
   ↓
순위 오르지 않음 감지
   ↓
Analytics Agent: 실패 원인 분석
   ↓
Control Tower: 디버깅 및 새로운 변수 조합 생성
   ↓
현재 캠페인 목록에 없는 조합인지 확인
   ↓
새로운 캠페인 생성 및 봇에게 할당
   ↓
반복 (최적 조합 발견까지)
```

---

## 📊 실패 판정 기준

### 1. 순위 개선 없음
```python
def is_campaign_failed(campaign_id: str) -> bool:
    """캠페인 실패 여부 판정"""
    
    # Before/After 순위 조회
    before_rank = get_rank_before_campaign(campaign_id)
    after_rank = get_rank_after_campaign(campaign_id)
    
    # 실패 기준
    if after_rank >= before_rank:
        # 순위가 전혀 오르지 않음
        return True
    
    if (before_rank - after_rank) < 5:
        # 순위가 5위 미만으로 상승 (미미한 개선)
        return True
    
    return False
```

### 2. 순위 하락
```python
def is_rank_decreased(campaign_id: str) -> bool:
    """순위 하락 여부 판정"""
    
    before_rank = get_rank_before_campaign(campaign_id)
    after_rank = get_rank_after_campaign(campaign_id)
    
    if after_rank > before_rank:
        # 순위가 오히려 하락
        return True
    
    return False
```

### 3. 비용 대비 효율 낮음
```python
def is_low_efficiency(campaign_id: str) -> bool:
    """비용 대비 효율 낮음 판정"""
    
    before_rank = get_rank_before_campaign(campaign_id)
    after_rank = get_rank_after_campaign(campaign_id)
    traffic_count = get_traffic_count(campaign_id)
    
    rank_improvement = before_rank - after_rank
    efficiency = rank_improvement / traffic_count
    
    # 100회 트래픽당 1위 미만 개선 → 비효율
    if efficiency < 0.01:
        return True
    
    return False
```

---

## 🔍 Analytics Agent: 실패 원인 분석

### 1. 변수별 영향도 분석
```python
def analyze_failure_cause(campaign_id: str) -> dict:
    """실패 원인 분석 (어떤 변수가 문제인지)"""
    
    # 1. 캠페인 정보 조회
    campaign = db.query(Campaign).filter(
        Campaign.campaign_id == campaign_id
    ).first()
    
    # 2. 18개 테스트 케이스별 순위 개선 계산
    test_case_results = []
    for test_case in campaign.test_cases:
        before_rank = get_rank_before_test_case(test_case["test_case_id"])
        after_rank = get_rank_after_test_case(test_case["test_case_id"])
        improvement = before_rank - after_rank
        
        test_case_results.append({
            "test_case_id": test_case["test_case_id"],
            "variables": test_case["variables"],
            "improvement": improvement
        })
    
    # 3. 데이터프레임 생성
    df = pd.DataFrame(test_case_results)
    
    # 4. 각 변수별 평균 개선도 계산
    variable_impact = {}
    
    for var_name in ["platform", "engagement", "user_agent", "cookie", "http_headers", "entry_path", "ip_strategy"]:
        # 변수별 그룹화
        grouped = df.groupby(f"variables.{var_name}")["improvement"].mean()
        
        # 최고 레벨과 최저 레벨 차이 계산
        impact = grouped.max() - grouped.min()
        
        variable_impact[var_name] = {
            "impact": impact,
            "best_level": grouped.idxmax(),
            "worst_level": grouped.idxmin()
        }
    
    # 5. 영향도 순으로 정렬
    sorted_variables = sorted(
        variable_impact.items(),
        key=lambda x: x[1]["impact"],
        reverse=True
    )
    
    # 6. 실패 원인 판정
    failure_causes = []
    
    for var_name, impact_data in sorted_variables[:3]:  # 상위 3개 변수
        if impact_data["impact"] < 0:
            # 음수 영향 → 이 변수가 문제
            failure_causes.append({
                "variable": var_name,
                "reason": f"{var_name}의 {impact_data['worst_level']} 레벨이 순위를 하락시킴",
                "recommendation": f"{var_name}을 {impact_data['best_level']}로 변경"
            })
    
    return {
        "campaign_id": campaign_id,
        "failure_causes": failure_causes,
        "variable_impact": variable_impact
    }
```

### 2. 예시 분석 결과
```json
{
  "campaign_id": "camp-001",
  "failure_causes": [
    {
      "variable": "user_agent",
      "reason": "user_agent의 Generic 레벨이 순위를 하락시킴",
      "recommendation": "user_agent을 Samsung로 변경"
    },
    {
      "variable": "engagement",
      "reason": "engagement의 Low 레벨이 순위를 하락시킴",
      "recommendation": "engagement을 High로 변경"
    }
  ],
  "variable_impact": {
    "user_agent": {
      "impact": -8.5,
      "best_level": "Samsung",
      "worst_level": "Generic"
    },
    "engagement": {
      "impact": -5.2,
      "best_level": "High",
      "worst_level": "Low"
    },
    ...
  }
}
```

---

## 🛠️ Control Tower: 새로운 변수 조합 생성

### 1. 실패 원인 기반 조합 생성
```python
def generate_new_combinations(failure_analysis: dict) -> list:
    """실패 원인 분석 결과 기반 새로운 변수 조합 생성"""
    
    new_combinations = []
    
    # 1. 실패 원인에서 추천된 변수 적용
    base_variables = {}
    for cause in failure_analysis["failure_causes"]:
        var_name = cause["variable"]
        recommended_level = cause["recommendation"].split("을 ")[1].split("로")[0]
        base_variables[var_name] = recommended_level
    
    # 2. 나머지 변수는 최고 영향도 레벨 사용
    for var_name, impact_data in failure_analysis["variable_impact"].items():
        if var_name not in base_variables:
            base_variables[var_name] = impact_data["best_level"]
    
    # 3. 기본 조합 추가
    new_combinations.append(base_variables.copy())
    
    # 4. 변형 조합 생성 (각 변수를 한 번씩 바꿔봄)
    for var_name in base_variables.keys():
        # 현재 레벨
        current_level = base_variables[var_name]
        
        # 가능한 레벨들
        possible_levels = get_possible_levels(var_name)
        
        # 다른 레벨로 변경
        for level in possible_levels:
            if level != current_level:
                variant = base_variables.copy()
                variant[var_name] = level
                new_combinations.append(variant)
    
    return new_combinations


def get_possible_levels(var_name: str) -> list:
    """변수별 가능한 레벨 반환"""
    
    levels_map = {
        "platform": ["PC", "Mobile"],
        "engagement": ["High", "Medium", "Low"],
        "user_agent": ["Samsung", "LG", "Generic"],
        "cookie": ["Enabled", "Disabled"],
        "http_headers": ["Real", "Fake"],
        "entry_path": ["Naver Search", "Shopping Direct"],
        "ip_strategy": ["Per Traffic", "Per Session"]
    }
    
    return levels_map.get(var_name, [])
```

### 2. 중복 제거 (이미 테스트한 조합 제외)
```python
def filter_untested_combinations(
    product_id: str,
    new_combinations: list
) -> list:
    """이미 테스트한 조합 제외"""
    
    # 1. 해당 제품의 모든 캠페인 조회
    existing_campaigns = db.query(Campaign).filter(
        Campaign.product_id == product_id
    ).all()
    
    # 2. 이미 테스트한 조합 추출
    tested_combinations = set()
    for campaign in existing_campaigns:
        for test_case in campaign.test_cases:
            # 변수 조합을 해시 가능한 형태로 변환
            combo_tuple = tuple(sorted(test_case["variables"].items()))
            tested_combinations.add(combo_tuple)
    
    # 3. 새로운 조합 중 테스트 안 한 것만 필터링
    untested = []
    for combo in new_combinations:
        combo_tuple = tuple(sorted(combo.items()))
        if combo_tuple not in tested_combinations:
            untested.append(combo)
    
    return untested
```

### 3. 새로운 캠페인 자동 생성
```python
def auto_create_follow_up_campaign(
    product_id: str,
    failed_campaign_id: str
) -> Campaign:
    """실패한 캠페인 분석 후 자동으로 후속 캠페인 생성"""
    
    # 1. 실패 원인 분석
    failure_analysis = analyze_failure_cause(failed_campaign_id)
    
    # 2. 새로운 변수 조합 생성
    new_combinations = generate_new_combinations(failure_analysis)
    
    # 3. 중복 제거
    untested_combinations = filter_untested_combinations(
        product_id,
        new_combinations
    )
    
    if not untested_combinations:
        log.warning(f"No new combinations to test for {product_id}")
        return None
    
    # 4. 상위 18개 조합 선택 (L18 직교배열 크기)
    selected_combinations = untested_combinations[:18]
    
    # 5. 테스트 케이스 생성
    test_cases = []
    for i, combo in enumerate(selected_combinations):
        test_case = {
            "test_case_id": f"TC#{i+1}",
            "variables": combo,
            "pattern": generate_json_pattern(combo, product_id)
        }
        test_cases.append(test_case)
    
    # 6. 캠페인 생성
    campaign = Campaign(
        campaign_id=f"camp-{uuid.uuid4()}",
        product_id=product_id,
        keyword=get_keyword_from_product(product_id),
        test_cases=test_cases,
        status="ready",
        parent_campaign_id=failed_campaign_id,  # 부모 캠페인 기록
        generation=get_campaign_generation(failed_campaign_id) + 1  # 세대 증가
    )
    
    db.add(campaign)
    db.commit()
    
    log.info(f"Follow-up campaign {campaign.campaign_id} created (generation {campaign.generation})")
    
    return campaign
```

---

## 🔄 자동 피드백 루프 실행

### 1. 캠페인 완료 후 자동 실행
```python
def auto_feedback_loop():
    """캠페인 완료 후 자동으로 피드백 루프 실행"""
    
    while True:
        # 1. 완료된 캠페인 중 피드백 루프 실행 안 한 것 조회
        completed_campaigns = db.query(Campaign).filter(
            Campaign.status == "completed",
            Campaign.feedback_loop_executed == False
        ).all()
        
        for campaign in completed_campaigns:
            try:
                # 2. 실패 여부 판정
                if is_campaign_failed(campaign.campaign_id):
                    log.warning(f"Campaign {campaign.campaign_id} failed")
                    
                    # 3. 실패 원인 분석
                    failure_analysis = analyze_failure_cause(campaign.campaign_id)
                    
                    # 4. 새로운 캠페인 자동 생성
                    follow_up_campaign = auto_create_follow_up_campaign(
                        campaign.product_id,
                        campaign.campaign_id
                    )
                    
                    if follow_up_campaign:
                        # 5. 자동 시작 (선택사항)
                        # follow_up_campaign.status = "running"
                        # db.commit()
                        
                        log.info(f"Follow-up campaign {follow_up_campaign.campaign_id} created")
                    
                    # 6. 실패 분석 결과 저장
                    campaign.failure_analysis = failure_analysis
                    campaign.feedback_loop_executed = True
                    db.commit()
                    
                else:
                    # 성공 → 피드백 루프 불필요
                    campaign.feedback_loop_executed = True
                    db.commit()
                    
                    log.info(f"Campaign {campaign.campaign_id} succeeded, no feedback loop needed")
                
            except Exception as e:
                log.error(f"Feedback loop failed for {campaign.campaign_id}: {e}")
        
        # 5분마다 체크
        time.sleep(300)
```

---

## 📊 피드백 루프 시나리오 예시

### Round 1: 초기 캠페인
```
Campaign ID: camp-001
Product ID: 87654321
Keyword: 삼성 갤럭시 S24

테스트 케이스:
  TC#1: {platform: PC, engagement: High, user_agent: Samsung, ...}
  TC#2: {platform: PC, engagement: High, user_agent: LG, ...}
  ...
  TC#18: {platform: Mobile, engagement: Low, user_agent: Generic, ...}

결과:
  Before 순위: 45위
  After 순위: 43위 (2위 상승, 실패 판정)
```

### Analytics Agent: 실패 원인 분석
```json
{
  "failure_causes": [
    {
      "variable": "user_agent",
      "reason": "Generic User-Agent가 순위를 하락시킴",
      "recommendation": "user_agent을 Samsung로 변경"
    },
    {
      "variable": "engagement",
      "reason": "Low engagement가 순위를 하락시킴",
      "recommendation": "engagement을 High로 변경"
    }
  ]
}
```

### Control Tower: 새로운 조합 생성
```
새로운 조합 18개 생성:
  1. {user_agent: Samsung, engagement: High, ...} (추천 조합)
  2. {user_agent: Samsung, engagement: Medium, ...}
  3. {user_agent: LG, engagement: High, ...}
  ...
  18. {user_agent: Samsung, engagement: High, cookie: Disabled, ...}

중복 제거:
  - TC#1 (이미 테스트함) → 제외
  - TC#2 (이미 테스트함) → 제외
  ...
  
최종 선택: 12개 새로운 조합 (중복 제외 후)
```

### Round 2: 후속 캠페인 자동 생성
```
Campaign ID: camp-002
Parent Campaign: camp-001
Generation: 2

테스트 케이스:
  TC#1: {user_agent: Samsung, engagement: High, cookie: Enabled, ...}
  TC#2: {user_agent: Samsung, engagement: High, cookie: Disabled, ...}
  ...
  TC#12: {user_agent: Samsung, engagement: Medium, http_headers: Real, ...}

결과:
  Before 순위: 43위
  After 순위: 28위 (15위 상승, 성공!)
```

### Analytics Agent: 성공 분석
```json
{
  "success": true,
  "rank_improvement": 15,
  "best_combination": {
    "user_agent": "Samsung",
    "engagement": "High",
    "cookie": "Enabled",
    "http_headers": "Real",
    "entry_path": "Naver Search",
    "ip_strategy": "Per Traffic",
    "platform": "Mobile"
  }
}
```

### Control Tower: 최적 조합 저장
```
최적 조합 DB에 저장:
  Product ID: 87654321
  Best Combination: {user_agent: Samsung, engagement: High, ...}
  Rank Improvement: 15위
  
다음 캠페인에 자동 적용
```

---

## 🎯 피드백 루프 종료 조건

### 1. 성공 기준 달성
```python
def should_stop_feedback_loop(product_id: str) -> bool:
    """피드백 루프 종료 여부 판정"""
    
    # 1. 최근 캠페인 조회
    latest_campaign = db.query(Campaign).filter(
        Campaign.product_id == product_id
    ).order_by(Campaign.created_at.desc()).first()
    
    # 2. 순위 개선도 확인
    before_rank = get_rank_before_campaign(latest_campaign.campaign_id)
    after_rank = get_rank_after_campaign(latest_campaign.campaign_id)
    improvement = before_rank - after_rank
    
    # 3. 종료 조건
    if improvement >= 20:
        # 20위 이상 상승 → 성공
        return True
    
    if after_rank <= 10:
        # 10위 이내 진입 → 성공
        return True
    
    # 4. 세대 제한
    if latest_campaign.generation >= 5:
        # 5세대 이상 → 종료 (무한 루프 방지)
        return True
    
    return False
```

### 2. 더 이상 테스트할 조합 없음
```python
def has_more_combinations(product_id: str) -> bool:
    """테스트할 조합이 더 있는지 확인"""
    
    # 1. 모든 가능한 조합 수 계산
    total_combinations = 2 * 3 * 3 * 2 * 2 * 2 * 2  # 7개 변수
    # = 2 (platform) × 3 (engagement) × 3 (user_agent) × 2 (cookie) × 2 (http_headers) × 2 (entry_path) × 2 (ip_strategy)
    # = 288개
    
    # 2. 이미 테스트한 조합 수
    tested_count = db.query(Campaign).filter(
        Campaign.product_id == product_id
    ).count() * 18  # 캠페인당 18개 테스트 케이스
    
    # 3. 남은 조합 확인
    if tested_count >= total_combinations:
        return False
    
    return True
```

---

## 🚀 API 엔드포인트

### 1. 피드백 루프 수동 트리거
```http
POST /api/v1/control/trigger_feedback_loop
Content-Type: application/json

{
  "campaign_id": "camp-001"
}

Response:
{
  "feedback_loop_triggered": true,
  "failure_analysis": {...},
  "follow_up_campaign_id": "camp-002",
  "new_combinations_count": 12
}
```

### 2. 피드백 루프 상태 조회
```http
GET /api/v1/control/feedback_loop_status/{product_id}

Response:
{
  "product_id": "87654321",
  "total_campaigns": 3,
  "current_generation": 3,
  "best_rank_improvement": 15,
  "should_continue": true,
  "remaining_combinations": 234
}
```

---

## 📊 데이터베이스 스키마 업데이트

### campaigns 테이블
```sql
ALTER TABLE campaigns ADD COLUMN parent_campaign_id VARCHAR(50);
ALTER TABLE campaigns ADD COLUMN generation INTEGER DEFAULT 1;
ALTER TABLE campaigns ADD COLUMN failure_analysis JSONB;
ALTER TABLE campaigns ADD COLUMN feedback_loop_executed BOOLEAN DEFAULT FALSE;
```

### best_combinations 테이블 (신규)
```sql
CREATE TABLE best_combinations (
    id SERIAL PRIMARY KEY,
    product_id VARCHAR(50) NOT NULL,
    combination JSONB NOT NULL,
    rank_improvement INTEGER NOT NULL,
    campaign_id VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(product_id)
);
```

---

## 🎓 결론

### 자가 학습 피드백 루프의 핵심

**완전 자동화**:
1. ✅ 캠페인 완료 → 자동 실패 판정
2. ✅ 실패 원인 분석 → 어떤 변수가 문제인지 파악
3. ✅ 새로운 조합 생성 → 중복 제거
4. ✅ 후속 캠페인 자동 생성 → 봇에게 할당
5. ✅ 반복 → 최적 조합 발견까지

**장점**:
- ✅ **지속적 개선**: 실패에서 학습하여 계속 개선
- ✅ **자동화**: 사용자 개입 없이 자동 실행
- ✅ **효율성**: 이미 테스트한 조합 제외
- ✅ **무한 루프 방지**: 세대 제한, 성공 기준

**예상 결과**:
- Round 1: 45위 → 43위 (실패)
- Round 2: 43위 → 28위 (성공!)
- 최적 조합: {user_agent: Samsung, engagement: High, ...}
