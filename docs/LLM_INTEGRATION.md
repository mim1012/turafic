# Turafic LLM 통합: ChatGPT-5 & Claude API

## 🎯 개요

**ChatGPT-5 API**와 **Claude API**를 연동하여 자가 학습 및 분석 시스템을 고도화합니다.

---

## 🤖 LLM 역할 분담

### ChatGPT-5 API
- ✅ **실패 원인 분석**: 복잡한 데이터 패턴 분석
- ✅ **새로운 변수 조합 생성**: 창의적인 조합 제안
- ✅ **자연어 리포트 생성**: 사용자 친화적인 분석 리포트

### Claude API
- ✅ **코드 디버깅**: 에러 로그 분석 및 수정 제안
- ✅ **전략 수립**: 장기 전략 및 최적화 방안
- ✅ **데이터 검증**: 분석 결과 교차 검증

---

## 🏗️ 아키텍처

```
Analytics Agent
   ├─ ChatGPT-5 API
   │    ├─ 실패 원인 분석
   │    ├─ 새로운 변수 조합 생성
   │    └─ 자연어 리포트 생성
   │
   └─ Claude API
        ├─ 코드 디버깅
        ├─ 전략 수립
        └─ 데이터 검증
```

---

## 🔧 구현

### 1. ChatGPT-5 API 클라이언트

```python
# server/core/llm_clients.py

import os
from openai import OpenAI

class ChatGPT5Client:
    """ChatGPT-5 API 클라이언트"""
    
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = "gpt-4.1-mini"  # 또는 gpt-4.1-nano
    
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
2. 각 변수의 영향도는 얼마나 되는가?
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
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert in Naver Shopping ranking optimization."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
    
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
    }},
    ... (18개)
  ]
}}
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert in Naver Shopping ranking optimization."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.7  # 창의성을 위해 temperature 높임
        )
        
        result = json.loads(response.choices[0].message.content)
        return result["combinations"]
    
    def generate_report(self, analysis_data: dict) -> str:
        """자연어 리포트 생성"""
        
        prompt = f"""
당신은 네이버 쇼핑 순위 최적화 전문가입니다.

다음 분석 결과를 바탕으로 사용자 친화적인 리포트를 작성해주세요:

{json.dumps(analysis_data, indent=2, ensure_ascii=False)}

**리포트 구성:**
1. 요약 (3줄)
2. 주요 발견 사항
3. 실패 원인 분석
4. 권장 사항
5. 다음 단계

마크다운 형식으로 작성해주세요.
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert in Naver Shopping ranking optimization."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5
        )
        
        report = response.choices[0].message.content
        return report
```

### 2. Claude API 클라이언트

```python
# server/core/llm_clients.py

import anthropic

class ClaudeClient:
    """Claude API 클라이언트"""
    
    def __init__(self):
        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        self.model = "claude-3-5-sonnet-20241022"
    
    def debug_error(self, error_log: str, context: dict) -> dict:
        """에러 로그 분석 및 디버깅"""
        
        prompt = f"""
당신은 Python 및 Android 개발 전문가입니다.

다음 에러가 발생했습니다:

**에러 로그:**
```
{error_log}
```

**컨텍스트:**
{json.dumps(context, indent=2, ensure_ascii=False)}

**분석 요청:**
1. 에러의 근본 원인은 무엇인가?
2. 어떻게 수정해야 하는가?
3. 재발 방지 방법은?

JSON 형식으로 답변해주세요:
{{
  "error_type": "에러 유형",
  "root_cause": "근본 원인",
  "fix": "수정 방법",
  "code_suggestion": "수정 코드 (있다면)",
  "prevention": "재발 방지 방법"
}}
"""
        
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        result = json.loads(response.content[0].text)
        return result
    
    def formulate_strategy(self, campaign_history: list) -> dict:
        """장기 전략 수립"""
        
        prompt = f"""
당신은 네이버 쇼핑 순위 최적화 전략가입니다.

다음은 지금까지의 캠페인 히스토리입니다:

{json.dumps(campaign_history, indent=2, ensure_ascii=False)}

**전략 수립 요청:**
1. 전체적인 패턴 분석
2. 장기 전략 제안
3. 리스크 요인
4. 예상 ROI

JSON 형식으로 답변해주세요:
{{
  "pattern_analysis": "패턴 분석",
  "long_term_strategy": "장기 전략",
  "risk_factors": ["리스크 1", "리스크 2", ...],
  "expected_roi": "예상 ROI",
  "timeline": "예상 소요 시간"
}}
"""
        
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        result = json.loads(response.content[0].text)
        return result
    
    def validate_analysis(
        self,
        chatgpt_analysis: dict,
        campaign_data: dict
    ) -> dict:
        """ChatGPT 분석 결과 검증"""
        
        prompt = f"""
당신은 데이터 분석 검증 전문가입니다.

다음은 ChatGPT-5가 분석한 결과입니다:

**ChatGPT 분석:**
{json.dumps(chatgpt_analysis, indent=2, ensure_ascii=False)}

**원본 데이터:**
{json.dumps(campaign_data, indent=2, ensure_ascii=False)}

**검증 요청:**
1. ChatGPT 분석이 데이터와 일치하는가?
2. 논리적 오류가 있는가?
3. 개선 사항이 있는가?

JSON 형식으로 답변해주세요:
{{
  "is_valid": true/false,
  "validation_score": 0.0-1.0,
  "issues": ["이슈 1", "이슈 2", ...],
  "improvements": ["개선 사항 1", "개선 사항 2", ...],
  "final_recommendation": "최종 권장 사항"
}}
"""
        
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        result = json.loads(response.content[0].text)
        return result
```

---

## 🔄 통합 워크플로우

### 1. 실패 원인 분석 (ChatGPT-5 + Claude 교차 검증)

```python
# server/core/analytics_engine.py

class AnalyticsEngine:
    """LLM 통합 분석 엔진"""
    
    def __init__(self):
        self.chatgpt = ChatGPT5Client()
        self.claude = ClaudeClient()
    
    def analyze_campaign_failure(self, campaign_id: str) -> dict:
        """캠페인 실패 분석 (LLM 통합)"""
        
        # 1. 캠페인 데이터 수집
        campaign_data = self._collect_campaign_data(campaign_id)
        
        # 2. ChatGPT-5로 실패 원인 분석
        chatgpt_analysis = self.chatgpt.analyze_failure(campaign_data)
        
        # 3. Claude로 분석 결과 검증
        validation = self.claude.validate_analysis(
            chatgpt_analysis,
            campaign_data
        )
        
        # 4. 검증 결과 반영
        if validation["is_valid"] and validation["validation_score"] >= 0.8:
            # ChatGPT 분석 그대로 사용
            final_analysis = chatgpt_analysis
        else:
            # Claude의 개선 사항 반영
            final_analysis = self._merge_analyses(
                chatgpt_analysis,
                validation
            )
        
        # 5. 결과 저장
        self._save_analysis(campaign_id, final_analysis, validation)
        
        return final_analysis
    
    def _collect_campaign_data(self, campaign_id: str) -> dict:
        """캠페인 데이터 수집"""
        
        campaign = db.query(Campaign).filter(
            Campaign.campaign_id == campaign_id
        ).first()
        
        # Before/After 순위
        before_rank = get_rank_before_campaign(campaign_id)
        after_rank = get_rank_after_campaign(campaign_id)
        
        # 18개 테스트 케이스별 결과
        test_case_results = []
        for test_case in campaign.test_cases:
            tc_before = get_rank_before_test_case(test_case["test_case_id"])
            tc_after = get_rank_after_test_case(test_case["test_case_id"])
            
            test_case_results.append({
                "test_case_id": test_case["test_case_id"],
                "variables": test_case["variables"],
                "before_rank": tc_before,
                "after_rank": tc_after,
                "improvement": tc_before - tc_after
            })
        
        return {
            "campaign_id": campaign_id,
            "product_id": campaign.product_id,
            "keyword": campaign.keyword,
            "before_rank": before_rank,
            "after_rank": after_rank,
            "rank_improvement": before_rank - after_rank,
            "test_case_results": test_case_results
        }
    
    def _merge_analyses(
        self,
        chatgpt_analysis: dict,
        claude_validation: dict
    ) -> dict:
        """ChatGPT와 Claude 분석 결과 병합"""
        
        merged = chatgpt_analysis.copy()
        
        # Claude의 개선 사항 적용
        if claude_validation.get("final_recommendation"):
            merged["claude_recommendation"] = claude_validation["final_recommendation"]
        
        # 신뢰도 조정
        merged["confidence"] = (
            chatgpt_analysis["confidence"] * 0.7 +
            claude_validation["validation_score"] * 0.3
        )
        
        return merged
    
    def _save_analysis(
        self,
        campaign_id: str,
        analysis: dict,
        validation: dict
    ):
        """분석 결과 저장"""
        
        campaign = db.query(Campaign).filter(
            Campaign.campaign_id == campaign_id
        ).first()
        
        campaign.failure_analysis = {
            "chatgpt_analysis": analysis,
            "claude_validation": validation,
            "timestamp": datetime.now().isoformat()
        }
        
        db.commit()
```

### 2. 새로운 변수 조합 생성 (ChatGPT-5)

```python
def generate_follow_up_combinations(
    self,
    campaign_id: str
) -> list:
    """후속 캠페인 변수 조합 생성 (ChatGPT-5)"""
    
    # 1. 실패 분석 결과 조회
    campaign = db.query(Campaign).filter(
        Campaign.campaign_id == campaign_id
    ).first()
    
    failure_analysis = campaign.failure_analysis["chatgpt_analysis"]
    
    # 2. 이미 테스트한 조합 수집
    tested_combinations = self._get_tested_combinations(
        campaign.product_id
    )
    
    # 3. ChatGPT-5로 새로운 조합 생성
    new_combinations = self.chatgpt.generate_new_combinations(
        failure_analysis,
        tested_combinations
    )
    
    # 4. 중복 제거 (한 번 더 확인)
    unique_combinations = self._filter_unique(
        new_combinations,
        tested_combinations
    )
    
    return unique_combinations[:18]  # 상위 18개
```

### 3. 에러 디버깅 (Claude)

```python
def auto_debug_bot_error(self, task_id: str):
    """봇 에러 자동 디버깅 (Claude)"""
    
    # 1. 실패한 작업 조회
    task = db.query(Task).filter(
        Task.task_id == task_id
    ).first()
    
    if not task or task.status != "failed":
        return None
    
    # 2. 에러 로그 및 컨텍스트 수집
    error_log = task.error_message
    context = {
        "task_id": task_id,
        "bot_id": task.bot_id,
        "campaign_id": task.campaign_id,
        "pattern": task.pattern,
        "retry_count": task.retry_count
    }
    
    # 3. Claude로 디버깅
    debug_result = self.claude.debug_error(error_log, context)
    
    # 4. 자동 수정 시도
    if debug_result.get("code_suggestion"):
        # 코드 수정 제안이 있으면 적용 (선택사항)
        self._apply_fix(task, debug_result)
    
    # 5. 디버깅 결과 저장
    task.debug_result = debug_result
    db.commit()
    
    return debug_result
```

### 4. 장기 전략 수립 (Claude)

```python
def formulate_product_strategy(self, product_id: str) -> dict:
    """제품별 장기 전략 수립 (Claude)"""
    
    # 1. 캠페인 히스토리 수집
    campaigns = db.query(Campaign).filter(
        Campaign.product_id == product_id
    ).order_by(Campaign.created_at).all()
    
    campaign_history = []
    for campaign in campaigns:
        campaign_history.append({
            "campaign_id": campaign.campaign_id,
            "generation": campaign.generation,
            "before_rank": get_rank_before_campaign(campaign.campaign_id),
            "after_rank": get_rank_after_campaign(campaign.campaign_id),
            "improvement": get_rank_improvement(campaign.campaign_id),
            "status": campaign.status,
            "test_cases_count": len(campaign.test_cases)
        })
    
    # 2. Claude로 전략 수립
    strategy = self.claude.formulate_strategy(campaign_history)
    
    # 3. 전략 저장
    product_strategy = ProductStrategy(
        product_id=product_id,
        strategy=strategy,
        created_at=datetime.now()
    )
    
    db.add(product_strategy)
    db.commit()
    
    return strategy
```

---

## 📊 API 엔드포인트

### 1. LLM 분석 트리거
```http
POST /api/v1/analytics/llm_analyze/{campaign_id}

Response:
{
  "campaign_id": "camp-001",
  "chatgpt_analysis": {...},
  "claude_validation": {...},
  "final_analysis": {...},
  "confidence": 0.85
}
```

### 2. 새로운 조합 생성
```http
POST /api/v1/analytics/llm_generate_combinations/{campaign_id}

Response:
{
  "campaign_id": "camp-001",
  "new_combinations": [...],
  "count": 18,
  "rationale": "..."
}
```

### 3. 에러 디버깅
```http
POST /api/v1/analytics/llm_debug_error/{task_id}

Response:
{
  "task_id": "task-001",
  "error_type": "network_timeout",
  "root_cause": "...",
  "fix": "...",
  "code_suggestion": "..."
}
```

### 4. 장기 전략 조회
```http
GET /api/v1/analytics/llm_strategy/{product_id}

Response:
{
  "product_id": "87654321",
  "pattern_analysis": "...",
  "long_term_strategy": "...",
  "risk_factors": [...],
  "expected_roi": "...",
  "timeline": "..."
}
```

---

## 🔒 환경 변수 설정

```bash
# .env

# OpenAI API (ChatGPT-5)
OPENAI_API_KEY=sk-...

# Anthropic API (Claude)
ANTHROPIC_API_KEY=sk-ant-...
```

---

## 📦 의존성 설치

```bash
# requirements.txt에 추가
openai>=1.0.0
anthropic>=0.18.0
```

```bash
pip3 install openai anthropic
```

---

## 🎯 LLM 통합 장점

### 1. ChatGPT-5
- ✅ **창의적 분석**: 복잡한 패턴 발견
- ✅ **자연어 리포트**: 사용자 친화적
- ✅ **빠른 응답**: 실시간 분석 가능

### 2. Claude
- ✅ **정확한 검증**: 분석 결과 교차 검증
- ✅ **코드 디버깅**: 에러 수정 제안
- ✅ **전략 수립**: 장기 전략 및 리스크 분석

### 3. 교차 검증
- ✅ **신뢰도 향상**: 두 LLM의 결과 비교
- ✅ **오류 감소**: 상호 보완
- ✅ **최적화**: 최상의 결과 도출

---

## 🚀 실행 예시

### 1. 캠페인 실패 분석
```python
from server.core.analytics_engine import AnalyticsEngine

engine = AnalyticsEngine()

# 실패한 캠페인 분석
analysis = engine.analyze_campaign_failure("camp-001")

print(analysis)
# {
#   "failure_causes": [
#     {
#       "variable": "user_agent",
#       "reason": "Generic User-Agent가 봇으로 감지됨",
#       "recommendation": "Samsung User-Agent 사용",
#       "impact_score": 8.5
#     }
#   ],
#   "best_combination_prediction": {...},
#   "confidence": 0.85
# }
```

### 2. 새로운 조합 생성
```python
# 새로운 조합 생성
combinations = engine.generate_follow_up_combinations("camp-001")

print(len(combinations))  # 18

print(combinations[0])
# {
#   "platform": "Mobile",
#   "engagement": "High",
#   "user_agent": "Samsung",
#   "cookie": "Enabled",
#   "http_headers": "Real",
#   "entry_path": "Naver Search",
#   "ip_strategy": "Per Traffic",
#   "rationale": "Samsung User-Agent + High engagement 조합이 가장 효과적"
# }
```

### 3. 에러 디버깅
```python
# 봇 에러 디버깅
debug_result = engine.auto_debug_bot_error("task-001")

print(debug_result)
# {
#   "error_type": "root_permission_denied",
#   "root_cause": "su 명령어 실행 실패",
#   "fix": "Root 권한 재확인 필요",
#   "code_suggestion": "...",
#   "prevention": "봇 등록 시 Root 권한 자동 확인"
# }
```

### 4. 장기 전략 수립
```python
# 제품별 장기 전략
strategy = engine.formulate_product_strategy("87654321")

print(strategy)
# {
#   "pattern_analysis": "High engagement + Samsung User-Agent 조합이 일관되게 효과적",
#   "long_term_strategy": "Samsung User-Agent 중심으로 최적화, Mobile 플랫폼 우선",
#   "risk_factors": ["네이버 알고리즘 변경", "봇 탐지 강화"],
#   "expected_roi": "20위 이상 상승 예상",
#   "timeline": "2-3주"
# }
```

---

## 🎓 결론

### LLM 통합의 핵심

**ChatGPT-5 + Claude 교차 검증**:
1. ✅ ChatGPT-5: 실패 원인 분석 + 새로운 조합 생성
2. ✅ Claude: 분석 결과 검증 + 에러 디버깅 + 전략 수립
3. ✅ 교차 검증: 신뢰도 향상, 오류 감소

**완전 자동화**:
- ✅ 캠페인 실패 → LLM 분석 → 새로운 조합 생성 → 후속 캠페인 자동 생성
- ✅ 봇 에러 → LLM 디버깅 → 자동 수정
- ✅ 장기 전략 → LLM 수립 → 자동 적용

**예상 효과**:
- ✅ 분석 정확도 30% 향상
- ✅ 최적 조합 발견 시간 50% 단축
- ✅ 에러 해결 시간 70% 단축
