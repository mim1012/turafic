# Turafic 프로젝트 전체 아키텍처 (최종 정리)

## 🎯 프로젝트 목표

네이버 쇼핑 상품의 트래픽을 생성하여 순위를 향상시키고, **과학적 실험 설계(L18 직교배열)**를 통해 어떤 사용자 행동 패턴이 순위에 영향을 미치는지 분석합니다.

---

## 🏗️ 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                        사용자 (로컬 PC)                          │
│  - 제품 URL 입력                                                 │
│  - 대시보드 모니터링 (http://localhost:3000)                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   C&C 서버 (Railway 클라우드)                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Control Tower Agent (컨트롤 타워)                         │  │
│  │  - 캠페인 생성 (L18 테스트 케이스)                         │  │
│  │  - 에러 분석 및 복구                                       │  │
│  │  - 자동 의사결정                                           │  │
│  │  - LLM 통합 (ChatGPT-5 + Claude API)                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                            │                                     │
│         ┌──────────────────┼──────────────────┐                 │
│         ▼                  ▼                  ▼                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Traffic   │  │ Monitoring  │  │  Analytics  │             │
│  │    Agent    │  │    Agent    │  │    Agent    │             │
│  │             │  │             │  │             │             │
│  │ - 봇 관리   │  │ - 순위 체크 │  │ - ANOVA     │             │
│  │ - 작업 할당 │  │ - 이상 탐지 │  │ - 최적 조합 │             │
│  │ - IP 변경   │  │ - 대시보드  │  │ - 리포트    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│  Database (PostgreSQL)                                          │
│  - Bots, Campaigns, Tasks, Rankings, Feedback                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Android 봇 네트워크 (22개)                    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  트래픽 작업 봇 그룹 (18개 봇, 6개 그룹)                  │  │
│  │                                                            │  │
│  │  그룹 1: 대장 Bot-1 + 쫄병 Bot-2,3,4 (TC#1,2,3 전담)      │  │
│  │  그룹 2: 대장 Bot-5 + 쫄병 Bot-6,7 (TC#4,5 전담)          │  │
│  │  그룹 3: 대장 Bot-8 + 쫄병 Bot-9,10 (TC#6,7 전담)         │  │
│  │  그룹 4: 대장 Bot-11 + 쫄병 Bot-12,13 (TC#8,9 전담)       │  │
│  │  그룹 5: 대장 Bot-14 + 쫄병 Bot-15,16 (TC#10,11,12 전담)  │  │
│  │  그룹 6: 대장 Bot-17 + 쫄병 Bot-18 (TC#13~18 전담)        │  │
│  │                                                            │  │
│  │  역할:                                                     │  │
│  │  - 대장: 핫스팟 제공, 5분마다 비행기 모드 토글 → IP 변경  │  │
│  │  - 쫄병: 대장 핫스팟 연결, 자동 IP 변경                   │  │
│  │  - 각 봇: 1개 테스트 케이스 전담 (100회 반복)             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  순위 체크 봇 그룹 (4개 봇, 1개 그룹)                     │  │
│  │                                                            │  │
│  │  대장 Bot-RC1 + 쫄병 Bot-RC2,3,4                           │  │
│  │                                                            │  │
│  │  역할:                                                     │  │
│  │  - 30분마다 순위 체크 (18개 제품 분산 처리)               │  │
│  │  - Before/After 순위 비교                                 │  │
│  │  - 광고 필터링 (8가지 패턴)                               │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🤖 4-Agent 아키텍처 (상세)

### 1. Control Tower Agent (컨트롤 타워)

**역할**: 전체 시스템의 두뇌, 핵심 의사결정 담당

**주요 기능**:
1. **캠페인 생성**
   - 사용자 입력 (제품 URL) → L18 테스트 케이스 18개 자동 생성
   - JSON 패턴 생성 (UI 좌표 맵 기반)
   - 데이터베이스에 저장

2. **에러 분석 및 복구**
   - 봇 에러 감지 → LLM 디버깅 → 자동 수정
   - 네트워크 에러 → 재시도 로직
   - 순위 하락 → 실패 원인 분석

3. **자동 의사결정**
   - 순위 개선 없음 → 트래픽 증가 or 중단
   - 봇 탐지 감지 → IP 변경 빈도 조정
   - 성공 패턴 발견 → 후속 캠페인 생성

4. **LLM 통합**
   - ChatGPT-5: 실패 원인 분석, 새로운 변수 조합 생성
   - Claude: 분석 결과 검증, 코드 디버깅, 전략 수립

**API**:
- `POST /api/v1/campaigns/create` - 캠페인 생성
- `POST /api/v1/control/analyze_failure` - 실패 분석
- `POST /api/v1/control/trigger_feedback_loop` - 피드백 루프 트리거

---

### 2. Traffic Agent (트래픽 담당)

**역할**: 봇 관리 및 작업 할당

**주요 기능**:
1. **봇 관리**
   - 봇 등록 (역할: 대장/쫄병, 그룹 할당)
   - 봇 상태 모니터링 (온라인/오프라인/작업중)
   - 봇 그룹 관리 (핫스팟 연결 확인)

2. **작업 할당**
   - "1봇 = 1캠페인 전담" 모델
   - 미할당 캠페인 → 유휴 봇에게 자동 할당
   - JSON 패턴 전송 (UI 좌표, 액션 시퀀스)

3. **IP 변경 스케줄링**
   - 대장 봇: 5분마다 비행기 모드 토글
   - 쫄병 봇: 대장 봇 IP 변경 시 자동 변경
   - Per Traffic / Per Session 전략

**API**:
- `POST /api/v1/bots/register` - 봇 등록
- `GET /api/v1/tasks/get_task?bot_id=xxx` - 작업 요청
- `POST /api/v1/tasks/complete` - 작업 완료 보고

---

### 3. Monitoring Agent (모니터링 담당)

**역할**: 실시간 모니터링 및 이상 탐지

**주요 기능**:
1. **순위 체크**
   - Before 순위 체크 (캠페인 시작 전)
   - 30분마다 순위 체크 (캠페인 진행 중)
   - After 순위 체크 (캠페인 완료 후)
   - 광고 필터링 (8가지 패턴)

2. **이상 탐지**
   - 순위 급락 감지 → Control Tower에 알림
   - 봇 에러 급증 감지 → 긴급 중단
   - 네트워크 지연 감지 → 타임아웃 조정

3. **실시간 대시보드**
   - WebSocket 기반 실시간 업데이트
   - 봇 상태, 캠페인 진행률, 순위 변동 시각화
   - 로그 스트리밍

**API**:
- `GET /api/v1/rank/check?product_id=xxx&keyword=yyy` - 순위 체크
- `GET /api/v1/rank/history/{product_id}` - 순위 이력
- `WS /ws/dashboard` - 실시간 대시보드 WebSocket

---

### 4. Analytics Agent (통계분석 담당)

**역할**: 결과 분석 및 최적 조합 도출

**주요 기능**:
1. **ANOVA 분석**
   - 18개 테스트 케이스별 순위 개선도 계산
   - 각 변수별 영향도 분석 (F-value, p-value)
   - 최고 레벨 vs 최저 레벨 차이

2. **최적 조합 도출**
   - 순위 개선에 가장 효과적인 변수 조합 발견
   - 예측 모델 생성 (회귀 분석)
   - 권장 설정 제안

3. **리포트 생성**
   - PDF 리포트 자동 생성
   - 시각화 (차트, 그래프)
   - 자연어 요약 (LLM 활용)

**API**:
- `POST /api/v1/analytics/analyze_campaign` - 캠페인 분석
- `GET /api/v1/analytics/report/{campaign_id}` - 리포트 조회
- `POST /api/v1/analytics/predict` - 순위 예측

---

## 🔄 완전 자동화 워크플로우

### 사용자 입력
```
사용자: "https://shopping.naver.com/products/87654321" 입력
키워드: "삼성 갤럭시 S24"
```

### 자동 실행 프로세스

```
1. Control Tower: 캠페인 생성
   - L18 테스트 케이스 18개 생성
   - JSON 패턴 생성 (UI 좌표 맵 기반)
   - DB에 저장
   ↓
2. Monitoring: Before 순위 체크
   - 현재 순위: 45위
   - DB에 저장
   ↓
3. Traffic: 18개 봇에게 작업 할당
   - Bot-1 → TC#1 (100회)
   - Bot-2 → TC#2 (100회)
   - ...
   - Bot-18 → TC#18 (100회)
   ↓
4. Traffic: 5분마다 IP 변경
   - 대장 봇: 비행기 모드 토글
   - 쫄병 봇: 자동 IP 변경
   ↓
5. Monitoring: 30분마다 순위 체크
   - 30분 후: 43위 (↑2위)
   - 60분 후: 38위 (↑5위)
   - 90분 후: 28위 (↑10위)
   ↓
6. Control Tower: 실시간 의사결정
   - 순위 개선 중 → 계속 진행
   - 순위 하락 → 중단 또는 트래픽 증가
   ↓
7. Traffic: 작업 완료 보고
   - 18개 봇 모두 100회 완료
   - 총 1,800회 트래픽 생성
   ↓
8. Monitoring: After 순위 체크
   - 최종 순위: 28위 (↑17위)
   - DB에 저장
   ↓
9. Analytics: ANOVA 분석
   - 변수별 영향도 계산
   - 최적 조합 도출
   - 리포트 생성
   ↓
10. Control Tower: 피드백 루프
    - 성공 → 최적 조합 저장
    - 실패 → LLM 분석 → 새로운 조합 생성 → 후속 캠페인
    ↓
11. 사용자: 리포트 확인
    - 대시보드에서 결과 확인
    - PDF 리포트 다운로드
```

---

## 📊 L18 테스트 케이스 (최종)

### 7차원 변수 (쿠팡 실패 사례 반영)

| 변수 | 수준 | 설명 |
|------|------|------|
| **Platform** | PC, Mobile | 접속 기기 유형 |
| **Engagement** | High, Medium, Low | 체류 시간, 스크롤 깊이, 액션 확률 |
| **User-Agent** | Samsung, LG, Generic | 구체적 기기명 User-Agent |
| **HTTP Headers** | minimal, standard, full | HTTP 헤더 완성도 |
| **Page Loading** | domcontentloaded, networkidle, load | 페이지 로딩 전략 |
| **Mouse Movement** | linear, bezier, human | 마우스 이동 패턴 |
| **IP Strategy** | Per Traffic, Per Session | IP 변경 빈도 |

### 고정 변수 (최적값)
- Cookie: **Enabled**
- Entry Path: **Naver Search**
- DOM Wait Strategy: **complex**
- Timing Variability: **gaussian**
- Scroll Pattern: **human**
- JS Execution Wait: **medium**

### 18개 테스트 케이스

| TC# | Platform | Engagement | User-Agent | HTTP Headers | Page Loading | Mouse Movement | IP Strategy |
|-----|----------|------------|------------|--------------|--------------|----------------|-------------|
| TC#1 | PC | High | Samsung | minimal | domcontentloaded | linear | Per Traffic |
| TC#2 | PC | High | LG | standard | networkidle | bezier | Per Session |
| TC#3 | PC | High | Generic | full | load | human | Per Traffic |
| TC#4 | PC | Medium | Samsung | minimal | networkidle | human | Per Session |
| TC#5 | PC | Medium | LG | standard | load | linear | Per Traffic |
| TC#6 | PC | Medium | Generic | full | domcontentloaded | bezier | Per Session |
| TC#7 | PC | Low | Samsung | standard | domcontentloaded | bezier | Per Traffic |
| TC#8 | PC | Low | LG | full | networkidle | human | Per Session |
| TC#9 | PC | Low | Generic | minimal | load | linear | Per Traffic |
| TC#10 | Mobile | High | Samsung | full | networkidle | linear | Per Session |
| TC#11 | Mobile | High | LG | minimal | load | bezier | Per Traffic |
| TC#12 | Mobile | High | Generic | standard | domcontentloaded | human | Per Session |
| TC#13 | Mobile | Medium | Samsung | standard | load | bezier | Per Traffic |
| TC#14 | Mobile | Medium | LG | full | domcontentloaded | human | Per Session |
| TC#15 | Mobile | Medium | Generic | minimal | networkidle | linear | Per Traffic |
| TC#16 | Mobile | Low | Samsung | full | load | human | Per Traffic |
| TC#17 | Mobile | Low | LG | minimal | domcontentloaded | linear | Per Session |
| TC#18 | Mobile | Low | Generic | standard | networkidle | bezier | Per Traffic |

---

## 🗄️ 데이터베이스 스키마

### Bots (봇 정보)
```sql
CREATE TABLE bots (
    bot_id VARCHAR(50) PRIMARY KEY,
    role VARCHAR(20) NOT NULL,  -- 'leader' or 'follower' or 'rank_checker'
    group_id VARCHAR(50),
    status VARCHAR(20) DEFAULT 'offline',
    assigned_campaign_id VARCHAR(50),
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Campaigns (캠페인 정보)
```sql
CREATE TABLE campaigns (
    campaign_id VARCHAR(50) PRIMARY KEY,
    product_id VARCHAR(50) NOT NULL,
    naver_product_id VARCHAR(50) NOT NULL,
    keyword VARCHAR(200) NOT NULL,
    test_case_id VARCHAR(10) NOT NULL,
    variables JSONB NOT NULL,
    pattern JSONB NOT NULL,
    traffic_count INTEGER DEFAULT 100,
    assigned_bot_id VARCHAR(50),
    status VARCHAR(20) DEFAULT 'pending',
    before_rank INTEGER,
    after_rank INTEGER,
    rank_improvement INTEGER,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);
```

### Tasks (작업 정보)
```sql
CREATE TABLE tasks (
    task_id SERIAL PRIMARY KEY,
    campaign_id VARCHAR(50) NOT NULL,
    bot_id VARCHAR(50) NOT NULL,
    pattern JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);
```

### Rankings (순위 정보)
```sql
CREATE TABLE rankings (
    ranking_id SERIAL PRIMARY KEY,
    product_id VARCHAR(50) NOT NULL,
    keyword VARCHAR(200) NOT NULL,
    rank INTEGER NOT NULL,
    page INTEGER NOT NULL,
    position INTEGER NOT NULL,
    campaign_id VARCHAR(50),
    checked_at TIMESTAMP DEFAULT NOW()
);
```

### Feedback (피드백 루프)
```sql
CREATE TABLE feedback (
    feedback_id SERIAL PRIMARY KEY,
    product_id VARCHAR(50) NOT NULL,
    generation INTEGER NOT NULL,
    failure_causes JSONB NOT NULL,
    new_combinations JSONB NOT NULL,
    rank_improvement INTEGER NOT NULL,
    campaign_id VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## 🚀 로컬 서버 모니터링 대시보드

### 개념
사용자가 로컬 PC에서 `http://localhost:3000`으로 접속하여 실시간으로 봇 상태, 캠페인 진행률, 순위 변동을 모니터링할 수 있습니다.

### 기술 스택
- **Frontend**: React + TypeScript
- **Backend**: FastAPI (WebSocket)
- **실시간 통신**: WebSocket
- **차트**: Chart.js 또는 Recharts
- **배포**: Railway (C&C 서버) + 로컬 (대시보드)

### 대시보드 화면 구성

#### 1. 메인 대시보드
```
┌─────────────────────────────────────────────────────────────┐
│  Turafic 실시간 모니터링 대시보드                            │
├─────────────────────────────────────────────────────────────┤
│  📊 캠페인 개요                                              │
│  ┌──────────┬──────────┬──────────┬──────────┐              │
│  │ 총 캠페인 │ 진행 중  │ 완료     │ 실패     │              │
│  │   18개   │   12개   │   5개    │   1개    │              │
│  └──────────┴──────────┴──────────┴──────────┘              │
│                                                              │
│  🤖 봇 상태                                                  │
│  ┌──────────┬──────────┬──────────┬──────────┐              │
│  │ 총 봇    │ 온라인   │ 작업 중  │ 오프라인 │              │
│  │   22개   │   20개   │   12개   │   2개    │              │
│  └──────────┴──────────┴──────────┴──────────┘              │
│                                                              │
│  📈 순위 변동 (실시간)                                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  제품: 삼성 갤럭시 S24                                │  │
│  │  Before: 45위 → 현재: 28위 (↑17위)                   │  │
│  │                                                        │  │
│  │  [차트: 시간별 순위 변동]                             │  │
│  │   45 ┤                                                │  │
│  │   40 ┤     ●                                          │  │
│  │   35 ┤         ●                                      │  │
│  │   30 ┤             ●                                  │  │
│  │   25 ┤                 ●                              │  │
│  │      └─────┬─────┬─────┬─────┬─────                  │  │
│  │           30분  60분  90분  120분                     │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

#### 2. 봇 상태 모니터링
```
┌─────────────────────────────────────────────────────────────┐
│  🤖 봇 상태 (22개)                                           │
├─────────────────────────────────────────────────────────────┤
│  그룹 1 (트래픽 작업)                                        │
│  ┌────────┬────────┬────────┬────────┬─────────────────┐   │
│  │ Bot ID │ 역할   │ 상태   │ 작업   │ 진행률          │   │
│  ├────────┼────────┼────────┼────────┼─────────────────┤   │
│  │ Bot-1  │ 대장   │ 🟢온라인│ TC#1   │ ████████░░ 80%  │   │
│  │ Bot-2  │ 쫄병   │ 🟢온라인│ TC#2   │ ██████░░░░ 60%  │   │
│  │ Bot-3  │ 쫄병   │ 🟢온라인│ TC#3   │ ██████░░░░ 60%  │   │
│  │ Bot-4  │ 쫄병   │ 🔴오프라인│ -      │ -               │   │
│  └────────┴────────┴────────┴────────┴─────────────────┘   │
│                                                              │
│  그룹 RC (순위 체크)                                         │
│  ┌────────┬────────┬────────┬──────────┬──────────────┐    │
│  │ Bot ID │ 역할   │ 상태   │ 마지막 체크│ 다음 체크   │    │
│  ├────────┼────────┼────────┼──────────┼──────────────┤    │
│  │ Bot-RC1│ 대장   │ 🟢온라인│ 5분 전   │ 25분 후      │    │
│  │ Bot-RC2│ 쫄병   │ 🟢온라인│ 5분 전   │ 25분 후      │    │
│  │ Bot-RC3│ 쫄병   │ 🟢온라인│ 5분 전   │ 25분 후      │    │
│  │ Bot-RC4│ 쫄병   │ 🟢온라인│ 5분 전   │ 25분 후      │    │
│  └────────┴────────┴────────┴──────────┴──────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

#### 3. 캠페인 진행률
```
┌─────────────────────────────────────────────────────────────┐
│  📊 캠페인 진행률 (18개 테스트 케이스)                       │
├─────────────────────────────────────────────────────────────┤
│  ┌──────┬────────┬──────┬──────┬──────────┬──────────┐     │
│  │ TC#  │ 변수   │ 봇   │ 상태 │ 진행률   │ 순위 개선│     │
│  ├──────┼────────┼──────┼──────┼──────────┼──────────┤     │
│  │ TC#1 │ PC/High│ Bot-1│ 진행 │ ████░░ 80%│ +2위     │     │
│  │ TC#2 │ PC/High│ Bot-2│ 진행 │ ███░░░ 60%│ +1위     │     │
│  │ TC#3 │ PC/High│ Bot-3│ 진행 │ ███░░░ 60%│ +3위     │     │
│  │ TC#4 │ PC/Med │ Bot-4│ 오프 │ ░░░░░░ 0% │ -        │     │
│  │ TC#5 │ PC/Med │ Bot-5│ 완료 │ ██████ 100%│ +5위     │     │
│  │ ...  │ ...    │ ...  │ ...  │ ...      │ ...      │     │
│  └──────┴────────┴──────┴──────┴──────────┴──────────┘     │
└─────────────────────────────────────────────────────────────┘
```

#### 4. 실시간 로그
```
┌─────────────────────────────────────────────────────────────┐
│  📜 실시간 로그                                              │
├─────────────────────────────────────────────────────────────┤
│  [12:34:56] Bot-1: 작업 시작 (TC#1)                         │
│  [12:35:01] Bot-1: 네이버 쇼핑 검색 완료                     │
│  [12:35:05] Bot-1: 상품 페이지 진입                          │
│  [12:35:10] Bot-1: 스크롤 시작 (100%)                        │
│  [12:35:15] Bot-1: 랜덤 액션 (장바구니)                      │
│  [12:35:20] Bot-1: 작업 완료 (1/100)                         │
│  [12:35:25] Bot-RC1: 순위 체크 시작                          │
│  [12:35:30] Bot-RC1: 현재 순위 43위 (↑2위)                  │
│  [12:35:35] Control Tower: 순위 개선 중, 계속 진행           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 핵심 특징

### 1. 완전 자동화
- ✅ 사용자는 제품 URL만 입력
- ✅ 나머지 모든 과정 자동 실행
- ✅ 결과 리포트 자동 생성 및 전송

### 2. 자가 학습
- ✅ 실패 시 LLM 분석 → 새로운 조합 생성
- ✅ 후속 캠페인 자동 생성
- ✅ 최적 조합 발견까지 반복

### 3. 실시간 모니터링
- ✅ WebSocket 기반 실시간 업데이트
- ✅ 봇 상태, 캠페인 진행률, 순위 변동 시각화
- ✅ 로그 스트리밍

### 4. 과학적 실험 설계
- ✅ L18 직교배열 (7차원 변수 → 18개 테스트 케이스)
- ✅ ANOVA 분석 (변수별 영향도)
- ✅ 최적 조합 도출

### 5. 탐지 회피
- ✅ 핫스팟 기반 IP 변경 (5분 주기)
- ✅ 자연스러운 마우스 이동 (베지어 곡선)
- ✅ React Hydration 대기 (networkidle)
- ✅ 전체 HTTP 헤더 (full)

---

## 🚀 다음 단계

### Phase 1: 로컬 대시보드 구현 (3일)
1. React 프로젝트 생성
2. WebSocket 연동
3. 실시간 차트 구현

### Phase 2: Android 봇 에이전트 개발 (8일)
1. MVP (서버 API 호출 + Root 탭)
2. 기본 액션 (9개)
3. 백그라운드 서비스
4. UI 좌표 맵
5. 고급 액션

### Phase 3: 서버 API 개발 (10일)
1. Control Tower Agent
2. Traffic Agent
3. Monitoring Agent
4. Analytics Agent

### Phase 4: 통합 테스트 (5일)
1. 4개 에이전트 통합
2. 22개 봇 통합
3. 완전 자동화 테스트

**총 소요 시간: 약 26일**

---

## 📚 관련 문서

- [CLAUDE.md](../CLAUDE.md) - 프로젝트 전체 개요
- [ARCHITECTURE.md](../ARCHITECTURE.md) - 핵심 설계 원칙
- [4_AGENT_AUTOMATION.md](./4_AGENT_AUTOMATION.md) - 4-Agent 자동화
- [SELF_LEARNING_FEEDBACK_LOOP.md](./SELF_LEARNING_FEEDBACK_LOOP.md) - 피드백 루프
- [LLM_INTEGRATION.md](./LLM_INTEGRATION.md) - LLM 통합
- [L18_NEW_VARIABLES.md](./L18_NEW_VARIABLES.md) - 새로운 L18 변수
- [COUPANG_FAILURE_ANALYSIS.md](./COUPANG_FAILURE_ANALYSIS.md) - 쿠팡 실패 분석

---

이 문서는 Turafic 프로젝트의 전체 아키텍처를 한눈에 파악할 수 있도록 정리한 것입니다.
