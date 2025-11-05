# Turafic: 통합 시스템 아키텍처

**작성일**: 2025-11-05  
**버전**: 2.0  
**작성자**: Manus AI Agent

**목적**: 기존 4-Agent 아키텍처와 새로운 7-Layer 아키텍처를 통합하여, `Ranking Observer`, `Validation & Analytics`, `Variable Weight Manager` 등의 새로운 개념을 포함하는 최종 시스템 아키텍처를 정의합니다.

---

## 1. 🎯 시스템 개요

**Turafic**은 사용자의 최소한의 개입(플랫폼, 키워드, 제품 ID)만으로 트래픽 생성 및 순위 최적화를 완전 자동화하는 AI 기반 시스템입니다. 본 문서는 시스템의 모든 구성 요소와 데이터 흐름을 상세히 기술하는 최종 아키텍처 가이드입니다.

### 1.1. 핵심 목표

| 목표 | 설명 |
|---|---|
| **완전 자동화** | 사용자는 캠페인 목표만 설정하고, 시스템이 변수 생성부터 실패 분석, 재시도까지 모든 과정을 자동으로 처리합니다. |
| **지능형 순위 분석** | `Reliability Score`와 `플랫폼별 오차보정`을 통해 노이즈를 최소화하고, 신뢰도 높은 순위 데이터만을 분석에 활용합니다. |
| **지속적인 자가 학습** | `Variable Weight Manager`를 통해 효과가 검증된 변수(`confirmed`)에 가중치를 부여하여, 시간이 지남에 따라 시스템이 스스로 더 효율적인 전략을 학습합니다. |
| **확장 가능한 구조** | 22개에서 최대 100개까지 물리 디바이스 확장이 가능하며, `Mall Subtype`을 통해 네이버/쿠팡 외 다른 플랫폼으로도 확장이 용이합니다. |

---

## 2. 🏗️ 7-Layer 통합 아키텍처

Turafic 시스템은 7개의 독립적인 레이어로 구성되어, 각 레이어는 명확하게 정의된 역할을 수행합니다. 이를 통해 시스템의 유지보수성과 확장성을 극대화합니다.

```mermaid
graph TD
    A[User Interface] --> B[Control Tower Layer];
    B --> C[Bot Network Layer];
    C --> D[Ranking Observer Layer];
    D --> E[Validation & Analytics Layer];
    E --> B;
    E --> F[Feedback & Learning Layer];
    F --> B;
    D --> G[Database Layer];
    E --> G;
    F --> G;
    B --> G;
    G --> H[Reporting & Insight Layer];
    B --> H;

    subgraph Layer 1
        A(🧠 USER INTERFACE)
    end
    subgraph Layer 2
        B(🧩 CONTROL TOWER)
    end
    subgraph Layer 3
        C(📱 BOT NETWORK)
    end
    subgraph Layer 4
        D(🧭 RANKING OBSERVER)
    end
    subgraph Layer 5
        E(📊 VALIDATION & ANALYTICS)
    end
    subgraph Layer 6
        F(🧠 FEEDBACK & LEARNING)
    end
    subgraph Layer 7
        G(🗄️ DATABASE)
    end
    subgraph Layer 8
        H(📢 REPORTING & INSIGHT)
    end
```

### 2.1. Layer 1: 🧠 User Interface
- **역할**: 사용자와 시스템 간의 상호작용을 담당합니다.
- **구성 요소**: React + TypeScript 기반 웹 대시보드
- **주요 기능**:
    - 캠페인 생성: 플랫폼, **Mall Subtype(단일/가격비교)**, 키워드, ProductID 입력
    - 실시간 모니터링: WebSocket을 통한 봇 상태, 순위 변화, 이벤트 로그 확인
    - 결과 분석: 순위 변화 그래프(`ΔRank vs Reliability`), `confirmed` 변수 현황, 가중치 변화 추적
    - **관리자 뷰**: 순위 변동 이력 상세 분석 (트래픽 횟수별 그래프, 유의미한 개선 이벤트 목록 등)

### 2.2. Layer 2: 🧩 Control Tower
- **역할**: 시스템의 두뇌로서, 모든 작업을 총괄하고 오케스트레이션합니다.
- **구성 요소**: FastAPI 기반 Control Tower Agent
- **주요 기능**:
    - **캠페인 관리**: 사용자 입력을 받아 캠페인을 생성하고, 플랫폼별/Mall Subtype별 설정을 로드합니다.
    - **변수 및 패턴 생성**: `Variable Weight Manager`로부터 가중치를 받아 `confirmed` → `significant` → `L18` 순서로 변수 조합을 생성합니다.
    - **작업 할당**: 생성된 JSON 패턴을 `Task Dispatcher`를 통해 Traffic Bot과 RankCheck Bot에 할당합니다.
    - **피드백 제어**: `Validation & Analytics Layer`와 `Feedback & Learning Layer`로부터 피드백을 받아 전체 워크플로우를 제어합니다.

### 2.3. Layer 3: 📱 Bot Network
- **역할**: 실제 작업을 수행하는 물리적 Android 디바이스 네트워크입니다.
- **구성 요소**: 22~100개의 Android 폰 (zu12, zcu12, zru12 APK 설치)
- **주요 기능**:
    - **Traffic Bots (18개)**: JSON 패턴에 따라 트래픽 생성 작업을 수행하고, 5분마다 핫스팟을 재시작하여 IP를 변경합니다.
    - **Ranking Bots (4개)**: 광고 영역을 필터링하고, 3회 샘플링을 통해 순위를 측정한 후 `Reliability Score`를 계산하여 `Ranking Observer`로 전송합니다.

### 2.4. Layer 4: 🧭 Ranking Observer (⭐ 신규)
- **역할**: 모든 봇으로부터 원시(raw) 순위 데이터를 수집하고, 1차 정규화 및 검증을 수행합니다.
- **구성 요소**: FastAPI 기반 Ranking Observer 모듈
- **주요 기능**:
    - **원시 데이터 수집**: 모든 Ranking Bot의 순위 측정 결과(3회 샘플 포함)와 `Reliability Score`를 수집하여 `ranking_history` 테이블에 저장합니다.
    - **광고 필터 정규화**: `Reference Dataset`을 기반으로 광고 필터링의 정확도를 보정합니다.
    - **데이터 분류**: `reliability_score`를 기준으로 데이터를 분류하여, 신뢰도 높은 데이터는 `Validation & Analytics Layer`로, 불안정한(`unstable`) 데이터는 `ranking_anomalies` 큐로 보냅니다.

### 2.5. Layer 5: 📊 Validation & Analytics (⭐ v2.0)
- **역할**: 정규화된 순위 데이터를 심층 분석하여 유의미한 순위 변화(`ΔRank`)를 감지합니다.
- **구성 요소**: FastAPI 기반 Analytics & Validator 모듈
- **주요 기능**:
    - **ΔRank 계산**: 최근 3회 측정치의 중앙값과 가중 평균을 사용하여 `ΔRank`를 계산합니다.
    - **플랫폼별 오차보정**: 네이버(±1), 쿠팡(±1.5) 등 플랫폼별 순위 집계 오차를 보정합니다.
    - **유의미한 변화 감지 (v2.0)**: **100회 트래픽 작업 완료 후**, `reliability ≥ 0.8`이고 **`ΔRank ≥ 50`**인 경우, '유의미한 변화'로 판정하고 해당 변수 조합을 `significant_variables` 테이블에 저장합니다.
    - **피드백 전송**: 분석 결과를 Control Tower로 전송하여 피드백 루프를 완성합니다.

### 2.6. Layer 6: 🧠 Feedback & Learning (⭐ 신규)
- **역할**: `significant_variables`를 자동으로 테스트하고, 결과에 따라 변수 가중치를 학습합니다.
- **구성 요소**: FastAPI 기반 Feedback Analyzer & Variable Tester 모듈
- **주요 기능**:
    - **자동 테스트**: `pending` 상태의 `significant_variables`를 1시간마다 자동으로 테스트하는 별도 캠페인을 생성합니다.
    - **가중치 관리**: 테스트 결과에 따라 변수 상태를 `confirmed` 또는 `rejected`로 업데이트하고, `variable_weights` 테이블의 가중치를 조정합니다. (`confirmed`: +0.2, `rejected`: -0.5)
    - **가중치 동기화**: 업데이트된 가중치를 Control Tower의 `Variable Weight Manager`와 주기적으로 동기화합니다.

### 2.7. Layer 7: 🗄️ Database
- **역할**: 시스템의 모든 데이터를 저장하고 관리합니다.
- **구성 요소**: PostgreSQL
- **신규 테이블 스키마**:

| 테이블명 | 역할 |
|---|---|
| `ranking_history` | 모든 봇의 원시 순위 측정 기록 (트래픽 작업 횟수, 3회 샘플, reliability_score 포함) |
| `ranking_validated` | 신뢰도 검증(reliability ≥ 0.8)을 통과한 정제된 순위 데이터 |
| `ranking_anomalies` | 신뢰도가 낮거나(`unstable`) 노이즈로 판정된 데이터 큐 |
| `variable_weights` | `confirmed` 변수의 가중치를 관리 (변수 조합, 가중치, 사용 횟수 등) |
| `significant_variables` | 유의미한 순위 변화를 유발한 변수 조합 (test_status: pending, testing, confirmed, rejected) |

---

## 3. 🔄 데이터 워크플로우

Turafic의 워크플로우는 순차적이면서도 지속적으로 순환하는 피드백 루프 구조를 가집니다.

```mermaid
sequenceDiagram
    participant User
    participant ControlTower
    participant BotNetwork
    participant RankingObserver
    participant Validator
    participant FeedbackLearner
    participant Database

    User->>ControlTower: 1. 캠페인 생성 요청 (키워드, PID)
    ControlTower->>ControlTower: 2. 변수 조합 생성 (가중치 기반)
    ControlTower->>BotNetwork: 3. 작업 할당 (JSON 패턴)
    BotNetwork->>BotNetwork: 4. 트래픽 생성 / 순위 측정 (3회 샘플링)
    BotNetwork->>RankingObserver: 5. 원시 순위 데이터 보고 (Reliability Score 포함)
    RankingObserver->>Database: 6. ranking_history에 저장
    RankingObserver->>Validator: 7. 정제된 데이터 전송 (reliability ≥ 0.8)
    Validator->>Validator: 8. ΔRank 계산 (중앙값+가중평균, 오차보정)
    alt 100회 트래픽 완료 & 유의미한 순위 변화 (ΔRank ≥ 50)
        Validator->>Database: 9. significant_variables에 저장 (status: pending)
    end
    Validator->>ControlTower: 10. 분석 결과 피드백
    FeedbackLearner->>Database: 11. pending 상태 변수 조회 (1시간마다)
    FeedbackLearner->>ControlTower: 12. 별도 테스트 캠페인 생성 요청
    ControlTower->>BotNetwork: 13. 테스트 캠페인 실행
    BotNetwork-->>Validator: (5~8번 과정 반복)
    Validator->>FeedbackLearner: 14. 테스트 결과 피드백
    FeedbackLearner->>Database: 15. 변수 상태 업데이트 (confirmed/rejected) 및 가중치 조정
    FeedbackLearner->>ControlTower: 16. 업데이트된 가중치 동기화
```

### 워크플로우 설명

1.  **캠페인 시작**: 사용자가 UI에서 캠페인 정보를 입력하면, Control Tower는 `Variable Weight Manager`의 가중치를 기반으로 최적의 변수 조합을 생성하여 Bot Network에 작업을 할당합니다.
2.  **데이터 수집 및 정제**: Ranking Bot은 3회 샘플링과 광고 필터링을 통해 순위를 측정하고 `Reliability Score`를 계산하여 `Ranking Observer`에 보고합니다. `Ranking Observer`는 이 원시 데이터를 `ranking_history`에 저장하고, 신뢰도 높은 데이터만 `Validator`로 넘깁니다.
3.  **변화 감지 및 저장**: `Validator`는 플랫폼별 오차를 보정하고, 중앙값/가중평균을 통해 정확한 `ΔRank`를 계산합니다. 만약 유의미한 순위 상승이 감지되면, 해당 변수 조합은 `significant_variables` 테이블에 `pending` 상태로 저장됩니다.
4.  **자동 테스트 및 학습**: `Feedback & Learning` 레이어는 `pending` 상태의 변수들을 주기적으로 가져와 별도의 검증 캠페인을 실행합니다. 테스트 결과에 따라 변수의 상태는 `confirmed` 또는 `rejected`로 변경되며, `variable_weights` 테이블의 가중치가 업데이트됩니다.
5.  **지속적인 최적화**: 업데이트된 가중치는 다시 Control Tower의 `Variable Weight Manager`와 동기화되어, 다음 캠페인 생성 시 더 효과적인 변수가 우선적으로 사용되는 선순환 구조를 만듭니다.

---

## 4. 💡 핵심 개선 사항

| 개선 사항 | 기존 아키텍처 | **통합 아키텍처 (v2.0)** |
|---|---|---|
| **순위 측정** | 개별 봇이 직접 서버에 보고 | **Ranking Observer**가 중앙에서 수집, 정규화, 1차 검증 |
| **순위 분석** | 단순 평균값 비교 | **Validation & Analytics**에서 중앙값, 가중평균, 플랫폼별 오차보정, 신뢰도 기반 분석 |
| **변수 관리** | 유의미한 변수 저장만 수행 | **Feedback & Learning** 레이어에서 자동 테스트 및 가중치 부여/삭감 (`confirmed`/`rejected`) |
| **데이터베이스** | 5개 테이블 | **9개 테이블** (ranking_history, validated, anomalies, weights 추가) |
| **플랫폼 확장성** | 네이버/쿠팡에 고정 | **Mall Subtype** 개념 도입으로 가격비교 사이트 등 타 플랫폼 확장 용이 |

이 통합 아키텍처는 Turafic 시스템의 안정성, 정확성, 그리고 지능을 한 단계 끌어올려, 경쟁 시스템이 따라올 수 없는 수준의 완전 자동화 및 자가 학습 최적화를 구현합니다.
