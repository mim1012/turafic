# Turafic 시스템 아키텍처

## 개요

Turafic은 **C&C 서버 기반 분산 봇 네트워크 시스템**으로, 네이버 쇼핑 트래픽 생성 및 순위 최적화를 위한 완전 자동화 플랫폼입니다.

## 전체 아키텍처

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
│  │  - A/B 테스트 그룹 관리 (1~9)                            ││
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
         │ HTTP (봇 등록, 작업 요청, 결과 보고)
         ▼
┌─────────────────────────────────────────────────────────────┐
│                       봇 네트워크                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐       ┌─────────┐  │
│  │ 봇 #1   │  │ 봇 #2   │  │ 봇 #3   │  ...  │ 봇 #N   │  │
│  │ (APK)   │  │ (APK)   │  │ (APK)   │       │ (APK)   │  │
│  │ 그룹 1  │  │ 그룹 2  │  │ 그룹 3  │       │ 그룹 9  │  │
│  └─────────┘  └─────────┘  └─────────┘       └─────────┘  │
└─────────────────────────────────────────────────────────────┘
         │
         │ 루팅 기반 제어 (su + input tap/text)
         │ 비행기 모드 IP 변경 (1 트래픽당 1회)
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    네이버 쇼핑                                │
│              (트래픽 생성 대상 서비스)                         │
└─────────────────────────────────────────────────────────────┘
```

## 주요 구성 요소

### 1. C&C 서버 (Command & Control Server)

**역할**: 봇 네트워크의 중앙 제어 및 작업 할당

**기술 스택**:
- FastAPI (Python 3.10+)
- PostgreSQL (데이터베이스)
- Redis (캐시)
- SQLAlchemy (ORM)

**주요 기능**:
- 봇 등록 및 관리
- A/B 테스트 그룹 자동 할당 (1~9)
- JSON 작업 패턴 동적 생성
- 작업 결과 수집 및 통계 분석
- 관리자 대시보드 API 제공

**파일 구조**:
```
server/
├── main.py                 # FastAPI 앱 진입점
├── api/
│   ├── bot_management.py   # 봇 관리 API
│   ├── task_assignment.py  # 작업 할당 API
│   └── admin.py            # 관리자 대시보드 API
├── core/
│   ├── database.py         # DB 연결 및 모델
│   ├── cache.py            # Redis 캐시
│   └── task_engine.py      # 작업 할당 로직
└── config/
    └── server_settings.py  # 서버 설정
```

### 2. Android 봇 에이전트 (APK)

**역할**: 안드로이드 기기에서 독립적으로 동작하는 트래픽 생성 봇

**기술 스택**:
- Java/Kotlin
- Retrofit (HTTP 통신)
- 루팅 기반 제어 (su 명령어)

**주요 기능**:
- 서버와 HTTP 통신 (봇 등록, 작업 요청, 결과 보고)
- 루팅 기반 저수준 제어 (`input tap`, `input text`)
- 비행기 모드 IP 변경 (1 트래픽당 1회)
- 백그라운드 서비스 (24시간 지속 동작)
- 부팅 시 자동 시작

**파일 구조**:
```
android_agent/
└── app/src/main/java/com/turafic/agent/
    ├── MainActivity.java          # 메인 액티비티
    ├── service/
    │   ├── BotService.java        # 백그라운드 서비스
    │   └── BootReceiver.java      # 부팅 시 자동 시작
    ├── network/
    │   ├── ApiClient.java         # Retrofit 클라이언트
    │   └── ServerApi.java         # API 인터페이스
    ├── executor/
    │   ├── TaskExecutor.java      # 작업 실행 엔진
    │   └── RootController.java    # 루팅 기반 제어
    └── utils/
        ├── AirplaneModeManager.java # 비행기 모드 제어
        └── DeviceInfo.java          # 기기 정보 수집
```

### 3. 데이터베이스 스키마

#### Bots 테이블
| 컬럼 | 타입 | 설명 |
|---|---|---|
| bot_id | UUID | 봇 고유 ID (Primary Key) |
| android_id | String | 기기 고유 식별자 (Unique) |
| device_model | String | 기기 모델 (예: SM-G996N) |
| android_version | String | Android 버전 |
| screen_resolution | String | 화면 해상도 (예: 1080x2340) |
| group | Integer | A/B 테스트 그룹 (1~9) |
| status | String | 상태 (active, inactive, error) |
| success_count | Integer | 성공 횟수 |
| fail_count | Integer | 실패 횟수 |

#### Tasks 테이블
| 컬럼 | 타입 | 설명 |
|---|---|---|
| task_id | UUID | 작업 ID (Primary Key) |
| bot_id | UUID | 봇 ID (Foreign Key) |
| group | Integer | 테스트 그룹 |
| pattern | JSON | 작업 패턴 (JSON) |
| status | String | 상태 (assigned, running, success, failed) |
| log | Text | 실행 로그 |

### 4. UI 좌표 맵 (Redis 캐시)

해상도별 UI 요소 좌표를 저장하여 빠른 조회 제공:

```json
{
  "1080x2340": {
    "search_bar": {"x": 540, "y": 150},
    "product_item_1": {"x": 540, "y": 600},
    "buy_button": {"x": 540, "y": 1800}
  }
}
```

## 작업 흐름 (Workflow)

### 1. 봇 등록 및 그룹 할당

```
1. 봇 부팅 → 앱 자동 시작 (BootReceiver)
2. 서버에 봇 등록 요청 (POST /api/v1/bots/register)
   - 기기 정보 전송 (모델, Android 버전, 해상도, Android ID)
3. 서버: 기존 봇 확인 (android_id 기준)
   - 신규 봇 → UUID 발급, A/B 그룹 할당 (라운드 로빈)
   - 기존 봇 → 기존 bot_id 반환
4. 봇: bot_id 및 group 저장
```

### 2. 작업 요청 및 실행

```
1. 봇: 5분 간격으로 작업 요청 (GET /api/v1/tasks/get_task?bot_id=xxx)
2. 서버: 봇의 그룹 확인 → 테스트 매트릭스 로드
3. 서버: 봇의 해상도에 맞는 UI 좌표 조회 (Redis)
4. 서버: JSON 작업 패턴 생성 (참여 수준, 브라우저 지문 반영)
5. 서버: 무작위성 추가 (좌표 ±10px, 시간 ±20%)
6. 서버: 작업 ID 생성 및 DB 저장 → 봇에게 패턴 전송
7. 봇: 비행기 모드로 IP 변경
8. 봇: 작업 패턴 실행 (RootController)
   - 삼성 브라우저 강제 종료 → 시작
   - 검색창 터치 → 키워드 입력
   - 상품 클릭 → 체류 → 뒤로 가기
9. 봇: 결과 보고 (POST /api/v1/tasks/report_result)
10. 서버: 작업 상태 업데이트, 봇 통계 업데이트
```

### 3. 관리자 모니터링

```
1. 관리자: 대시보드 접속 (GET /api/v1/admin/dashboard)
2. 서버: 실시간 통계 반환
   - 전체 봇 수 / 활성 봇 수
   - 전체 작업 수 / 성공률
   - 시간당 작업 처리량
3. 관리자: 그룹별 성공률 확인 (GET /api/v1/admin/tasks/statistics)
4. 관리자: 최적 조합 도출 (ANOVA 분석)
```

## 핵심 설계 원칙

### 1. "1봇 = 1캠페인 전담" 작업 할당 모델

- 각 봇은 하나의 캠페인(테스트 케이스)에만 전담 할당
- 할당된 캠페인을 100회 반복 실행
- 여러 봇이 다른 테스트 케이스를 병렬 실행하여 전체 테스트 시간 단축
- 테스트 케이스별 순수한 결과 측정 가능
- 상세 내용: `TASK_ALLOCATION_MODEL.md` 참고

### 2. 봇 ID 기반 상태 관리 (Stateful)

- IP가 변경되어도 봇 ID는 불변
- 각 봇의 상태, 성과, 이력 추적 가능
- A/B 테스트 그룹 관리 용이

### 3. 모듈 분리 (Separation of Concerns)

- API 계층 (`api/`)
- 비즈니스 로직 (`core/`)
- 데이터 모델 (`models/`)
- 설정 (`config/`)

### 4. 확장성 (Scalability)

- 봇 수천 대 동시 관리 가능
- 데이터베이스 수평 확장 (PostgreSQL)
- 캐시 레이어 (Redis)

### 5. 유연성 (Flexibility)

- 코드 수정 없이 JSON으로 작업 변경 가능
- 테스트 매트릭스 외부 파일 관리 (`test_matrix.json`)
- 환경 변수 기반 설정

### 6. 탐지 회피 (Anti-Detection)

- 무작위성 추가 (좌표, 시간)
- 다양한 브라우저 지문 (7종 기기 모델)
- IP 로테이션 (비행기 모드)
- 인간적인 행동 패턴 (체류 시간 변화)

## 보안 고려사항

⚠️ **이 시스템은 연구 및 교육 목적으로만 사용해야 합니다.**

- 타사 서비스 약관 위반 가능성
- 법적 책임은 사용자에게 있음
- 루팅된 기기 필요 (보안 위험)

## 향후 개선 방향

### 1. 자가 치유 시스템 (Self-Healing)
- AI 비전 (GPT-4 Vision)으로 UI 변경 자동 감지
- UI 좌표 맵 자동 업데이트

### 2. 인간 행동 시뮬레이션 엔진
- 고수준 목표 → 저수준 패턴 변환
- 행동 프리미티브 라이브러리 (`scroll_with_hesitation` 등)

### 3. 하이브리드 제어 시스템
- Appium 모드 (개발/디버깅)
- 루팅 모드 (프로덕션)
- 상황에 따라 자동 전환

### 4. 관리자 대시보드 웹 UI
- React 기반 SPA
- 실시간 차트 (Chart.js)
- 봇 원격 제어 기능

## 라이선스

MIT License
