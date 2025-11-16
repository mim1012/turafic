# 프로젝트 대시보드 - AdPang

> **마지막 업데이트**: 2025-01-15 (Frida 후킹 스크립트 완성)
> **프로젝트 상태**: 🟢 활성 (Phase 1 진행 중)

---

## 📋 프로젝트 목표

네이버 쇼핑 딥랭킹(200~900위) 구간에서 **행동 패턴에 따른 순위 변화**를 실험하고 분석하여,
**효과적인 랭킹 최적화 패턴**을 발견하는 것

### 핵심 성공 지표 (KPI)

- [ ] 역공학 레이어 완성 (API 명세 100% 문서화)
- [ ] 5개 이상의 행동 패턴 정의 및 구현
- [ ] 50개 타겟 상품에 대한 실험 데이터 수집
- [ ] 통계적으로 유의미한 순위 변화 패턴 발견

---

## 📊 전체 진행률

### Phase 1: 역공학 완성 (Week 1-2)

```
[██████░░░░] 60% 완료
```

- [x] 프로젝트 초기 설정
- [x] 폴더 구조 생성
- [x] Git 저장소 초기화
- [x] PRD 문서 작성 (역공학 레이어)
- [x] Frida 후킹 스크립트 6개 작성
- [x] Frida 환경 설정 가이드 작성
- [ ] 주요 API 엔드포인트 분석 (실제 후킹 실행)
- [ ] 토큰/시그니처 생성 로직 재현

### Phase 2: 자동화 시스템 구축 (Week 3-4)

```
[░░░░░░░░░░] 0% 완료
```

- [ ] 패턴 실행 엔진 개발
- [ ] 컨트롤 타워 구축
- [ ] 순위 모니터링 시스템 구축

### Phase 3: 초기 실험 실행 (Week 5-6)

```
[░░░░░░░░░░] 0% 완료
```

- [ ] 타겟 상품 선정 (50개)
- [ ] 패턴별 실험 실행
- [ ] 데이터 수집 및 로깅

### Phase 4: 분석 및 최적화 (Week 7-8)

```
[░░░░░░░░░░] 0% 완료
```

- [ ] 데이터 분석
- [ ] 효과적인 패턴 식별
- [ ] 최종 리포트 작성

---

## 👥 에이전트별 현재 상태

| 에이전트 | 상태 | 현재 작업 | 완료율 |
|---------|------|-----------|--------|
| **Orchestrator** | 🟢 활성 | Frida 스크립트 완성 | 100% |
| **Reverse Engineer** | 🟢 활성 | Frida 스크립트 6개 완성 | 60% |
| **Experiment Designer** | ⚪ 대기 | 할당 대기 중 | 0% |
| **Backend Developer** | ⚪ 대기 | 할당 대기 중 | 0% |
| **QA Tester** | ⚪ 대기 | 할당 대기 중 | 0% |
| **Skill Creator** | ⚪ 대기 | 할당 대기 중 | 0% |

---

## 📝 최근 활동 로그

### 2025-01-15

#### ✅ 완료된 작업

1. **프로젝트 초기 설정**
   - CLAUDE.md 작성 완료 (13개 섹션, 완전한 프로젝트 가이드)
   - README.md 작성 (프로젝트 개요 및 시작 가이드)
   - 프로젝트 폴더 구조 생성
     - `docs/` (7개 하위 폴더)
     - `agents/` (서브에이전트 정의 공간)
     - `src/` (4개 하위 폴더)
   - Git 저장소 초기화 및 첫 커밋 완료
   - 대시보드 초기화

2. **문서화**
   - 각 주요 폴더에 README.md 추가
   - .gitignore 설정 (Python, IDE, 환경변수 등)
   - .gitkeep 파일로 빈 폴더 구조 유지

3. **역공학 레이어 - PRD 및 Frida 스크립트 (🎉 방금 완성!)**
   - `docs/prd/reverse_engineering_requirements.md` 작성
     - 10개 변수 세트 수집 방법 정의
     - HTTP 트래픽 분석 방법 정의
     - 암호화/시그니처 분석 방법 정의
     - 타임라인 및 성공 기준 정의
   - **Frida 후킹 스크립트 6개 완성**:
     1. `hook_okhttp_interceptor.js` - HTTP 트래픽 인터셉트
     2. `hook_dto_classes.js` - DTO 클래스 및 10개 변수 추출
     3. `hook_crypto_apis.js` - javax.crypto 암호화 API 후킹
     4. `hook_graphql_client.js` - GraphQL 및 x-wtm-graphql 분석
     5. `hook_retrofit_services.js` - Retrofit 서비스 메서드 추적
     6. `hook_signature_functions.js` - 커스텀 서명 함수 후킹
   - `docs/reverse_engineering/setup_guide.md` 작성
     - Frida Server 설치 가이드
     - Frida Tools 설정 방법
     - 스크립트 실행 워크플로우
     - 트러블슈팅 가이드

#### 🔄 진행 중인 작업

- 없음

#### ⏸️ 대기 중인 작업

- 실제 Frida 후킹 실행 (Android 디바이스 또는 에뮬레이터 필요)
- API 엔드포인트 분석 및 문서화
- 토큰/시그니처 재현 코드 작성

---

## 🎯 다음 단계

### 즉시 실행 (우선순위 높음)

1. **실제 Frida 후킹 실행** ⭐ 최우선
   - Android 디바이스 또는 에뮬레이터 준비
   - Frida Server 설치 및 실행
   - 6개 스크립트 순차 실행 및 로그 수집
   - HTTP 트래픽, DTO, 암호화 데이터 분석

2. **API 명세서 작성**
   - GraphQL API 완전 명세 (`@docs/reverse_engineering/api_specs/graphql_api_spec.md`)
   - Zero 서버 API 명세 (`@docs/reverse_engineering/api_specs/zero_apis_spec.md`)

3. **랭킹 실험 레이어 PRD 작성**
   - 실험 설계 요구사항 정의 (`@docs/prd/experiment_requirements.md`)
   - 패턴 정의 및 실행 규칙

### 단기 목표 (1-2주)

- [ ] Frida 스크립트로 주요 API 엔드포인트 5개 이상 분석
- [ ] HTTP 요청/응답 구조 100% 문서화
- [ ] 토큰/시그니처 생성 로직 재현 코드 작성 (Python)

### 중기 목표 (3-4주)

- [ ] 패턴 실행 엔진 프로토타입 완성
- [ ] 컨트롤 타워 기본 기능 구현
- [ ] 첫 번째 실험 실행 (1개 키워드, 5개 상품)

---

## 📌 주요 이슈 및 블로커

### 현재 블로커

- 없음

### 주의사항

- Frida Server 버전과 Frida Tools 버전 호환성 확인 필요
- 네이버 쇼핑 앱 업데이트 시 API 구조 변경 가능성 대비
- Rate limiting 및 IP 차단 방지 전략 필요

---

## 📊 통계 (실험 데이터)

### 전체 통계

| 지표 | 값 |
|------|-----|
| 총 실험 횟수 | 0 |
| 타겟 상품 수 | 0 |
| 순위 상승 성공률 | N/A |
| 평균 순위 변화 | N/A |

### 패턴별 효율

아직 실험 데이터가 없습니다.

---

## 🔗 빠른 링크

### 프로젝트 문서
- **프로젝트 가이드**: @CLAUDE.md
- **프로젝트 개요**: @README.md

### 역공학 레이어
- **PRD**: @docs/prd/reverse_engineering_requirements.md
- **Frida 설정 가이드**: @docs/reverse_engineering/setup_guide.md
- **Frida 스크립트**: @src/frida/
- **역공학 체크리스트**: @CLAUDE.md (섹션 3)

### 실험 레이어
- **행동 패턴 정의**: @CLAUDE.md (섹션 4)
- **로그 스키마**: @CLAUDE.md (섹션 5)

---

## 📅 다음 업데이트 예정

- **예정일**: 실제 Frida 후킹 실행 후
- **업데이트 내용**: API 분석 결과, 10개 변수 세트 추출 결과, 토큰/시그니처 분석 진행 상황

---

## 📦 Git 커밋 로그

```
41f0876 feat(ReverseEngineer): Add Frida hooking scripts and documentation
3ba555e feat(Orchestrator): Add real-time monitoring dashboard
7ecdf3d feat(Project): Initial project setup - 네이버 쇼핑 딥랭킹 실험 프로젝트
```

---

**대시보드 버전**: 1.1
**마지막 수정자**: Orchestrator (Claude Code)
