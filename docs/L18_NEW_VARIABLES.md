# L18 테스트 케이스 - 새로운 변수 (쿠팡 실패 사례 반영)

## 📊 변경 사항 요약

### 기존 변수 (7개)
1. Platform (PC, Mobile)
2. Engagement (High, Medium, Low)
3. User-Agent (Real Device, Randomized, Fixed)
4. Cookie (Fresh, Persistent, Partial)
5. IP Strategy (Per Traffic, Per Session)
6. Entry Path (Naver Search, Shopping Direct)
7. HTTP Headers (Standard, Enhanced, Minimal)

### 새로운 변수 (7개) - 쿠팡 실패 사례 반영
1. Platform (PC, Mobile) - **유지**
2. Engagement (High, Medium, Low) - **유지**
3. User-Agent (Samsung, LG, Generic) - **변경** (구체적 기기명)
4. **HTTP Headers Completeness** (minimal, standard, full) - **신규**
5. **Page Loading Strategy** (domcontentloaded, networkidle, load) - **신규**
6. **Mouse Movement** (linear, bezier, human) - **신규**
7. IP Strategy (Per Traffic, Per Session) - **유지**

### 고정 변수 (최적값 사용)
- Cookie: **Enabled** (고정)
- Entry Path: **Naver Search** (고정)
- DOM Wait Strategy: **complex** (고정)
- Timing Variability: **gaussian** (고정)
- Scroll Pattern: **human** (고정)
- JS Execution Wait: **medium** (고정)

---

## 📋 새로운 L18 테스트 케이스

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

## 📖 변수 상세 설명

### 1. User-Agent (구체적 기기명)

| Level | 설명 | User-Agent 예시 |
|-------|------|-----------------|
| **Samsung** | Samsung Galaxy S24 | `Mozilla/5.0 (Linux; Android 14; SM-S928N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36` |
| **LG** | LG V60 ThinQ | `Mozilla/5.0 (Linux; Android 12; LM-V600N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36` |
| **Generic** | 일반 Android | `Mozilla/5.0 (Linux; Android 10; Android SDK built for x86) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36` |

### 2. HTTP Headers Completeness (HTTP 헤더 완성도)

#### minimal (최소 헤더)
```http
Referer: https://shopping.naver.com/
```

**특징**:
- 최소한의 헤더만 전송
- 봇 탐지 가능성 높음
- 테스트용

#### standard (표준 헤더)
```http
User-Agent: Mozilla/5.0 (Linux; Android 14; SM-S928N) ...
Referer: https://shopping.naver.com/
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
```

**특징**:
- 일반적인 브라우저 헤더
- 안정적
- 권장

#### full (전체 헤더)
```http
User-Agent: Mozilla/5.0 (Linux; Android 14; SM-S928N) ...
Referer: https://shopping.naver.com/
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Cache-Control: max-age=0
```

**특징**:
- 실제 브라우저와 동일
- 탐지 회피 최고
- 가장 안전

### 3. Page Loading Strategy (페이지 로딩 전략)

| Level | 설명 | 대기 시간 | 사용 시나리오 |
|-------|------|----------|--------------|
| **domcontentloaded** | DOM 로드 완료 시 | ~2초 | 빠른 페이지, 정적 콘텐츠 |
| **networkidle** | 네트워크 유휴 상태 | ~5초 | React/Vue 등 SPA, 동적 콘텐츠 |
| **load** | 모든 리소스 로드 완료 | ~10초 | 이미지/비디오 많은 페이지 |

**쿠팡 실패 원인**:
- `domcontentloaded`만 사용 → React Hydration 전에 액션 → 실패

**네이버 쇼핑 권장**:
- **networkidle** (React 기반 SPA)

### 4. Mouse Movement (마우스 이동 패턴)

#### linear (직선 이동)
```
시작점 (100, 200) → 끝점 (500, 800)
직선으로 즉시 이동
```

**특징**:
- 빠름
- 부자연스러움
- 봇 탐지 가능

#### bezier (베지어 곡선)
```
시작점 (100, 200) → 제어점1 (200, 150) → 제어점2 (400, 850) → 끝점 (500, 800)
부드러운 곡선으로 이동
```

**특징**:
- 자연스러움
- 중간 속도
- 권장

#### human (인간 패턴)
```
베지어 곡선 + 랜덤 지터 + 가변 속도
실제 사용자의 마우스 이동 패턴 모방
```

**특징**:
- 가장 자연스러움
- 느림
- 탐지 회피 최고

---

## 🎯 변수 선택 이유

### 쿠팡 실패 사례에서 배운 점

1. **Page Loading Strategy 추가**
   - 쿠팡: `domcontentloaded`만 사용 → React Hydration 실패
   - 네이버: `networkidle` 필요 (React 기반)

2. **HTTP Headers Completeness 추가**
   - 쿠팡: Referer만 설정 → 봇 탐지
   - 네이버: 전체 헤더 필요

3. **Mouse Movement 추가**
   - 쿠팡: 직선 이동 → 부자연스러움
   - 네이버: 베지어 곡선 또는 인간 패턴 필요

### 제외된 변수 및 이유

1. **Cookie** (Fresh, Persistent, Partial)
   - 쿠키는 항상 Enabled로 고정
   - 쿠키 없으면 로그인 상태 유지 불가

2. **Entry Path** (Naver Search, Shopping Direct)
   - 진입 경로 차이가 순위에 미치는 영향 미미
   - Naver Search로 고정

3. **DOM Wait Strategy**
   - 항상 complex로 고정 (React Hydration 대기)

4. **Timing Variability**
   - 항상 gaussian으로 고정 (자연스러운 타이밍)

5. **Scroll Pattern**
   - 항상 human으로 고정 (자연스러운 스크롤)

6. **JS Execution Wait**
   - 항상 medium(3초)로 고정

---

## 🚀 구현 우선순위

### Phase 1: 기존 변수로 테스트 (1주)
- 기존 L18 테스트 케이스 실행
- 결과 분석

### Phase 2: 새로운 변수로 테스트 (1주)
- 새로운 L18 테스트 케이스 실행
- 결과 비교

### Phase 3: 최적 조합 도출 (3일)
- ANOVA 분석
- 최적 변수 조합 도출
- 최종 권장 설정 확정

---

## 📊 예상 효과

### 기존 변수
- 순위 개선: **5-10위**
- 성공률: **60%**
- 봇 탐지 회피율: **70%**

### 새로운 변수 (쿠팡 실패 사례 반영)
- 순위 개선: **15-25위** (예상)
- 성공률: **85%** (예상)
- 봇 탐지 회피율: **95%** (예상)

---

## 🎓 결론

쿠팡 실패 사례를 분석하여 **Page Loading Strategy**, **HTTP Headers Completeness**, **Mouse Movement** 변수를 추가했습니다.

이를 통해:
- ✅ React Hydration 대기 문제 해결
- ✅ HTTP 헤더 완성도 향상
- ✅ 자연스러운 마우스 이동 패턴 구현
- ✅ 봇 탐지 회피율 향상

네이버 쇼핑에서도 동일한 문제가 발생할 가능성이 높으므로, 새로운 변수를 적용하여 성공률을 높일 수 있습니다.
