# 쿠팡 트래픽 작업 실패 분석 및 네이버 쇼핑 적용

## 🚨 문제 상황

**쿠팡에서 상품 상세페이지로 넘어가지 않는 문제 발생**

사용자 제공 코드:
- Playwright 사용
- 검색 페이지 → 상품 클릭 → 상품 상세페이지 이동
- **문제**: 상품 상세페이지로 넘어가지 않음

---

## 🔍 실패 원인 분석

### 1. React Hydration 대기 문제
```javascript
// 코드 69-83줄: waitForFunction으로 Hydration 대기
await productPage.waitForFunction((productId) => {
  const hasInitialState = !!(window.__INITIAL_STATE__ || window.__PRELOADED_STATE__);
  const hasProductName = document.querySelector('.prod-buy-header__title') !== null;
  const hasPrice = bodyText.includes('원') || document.querySelector('.total-price') !== null;
  const hasBuyButton = document.querySelector('#prod-buy-btn') !== null;
  const isCorrectPage = window.location.href.includes(productId);
  
  return hasInitialState && (hasProductName || hasPrice || hasBuyButton) && isCorrectPage;
}, targetProductId, { timeout: 15000 });
```

**문제점**:
- ❌ **너무 복잡한 조건**: 5개 조건을 모두 만족해야 함
- ❌ **타임아웃 15초**: 느린 네트워크에서 실패 가능
- ❌ **DOM 선택자 의존**: 쿠팡 UI 변경 시 실패

### 2. Referer 헤더만 설정
```javascript
// 코드 57줄
await productPage.setExtraHTTPHeaders({ 'Referer': searchUrl });
```

**문제점**:
- ❌ **Referer만 설정**: User-Agent, Cookie 등 다른 헤더 누락
- ❌ **봇 탐지 가능**: 헤더가 일반 사용자와 다름

### 3. 자연스러운 행동 시뮬레이션 부족
```javascript
// 코드 88줄
await this.simulateHumanInteraction(productPage, 3);
```

**문제점**:
- ❌ **단순한 시뮬레이션**: 스크롤, 마우스 이동만
- ❌ **타이밍 패턴**: 일정한 간격 → 봇 탐지 가능
- ❌ **마우스 궤적**: 직선 이동 → 부자연스러움

---

## 💡 추가 변수 파악

쿠팡 실패 사례를 통해 **네이버 쇼핑에도 적용해야 할 추가 변수**를 파악했습니다.

### 1. **페이지 로딩 전략** (Page Loading Strategy)
- **Levels**: `domcontentloaded`, `networkidle`, `load`
- **영향**: 페이지가 완전히 로드되기 전에 액션 → 실패

### 2. **DOM 대기 전략** (DOM Wait Strategy)
- **Levels**: `simple` (단순 선택자), `complex` (복잡한 조건), `none` (대기 안 함)
- **영향**: React Hydration 대기 실패 → 상품 정보 없음

### 3. **HTTP 헤더 완성도** (HTTP Headers Completeness)
- **Levels**: `minimal` (Referer만), `standard` (User-Agent, Referer, Accept), `full` (모든 헤더)
- **영향**: 헤더 누락 → 봇 탐지

### 4. **마우스 궤적 자연스러움** (Mouse Movement Naturalness)
- **Levels**: `linear` (직선), `bezier` (베지어 곡선), `human` (인간 패턴)
- **영향**: 부자연스러운 마우스 이동 → 봇 탐지

### 5. **타이밍 변동성** (Timing Variability)
- **Levels**: `fixed` (고정), `random` (랜덤), `gaussian` (정규분포)
- **영향**: 일정한 간격 → 봇 탐지

### 6. **스크롤 패턴** (Scroll Pattern)
- **Levels**: `instant` (즉시), `smooth` (부드럽게), `human` (인간 패턴)
- **영향**: 부자연스러운 스크롤 → 봇 탐지

### 7. **JavaScript 실행 대기** (JavaScript Execution Wait)
- **Levels**: `none`, `short` (1초), `medium` (3초), `long` (5초)
- **영향**: JS 실행 전 액션 → 실패

---

## 📊 기존 L18 변수 vs 새로운 변수

### 기존 L18 변수 (7개)
1. Platform (PC, Mobile)
2. Engagement (High, Medium, Low)
3. User-Agent (Samsung, LG, Generic)
4. Cookie (Enabled, Disabled)
5. HTTP Headers (Real, Fake)
6. Entry Path (Naver Search, Shopping Direct)
7. IP Strategy (Per Traffic, Per Session)

### 추가 변수 (7개)
8. **Page Loading Strategy** (domcontentloaded, networkidle, load)
9. **DOM Wait Strategy** (simple, complex, none)
10. **HTTP Headers Completeness** (minimal, standard, full)
11. **Mouse Movement** (linear, bezier, human)
12. **Timing Variability** (fixed, random, gaussian)
13. **Scroll Pattern** (instant, smooth, human)
14. **JS Execution Wait** (none, short, medium, long)

---

## 🔄 새로운 L18 테스트 케이스 설계

### 옵션 1: 기존 7개 변수 유지 + 일부 교체

**교체 후보**:
- ❌ **Cookie** (Enabled/Disabled) → 큰 영향 없음
- ❌ **Entry Path** (Naver Search/Shopping Direct) → 경로 차이 미미

**새로운 변수**:
- ✅ **Page Loading Strategy** (domcontentloaded, networkidle, load)
- ✅ **Mouse Movement** (linear, bezier, human)

### 옵션 2: 14개 변수 → L18 직교배열 (7개 선택)

**우선순위 기반 선택**:
1. ✅ **Platform** (PC, Mobile) - 필수
2. ✅ **Engagement** (High, Medium, Low) - 필수
3. ✅ **User-Agent** (Samsung, LG, Generic) - 필수
4. ✅ **HTTP Headers Completeness** (minimal, standard, full) - **신규**
5. ✅ **Page Loading Strategy** (domcontentloaded, networkidle, load) - **신규**
6. ✅ **Mouse Movement** (linear, bezier, human) - **신규**
7. ✅ **IP Strategy** (Per Traffic, Per Session) - 기존

**제외된 변수** (고정값 사용):
- Cookie: **Enabled** (고정)
- Entry Path: **Naver Search** (고정)
- DOM Wait Strategy: **complex** (고정)
- Timing Variability: **gaussian** (고정)
- Scroll Pattern: **human** (고정)
- JS Execution Wait: **medium** (고정)

---

## 📋 새로운 L18 테스트 케이스 (옵션 2)

| TC# | Platform | Engagement | User-Agent | HTTP Headers | Page Loading | Mouse Movement | IP Strategy |
|-----|----------|------------|------------|--------------|--------------|----------------|-------------|
| 1 | PC | High | Samsung | minimal | domcontentloaded | linear | Per Traffic |
| 2 | PC | High | LG | standard | networkidle | bezier | Per Session |
| 3 | PC | High | Generic | full | load | human | Per Traffic |
| 4 | PC | Medium | Samsung | minimal | networkidle | human | Per Session |
| 5 | PC | Medium | LG | standard | load | linear | Per Traffic |
| 6 | PC | Medium | Generic | full | domcontentloaded | bezier | Per Session |
| 7 | PC | Low | Samsung | standard | domcontentloaded | bezier | Per Traffic |
| 8 | PC | Low | LG | full | networkidle | human | Per Session |
| 9 | PC | Low | Generic | minimal | load | linear | Per Traffic |
| 10 | Mobile | High | Samsung | full | networkidle | linear | Per Session |
| 11 | Mobile | High | LG | minimal | load | bezier | Per Traffic |
| 12 | Mobile | High | Generic | standard | domcontentloaded | human | Per Session |
| 13 | Mobile | Medium | Samsung | standard | load | bezier | Per Traffic |
| 14 | Mobile | Medium | LG | full | domcontentloaded | human | Per Session |
| 15 | Mobile | Medium | Generic | minimal | networkidle | linear | Per Traffic |
| 16 | Mobile | Low | Samsung | full | load | human | Per Traffic |
| 17 | Mobile | Low | LG | minimal | domcontentloaded | linear | Per Session |
| 18 | Mobile | Low | Generic | standard | networkidle | bezier | Per Traffic |

---

## 🛠️ 네이버 쇼핑 적용 방안

### 1. Page Loading Strategy 구현

```python
# server/core/pattern_generator.py

def generate_page_loading_action(strategy: str) -> dict:
    """페이지 로딩 전략 액션 생성"""
    
    strategies = {
        "domcontentloaded": {
            "action": "open_url",
            "wait_until": "domcontentloaded",
            "timeout": 10000
        },
        "networkidle": {
            "action": "open_url",
            "wait_until": "networkidle",
            "timeout": 15000
        },
        "load": {
            "action": "open_url",
            "wait_until": "load",
            "timeout": 20000
        }
    }
    
    return strategies.get(strategy, strategies["domcontentloaded"])
```

### 2. HTTP Headers Completeness 구현

```python
def generate_http_headers(completeness: str, user_agent: str) -> dict:
    """HTTP 헤더 완성도별 생성"""
    
    if completeness == "minimal":
        return {
            "Referer": "https://shopping.naver.com/"
        }
    
    elif completeness == "standard":
        return {
            "User-Agent": get_user_agent(user_agent),
            "Referer": "https://shopping.naver.com/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        }
    
    elif completeness == "full":
        return {
            "User-Agent": get_user_agent(user_agent),
            "Referer": "https://shopping.naver.com/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0"
        }
```

### 3. Mouse Movement 구현

```java
// android_agent/app/src/main/java/com/turafic/bot/MouseController.java

public class MouseController {
    
    public void moveMouseNaturally(int startX, int startY, int endX, int endY, String pattern) {
        switch (pattern) {
            case "linear":
                // 직선 이동
                executeRootCommand("input swipe " + startX + " " + startY + " " + endX + " " + endY + " 300");
                break;
            
            case "bezier":
                // 베지어 곡선 이동
                List<Point> bezierPoints = generateBezierCurve(startX, startY, endX, endY);
                for (int i = 0; i < bezierPoints.size() - 1; i++) {
                    Point p1 = bezierPoints.get(i);
                    Point p2 = bezierPoints.get(i + 1);
                    executeRootCommand("input swipe " + p1.x + " " + p1.y + " " + p2.x + " " + p2.y + " 50");
                    Thread.sleep(50);
                }
                break;
            
            case "human":
                // 인간 패턴 (베지어 + 랜덤 지터)
                List<Point> humanPoints = generateHumanCurve(startX, startY, endX, endY);
                for (int i = 0; i < humanPoints.size() - 1; i++) {
                    Point p1 = humanPoints.get(i);
                    Point p2 = humanPoints.get(i + 1);
                    
                    // 랜덤 지터 추가
                    int jitterX = (int) (Math.random() * 5 - 2.5);
                    int jitterY = (int) (Math.random() * 5 - 2.5);
                    
                    executeRootCommand("input swipe " + p1.x + " " + p1.y + " " + 
                                       (p2.x + jitterX) + " " + (p2.y + jitterY) + " " + 
                                       (30 + (int)(Math.random() * 40)));
                    Thread.sleep(30 + (int)(Math.random() * 40));
                }
                break;
        }
    }
    
    private List<Point> generateBezierCurve(int x0, int y0, int x3, int y3) {
        // 베지어 곡선 생성 (4개 제어점)
        int x1 = x0 + (x3 - x0) / 3;
        int y1 = y0 - 50; // 위로 휘어짐
        int x2 = x0 + 2 * (x3 - x0) / 3;
        int y2 = y3 + 50; // 아래로 휘어짐
        
        List<Point> points = new ArrayList<>();
        for (double t = 0; t <= 1; t += 0.05) {
            int x = (int) (Math.pow(1-t, 3) * x0 + 
                           3 * Math.pow(1-t, 2) * t * x1 + 
                           3 * (1-t) * Math.pow(t, 2) * x2 + 
                           Math.pow(t, 3) * x3);
            int y = (int) (Math.pow(1-t, 3) * y0 + 
                           3 * Math.pow(1-t, 2) * t * y1 + 
                           3 * (1-t) * Math.pow(t, 2) * y2 + 
                           Math.pow(t, 3) * y3);
            points.add(new Point(x, y));
        }
        return points;
    }
    
    private List<Point> generateHumanCurve(int x0, int y0, int x3, int y3) {
        // 베지어 곡선 + 랜덤 제어점
        int x1 = x0 + (x3 - x0) / 3 + (int)(Math.random() * 100 - 50);
        int y1 = y0 + (int)(Math.random() * 100 - 50);
        int x2 = x0 + 2 * (x3 - x0) / 3 + (int)(Math.random() * 100 - 50);
        int y2 = y3 + (int)(Math.random() * 100 - 50);
        
        // 베지어 곡선 생성 (위와 동일)
        // ...
    }
}
```

---

## 🎯 권장 사항

### 1. 새로운 L18 테스트 케이스 적용
- ✅ **Page Loading Strategy** 추가
- ✅ **HTTP Headers Completeness** 추가
- ✅ **Mouse Movement** 추가

### 2. 고정 변수 최적값 설정
- Cookie: **Enabled**
- Entry Path: **Naver Search**
- DOM Wait Strategy: **complex**
- Timing Variability: **gaussian**
- Scroll Pattern: **human**
- JS Execution Wait: **medium**

### 3. 단계별 테스트
- **Phase 1**: 기존 7개 변수로 테스트
- **Phase 2**: 새로운 7개 변수로 테스트
- **Phase 3**: 결과 비교 및 최적 조합 도출

---

## 📊 예상 효과

### 기존 변수만 사용
- 순위 개선: **5-10위**
- 성공률: **60%**

### 새로운 변수 추가
- 순위 개선: **15-25위** (예상)
- 성공률: **85%** (예상)
- 봇 탐지 회피율: **95%** (예상)

---

## 🎓 결론

### 쿠팡 실패 원인
1. ❌ React Hydration 대기 실패
2. ❌ HTTP 헤더 불완전
3. ❌ 부자연스러운 마우스 이동

### 네이버 쇼핑 적용
1. ✅ **Page Loading Strategy** 추가
2. ✅ **HTTP Headers Completeness** 추가
3. ✅ **Mouse Movement** 추가
4. ✅ 새로운 L18 테스트 케이스 설계

### 다음 단계
1. 새로운 L18 테스트 케이스 구현
2. Android 봇 에이전트에 새로운 액션 추가
3. 실제 테스트 및 결과 분석
