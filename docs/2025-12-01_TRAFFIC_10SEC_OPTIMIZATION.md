# Traffic 10초 최적화 문서 (2025.12.01)

## 개요

통검(통합검색) 및 쇼검(쇼핑검색) 모드 모두 **1회 실행당 10초 이내** 완료를 목표로 최적화 작업 수행.

## 최종 결과

| 모드 | 이전 속도 | 최적화 후 | 상태 |
|------|-----------|-----------|------|
| 통검 | 27.9초 | **9.2초** | ✅ 성공 |
| 쇼검 | 9.4초 | **9.2초** | ✅ 성공 |

## 핵심 변경 사항

### 1. 쇼검 모드 - 새 탭 방식 구현

**문제**: 쇼핑탭과 상품 링크가 `target="_blank"`로 새 탭에서 열림. 기존 코드는 같은 탭에서 처리하려 해서 실패.

**해결**: 실제 사용자 행동을 모방하는 새 탭 처리 방식 구현

```typescript
// 쇼핑탭 클릭 → 새 탭으로 열림
let pagesBefore = (await this.browser.pages()).length;
await this.page.mouse.click(shoppingTab.x, shoppingTab.y);
await this.delay(1500);

// 새 탭 전환
let pages = await this.browser.pages();
const shoppingPage = pages[pages.length - 1] as Page;
await shoppingPage.bringToFront();
await shoppingPage.setViewport({ width: 1366, height: 768, ... });

// MID 상품 클릭 → 또 새 탭으로 열림
pagesBefore = (await this.browser.pages()).length;
await shoppingPage.mouse.click(midInfo.x, midInfo.y);
await this.delay(1500);

// 상품 페이지 새 탭 전환
pages = await this.browser.pages();
const productPage = pages[pages.length - 1] as Page;
await productPage.bringToFront();
```

**핵심 포인트**:
- `browser.pages()`로 탭 수 변화 감지
- `page.bringToFront()`로 새 탭 활성화
- 새 탭마다 `setViewport()` 재설정 필수
- 작업 완료 후 `productPage.close()`, `shoppingPage.close()`로 탭 정리

### 2. 지연 시간 최적화

**TrafficEngineBaseSimple.ts 변경 내역**:

| 위치 | 이전 | 최적화 후 |
|------|------|-----------|
| 네이버 메인 접속 후 | 1.5~2.5초 | **0.5초** |
| 검색 후 | 2.5~3.5초 | **1초** |
| 스크롤 | 3회 x 0.5초 | **2회 x 0.2초** |
| Bridge URL 클릭 후 | 3초 | **1.5초** |
| 페이지 로딩 후 | 3초 | **1.5초** |
| Bridge redirect 대기 | 10회 x 1초 | **5회 x 0.5초** |
| 최종 검증 전 | 1초 | **0.5초** |
| Catalog URL 이동 후 | 3초 | **1.5초** |

**총 절약**: 약 18초 → 약 9초

### 3. CAPTCHA 주의사항

**너무 빠르면 CAPTCHA 발생!**

초기 최적화 시 모든 지연을 500ms로 줄였더니 CAPTCHA 발생.
핵심 전환점(검색 후, 클릭 후)에는 최소 1~1.5초 유지 필요.

**안전한 지연 시간**:
- 페이지 전환 후: 1~1.5초 (최소)
- 클릭 후: 1.5초
- 스크롤: 0.2초 (빠르게 가능)

## 트래픽 시스템 폴더 구조

```
server/services/traffic/
├── base.ts                      # TrafficBase 추상 클래스 (v1-v6 상속용)
├── index.ts                     # 모듈 exports
├── types.ts                     # 타입 정의
├── utils.ts                     # 유틸리티 함수
├── engineRouter.ts              # 동적 엔진 선택기
├── engine-patterns.json         # 엔진 패턴 설정
├── README.md                    # 문서
│
├── [레거시 트래픽 모듈 v1-v6]
│   ├── fullnameSearch.ts        # 상품명 검색 ✅
│   ├── midTarget.ts             # MID 타겟팅
│   ├── shoppingDiCategory.ts    # 쇼핑 카테고리
│   ├── packetFast.ts            # HTTP 패킷
│   ├── abTestTraffic.ts         # A/B 테스트
│   └── abTestTrafficV5.ts       # A/B 테스트 v5
│
├── engines/                     # 신규 엔진 시스템 (v7-v20)
│   ├── base/                    # 베이스 모듈
│   ├── integrated/              # 통합 모듈
│   ├── TrafficEngineBase.ts     # 핵심 엔진 로직
│   ├── TrafficEngineBaseSimple.ts  # ⭐ 10초 최적화 적용된 핵심 파일
│   │
│   ├── TrafficEngineV7.ts       # v7 표준
│   ├── TrafficEngineV7Fullname.ts  # v7 상품명 검색
│   ├── TrafficEngineV7Simple.ts # v7 간소화
│   ├── TrafficEngineV7Lazy.ts   # v7 지연 실행
│   ├── TrafficEngineV7Ultra.ts  # v7 공격적 타이밍
│   │
│   ├── TrafficEngineV8.ts ~ V20.ts           # 표준 (14개)
│   ├── TrafficEngineV8Fullname.ts ~ V20Fullname.ts  # 상품명 (14개)
│   └── TrafficEngineV8Simple.ts ~ V20Simple.ts      # 간소화 (14개)
│
├── profiles/                    # 14개 디바이스 핑거프린트
│   ├── v7-samsung-s23.json
│   ├── v8-iphone-15-pro.json
│   ├── v9-samsung-s24-ultra.json
│   ├── v10-xiaomi-13-pro.json
│   ├── v11-iphone-14-pro-max.json
│   ├── v12-oppo-find-x5-pro.json
│   ├── v13-google-pixel-8-pro.json
│   ├── v14-oneplus-11.json
│   ├── v15-vivo-x90-pro.json
│   ├── v16-samsung-z-fold5.json
│   ├── v17-iphone-13-pro.json
│   ├── v18-asus-rog-phone-7.json
│   ├── v19-samsung-a54.json
│   └── v20-motorola-edge-40-pro.json
│
├── shared/                      # 공유 유틸리티 (조합 패턴)
│   ├── behaviors/
│   │   ├── StrategyExecutor.ts  # 전략 실행기
│   │   └── StrategyLoader.ts    # 전략 로더
│   ├── browser/
│   │   ├── BrowserManager.ts    # 브라우저 생명주기
│   │   ├── NavigationOps.ts     # 페이지 네비게이션
│   │   ├── InputOps.ts          # 검색 입력 처리
│   │   └── MidMatcher.ts        # MID 매칭/클릭
│   ├── captcha/
│   │   ├── index.ts             # CAPTCHA 모듈 인덱스
│   │   └── ReceiptCaptchaSolver.ts  # Claude Vision CAPTCHA 해결기
│   ├── config/
│   │   └── EngineConfigLoader.ts  # 엔진 설정 로더
│   ├── detection/
│   │   ├── BlockDetector.ts     # 차단 감지
│   │   └── BridgeDetector.ts    # 브릿지 URL 감지
│   ├── fingerprint/
│   │   ├── types.ts             # FingerprintProfile 인터페이스
│   │   ├── ProfileLoader.ts     # JSON 프로필 로더
│   │   └── ProfileApplier.ts    # 브라우저 핑거프린트 적용
│   ├── navigation/              # 네비게이션 유틸
│   ├── profile/
│   │   ├── HistoryWarmer.ts     # 히스토리 워밍
│   │   └── ProfileManager.ts    # 프로필 관리
│   └── utils/
│       ├── Logger.ts            # 로깅
│       └── ProductInfoFetcher.ts  # 상품 정보 fetcher
│
└── strategies/                  # 트래픽 전략 모듈
    ├── dwell/
    │   ├── long.json            # 긴 체류 전략
    │   └── short.json           # 짧은 체류 전략
    └── input/
        ├── paste.json           # 붙여넣기 입력
        └── typing.json          # 타이핑 입력
```

### 수정된 파일

1. **`server/services/traffic/engines/TrafficEngineBaseSimple.ts`**
   - `execute()`: 통검 모드 지연 시간 최적화
   - `executeShoppingTabMode()`: 쇼검 모드 새 탭 방식 구현
   - `findAndClickMid()`: Bridge URL 클릭 후 지연 1.5초로 단축
   - `navigateViaCatalogUrl()`: 지연 1.5초로 단축

### 테스트 파일

| 파일 | 용도 |
|------|------|
| `test-tonggeom-v9.ts` | 통검 모드 테스트 |
| `test-shogeom-fast.ts` | 쇼검 빠른 모드 테스트 |
| `test-shogeom-new-tab.ts` | 새 탭 방식 디버깅 |
| `test-shogeom-user-behavior.ts` | 사용자 행동 패턴 분석 |
| `test-shogeom-same-tab.ts` | 같은 탭 방식 테스트 (실패) |

## 플로우 차트

### 통검 모드 (9.2초)
```
[0.0s] 네이버 모바일 메인 접속
[0.5s] 풀네임 검색 입력 + 제출
[1.5s] 검색 결과 로딩 대기
[1.9s] 스크롤 (2회)
[2.3s] MID 링크 찾기 + Bridge URL 클릭
[3.8s] 페이지 로딩 대기
[5.3s] Bridge redirect 대기 (필요시)
[7.8s] 최종 검증
[9.2s] 완료
```

### 쇼검 모드 (9.2초)
```
[0.0s] 네이버 PC 메인 접속
[0.5s] 풀네임 검색 입력 + 제출
[1.0s] 검색 결과 로딩 대기
[1.5s] 쇼핑탭 클릭 (새 탭 열림)
[3.0s] 새 탭 전환 + 뷰포트 설정
[4.0s] MID 상품 찾기 + 스크롤
[5.0s] 상품 클릭 (새 탭 열림)
[6.5s] 상품 페이지 새 탭 전환
[7.5s] 체류 스크롤 (2회)
[8.1s] 탭 정리
[9.2s] 완료
```

## 뷰포트 설정 (필수)

```typescript
await page.setViewport({
  width: 1366,
  height: 768,
  deviceScaleFactor: 1,
  isMobile: false,
  hasTouch: false,
});
```

**1366x768 선택 이유**:
- 한국 PC 모니터 1위 해상도
- PRB 기본값 800x600은 봇 탐지 위험
- CAPTCHA 발생률 최저

## 지문 동기화 (필수)

```typescript
await page.evaluateOnNewDocument(() => {
  // CDC 디버그 변수 제거
  delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Array;
  delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Object;
  delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Promise;

  // 창 크기 동기화
  Object.defineProperty(window, 'outerWidth',  { value: 1366 });
  Object.defineProperty(window, 'outerHeight', { value: 768 });
  Object.defineProperty(window, 'innerWidth',  { value: 1366 });
  Object.defineProperty(window, 'innerHeight', { value: 768 });

  // screen 동기화
  Object.defineProperties(screen, {
    availWidth:  { value: 1366 },
    availHeight: { value: 728 },  // 작업표시줄 고려 -40px
    width:       { value: 1366 },
    height:      { value: 768 },
  });

  // User-Agent + Client Hints
  const realUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
  Object.defineProperty(navigator, 'userAgent', { value: realUA });
  Object.defineProperty(navigator, 'platform', { value: 'Win32' });
  Object.defineProperty(navigator, 'userAgentData', {
    value: {
      brands: [
        { brand: "Google Chrome", version: "130" },
        { brand: "Chromium", version: "130" },
        { brand: "Not=A?Brand", version: "99" }
      ],
      platform: "Windows",
      mobile: false,
    }
  });

  // WebGL Renderer
  const getParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return "Intel Inc.";
    if (parameter === 37446) return "Intel(R) UHD Graphics 630";
    return getParameter.call(this, parameter);
  };
});
```

## 주의사항

1. **새 탭에는 `evaluateOnNewDocument` 미적용**
   - 새 탭 열린 후 `injectFingerprint()` 별도 호출 필요 (제한적)
   - 또는 빠르게 작업하고 탭 닫기

2. **Bridge URL 직접 클릭 권장**
   - Catalog URL 우회는 트래킹에 영향 없음 확인됨
   - Bridge URL 클릭이 네이버 순위 반영에 유리

3. **CAPTCHA 발생 시**
   - 지연 시간 증가 (1.5초 → 2초)
   - IP 쿨다운 5분 대기
   - Claude Vision CAPTCHA 해결기 활용

## 실행 방법

```bash
# 통검 테스트
npx tsx test-tonggeom-v9.ts

# 쇼검 테스트
npx tsx test-shogeom-fast.ts

# 엔진 기반 테스트
npx tsx test-engine-single.ts
```

## 변경 이력

| 날짜 | 변경 내용 |
|------|-----------|
| 2025.12.01 | 통검/쇼검 10초 최적화 완료 |
| 2025.12.01 | 쇼검 새 탭 방식 구현 |
| 2025.12.01 | 지연 시간 전면 최적화 |
