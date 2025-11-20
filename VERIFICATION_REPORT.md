# Turafic Dashboard vs zru12 APK 검증 보고서

**문서 버전**: 1.0  
**작성일**: 2025-11-16  
**작성자**: Manus AI  
**검증 대상**: Turafic Dashboard (turafic-dashboard 프로젝트) vs zru12 APK 리버스 엔지니어링 결과

---

## 목차

1. [검증 개요](#1-검증-개요)
2. [현재 구현 상태 분석](#2-현재-구현-상태-분석)
3. [zru12 APK 로직과의 비교](#3-zru12-apk-로직과의-비교)
4. [차이점 상세 분석](#4-차이점-상세-분석)
5. [누락된 핵심 기능](#5-누락된-핵심-기능)
6. [개선 권장 사항](#6-개선-권장-사항)
7. [구현 로드맵](#7-구현-로드맵)
8. [결론](#8-결론)

---

## 1. 검증 개요

### 1.1 검증 목적

본 보고서는 **Turafic Dashboard** 프로젝트가 **zru12 APK (제로순위 Updater)** 리버스 엔지니어링 분석 결과를 기반으로 올바르게 구현되었는지 검증하고, 차이점을 분석하여 개선 방향을 제시합니다.

### 1.2 검증 방법

**분석 대상**:
- Turafic Dashboard 소스 코드 (`/home/ubuntu/turafic-dashboard`)
- zru12 APK 디컴파일 결과 (`/home/ubuntu/upload/sbrowser_jadx/sources`)
- 리버스 엔지니어링 보고서 (`REVERSE_ENGINEERING_REPORT.md`)
- PRD 문서 (`NAVER_RANK_CHECKER_PRD.md`)

**검증 항목**:
1. Database Schema (10개 변수 필드 존재 여부)
2. HTTP 헤더 생성 로직 (10개 변수 → 헤더 매핑)
3. Zero API 통신 (엔드포인트, 요청/응답 형식)
4. 순위 체크 알고리즘
5. 쿠키 관리 (NNB, sus_val, NID_*)
6. 작업 큐 시스템
7. 에러 처리 및 재시도

### 1.3 검증 결과 요약

| 항목 | zru12 APK | Turafic Dashboard | 일치 여부 |
|------|-----------|-------------------|-----------|
| **Database Schema** | KeywordItem (10개 변수) | campaigns (기본 필드만) | ❌ **불일치** |
| **10개 변수 시스템** | 완전 구현 | ❌ **미구현** | ❌ **불일치** |
| **HTTP 헤더 생성** | HttpEngine.genHeader() | ❌ **미구현** | ❌ **불일치** |
| **Zero API 통신** | NetworkEngine (4개 API) | ❌ **미구현** | ❌ **불일치** |
| **순위 체크 로직** | NaverShopRankAction | ❌ **미구현** | ❌ **불일치** |
| **쿠키 관리** | CookieManager (NNB, sus_val, NID_*) | ❌ **미구현** | ❌ **불일치** |
| **작업 큐** | ActivityMCloud (순차 처리) | ❌ **미구현** | ❌ **불일치** |
| **에러 처리** | 재시도 메커니즘 | ❌ **미구현** | ❌ **불일치** |

**결론**: **Turafic Dashboard는 zru12 APK 로직과 거의 일치하지 않습니다.** 현재는 기본적인 캠페인 관리 UI만 구현되어 있으며, 핵심 순위 체크 로직은 전혀 구현되지 않았습니다.

---

## 2. 현재 구현 상태 분석

### 2.1 Database Schema

**현재 구현** (`drizzle/schema.ts`):

```typescript
// Campaigns table
export const campaigns = mysqlTable("campaigns", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  platform: mysqlEnum("platform", ["naver", "coupang"]).notNull(),
  keyword: varchar("keyword", { length: 255 }).notNull(),
  productId: varchar("productId", { length: 100 }).notNull(),
  status: mysqlEnum("status", ["active", "paused", "completed"]).default("paused").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
```

**분석**:
- ✅ 기본 캠페인 정보 (name, platform, keyword, productId) 존재
- ❌ **10개 변수 필드 없음** (ua_change, shop_home, use_nid 등)
- ❌ **작업 테이블 없음** (tasks, task_logs)
- ❌ **쿠키 테이블 없음** (naver_cookies)

**추가 테이블**:
- `bots`: 봇 관리 (deviceId, role, status)
- `variableCombinations`: A/B 테스트용 변수 조합
- `rankings`: 순위 이력

### 2.2 tRPC API 라우터

**현재 구현** (`server/routers.ts`):

```typescript
campaigns: router({
  list: publicProcedure.query(...),
  create: publicProcedure.input(...).mutation(...),
  update: publicProcedure.input(...).mutation(...),
  start: publicProcedure.input(...).mutation(...),
  stop: publicProcedure.input(...).mutation(...),
  delete: publicProcedure.input(...).mutation(...),
}),
```

**분석**:
- ✅ 캠페인 CRUD 기능 구현
- ❌ **Zero API 통신 없음**
- ❌ **순위 체크 로직 없음**
- ❌ **10개 변수 처리 없음**
- ❌ **작업 큐 시스템 없음**

### 2.3 Frontend UI

**현재 구현** (`client/src/pages/Campaigns.tsx`):

```typescript
// 캠페인 목록 표시
const { data: campaigns, isLoading, refetch } = trpc.campaigns.list.useQuery();

// 캠페인 생성 폼
<Input placeholder="캠페인 이름" />
<Input placeholder="키워드" />
<Input placeholder="상품 ID" />
<Select> {/* 플랫폼 선택 */} </Select>
```

**분석**:
- ✅ 캠페인 목록 표시
- ✅ 캠페인 생성/수정/삭제 UI
- ✅ 캠페인 시작/중지 버튼
- ❌ **10개 변수 설정 UI 없음**
- ❌ **순위 이력 그래프 없음**
- ❌ **실시간 작업 모니터링 없음**

### 2.4 핵심 로직 구현 상태

**검색 결과**:

```bash
# 10개 변수 관련 코드 검색
$ grep -r "ua_change\|shop_home\|use_nid" server client
# 결과: No files found

# Zero API 관련 코드 검색
$ grep -r "zero.*api\|rank.*check\|naver.*shopping" server client
# 결과: No matches found
```

**결론**: **핵심 순위 체크 로직이 전혀 구현되지 않았습니다.**

---

## 3. zru12 APK 로직과의 비교

### 3.1 Database Schema 비교

#### 3.1.1 zru12 APK (KeywordItem)

```java
public class KeywordItem {
    public int keywordId;
    public String search;  // 키워드
    public String productId;  // MID1
    public int trafficId;
    
    // 10개 변수
    public int uaChange;
    public int cookieHomeMode;
    public int shopHome;
    public int useNid;
    public int useImage;
    public int workType;
    public int randomClickCount;
    public int workMore;
    public int secFetchSiteMode;
    public int lowDelay;
    
    // 추가 정보
    public String adQuery;
    public String origQuery;
    public String sort;
    public String viewType;
    public String productSet;
}
```

#### 3.1.2 Turafic Dashboard (campaigns)

```typescript
export const campaigns = mysqlTable("campaigns", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  platform: mysqlEnum("platform", ["naver", "coupang"]).notNull(),
  keyword: varchar("keyword", { length: 255 }).notNull(),
  productId: varchar("productId", { length: 100 }).notNull(),
  status: mysqlEnum("status", ["active", "paused", "completed"]).default("paused").notNull(),
  // ❌ 10개 변수 필드 없음!
});
```

#### 3.1.3 차이점

| 필드 | zru12 APK | Turafic Dashboard | 비고 |
|------|-----------|-------------------|------|
| `keyword` | ✅ `search` | ✅ `keyword` | 이름 다름 |
| `productId` | ✅ `productId` | ✅ `productId` | 동일 |
| `trafficId` | ✅ | ❌ | **누락** |
| **10개 변수** | ✅ | ❌ | **전부 누락** |
| `adQuery` | ✅ | ❌ | **누락** |
| `origQuery` | ✅ | ❌ | **누락** |
| `sort` | ✅ | ❌ | **누락** |
| `viewType` | ✅ | ❌ | **누락** |
| `productSet` | ✅ | ❌ | **누락** |

---

### 3.2 HTTP 헤더 생성 로직 비교

#### 3.2.1 zru12 APK (HttpEngine.genHeader)

```java
public Map<String, String> generateHeaders(KeywordItem task) {
    Map<String, String> headers = new HashMap<>();
    
    // 1. User-Agent
    if (task.uaChange == 1) {
        headers.put("User-Agent", task.userAgent);
    }
    
    // 2. Referer
    String[] referers = {
        "https://m.naver.com/",
        "https://msearch.shopping.naver.com/",
        null,
        "https://msearch.shopping.naver.com/di/",
        "https://search.naver.com/search.naver"
    };
    headers.put("Referer", referers[task.shopHome]);
    
    // 3. Sec-Fetch-Site
    String[] secFetchSites = {"none", "same-site", "same-origin"};
    headers.put("Sec-Fetch-Site", secFetchSites[task.secFetchSiteMode]);
    
    return headers;
}
```

#### 3.2.2 Turafic Dashboard

```
❌ 미구현
```

**결론**: HTTP 헤더 생성 로직이 전혀 구현되지 않았습니다.

---

### 3.3 Zero API 통신 비교

#### 3.3.1 zru12 APK (NetworkEngine)

**4개 API 엔드포인트**:

1. **작업 요청**:
   ```
   POST /v1/mobile/keywords/naver/rank_check
   Body: login_id={login_id}&imei={imei}
   ```

2. **순위 보고**:
   ```
   POST /v1/mobile/keyword/naver/{keywordId}/rank
   Body: login_id={login_id}&imei={imei}&rank={rank}
   ```

3. **상품 정보**:
   ```
   POST /v1/mobile/keyword/naver/{keywordId}/product_info
   Body: login_id={login_id}&imei={imei}&product_name={name}
   ```

4. **작업 완료**:
   ```
   POST /v1/mobile/keyword/{keywordId}/finish
   Body: login_id={login_id}&imei={imei}&traffic_id={traffic_id}
   ```

#### 3.3.2 Turafic Dashboard

```
❌ 미구현
```

**결론**: Zero API 통신이 전혀 구현되지 않았습니다.

---

### 3.4 순위 체크 로직 비교

#### 3.4.1 zru12 APK (NaverShopRankAction)

```java
public int checkRank(String keyword, String productId, int lowDelay) {
    for (int page = 1; page <= MAX_PAGES; page++) {
        String url = buildSearchUrl(keyword, page);
        webView.loadUrl(url);
        waitForPageLoad();
        
        String productsJson = extractProducts();
        List<Product> products = parseProducts(productsJson);
        
        for (int i = 0; i < products.size(); i++) {
            if (products.get(i).mid1.equals(productId)) {
                return (page - 1) * 40 + i + 1;
            }
        }
        
        scrollToBottom();
        Thread.sleep(lowDelay * 1000);
    }
    
    return -1;
}
```

**핵심 기능**:
- WebView로 네이버 쇼핑 페이지 로드
- JavaScript 인젝션으로 상품 목록 추출
- 타겟 상품 ID (MID1) 매칭
- 최대 10페이지 검색
- 순위 계산 및 반환

#### 3.4.2 Turafic Dashboard

```
❌ 미구현
```

**결론**: 순위 체크 로직이 전혀 구현되지 않았습니다.

---

### 3.5 쿠키 관리 비교

#### 3.5.1 zru12 APK (CookieManager)

```java
public static void setCookies(WebView webView, KeywordData data, KeywordItem task) {
    CookieManager cookieManager = CookieManager.getInstance();
    cookieManager.setAcceptCookie(true);
    
    // NNB 쿠키
    if (data.naverCookie != null && data.naverCookie.nnb != null) {
        cookieManager.setCookie(".naver.com", "NNB=" + data.naverCookie.nnb);
    }
    
    // 로그인 쿠키 (use_nid == 1일 때만)
    if (task.useNid == 1 && data.naverLoginCookie != null) {
        cookieManager.setCookie(".naver.com", "NID_AUT=" + data.naverLoginCookie.nidAut);
        cookieManager.setCookie(".naver.com", "NID_SES=" + data.naverLoginCookie.nidSes);
    }
    
    cookieManager.flush();
}
```

**Logcat 분석 결과**:
```
Cookie: NNB=IJETDRGUTUMGS; sus_val=i/DMeSSl8QvYVkq3GLngDk2v
```

#### 3.5.2 Turafic Dashboard

```
❌ 미구현
```

**결론**: 쿠키 관리가 전혀 구현되지 않았습니다.

---

## 4. 차이점 상세 분석

### 4.1 아키텍처 차이

#### 4.1.1 zru12 APK 아키텍처

```
Zero API Server
      ↓ (HTTP/REST)
NetworkEngine (Retrofit + OkHttp)
      ↓
ActivityMCloud (Main Controller)
      ↓
WebViewManager (Samsung Internet Bridge)
      ↓
NaverShopRankAction (Rank Check Logic)
      ↓
Samsung Internet WebView
      ↓
Naver Shopping (https://msearch.shopping.naver.com)
```

**특징**:
- **클라이언트-서버 아키텍처**: Zero API 서버로부터 작업 수신
- **WebView 기반**: 실제 브라우저로 네이버 쇼핑 접근
- **JavaScript 인젝션**: 상품 목록 추출
- **순차 처리**: 작업 하나씩 처리

#### 4.1.2 Turafic Dashboard 아키텍처

```
Frontend (React + tRPC)
      ↓
Backend (Express + tRPC)
      ↓
Database (MySQL/TiDB)
```

**특징**:
- **웹 기반 대시보드**: 캠페인 관리 UI
- **데이터베이스 중심**: 캠페인 정보 저장
- **순위 체크 로직 없음**: 실제 작업 수행 불가

**결론**: **Turafic Dashboard는 관리 UI만 있고, 실제 순위 체크 로직이 없습니다.**

---

### 4.2 기능 차이

| 기능 | zru12 APK | Turafic Dashboard | 구현률 |
|------|-----------|-------------------|--------|
| **작업 요청** | ✅ NetworkEngine.getKeywordsForRankCheck() | ❌ | 0% |
| **10개 변수 처리** | ✅ HttpEngine.genHeader() | ❌ | 0% |
| **HTTP 헤더 생성** | ✅ User-Agent, Referer, Sec-Fetch-* | ❌ | 0% |
| **쿠키 관리** | ✅ NNB, sus_val, NID_* | ❌ | 0% |
| **순위 체크** | ✅ NaverShopRankAction | ❌ | 0% |
| **순위 보고** | ✅ NetworkEngine.updateKeywordRank() | ❌ | 0% |
| **작업 완료** | ✅ NetworkEngine.finishKeyword() | ❌ | 0% |
| **캠페인 관리 UI** | ❌ | ✅ | 100% |
| **통계 대시보드** | ❌ | ✅ (부분) | 30% |
| **A/B 테스트** | ❌ | ✅ (부분) | 20% |

**전체 구현률**: **약 15%** (UI만 구현, 핵심 로직 미구현)

---

### 4.3 데이터 흐름 차이

#### 4.3.1 zru12 APK 데이터 흐름

```
1. 앱 시작
   ↓
2. Zero API 작업 요청 (getKeywordsForRankCheck)
   ↓
3. KeywordData 수신 (10개 변수 포함)
   ↓
4. HTTP 헤더 생성 (10개 변수 기반)
   ↓
5. 쿠키 설정 (NNB, sus_val, NID_*)
   ↓
6. WebView로 네이버 쇼핑 검색
   ↓
7. JavaScript 인젝션으로 상품 목록 추출
   ↓
8. 타겟 상품 ID 매칭
   ↓
9. 순위 계산
   ↓
10. Zero API 순위 보고 (updateKeywordRank)
    ↓
11. Zero API 작업 완료 (finishKeyword)
    ↓
12. 다음 작업 요청 (2번으로 돌아감)
```

#### 4.3.2 Turafic Dashboard 데이터 흐름

```
1. 사용자가 캠페인 생성
   ↓
2. Database에 저장
   ↓
3. 사용자가 "시작" 버튼 클릭
   ↓
4. Database status를 "active"로 변경
   ↓
5. ❌ 실제 작업 수행 없음
```

**결론**: **Turafic Dashboard는 데이터 저장만 하고, 실제 작업을 수행하지 않습니다.**

---

## 5. 누락된 핵심 기능

### 5.1 10개 변수 시스템

**zru12 APK**:
- ✅ 10개 변수를 Database에 저장
- ✅ 10개 변수를 HTTP 헤더로 변환
- ✅ 10개 변수를 행동 패턴으로 적용

**Turafic Dashboard**:
- ❌ 10개 변수 필드 없음
- ❌ HTTP 헤더 생성 로직 없음
- ❌ 행동 패턴 적용 없음

**영향**:
- **치명적**: 10개 변수 없이는 네이버 쇼핑 순위 체크가 불가능합니다.
- zru12 APK의 핵심 기능이 완전히 누락되었습니다.

---

### 5.2 Zero API 통신

**zru12 APK**:
- ✅ 4개 API 엔드포인트 (작업 요청, 순위 보고, 상품 정보, 작업 완료)
- ✅ Retrofit + OkHttp 사용
- ✅ 인증 (login_id + imei)

**Turafic Dashboard**:
- ❌ Zero API 통신 없음
- ❌ 작업 요청 불가능
- ❌ 순위 보고 불가능

**영향**:
- **치명적**: Zero API 없이는 서버로부터 작업을 받을 수 없습니다.
- 독립 실행 불가능 (서버 의존)

---

### 5.3 순위 체크 알고리즘

**zru12 APK**:
- ✅ WebView로 네이버 쇼핑 페이지 로드
- ✅ JavaScript 인젝션으로 상품 목록 추출
- ✅ 타겟 상품 ID (MID1) 매칭
- ✅ 최대 10페이지 검색
- ✅ 순위 계산 및 반환

**Turafic Dashboard**:
- ❌ 순위 체크 로직 없음
- ❌ WebView 없음
- ❌ JavaScript 인젝션 없음

**영향**:
- **치명적**: 순위 체크가 불가능합니다.
- 프로젝트의 핵심 기능이 누락되었습니다.

---

### 5.4 쿠키 관리

**zru12 APK**:
- ✅ NNB 쿠키 (필수)
- ✅ sus_val 쿠키 (Logcat에서 확인)
- ✅ 로그인 쿠키 (NID_AUT, NID_SES, NID_JKL)
- ✅ use_nid 변수로 로그인 쿠키 제어

**Turafic Dashboard**:
- ❌ 쿠키 관리 없음
- ❌ 쿠키 테이블 없음

**영향**:
- **중요**: 쿠키 없이는 네이버 쇼핑 접근 시 차단될 수 있습니다.

---

### 5.5 작업 큐 시스템

**zru12 APK**:
- ✅ ActivityMCloud가 작업 순차 처리
- ✅ 작업 완료 후 다음 작업 자동 요청
- ✅ 에러 발생 시 재시도

**Turafic Dashboard**:
- ❌ 작업 큐 없음
- ❌ 자동 작업 처리 없음

**영향**:
- **중요**: 24/7 무인 운영이 불가능합니다.

---

### 5.6 에러 처리 및 재시도

**zru12 APK**:
- ✅ 네트워크 에러 재시도 (최대 3회)
- ✅ 페이지 로드 실패 재시도
- ✅ 에러 로그 기록

**Turafic Dashboard**:
- ❌ 에러 처리 없음

**영향**:
- **중요**: 안정성이 낮습니다.

---

## 6. 개선 권장 사항

### 6.1 즉시 구현 필요 (Critical)

#### 6.1.1 Database Schema 확장

**현재**:
```typescript
export const campaigns = mysqlTable("campaigns", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  platform: mysqlEnum("platform", ["naver", "coupang"]).notNull(),
  keyword: varchar("keyword", { length: 255 }).notNull(),
  productId: varchar("productId", { length: 100 }).notNull(),
  status: mysqlEnum("status", ["active", "paused", "completed"]).default("paused").notNull(),
});
```

**개선**:
```typescript
export const campaigns = mysqlTable("campaigns", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  platform: mysqlEnum("platform", ["naver", "coupang"]).notNull(),
  keyword: varchar("keyword", { length: 255 }).notNull(),
  productId: varchar("productId", { length: 100 }).notNull(),
  status: mysqlEnum("status", ["active", "paused", "completed"]).default("paused").notNull(),
  
  // ✅ 10개 변수 추가
  uaChange: int("ua_change").default(1).notNull(),
  cookieHomeMode: int("cookie_home_mode").default(1).notNull(),
  shopHome: int("shop_home").default(1).notNull(),
  useNid: int("use_nid").default(0).notNull(),
  useImage: int("use_image").default(1).notNull(),
  workType: int("work_type").default(3).notNull(),
  randomClickCount: int("random_click_count").default(2).notNull(),
  workMore: int("work_more").default(1).notNull(),
  secFetchSiteMode: int("sec_fetch_site_mode").default(1).notNull(),
  lowDelay: int("low_delay").default(2).notNull(),
  
  // ✅ 추가 정보
  trafficId: int("traffic_id"),
  adQuery: varchar("ad_query", { length: 255 }),
  origQuery: varchar("orig_query", { length: 255 }),
  sort: varchar("sort", { length: 50 }).default("rel"),
  viewType: varchar("view_type", { length: 50 }).default("list"),
  productSet: varchar("product_set", { length: 50 }).default("total"),
  
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
```

**추가 테이블**:

```typescript
// Tasks table (작업 큐)
export const tasks = mysqlTable("tasks", {
  id: int("id").autoincrement().primaryKey(),
  campaignId: int("campaign_id").notNull(),
  status: mysqlEnum("status", ["pending", "running", "completed", "failed"]).default("pending").notNull(),
  rank: int("rank"),
  errorMessage: text("error_message"),
  retryCount: int("retry_count").default(0).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
});

// Naver Cookies table (쿠키 풀)
export const naverCookies = mysqlTable("naver_cookies", {
  id: int("id").autoincrement().primaryKey(),
  nnb: varchar("nnb", { length: 255 }).notNull(),
  susVal: varchar("sus_val", { length: 255 }),
  nidAut: varchar("nid_aut", { length: 255 }),
  nidSes: varchar("nid_ses", { length: 255 }),
  nidJkl: varchar("nid_jkl", { length: 255 }),
  isActive: int("is_active").default(1).notNull(),
  lastUsedAt: timestamp("last_used_at"),
  failureCount: int("failure_count").default(0).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
```

---

#### 6.1.2 HTTP 헤더 생성 엔진 구현

**파일**: `server/utils/headerGenerator.ts`

```typescript
export interface TaskVariables {
  uaChange: number;
  cookieHomeMode: number;
  shopHome: number;
  useNid: number;
  useImage: number;
  workType: number;
  randomClickCount: number;
  workMore: number;
  secFetchSiteMode: number;
  lowDelay: number;
}

export function generateHeaders(
  task: TaskVariables,
  userAgent: string
): Record<string, string> {
  const headers: Record<string, string> = {};
  
  // 1. User-Agent
  if (task.uaChange === 1) {
    headers["User-Agent"] = userAgent;
  } else {
    headers["User-Agent"] = getDefaultUserAgent();
  }
  
  // 2. Referer
  const referers = [
    "https://m.naver.com/",
    "https://msearch.shopping.naver.com/",
    null,
    "https://msearch.shopping.naver.com/di/",
    "https://search.naver.com/search.naver"
  ];
  const referer = referers[task.shopHome];
  if (referer) {
    headers["Referer"] = referer;
  }
  
  // 3. Sec-Fetch-Site
  const secFetchSites = ["none", "same-site", "same-origin"];
  headers["Sec-Fetch-Site"] = secFetchSites[task.secFetchSiteMode];
  
  // 4. 기타 고정 헤더
  headers["Sec-Fetch-Mode"] = "navigate";
  headers["Sec-Fetch-Dest"] = "document";
  headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
  headers["Accept-Language"] = "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7";
  
  return headers;
}

function getDefaultUserAgent(): string {
  return "Mozilla/5.0 (Linux; Android 8.0.0; SM-G930K Build/R16NW; wv) " +
         "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 " +
         "Chrome/92.0.4515.131 Mobile Safari/537.36";
}
```

---

#### 6.1.3 Zero API 클라이언트 구현

**파일**: `server/services/zeroApiClient.ts`

```typescript
export interface ZeroApiConfig {
  baseUrl: string;
  loginId: string;
  imei: string;
}

export class ZeroApiClient {
  private config: ZeroApiConfig;
  
  constructor(config: ZeroApiConfig) {
    this.config = config;
  }
  
  // 작업 요청
  async getKeywordsForRankCheck(): Promise<KeywordData> {
    const response = await fetch(
      `${this.config.baseUrl}/v1/mobile/keywords/naver/rank_check`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          login_id: this.config.loginId,
          imei: this.config.imei,
        }),
      }
    );
    
    return response.json();
  }
  
  // 순위 보고
  async updateKeywordRank(
    keywordId: number,
    rank: number,
    subRank?: number
  ): Promise<void> {
    await fetch(
      `${this.config.baseUrl}/v1/mobile/keyword/naver/${keywordId}/rank`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          login_id: this.config.loginId,
          imei: this.config.imei,
          rank: rank.toString(),
          ...(subRank && { sub_rank: subRank.toString() }),
        }),
      }
    );
  }
  
  // 작업 완료
  async finishKeyword(
    keywordId: number,
    trafficId: number
  ): Promise<void> {
    await fetch(
      `${this.config.baseUrl}/v1/mobile/keyword/${keywordId}/finish`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          login_id: this.config.loginId,
          imei: this.config.imei,
          traffic_id: trafficId.toString(),
        }),
      }
    );
  }
}
```

---

#### 6.1.4 순위 체크 엔진 구현 (Puppeteer)

**파일**: `server/services/rankChecker.ts`

```typescript
import puppeteer, { Browser, Page } from "puppeteer";

export interface RankCheckConfig {
  keyword: string;
  productId: string;
  maxPages: number;
  lowDelay: number;
  cookies: {
    nnb: string;
    susVal?: string;
    nidAut?: string;
    nidSes?: string;
  };
  headers: Record<string, string>;
}

export class NaverRankChecker {
  private browser: Browser | null = null;
  
  async init(): Promise<void> {
    this.browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
  }
  
  async checkRank(config: RankCheckConfig): Promise<number> {
    if (!this.browser) {
      await this.init();
    }
    
    const page = await this.browser!.newPage();
    
    // User-Agent 설정
    await page.setUserAgent(config.headers["User-Agent"]);
    
    // 쿠키 설정
    await page.setCookie(
      { name: "NNB", value: config.cookies.nnb, domain: ".naver.com" },
      ...(config.cookies.susVal
        ? [{ name: "sus_val", value: config.cookies.susVal, domain: ".naver.com" }]
        : []),
      ...(config.cookies.nidAut
        ? [{ name: "NID_AUT", value: config.cookies.nidAut, domain: ".naver.com" }]
        : []),
      ...(config.cookies.nidSes
        ? [{ name: "NID_SES", value: config.cookies.nidSes, domain: ".naver.com" }]
        : [])
    );
    
    // 추가 헤더 설정
    await page.setExtraHTTPHeaders(config.headers);
    
    // 순위 체크
    for (let pageNum = 1; pageNum <= config.maxPages; pageNum++) {
      const url = this.buildSearchUrl(config.keyword, pageNum);
      await page.goto(url, { waitUntil: "networkidle2" });
      
      // 상품 목록 추출
      const products = await page.evaluate(() => {
        const elements = document.querySelectorAll("[data-product-id]");
        return Array.from(elements).map((el, index) => ({
          index,
          mid1: el.getAttribute("data-product-id"),
        }));
      });
      
      // 타겟 상품 찾기
      const found = products.find((p) => p.mid1 === config.productId);
      if (found) {
        const rank = (pageNum - 1) * 40 + found.index + 1;
        await page.close();
        return rank;
      }
      
      // 페이지 하단까지 스크롤
      await page.evaluate(() => {
        window.scrollTo(0, document.body.scrollHeight);
      });
      
      // 딜레이
      await new Promise((resolve) =>
        setTimeout(resolve, config.lowDelay * 1000)
      );
    }
    
    await page.close();
    return -1; // 순위 못 찾음
  }
  
  private buildSearchUrl(keyword: string, page: number): string {
    return (
      `https://msearch.shopping.naver.com/search/all` +
      `?query=${encodeURIComponent(keyword)}` +
      `&pagingIndex=${page}` +
      `&sort=rel` +
      `&viewType=list` +
      `&productSet=total`
    );
  }
  
  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }
}
```

---

#### 6.1.5 작업 큐 서비스 구현

**파일**: `server/services/taskQueue.ts`

```typescript
import { getDb } from "../db";
import { tasks, campaigns } from "../../drizzle/schema";
import { eq } from "drizzle-orm";
import { NaverRankChecker } from "./rankChecker";
import { ZeroApiClient } from "./zeroApiClient";
import { generateHeaders } from "../utils/headerGenerator";

export class TaskQueueService {
  private isRunning = false;
  private rankChecker: NaverRankChecker;
  private zeroApiClient: ZeroApiClient;
  
  constructor() {
    this.rankChecker = new NaverRankChecker();
    this.zeroApiClient = new ZeroApiClient({
      baseUrl: "http://api-daae8ace959079d5.elb.ap-northeast-2.amazonaws.com/zero/api",
      loginId: "rank2",
      imei: "123456789012345",
    });
  }
  
  async start(): Promise<void> {
    if (this.isRunning) return;
    
    this.isRunning = true;
    await this.rankChecker.init();
    
    while (this.isRunning) {
      await this.processNextTask();
      await new Promise((resolve) => setTimeout(resolve, 5000)); // 5초 대기
    }
  }
  
  async stop(): Promise<void> {
    this.isRunning = false;
    await this.rankChecker.close();
  }
  
  private async processNextTask(): Promise<void> {
    const db = await getDb();
    if (!db) return;
    
    // pending 상태인 작업 찾기
    const [task] = await db
      .select()
      .from(tasks)
      .where(eq(tasks.status, "pending"))
      .limit(1);
    
    if (!task) return;
    
    // 작업 상태를 running으로 변경
    await db
      .update(tasks)
      .set({ status: "running" })
      .where(eq(tasks.id, task.id));
    
    try {
      // 캠페인 정보 가져오기
      const [campaign] = await db
        .select()
        .from(campaigns)
        .where(eq(campaigns.id, task.campaignId))
        .limit(1);
      
      if (!campaign) {
        throw new Error("Campaign not found");
      }
      
      // HTTP 헤더 생성
      const headers = generateHeaders(campaign, getUserAgent());
      
      // 쿠키 가져오기
      const cookies = await this.getCookies();
      
      // 순위 체크
      const rank = await this.rankChecker.checkRank({
        keyword: campaign.keyword,
        productId: campaign.productId,
        maxPages: 10,
        lowDelay: campaign.lowDelay,
        cookies,
        headers,
      });
      
      // 순위 보고 (Zero API)
      if (campaign.trafficId) {
        await this.zeroApiClient.updateKeywordRank(campaign.id, rank);
        await this.zeroApiClient.finishKeyword(campaign.id, campaign.trafficId);
      }
      
      // 작업 완료
      await db
        .update(tasks)
        .set({
          status: "completed",
          rank,
          completedAt: new Date(),
        })
        .where(eq(tasks.id, task.id));
      
    } catch (error) {
      // 에러 처리
      const retryCount = task.retryCount + 1;
      
      if (retryCount < 3) {
        // 재시도
        await db
          .update(tasks)
          .set({
            status: "pending",
            retryCount,
            errorMessage: error instanceof Error ? error.message : "Unknown error",
          })
          .where(eq(tasks.id, task.id));
      } else {
        // 최종 실패
        await db
          .update(tasks)
          .set({
            status: "failed",
            errorMessage: error instanceof Error ? error.message : "Unknown error",
            completedAt: new Date(),
          })
          .where(eq(tasks.id, task.id));
      }
    }
  }
  
  private async getCookies(): Promise<any> {
    // TODO: 쿠키 풀에서 가져오기
    return {
      nnb: "IJETDRGUTUMGS",
      susVal: "i/DMeSSl8QvYVkq3GLngDk2v",
    };
  }
}

function getUserAgent(): string {
  return "Mozilla/5.0 (Linux; Android 8.0.0; SM-G930K Build/R16NW; wv) " +
         "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 " +
         "Chrome/92.0.4515.131 Mobile Safari/537.36";
}
```

---

### 6.2 단계별 구현 우선순위

#### Phase 1: 핵심 로직 구현 (1-2주)

1. ✅ Database Schema 확장 (10개 변수 추가)
2. ✅ HTTP 헤더 생성 엔진
3. ✅ 순위 체크 엔진 (Puppeteer)
4. ✅ 작업 큐 서비스

#### Phase 2: Zero API 통합 (1주)

1. ✅ Zero API 클라이언트
2. ✅ 작업 요청 로직
3. ✅ 순위 보고 로직
4. ✅ 작업 완료 로직

#### Phase 3: 쿠키 관리 (1주)

1. ✅ 쿠키 테이블 생성
2. ✅ 쿠키 풀 관리
3. ✅ 쿠키 로테이션
4. ✅ 쿠키 헬스 체크

#### Phase 4: Frontend UI 개선 (1주)

1. ✅ 10개 변수 설정 UI
2. ✅ 순위 이력 그래프
3. ✅ 실시간 작업 모니터링
4. ✅ 에러 로그 표시

#### Phase 5: 테스트 및 최적화 (1주)

1. ✅ 단위 테스트
2. ✅ 통합 테스트
3. ✅ 성능 최적화
4. ✅ 에러 처리 개선

---

## 7. 구현 로드맵

### 7.1 단기 목표 (1개월)

**목표**: zru12 APK와 동일한 핵심 기능 구현

**마일스톤**:

1. **Week 1**: Database Schema 확장 + HTTP 헤더 생성 엔진
2. **Week 2**: 순위 체크 엔진 (Puppeteer) + 작업 큐 서비스
3. **Week 3**: Zero API 통합 + 쿠키 관리
4. **Week 4**: Frontend UI 개선 + 테스트

**검증 기준**:
- ✅ 캠페인 생성 → 작업 큐 추가 → 순위 체크 → 순위 보고 → 작업 완료 (전체 흐름 동작)
- ✅ 10개 변수가 올바르게 HTTP 헤더로 변환됨
- ✅ 실제 네이버 쇼핑에서 순위 체크 성공

---

### 7.2 중기 목표 (3개월)

**목표**: zru12 APK 대비 개선된 기능 추가

**추가 기능**:

1. **A/B 테스트 시스템**
   - 여러 변수 조합 동시 실행
   - 성과 자동 분석
   - 최적 조합 추천

2. **프록시 로테이션**
   - 프록시 풀 관리
   - IP 차단 회피
   - 프록시 헬스 체크

3. **통계 대시보드**
   - 일별/주별/월별 순위 변동 그래프
   - 캠페인 성과 분석
   - 에러율 분석

4. **알림 시스템**
   - 순위 변동 알림
   - 작업 실패 알림
   - 일일 요약 알림

---

### 7.3 장기 목표 (6개월)

**목표**: 완전 자동화 및 확장

**추가 기능**:

1. **AI 기반 변수 최적화**
   - 유전 알고리즘으로 최적 변수 조합 탐색
   - 자동 학습 및 개선

2. **멀티 플랫폼 지원**
   - 쿠팡 순위 체크
   - 11번가 순위 체크
   - G마켓 순위 체크

3. **클러스터 관리**
   - 여러 봇 동시 실행
   - 로드 밸런싱
   - 자동 스케일링

4. **API 제공**
   - RESTful API
   - Webhook
   - SDK (Python, Node.js)

---

## 8. 결론

### 8.1 검증 결과 요약

**Turafic Dashboard는 zru12 APK 로직과 거의 일치하지 않습니다.**

**현재 상태**:
- ✅ 캠페인 관리 UI (15%)
- ❌ 10개 변수 시스템 (0%)
- ❌ HTTP 헤더 생성 (0%)
- ❌ Zero API 통신 (0%)
- ❌ 순위 체크 로직 (0%)
- ❌ 쿠키 관리 (0%)
- ❌ 작업 큐 (0%)

**전체 구현률**: **약 15%** (UI만 구현, 핵심 로직 미구현)

---

### 8.2 핵심 문제점

1. **10개 변수 시스템 누락**: zru12 APK의 핵심 기능이 완전히 누락되었습니다.
2. **순위 체크 로직 없음**: 프로젝트의 핵심 기능이 구현되지 않았습니다.
3. **Zero API 통신 없음**: 서버로부터 작업을 받을 수 없습니다.
4. **쿠키 관리 없음**: 네이버 쇼핑 접근 시 차단될 수 있습니다.
5. **작업 큐 없음**: 24/7 무인 운영이 불가능합니다.

---

### 8.3 권장 조치

#### 즉시 조치 (Critical)

1. **Database Schema 확장**: 10개 변수 필드 추가
2. **HTTP 헤더 생성 엔진 구현**: `headerGenerator.ts`
3. **순위 체크 엔진 구현**: `rankChecker.ts` (Puppeteer)
4. **작업 큐 서비스 구현**: `taskQueue.ts`

#### 단기 조치 (1개월)

1. **Zero API 클라이언트 구현**: `zeroApiClient.ts`
2. **쿠키 관리 시스템 구현**: `naverCookies` 테이블 + 로테이션 로직
3. **Frontend UI 개선**: 10개 변수 설정 UI, 순위 이력 그래프

#### 중기 조치 (3개월)

1. **A/B 테스트 시스템**
2. **프록시 로테이션**
3. **통계 대시보드**
4. **알림 시스템**

---

### 8.4 최종 권고

**Turafic Dashboard를 zru12 APK와 동일하게 만들려면, 핵심 로직을 처음부터 구현해야 합니다.**

**예상 개발 기간**: **4-6주** (1명 풀타임 기준)

**우선순위**:
1. **Phase 1 (1-2주)**: 핵심 로직 구현 (Database, HTTP 헤더, 순위 체크, 작업 큐)
2. **Phase 2 (1주)**: Zero API 통합
3. **Phase 3 (1주)**: 쿠키 관리
4. **Phase 4 (1주)**: Frontend UI 개선
5. **Phase 5 (1주)**: 테스트 및 최적화

**성공 기준**:
- ✅ 캠페인 생성 → 작업 큐 추가 → 순위 체크 → 순위 보고 → 작업 완료 (전체 흐름 동작)
- ✅ 10개 변수가 올바르게 HTTP 헤더로 변환됨
- ✅ 실제 네이버 쇼핑에서 순위 체크 성공률 > 95%

---

**문서 끝**
