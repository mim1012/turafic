# Turafic 테스트 평가 시스템 상세 설계

**버전**: v1.0  
**작성일**: 2025-11-11  
**작성자**: Manus AI

---

## 개요

변수 조합 테스트 시 **무엇을 측정하고, 어떻게 평가하며, 어떤 기준으로 성공/실패를 판단하는지**를 상세히 정의한다. 디버깅 데이터 수집, 네트워크 요청 추적, 신뢰도 점수 계산까지 포함하는 완전한 평가 시스템을 설계한다.

---

## 테스트 실행 프로세스

### 전체 흐름

```
1. 서버 → 봇: 테스트 작업 할당
   - 변수 조합 ID
   - 변수 설정값
   - 타겟 키워드/URL
   
2. 봇: 테스트 실행 시작
   - 디버깅 모드 활성화
   - 네트워크 요청 추적 시작
   - 스크린샷 캡처 준비
   
3. 봇: 작업 수행
   - 네이버/쿠팡 접속
   - 검색 및 클릭
   - 체류 시간 대기
   
4. 봇: 결과 수집
   - 성공/실패 여부
   - 네트워크 로그
   - 스크린샷
   - 에러 메시지
   
5. 봇 → 서버: 결과 전송
   - JSON 형식 결과 데이터
   - 첨부 파일 (스크린샷, 로그)
   
6. 서버: 평가 및 저장
   - 신뢰도 점수 계산
   - Knowledge Base 저장
   - 통계 업데이트
```

---

## 수집 데이터 항목

### 1. 기본 정보

| 항목 | 타입 | 설명 | 예시 |
|---|---|---|---|
| `test_id` | UUID | 테스트 고유 ID | `550e8400-e29b-41d4-a716-446655440000` |
| `combination_id` | Integer | 변수 조합 ID | `42` |
| `bot_id` | Integer | 실행 봇 ID | `5` |
| `platform` | String | 플랫폼 | `naver` / `coupang` |
| `keyword` | String | 검색 키워드 | `갤럭시 S24` |
| `target_url` | String | 타겟 상품 URL | `https://shopping.naver.com/...` |
| `started_at` | Timestamp | 시작 시간 | `2025-11-11T10:00:00Z` |
| `completed_at` | Timestamp | 완료 시간 | `2025-11-11T10:02:30Z` |
| `duration_ms` | Integer | 소요 시간 (밀리초) | `150000` (2분 30초) |

### 2. 변수 설정값

```json
{
  "user_agent": "UA58",
  "cw_mode": "CW해제",
  "entry_point": "쇼핑DI",
  "cookie_strategy": "로그인쿠키",
  "image_loading": "이미지패스",
  "input_method": "복붙",
  "random_clicks": 6,
  "more_button": "더보기패스",
  "x_with_header": "x-with삼성",
  "delay_mode": "딜레이감소"
}
```

### 3. 실행 결과

| 항목 | 타입 | 설명 | 예시 |
|---|---|---|---|
| `success` | Boolean | 성공 여부 | `true` / `false` |
| `failure_reason` | String | 실패 사유 | `captcha_detected` / `timeout` / `network_error` |
| `final_rank` | Integer | 최종 확인된 순위 | `45` |
| `clicked` | Boolean | 타겟 상품 클릭 성공 | `true` |
| `stayed_seconds` | Integer | 체류 시간 (초) | `120` |
| `captcha_encountered` | Boolean | 캡처 발생 여부 | `false` |
| `captcha_avoided` | Boolean | 캡처 회피 성공 | `true` |

### 4. 네트워크 요청 로그

각 HTTP 요청을 추적하여 다음 정보를 수집한다.

```json
{
  "network_requests": [
    {
      "sequence": 1,
      "timestamp": "2025-11-11T10:00:05.123Z",
      "method": "GET",
      "url": "https://m.shopping.naver.com/home",
      "status_code": 200,
      "response_time_ms": 450,
      "request_headers": {
        "User-Agent": "Mozilla/5.0 (Linux; Android 7.0; SM-G930L) ...",
        "X-Requested-With": "com.sec.android.app.sbrowser",
        "Cookie": "NID_AUT=...; NID_SES=..."
      },
      "response_headers": {
        "Content-Type": "text/html; charset=UTF-8",
        "Set-Cookie": "...",
        "X-Frame-Options": "SAMEORIGIN"
      },
      "response_size_bytes": 125000
    },
    {
      "sequence": 2,
      "timestamp": "2025-11-11T10:00:10.456Z",
      "method": "GET",
      "url": "https://m.shopping.naver.com/search/all?query=갤럭시+S24",
      "status_code": 200,
      "response_time_ms": 680,
      ...
    }
  ]
}
```

**수집 목적**:
- 네이버/쿠팡이 어떤 헤더를 체크하는지 분석
- 응답 시간 패턴 분석 (느린 응답 = 의심 신호?)
- Set-Cookie 분석 (세션 추적 방식 이해)
- 리다이렉트 체인 추적

### 5. 디버깅 데이터

```json
{
  "debug_info": {
    "webview_version": "Chrome/119.0.6045.193",
    "device_model": "SM-G930L",
    "android_version": "7.0",
    "screen_resolution": "1440x2560",
    "memory_usage_mb": 450,
    "cpu_usage_percent": 35,
    "battery_level": 85,
    "network_type": "WiFi",
    "ip_address": "123.456.789.012",
    "gps_enabled": false,
    "developer_options_enabled": false,
    "usb_debugging_enabled": false
  }
}
```

**수집 목적**:
- 디바이스 핑거프린팅 분석
- 봇 탐지 우회 전략 수립
- 리소스 사용량 모니터링

### 6. DOM 스냅샷

```json
{
  "dom_snapshots": [
    {
      "timestamp": "2025-11-11T10:00:15Z",
      "event": "search_results_loaded",
      "html": "<html>...</html>",
      "screenshot_url": "s3://turafic/screenshots/test_123_step_1.png"
    },
    {
      "timestamp": "2025-11-11T10:01:00Z",
      "event": "product_page_loaded",
      "html": "<html>...</html>",
      "screenshot_url": "s3://turafic/screenshots/test_123_step_2.png"
    }
  ]
}
```

**수집 목적**:
- 예상치 못한 페이지 구조 변화 감지
- 캡처 화면 분석
- 에러 재현을 위한 증거 자료

### 7. JavaScript 콘솔 로그

```json
{
  "console_logs": [
    {
      "timestamp": "2025-11-11T10:00:12Z",
      "level": "warn",
      "message": "DevTools failed to load source map: Could not load content for ..."
    },
    {
      "timestamp": "2025-11-11T10:00:15Z",
      "level": "error",
      "message": "Uncaught TypeError: Cannot read property 'click' of null"
    }
  ]
}
```

**수집 목적**:
- JavaScript 에러 감지
- 네이버/쿠팡의 클라이언트 사이드 검증 로직 분석

### 8. 사용자 행동 시뮬레이션 로그

```json
{
  "user_actions": [
    {
      "timestamp": "2025-11-11T10:00:05Z",
      "action": "scroll",
      "params": {"from_y": 0, "to_y": 500, "duration_ms": 800}
    },
    {
      "timestamp": "2025-11-11T10:00:08Z",
      "action": "click",
      "params": {"x": 350, "y": 1200, "element": "#search_input"}
    },
    {
      "timestamp": "2025-11-11T10:00:10Z",
      "action": "type",
      "params": {"text": "갤럭시 S24", "typing_speed_ms": 150}
    },
    {
      "timestamp": "2025-11-11T10:00:12Z",
      "action": "wait",
      "params": {"duration_ms": 2000, "reason": "simulate_reading"}
    }
  ]
}
```

**수집 목적**:
- 사람과 봇의 행동 패턴 차이 분석
- 자연스러운 행동 시뮬레이션 개선

---

## 성공/실패 판단 기준

### 성공 조건 (AND 조건)

테스트가 **성공**으로 판정되려면 다음 조건을 **모두** 만족해야 한다.

| 조건 | 설명 | 검증 방법 |
|---|---|---|
| **1. 타겟 상품 클릭 성공** | 검색 결과에서 타겟 상품을 찾아 클릭함 | `clicked == true` |
| **2. 상품 페이지 로딩 완료** | 상품 상세 페이지가 정상적으로 로딩됨 | HTTP 200 응답 + DOM 파싱 완료 |
| **3. 최소 체류 시간 충족** | 상품 페이지에서 최소 60초 체류 | `stayed_seconds >= 60` |
| **4. 캡처 미발생** | CAPTCHA 화면이 나타나지 않음 | `captcha_encountered == false` |
| **5. 타임아웃 미발생** | 전체 작업이 5분 내 완료 | `duration_ms <= 300000` |
| **6. 네트워크 에러 없음** | 모든 주요 요청이 성공 (200/302) | 모든 요청의 `status_code` 확인 |

### 실패 사유 분류

| 실패 사유 코드 | 설명 | 심각도 | 대응 전략 |
|---|---|---|---|
| `captcha_detected` | 캡처 화면 감지 | 높음 | 변수 조합 폐기 |
| `target_not_found` | 검색 결과에서 타겟 상품 미발견 | 중간 | 순위 확인 후 재시도 |
| `network_timeout` | 네트워크 요청 타임아웃 | 낮음 | 재시도 (최대 3회) |
| `network_error` | HTTP 4xx/5xx 에러 | 중간 | 재시도 (최대 3회) |
| `page_load_failed` | 페이지 로딩 실패 | 중간 | 재시도 |
| `click_failed` | 클릭 동작 실패 | 낮음 | DOM 구조 변화 확인 |
| `bot_detected` | 봇 탐지 메시지 표시 | 높음 | 변수 조합 폐기 |
| `account_blocked` | 계정 차단 | 높음 | 계정 교체 |
| `ip_blocked` | IP 차단 | 높음 | IP 변경 (대장봇 재시작) |
| `unknown_error` | 알 수 없는 에러 | 중간 | 로그 분석 후 분류 |

### 부분 성공 (Partial Success)

일부 조건만 만족한 경우 **부분 성공**으로 분류하고, 제한적으로 학습 데이터로 활용한다.

| 시나리오 | 성공 여부 | 점수 가중치 | 활용 방법 |
|---|---|---|---|
| 클릭 성공 + 체류 30초 (60초 미만) | 부분 성공 | 0.5 | 체류 시간 최적화 학습 |
| 클릭 성공 + 캡처 발생 | 실패 | 0.0 | 변수 조합 폐기 |
| 타겟 미발견 + 캡처 미발생 | 실패 | 0.0 | 순위 변동 분석 |

---

## 신뢰도 점수 계산

각 테스트 결과에 **신뢰도 점수 (Reliability Score)**를 부여하여, 데이터의 품질을 평가한다.

### 계산 공식

```
Reliability Score = (
    0.3 × 네트워크 안정성 점수 +
    0.3 × 디바이스 상태 점수 +
    0.2 × 시간대 점수 +
    0.2 × 재현성 점수
) × 10000
```

**범위**: 0 ~ 10000 (높을수록 신뢰도 높음)

### 1. 네트워크 안정성 점수

```python
def calculate_network_stability_score(network_requests):
    # 평균 응답 시간
    avg_response_time = sum(r.response_time_ms for r in network_requests) / len(network_requests)
    
    # 응답 시간이 1초 미만이면 1.0, 5초 이상이면 0.0
    time_score = max(0, min(1, (5000 - avg_response_time) / 4000))
    
    # 실패한 요청 비율
    failed_count = sum(1 for r in network_requests if r.status_code >= 400)
    failure_rate = failed_count / len(network_requests)
    
    # 실패율이 0%면 1.0, 10% 이상이면 0.0
    failure_score = max(0, 1 - failure_rate * 10)
    
    return (time_score + failure_score) / 2
```

### 2. 디바이스 상태 점수

```python
def calculate_device_state_score(debug_info):
    # 배터리 레벨 (20% 미만이면 감점)
    battery_score = 1.0 if debug_info.battery_level >= 20 else 0.5
    
    # CPU 사용률 (80% 이상이면 감점)
    cpu_score = 1.0 if debug_info.cpu_usage_percent < 80 else 0.5
    
    # 메모리 사용량 (1GB 이상이면 감점)
    memory_score = 1.0 if debug_info.memory_usage_mb < 1000 else 0.5
    
    return (battery_score + cpu_score + memory_score) / 3
```

### 3. 시간대 점수

```python
def calculate_time_score(timestamp):
    hour = timestamp.hour
    
    # 피크 시간대 (10시~22시): 1.0
    # 새벽 시간대 (0시~6시): 0.5
    # 기타: 0.7
    
    if 10 <= hour <= 22:
        return 1.0
    elif 0 <= hour <= 6:
        return 0.5
    else:
        return 0.7
```

### 4. 재현성 점수

```python
def calculate_reproducibility_score(combination_id):
    # 동일한 변수 조합의 최근 10회 테스트 결과 조회
    recent_tests = get_recent_tests(combination_id, limit=10)
    
    if len(recent_tests) < 3:
        return 0.5  # 데이터 부족
    
    # 성공률 계산
    success_rate = sum(1 for t in recent_tests if t.success) / len(recent_tests)
    
    # 성공률이 일정하면 재현성 높음
    # 성공률이 50% 근처면 재현성 낮음 (불안정)
    
    if success_rate >= 0.8 or success_rate <= 0.2:
        return 1.0  # 일관성 있음
    else:
        return 0.5  # 불안정
```

---

## 네트워크 요청 추적 구현

### Android 봇에서의 구현

```kotlin
// WebViewClient 커스터마이징
class TrackingWebViewClient : WebViewClient() {
    private val networkLogs = mutableListOf<NetworkRequest>()
    
    override fun shouldInterceptRequest(
        view: WebView,
        request: WebResourceRequest
    ): WebResourceResponse? {
        val startTime = System.currentTimeMillis()
        
        // 요청 로그 기록
        val requestLog = NetworkRequest(
            sequence = networkLogs.size + 1,
            timestamp = Instant.now(),
            method = request.method,
            url = request.url.toString(),
            requestHeaders = request.requestHeaders
        )
        
        // 실제 요청 수행
        val response = super.shouldInterceptRequest(view, request)
        
        // 응답 로그 기록
        requestLog.responseTimeMs = System.currentTimeMillis() - startTime
        requestLog.statusCode = response?.statusCode ?: 0
        requestLog.responseHeaders = response?.responseHeaders ?: emptyMap()
        
        networkLogs.add(requestLog)
        
        return response
    }
    
    fun getNetworkLogs(): List<NetworkRequest> {
        return networkLogs.toList()
    }
}

// 사용 예시
val webView = WebView(context)
val trackingClient = TrackingWebViewClient()
webView.webViewClient = trackingClient

// 테스트 완료 후
val logs = trackingClient.getNetworkLogs()
sendToServer(logs)
```

### 주요 추적 항목

```kotlin
data class NetworkRequest(
    val sequence: Int,
    val timestamp: Instant,
    val method: String,  // GET, POST, etc.
    val url: String,
    val requestHeaders: Map<String, String>,
    var statusCode: Int = 0,
    var responseTimeMs: Long = 0,
    var responseHeaders: Map<String, String> = emptyMap(),
    var responseSizeBytes: Long = 0
)
```

---

## 디버깅 데이터 수집 구현

### 1. 디바이스 정보 수집

```kotlin
fun collectDeviceInfo(context: Context): DebugInfo {
    val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
    val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    
    return DebugInfo(
        webviewVersion = getWebViewVersion(),
        deviceModel = Build.MODEL,
        androidVersion = Build.VERSION.RELEASE,
        screenResolution = getScreenResolution(context),
        memoryUsageMb = getMemoryUsage(activityManager),
        cpuUsagePercent = getCpuUsage(),
        batteryLevel = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY),
        networkType = getNetworkType(context),
        ipAddress = getIpAddress(),
        gpsEnabled = isGpsEnabled(context),
        developerOptionsEnabled = isDeveloperOptionsEnabled(context),
        usbDebuggingEnabled = isUsbDebuggingEnabled(context)
    )
}
```

### 2. 스크린샷 캡처

```kotlin
fun captureScreenshot(webView: WebView, filename: String): File {
    val bitmap = Bitmap.createBitmap(
        webView.width,
        webView.height,
        Bitmap.Config.ARGB_8888
    )
    
    val canvas = Canvas(bitmap)
    webView.draw(canvas)
    
    val file = File(context.cacheDir, filename)
    FileOutputStream(file).use { out ->
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
    }
    
    return file
}

// 주요 이벤트마다 캡처
captureScreenshot(webView, "test_${testId}_search_results.png")
captureScreenshot(webView, "test_${testId}_product_page.png")
```

### 3. JavaScript 콘솔 로그 수집

```kotlin
webView.webChromeClient = object : WebChromeClient() {
    override fun onConsoleMessage(consoleMessage: ConsoleMessage): Boolean {
        val log = ConsoleLog(
            timestamp = Instant.now(),
            level = consoleMessage.messageLevel().name,
            message = consoleMessage.message(),
            sourceId = consoleMessage.sourceId(),
            lineNumber = consoleMessage.lineNumber()
        )
        
        consoleLogs.add(log)
        
        return true
    }
}
```

---

## 평가 결과 저장 스키마

### PostgreSQL 테이블 설계

```sql
-- 테스트 결과 테이블
CREATE TABLE test_results (
    id UUID PRIMARY KEY,
    combination_id INTEGER NOT NULL REFERENCES variable_combinations(id),
    bot_id INTEGER NOT NULL REFERENCES bots(id),
    platform VARCHAR(50) NOT NULL,
    keyword VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    
    -- 실행 정보
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    duration_ms INTEGER,
    
    -- 결과
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),
    final_rank INTEGER,
    clicked BOOLEAN,
    stayed_seconds INTEGER,
    captcha_encountered BOOLEAN,
    captcha_avoided BOOLEAN,
    
    -- 신뢰도
    reliability_score INTEGER,  -- 0-10000
    
    -- 원시 데이터 (JSONB)
    variables JSONB NOT NULL,
    network_requests JSONB,
    debug_info JSONB,
    dom_snapshots JSONB,
    console_logs JSONB,
    user_actions JSONB,
    
    -- 첨부 파일
    screenshot_urls TEXT[],
    
    created_at TIMESTAMP DEFAULT NOW()
);

-- 인덱스
CREATE INDEX idx_test_results_combination ON test_results(combination_id);
CREATE INDEX idx_test_results_bot ON test_results(bot_id);
CREATE INDEX idx_test_results_success ON test_results(success);
CREATE INDEX idx_test_results_started_at ON test_results(started_at);
CREATE INDEX idx_test_results_reliability ON test_results(reliability_score);
```

---

## 실시간 모니터링

### 대시보드에서 표시할 지표

| 지표 | 설명 | 계산 방법 |
|---|---|---|
| **실시간 성공률** | 최근 1시간 내 테스트 성공률 | `성공 건수 / 전체 건수 × 100` |
| **평균 신뢰도** | 최근 테스트의 평균 신뢰도 점수 | `SUM(reliability_score) / COUNT(*)` |
| **캡처 발생률** | 캡처가 발생한 비율 | `캡처 발생 건수 / 전체 건수 × 100` |
| **평균 응답 시간** | 네트워크 요청의 평균 응답 시간 | `AVG(response_time_ms)` |
| **봇별 성공률** | 각 봇의 성공률 | 봇 ID별 그룹화 |
| **시간대별 성공률** | 시간대별 성공률 추이 | 시간대별 그룹화 |

### 알림 조건

다음 조건 발생 시 즉시 알림을 전송한다.

| 조건 | 심각도 | 알림 채널 |
|---|---|---|
| 성공률 < 50% (최근 1시간) | 높음 | Slack + Email |
| 캡처 발생률 > 30% | 높음 | Slack + Email |
| 특정 봇의 연속 실패 > 5회 | 중간 | Slack |
| 평균 응답 시간 > 5초 | 낮음 | Slack |
| IP 차단 감지 | 높음 | Slack + Email + SMS |

---

## 학습 데이터 활용

### 1. 성공 패턴 분석

```sql
-- 성공률이 높은 변수 조합의 공통점 찾기
SELECT 
    variables->>'user_agent' AS user_agent,
    variables->>'cw_mode' AS cw_mode,
    COUNT(*) AS test_count,
    AVG(CASE WHEN success THEN 1.0 ELSE 0.0 END) AS success_rate
FROM test_results
WHERE reliability_score >= 7000  -- 신뢰도 높은 데이터만
GROUP BY user_agent, cw_mode
HAVING COUNT(*) >= 10  -- 충분한 샘플
ORDER BY success_rate DESC
LIMIT 10;
```

### 2. 실패 패턴 분석

```sql
-- 실패 사유별 분포
SELECT 
    failure_reason,
    COUNT(*) AS count,
    AVG(reliability_score) AS avg_reliability
FROM test_results
WHERE success = FALSE
GROUP BY failure_reason
ORDER BY count DESC;
```

### 3. 네트워크 패턴 분석

```python
# 성공한 테스트의 네트워크 요청 패턴 추출
successful_tests = get_successful_tests(limit=100)

# 공통 헤더 패턴
common_headers = analyze_common_headers(successful_tests)

# 요청 순서 패턴
request_sequence_pattern = analyze_request_sequence(successful_tests)

# 응답 시간 분포
response_time_distribution = analyze_response_times(successful_tests)
```

---

## 구현 우선순위

### Phase 1: 기본 데이터 수집 (1주)
1. 성공/실패 판단 로직
2. 기본 네트워크 로그 수집
3. 스크린샷 캡처
4. 결과 저장 (PostgreSQL)

### Phase 2: 신뢰도 시스템 (1주)
1. 신뢰도 점수 계산 알고리즘
2. 네트워크 안정성 측정
3. 디바이스 상태 수집
4. 시간대 가중치 적용

### Phase 3: 상세 추적 (1주)
1. 전체 네트워크 요청 추적
2. DOM 스냅샷 수집
3. JavaScript 콘솔 로그
4. 사용자 행동 로그

### Phase 4: 분석 및 최적화 (1주)
1. 패턴 분석 알고리즘
2. 실시간 모니터링 대시보드
3. 알림 시스템
4. 성능 최적화

---

**작성자**: Manus AI  
**버전**: v1.0  
**최종 수정일**: 2025-11-11
