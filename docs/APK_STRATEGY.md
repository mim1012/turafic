# APK 봇 역할별 전략 가이드

## 📋 개요

Turafic 프로젝트는 **단일 APK + 설정 파일** 전략을 채택하여 개발 및 유지보수를 최적화합니다.

---

## 🎯 전략 결정: 단일 APK + 설정 파일

### 선택 이유

| 항목 | 장점 |
|------|------|
| **개발 효율성** | 1개 APK만 개발/관리 |
| **유지보수** | 버그 수정 1회, 업데이트 1회 배포 |
| **코드 품질** | 코드 중복 없음, DRY 원칙 준수 |
| **유연성** | 역할 변경 용이, 설정 파일로 제어 |
| **확장성** | 새로운 역할 추가 시 코드 수정 최소화 |

### 대안 비교

| 전략 | APK 개수 | 개발 난이도 | 유지보수 | 권장도 |
|------|---------|------------|---------|--------|
| 단일 APK + 설정 | 1개 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 역할별 개별 APK | 3개 | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| 하이브리드 | 2개 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

---

## 🤖 봇 역할 정의

### 1. Leader Bot (대장 봇)

**역할**:
- 핫스팟 제공 (WiFi Hotspot)
- IP 로테이션 관리 (비행기 모드 토글)
- 일반 트래픽 작업 수행

**핵심 기능**:
```java
public class LeaderBot {
    // 1. 핫스팟 활성화
    public void startHotspot() {
        WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        // WiFi Hotspot 활성화 코드
    }

    // 2. IP 변경 (비행기 모드 토글)
    public void changeIP() {
        // 모든 쫄병의 작업 완료 대기
        waitForFollowersCompletion();

        // 비행기 모드 ON
        executeRootCommand("cmd connectivity airplane-mode enable");
        Thread.sleep(3000);

        // 비행기 모드 OFF
        executeRootCommand("cmd connectivity airplane-mode disable");

        // 네트워크 재연결 대기
        waitForNetworkReconnection();
    }

    // 3. 일반 트래픽 작업
    public void executeTrafficTask(TaskPattern pattern) {
        // JSON 패턴 실행
        taskExecutor.execute(pattern);
    }
}
```

**설정 예시**:
```json
{
  "role": "leader",
  "is_leader": true,
  "ranking_group_id": "group-uuid-1234",
  "hotspot_ssid": "Turafic-Leader-1",
  "hotspot_password": "turafic2025",
  "ip_rotation_strategy": "wait_for_completion"
}
```

---

### 2. Follower Bot (쫄병 봇)

**역할**:
- 대장 봇의 핫스팟에 연결
- 대장 봇의 IP 공유하여 트래픽 생성
- 작업 완료 신호 전송

**핵심 기능**:
```java
public class FollowerBot {
    // 1. 대장 핫스팟 연결
    public void connectToLeaderHotspot(String ssid, String password) {
        WifiConfiguration wifiConfig = new WifiConfiguration();
        wifiConfig.SSID = String.format("\"%s\"", ssid);
        wifiConfig.preSharedKey = String.format("\"%s\"", password);

        WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        int netId = wifiManager.addNetwork(wifiConfig);
        wifiManager.enableNetwork(netId, true);
    }

    // 2. 일반 트래픽 작업
    public void executeTrafficTask(TaskPattern pattern) {
        // JSON 패턴 실행
        taskExecutor.execute(pattern);

        // 작업 완료 신호 전송
        reportTaskCompletion();
    }

    // 3. 작업 완료 보고
    private void reportTaskCompletion() {
        apiClient.post("/api/v1/ranking-groups/" + groupId + "/tasks/complete", {
            "minion_bot_id": botId
        });
    }
}
```

**설정 예시**:
```json
{
  "role": "follower",
  "is_leader": false,
  "ranking_group_id": "group-uuid-1234",
  "leader_hotspot_ssid": "Turafic-Leader-1",
  "leader_hotspot_password": "turafic2025"
}
```

---

### 3. Rank Checker Bot (순위 체크 봇)

**역할**:
- 네이버 쇼핑 검색 결과에서 상품 순위 확인
- 주기적인 순위 데이터 수집
- 순위 변동 분석 데이터 제공

**핵심 기능**:
```java
public class RankCheckerBot {
    // 1. 순위 체크 작업
    public RankResult checkRanking(String keyword, String targetProductId) {
        // 네이버 쇼핑 검색
        openUrl("https://m.shopping.naver.com/search?query=" + keyword);
        Thread.sleep(3000);

        // 상품 순위 찾기
        int rank = findProductRank(targetProductId);

        // 서버에 보고
        return new RankResult(keyword, targetProductId, rank, timestamp);
    }

    // 2. 상품 순위 찾기 (페이지 스크롤하면서)
    private int findProductRank(String targetProductId) {
        int currentRank = 1;

        for (int page = 1; page <= 10; page++) {  // 최대 10페이지
            List<String> products = parseProductsOnPage();

            for (String productId : products) {
                if (productId.equals(targetProductId)) {
                    return currentRank;
                }
                currentRank++;
            }

            // 다음 페이지로 스크롤
            scrollDown();
            Thread.sleep(2000);
        }

        return -1;  // 순위권 밖
    }

    // 3. 순위 보고
    public void reportRanking(RankResult result) {
        apiClient.post("/api/v1/rankings/report", result);
    }
}
```

**설정 예시**:
```json
{
  "role": "rank_checker",
  "is_leader": false,
  "ranking_group_id": null,
  "check_interval": 3600,
  "target_keywords": ["단백질쉐이크", "프로틴"],
  "target_products": ["product-id-1", "product-id-2"]
}
```

---

## 📱 APK 구조

### 패키지명
```
com.turafic.bot
```

### 앱 이름
```
Turafic Bot
```

### 버전 정보
```
versionCode: 1
versionName: "1.0.0"
minSdkVersion: 26 (Android 8.0)
targetSdkVersion: 34 (Android 14)
```

### 권한 요구사항
```xml
<manifest>
    <!-- 네트워크 -->
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE"/>

    <!-- WiFi Hotspot (대장 봇) -->
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
    <uses-permission android:name="android.permission.CHANGE_WIFI_STATE"/>

    <!-- 비행기 모드 (대장 봇, Root 필요) -->
    <uses-permission android:name="android.permission.WRITE_SETTINGS"/>

    <!-- 백그라운드 실행 -->
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>

    <!-- 기기 정보 -->
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
</manifest>
```

---

## 🔄 역할 선택 워크플로우

### 방법 1: 첫 실행 시 역할 선택 (권장)

```
앱 설치
   ↓
첫 실행 (SetupActivity)
   ↓
역할 선택 다이얼로그
   ↓
┌─────────────────────────────┐
│  봇 역할 선택                │
│                             │
│  ○ 대장 봇 (Leader)         │
│  ○ 쫄병 봇 (Follower)       │
│  ○ 순위 체크 봇 (Rank)      │
│                             │
│  [확인]         [취소]      │
└─────────────────────────────┘
   ↓
SharedPreferences 저장
   ↓
서버에 봇 등록 (역할 포함)
   ↓
BotService 시작
   ↓
역할에 따른 봇 실행
```

**구현 코드**:
```java
public class SetupActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 이미 역할이 설정되어 있으면 스킵
        SharedPreferences prefs = getSharedPreferences("bot_config", MODE_PRIVATE);
        if (prefs.contains("role")) {
            startService(new Intent(this, BotService.class));
            finish();
            return;
        }

        // 역할 선택 다이얼로그
        showRoleSelectionDialog();
    }

    private void showRoleSelectionDialog() {
        String[] roles = {"대장 봇 (Leader)", "쫄병 봇 (Follower)", "순위 체크 봇 (Rank Checker)"};

        new AlertDialog.Builder(this)
            .setTitle("봇 역할 선택")
            .setItems(roles, (dialog, which) -> {
                String role = "";
                boolean isLeader = false;

                switch (which) {
                    case 0:
                        role = "leader";
                        isLeader = true;
                        break;
                    case 1:
                        role = "follower";
                        break;
                    case 2:
                        role = "rank_checker";
                        break;
                }

                // SharedPreferences 저장
                SharedPreferences prefs = getSharedPreferences("bot_config", MODE_PRIVATE);
                prefs.edit()
                    .putString("role", role)
                    .putBoolean("is_leader", isLeader)
                    .apply();

                // 서버 등록
                registerBot(role, isLeader);
            })
            .setCancelable(false)
            .show();
    }

    private void registerBot(String role, boolean isLeader) {
        // API 호출
        apiClient.registerBot(new BotRegisterRequest(
            androidId,
            deviceModel,
            androidVersion,
            screenResolution,
            role,
            isLeader
        ), new Callback() {
            @Override
            public void onSuccess(BotRegisterResponse response) {
                // bot_id 저장
                SharedPreferences prefs = getSharedPreferences("bot_config", MODE_PRIVATE);
                prefs.edit().putString("bot_id", response.getBotId()).apply();

                // BotService 시작
                startService(new Intent(SetupActivity.this, BotService.class));
                finish();
            }
        });
    }
}
```

---

### 방법 2: 서버 API로 역할 결정

```
앱 설치
   ↓
첫 실행 (서버에 기본 등록)
   ↓
서버가 bot_id 발급
   ↓
관리자가 웹 대시보드에서 역할 설정
   ↓
봇이 주기적으로 역할 조회
   ↓
역할에 따른 봇 실행
```

**구현 코드**:
```java
public class BotService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // 서버에서 봇 정보 조회
        String botId = getBotId();

        apiClient.getBotInfo(botId, new Callback() {
            @Override
            public void onSuccess(BotInfoResponse response) {
                String role = response.getRole();
                boolean isLeader = response.isLeader();

                // SharedPreferences 업데이트
                SharedPreferences prefs = getSharedPreferences("bot_config", MODE_PRIVATE);
                prefs.edit()
                    .putString("role", role)
                    .putBoolean("is_leader", isLeader)
                    .apply();

                // 역할에 따른 봇 시작
                startBotByRole(role, isLeader);
            }
        });

        return START_STICKY;
    }

    private void startBotByRole(String role, boolean isLeader) {
        switch (role) {
            case "leader":
                new LeaderBot(this).start();
                break;
            case "follower":
                new FollowerBot(this).start();
                break;
            case "rank_checker":
                new RankCheckerBot(this).start();
                break;
        }
    }
}
```

---

## 📊 역할별 작업 흐름

### Leader Bot 작업 흐름

```
1. 서비스 시작
   ↓
2. WiFi Hotspot 활성화
   ↓
3. 서버에서 작업 요청
   ↓
4. JSON 작업 패턴 실행
   ↓
5. 작업 완료 보고
   ↓
6. 모든 쫄병의 완료 대기 (최대 3분)
   ↓
7. IP 변경 (비행기 모드 토글)
   ↓
8. 5분 대기
   ↓
9. 3단계로 돌아감 (반복)
```

### Follower Bot 작업 흐름

```
1. 서비스 시작
   ↓
2. 대장 핫스팟 연결
   ↓
3. 서버에서 작업 요청
   ↓
4. JSON 작업 패턴 실행
   ↓
5. 작업 완료 보고 + 그룹 완료 신호
   ↓
6. 대장의 IP 변경 대기
   ↓
7. 네트워크 재연결 대기
   ↓
8. 3단계로 돌아감 (반복)
```

### Rank Checker Bot 작업 흐름

```
1. 서비스 시작
   ↓
2. 서버에서 순위 체크 작업 요청
   ↓
3. 네이버 쇼핑 검색
   ↓
4. 상품 순위 찾기 (페이지 스크롤)
   ↓
5. 순위 데이터 서버 보고
   ↓
6. 60분 대기 (순위 체크 주기)
   ↓
7. 2단계로 돌아감 (반복)
```

---

## 🗂️ SharedPreferences 스키마

### 봇 설정 (bot_config)

```json
{
  "bot_id": "bot-uuid-1234",
  "role": "leader",  // "leader", "follower", "rank_checker"
  "is_leader": true,
  "ranking_group_id": "group-uuid-5678",
  "server_url": "https://turafic.railway.app",
  "last_sync": "2025-11-02T14:30:00Z"
}
```

### Leader Bot 추가 설정

```json
{
  "hotspot_ssid": "Turafic-Leader-1",
  "hotspot_password": "turafic2025",
  "ip_rotation_strategy": "wait_for_completion",
  "max_wait_time": 180000  // 3분 (밀리초)
}
```

### Follower Bot 추가 설정

```json
{
  "leader_hotspot_ssid": "Turafic-Leader-1",
  "leader_hotspot_password": "turafic2025"
}
```

### Rank Checker Bot 추가 설정

```json
{
  "check_interval": 3600,  // 60분 (초)
  "target_keywords": ["단백질쉐이크", "프로틴"],
  "target_products": ["product-id-1", "product-id-2"]
}
```

---

## 📡 서버 API 연동

### 1. 봇 등록

```http
POST /api/v1/bots/register
Content-Type: application/json

{
  "android_id": "abc123def456",
  "device_model": "SM-G998N",
  "android_version": "14",
  "screen_resolution": "1440x3200",
  "role": "leader",
  "is_leader": true
}
```

**응답**:
```json
{
  "bot_id": "bot-uuid-1234",
  "role": "leader",
  "ranking_group_id": "group-uuid-5678",
  "status": "active"
}
```

### 2. 작업 요청

```http
GET /api/v1/tasks/get_task?bot_id=bot-uuid-1234
```

**응답**:
```json
{
  "task_id": "task-uuid-9999",
  "campaign_id": "campaign-uuid-7777",
  "ranking_group_id": "group-uuid-5678",
  "pattern": [
    {"action": "tap", "x": 540, "y": 200},
    {"action": "text", "value": "단백질쉐이크"},
    ...
  ]
}
```

### 3. 작업 완료 보고

```http
POST /api/v1/tasks/report_result
Content-Type: application/json

{
  "bot_id": "bot-uuid-1234",
  "task_id": "task-uuid-9999",
  "status": "success",
  "timestamp": "2025-11-02T14:30:00Z"
}
```

### 4. 그룹 완료 신호 (Follower Bot만)

```http
POST /api/v1/ranking-groups/group-uuid-5678/tasks/complete
Content-Type: application/json

{
  "minion_bot_id": "bot-uuid-1234"
}
```

---

## 🧪 테스트 시나리오

### 시나리오 1: Leader Bot 단독 실행

```
1. APK 설치
2. 역할 선택: Leader Bot
3. 핫스팟 활성화 확인
4. 서버에서 작업 요청
5. 작업 실행 및 완료
6. IP 변경 (비행기 모드 토글)
7. 네트워크 재연결 확인
```

### 시나리오 2: Leader + 3 Followers

```
Leader:
1. 핫스팟 활성화
2. 작업 실행
3. 3명 쫄병 완료 대기
4. IP 변경

Follower 1-3:
1. Leader 핫스팟 연결
2. 작업 실행
3. 완료 신호 전송
4. Leader IP 변경 대기
5. 네트워크 재연결
```

### 시나리오 3: Rank Checker Bot

```
1. APK 설치
2. 역할 선택: Rank Checker
3. 서버에서 순위 체크 작업 요청
4. 네이버 쇼핑 검색 실행
5. 상품 순위 찾기 (페이지 스크롤)
6. 순위 데이터 서버 보고
7. 60분 대기
8. 반복
```

---

## 📝 구현 체크리스트

### Android APK 개발

- [ ] SetupActivity (역할 선택 UI)
- [ ] BotService (메인 서비스)
- [ ] LeaderBot (대장 봇 로직)
- [ ] FollowerBot (쫄병 봇 로직)
- [ ] RankCheckerBot (순위 체크 봇 로직)
- [ ] TaskExecutor (JSON 패턴 실행 엔진)
- [ ] RootController (Root 권한 제어)
- [ ] ApiClient (서버 통신)
- [ ] HotspotManager (WiFi Hotspot 관리)

### 서버 API 개발

- [ ] `/api/v1/bots/register` (봇 등록, role 파라미터 추가)
- [ ] `/api/v1/bots/{bot_id}` (봇 정보 조회, role 반환)
- [ ] `/api/v1/tasks/get_task` (역할별 작업 할당)
- [ ] `/api/v1/ranking-groups/{id}/tasks/complete` (쫄병 완료 신호)
- [ ] `/api/v1/rankings/report` (순위 데이터 보고)

### 데이터베이스

- [ ] `bots.role` 컬럼 추가
- [ ] `bots.config_json` 컬럼 추가
- [ ] 역할별 작업 할당 로직 구현

---

## 🎯 결론

**단일 APK + 설정 파일** 전략은 Turafic 프로젝트의 개발 효율성과 유지보수성을 극대화합니다.

### 핵심 장점

1. ✅ **1개 APK만 관리** → 개발/배포/업데이트 간편
2. ✅ **역할 유연성** → 설정 파일 또는 서버 API로 역할 변경
3. ✅ **코드 품질** → 중복 없음, DRY 원칙 준수
4. ✅ **확장성** → 새로운 역할 추가 용이

### 다음 단계

1. Android APK 개발 (turafic_bot.apk)
2. 서버 API 확장 (role 파라미터 추가)
3. 데이터베이스 마이그레이션 (bot roles)
4. 역할별 작업 엔진 구현
5. 실제 기기에서 테스트

---

**마지막 업데이트**: 2025-11-02
**버전**: 1.0
**작성자**: Turafic Development Team
