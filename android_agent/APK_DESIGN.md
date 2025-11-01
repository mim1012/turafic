# Turafic Android APK 상세 설계 문서

## 📦 패키지 구조

```
com.turafic.bot/
├── MainActivity.java           # 앱 진입점
├── SetupActivity.java          # 역할 선택 UI
├── service/
│   ├── BotService.java         # 메인 백그라운드 서비스
│   ├── LeaderBot.java          # 대장 봇 로직
│   ├── FollowerBot.java        # 쫄병 봇 로직
│   └── RankCheckerBot.java     # 순위 체크 봇 로직
├── executor/
│   ├── TaskExecutor.java       # JSON 패턴 실행 엔진
│   ├── RootController.java     # Root 권한 제어
│   └── ActionHandler.java      # 액션별 핸들러
├── network/
│   ├── ApiClient.java          # HTTP 클라이언트 (Retrofit)
│   ├── models/
│   │   ├── BotRegisterRequest.java
│   │   ├── BotRegisterResponse.java
│   │   ├── TaskResponse.java
│   │   └── RankResult.java
│   └── services/
│       ├── BotApiService.java
│       ├── TaskApiService.java
│       └── RankApiService.java
├── hotspot/
│   ├── HotspotManager.java     # WiFi Hotspot 관리
│   └── NetworkManager.java     # 네트워크 연결 관리
├── models/
│   ├── BotRole.java            # Enum: LEADER, FOLLOWER, RANK_CHECKER
│   ├── ActionStep.java         # JSON 패턴의 한 단계
│   └── TaskPattern.java        # 전체 작업 패턴
└── utils/
    ├── ConfigManager.java      # SharedPreferences 관리
    ├── LogManager.java         # 로그 관리
    └── DeviceInfoUtil.java     # 기기 정보 수집
```

---

## 🎨 주요 클래스 설계

### 1. SetupActivity.java

**역할**: 첫 실행 시 봇 역할 선택

```java
package com.turafic.bot;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

import com.turafic.bot.network.ApiClient;
import com.turafic.bot.network.models.BotRegisterRequest;
import com.turafic.bot.network.models.BotRegisterResponse;
import com.turafic.bot.service.BotService;
import com.turafic.bot.utils.ConfigManager;
import com.turafic.bot.utils.DeviceInfoUtil;

public class SetupActivity extends AppCompatActivity {
    private ApiClient apiClient;
    private ConfigManager configManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        configManager = new ConfigManager(this);
        apiClient = new ApiClient(configManager.getServerUrl());

        // 이미 역할이 설정되어 있으면 스킵
        if (configManager.hasRole()) {
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
                configManager.saveRole(role, isLeader);

                // 서버 등록
                registerBot(role, isLeader);
            })
            .setCancelable(false)
            .show();
    }

    private void registerBot(String role, boolean isLeader) {
        // 기기 정보 수집
        String androidId = DeviceInfoUtil.getAndroidId(this);
        String deviceModel = DeviceInfoUtil.getDeviceModel();
        String androidVersion = DeviceInfoUtil.getAndroidVersion();
        String screenResolution = DeviceInfoUtil.getScreenResolution(this);

        // 등록 요청
        BotRegisterRequest request = new BotRegisterRequest(
            androidId,
            deviceModel,
            androidVersion,
            screenResolution,
            role,
            isLeader
        );

        apiClient.registerBot(request, new ApiClient.Callback<BotRegisterResponse>() {
            @Override
            public void onSuccess(BotRegisterResponse response) {
                // bot_id 저장
                configManager.saveBotId(response.getBotId());
                configManager.saveRankingGroupId(response.getRankingGroupId());

                // BotService 시작
                startService(new Intent(SetupActivity.this, BotService.class));
                finish();
            }

            @Override
            public void onError(String error) {
                // 에러 처리
                new AlertDialog.Builder(SetupActivity.this)
                    .setTitle("등록 실패")
                    .setMessage("서버 등록에 실패했습니다: " + error)
                    .setPositiveButton("재시도", (d, w) -> registerBot(role, isLeader))
                    .show();
            }
        });
    }
}
```

---

### 2. BotService.java

**역할**: 메인 백그라운드 서비스

```java
package com.turafic.bot.service;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import androidx.annotation.Nullable;

import com.turafic.bot.models.BotRole;
import com.turafic.bot.utils.ConfigManager;

public class BotService extends Service {
    private ConfigManager configManager;
    private Thread botThread;

    @Override
    public void onCreate() {
        super.onCreate();
        configManager = new ConfigManager(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // 역할 로드
        String roleStr = configManager.getRole();
        BotRole role = BotRole.valueOf(roleStr.toUpperCase());
        boolean isLeader = configManager.isLeader();

        // 역할에 따른 봇 시작
        botThread = new Thread(() -> startBotByRole(role, isLeader));
        botThread.start();

        return START_STICKY;
    }

    private void startBotByRole(BotRole role, boolean isLeader) {
        switch (role) {
            case LEADER:
                new LeaderBot(this, configManager).start();
                break;
            case FOLLOWER:
                new FollowerBot(this, configManager).start();
                break;
            case RANK_CHECKER:
                new RankCheckerBot(this, configManager).start();
                break;
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
```

---

### 3. LeaderBot.java

**역할**: 대장 봇 로직

```java
package com.turafic.bot.service;

import android.content.Context;

import com.turafic.bot.hotspot.HotspotManager;
import com.turafic.bot.executor.RootController;
import com.turafic.bot.network.ApiClient;
import com.turafic.bot.utils.ConfigManager;

public class LeaderBot {
    private Context context;
    private ConfigManager configManager;
    private ApiClient apiClient;
    private HotspotManager hotspotManager;
    private RootController rootController;

    public LeaderBot(Context context, ConfigManager configManager) {
        this.context = context;
        this.configManager = configManager;
        this.apiClient = new ApiClient(configManager.getServerUrl());
        this.hotspotManager = new HotspotManager(context);
        this.rootController = new RootController();
    }

    public void start() {
        try {
            // 1. WiFi Hotspot 활성화
            String ssid = configManager.getConfigValue("hotspot_ssid");
            String password = configManager.getConfigValue("hotspot_password");
            hotspotManager.startHotspot(ssid, password);

            // 2. 작업 루프
            while (true) {
                // 작업 요청
                executeTrafficTask();

                // 쫄병 완료 대기
                waitForFollowersCompletion();

                // IP 변경
                changeIP();

                // 5분 대기
                Thread.sleep(300000);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void executeTrafficTask() {
        // 작업 실행 로직 (TaskExecutor 사용)
    }

    private void waitForFollowersCompletion() {
        // 쫄병 완료 대기 로직 (최대 3분)
    }

    private void changeIP() {
        // 비행기 모드 토글로 IP 변경
        rootController.enableAirplaneMode();
        Thread.sleep(3000);
        rootController.disableAirplaneMode();
    }
}
```

---

## 📡 API 통신 설계

### Retrofit 인터페이스

```java
package com.turafic.bot.network.services;

import com.turafic.bot.network.models.*;
import retrofit2.Call;
import retrofit2.http.*;

public interface BotApiService {
    @POST("/api/v1/bots/register")
    Call<BotRegisterResponse> registerBot(@Body BotRegisterRequest request);

    @GET("/api/v1/bots/{bot_id}")
    Call<BotInfoResponse> getBotInfo(@Path("bot_id") String botId);

    @GET("/api/v1/tasks/get_task")
    Call<TaskResponse> getTask(@Query("bot_id") String botId);

    @POST("/api/v1/tasks/report_result")
    Call<Void> reportResult(@Body TaskResultRequest request);

    @POST("/api/v1/ranking-groups/{group_id}/tasks/complete")
    Call<Void> reportTaskCompletion(
        @Path("group_id") String groupId,
        @Body TaskCompletionRequest request
    );
}
```

---

## 🔐 SharedPreferences 스키마

```java
package com.turafic.bot.utils;

import android.content.Context;
import android.content.SharedPreferences;

public class ConfigManager {
    private static final String PREFS_NAME = "bot_config";
    private SharedPreferences prefs;

    public ConfigManager(Context context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    // Bot ID
    public void saveBotId(String botId) {
        prefs.edit().putString("bot_id", botId).apply();
    }

    public String getBotId() {
        return prefs.getString("bot_id", "");
    }

    // Role
    public void saveRole(String role, boolean isLeader) {
        prefs.edit()
            .putString("role", role)
            .putBoolean("is_leader", isLeader)
            .apply();
    }

    public String getRole() {
        return prefs.getString("role", "follower");
    }

    public boolean isLeader() {
        return prefs.getBoolean("is_leader", false);
    }

    public boolean hasRole() {
        return prefs.contains("role");
    }

    // Server URL
    public String getServerUrl() {
        return prefs.getString("server_url", "https://turafic.railway.app");
    }

    // Ranking Group ID
    public void saveRankingGroupId(String groupId) {
        prefs.edit().putString("ranking_group_id", groupId).apply();
    }

    public String getRankingGroupId() {
        return prefs.getString("ranking_group_id", "");
    }

    // Config JSON values
    public void saveConfigValue(String key, String value) {
        prefs.edit().putString("config_" + key, value).apply();
    }

    public String getConfigValue(String key) {
        return prefs.getString("config_" + key, "");
    }
}
```

---

## 🚀 빌드 설정 (build.gradle)

```gradle
plugins {
    id 'com.android.application'
}

android {
    namespace 'com.turafic.bot'
    compileSdk 34

    defaultConfig {
        applicationId "com.turafic.bot"
        minSdk 26  // Android 8.0
        targetSdk 34  // Android 14
        versionCode 1
        versionName "1.0.0"
    }

    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}

dependencies {
    // Retrofit (HTTP Client)
    implementation 'com.squareup.retrofit2:retrofit:2.9.0'
    implementation 'com.squareup.retrofit2:converter-gson:2.9.0'

    // OkHttp (Logging)
    implementation 'com.squareup.okhttp3:logging-interceptor:4.11.0'

    // Gson (JSON Parsing)
    implementation 'com.google.code.gson:gson:2.10.1'

    // AndroidX
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.11.0'
}
```

---

## 📝 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.turafic.bot">

    <!-- 권한 -->
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
    <uses-permission android:name="android.permission.CHANGE_WIFI_STATE"/>
    <uses-permission android:name="android.permission.WRITE_SETTINGS"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.TuraficBot">

        <!-- SetupActivity (첫 실행) -->
        <activity
            android:name=".SetupActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- BotService (백그라운드) -->
        <service
            android:name=".service.BotService"
            android:enabled="true"
            android:exported="false" />
    </application>

</manifest>
```

---

## ✅ 구현 체크리스트

### Phase 1: 기본 구조
- [ ] 패키지 구조 생성
- [ ] MainActivity/SetupActivity 구현
- [ ] ConfigManager (SharedPreferences) 구현
- [ ] DeviceInfoUtil 구현

### Phase 2: 네트워크
- [ ] Retrofit API 인터페이스 정의
- [ ] ApiClient 구현
- [ ] Request/Response 모델 클래스 생성

### Phase 3: 봇 로직
- [ ] BotService (메인 서비스) 구현
- [ ] LeaderBot 구현
- [ ] FollowerBot 구현
- [ ] RankCheckerBot 구현

### Phase 4: 실행 엔진
- [ ] TaskExecutor (JSON 패턴 실행) 구현
- [ ] RootController (Root 제어) 구현
- [ ] ActionHandler (액션별 핸들러) 구현

### Phase 5: 핫스팟 & 네트워크
- [ ] HotspotManager 구현
- [ ] NetworkManager 구현
- [ ] IP 로테이션 로직 구현

### Phase 6: 테스트
- [ ] 로컬 환경 테스트
- [ ] 실제 기기 테스트 (Leader Bot)
- [ ] 실제 기기 테스트 (Follower Bot)
- [ ] 실제 기기 테스트 (Rank Checker Bot)

---

**마지막 업데이트**: 2025-11-02
**버전**: 1.0
