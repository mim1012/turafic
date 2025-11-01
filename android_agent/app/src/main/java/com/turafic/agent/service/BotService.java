package com.turafic.agent.service;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import com.turafic.agent.network.ApiClient;
import com.turafic.agent.network.ServerApi;
import com.turafic.agent.network.models.BotRegisterRequest;
import com.turafic.agent.network.models.BotRegisterResponse;
import com.turafic.agent.network.models.TaskResponse;
import com.turafic.agent.network.models.TaskResultReport;
import com.turafic.agent.executor.TaskExecutor;
import com.turafic.agent.utils.DeviceInfo;
import com.turafic.agent.utils.AirplaneModeManager;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

/**
 * Turafic Bot Service
 * 
 * 백그라운드에서 지속적으로 동작하는 서비스:
 * 1. 서버에 봇 등록
 * 2. 주기적으로 작업 요청 (5분 간격)
 * 3. 작업 실행
 * 4. 결과 보고
 * 5. 비행기 모드로 IP 변경
 */
public class BotService extends Service {
    
    private static final String TAG = "BotService";
    private static final long TASK_REQUEST_INTERVAL = 5 * 60 * 1000; // 5분
    private static final long INITIAL_DELAY = 5 * 1000; // 5초 (최초 작업 요청)
    
    private Handler handler;
    private ServerApi api;
    private String botId;
    private int group;
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "BotService created");
        
        handler = new Handler(Looper.getMainLooper());
        api = ApiClient.getApi();
        
        // 서버에 봇 등록
        registerBot();
    }
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "BotService started");
        
        // 주기적 작업 요청 시작
        handler.postDelayed(taskRequestRunnable, INITIAL_DELAY);
        
        // 서비스 종료 시 자동 재시작
        return START_STICKY;
    }
    
    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "BotService destroyed");
        
        // 핸들러 정리
        handler.removeCallbacks(taskRequestRunnable);
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return null;  // 바인딩 미지원
    }
    
    /**
     * 서버에 봇 등록
     */
    private void registerBot() {
        BotRegisterRequest request = new BotRegisterRequest(
            DeviceInfo.getDeviceModel(),
            DeviceInfo.getAndroidVersion(),
            DeviceInfo.getScreenResolution(this),
            DeviceInfo.getAndroidId(this)
        );
        
        api.registerBot(request).enqueue(new Callback<BotRegisterResponse>() {
            @Override
            public void onResponse(Call<BotRegisterResponse> call, Response<BotRegisterResponse> response) {
                if (response.isSuccessful() && response.body() != null) {
                    botId = response.body().getBotId();
                    group = response.body().getGroup();
                    Log.d(TAG, "Bot registered: " + botId + ", Group: " + group);
                } else {
                    Log.e(TAG, "Bot registration failed");
                }
            }
            
            @Override
            public void onFailure(Call<BotRegisterResponse> call, Throwable t) {
                Log.e(TAG, "Bot registration error: " + t.getMessage());
                
                // 5초 후 재시도
                handler.postDelayed(() -> registerBot(), 5000);
            }
        });
    }
    
    /**
     * 주기적 작업 요청 Runnable
     */
    private final Runnable taskRequestRunnable = new Runnable() {
        @Override
        public void run() {
            if (botId != null) {
                requestTask();
            }
            
            // 다음 작업 요청 예약
            handler.postDelayed(this, TASK_REQUEST_INTERVAL);
        }
    };
    
    /**
     * 서버에 작업 요청
     */
    private void requestTask() {
        Log.d(TAG, "Requesting task from server...");
        
        api.getTask(botId).enqueue(new Callback<TaskResponse>() {
            @Override
            public void onResponse(Call<TaskResponse> call, Response<TaskResponse> response) {
                if (response.isSuccessful() && response.body() != null) {
                    TaskResponse taskResponse = response.body();
                    Log.d(TAG, "Task received: " + taskResponse.getTaskId());
                    
                    // 작업 실행
                    executeTask(taskResponse);
                } else {
                    Log.e(TAG, "Task request failed: " + response.code());
                }
            }
            
            @Override
            public void onFailure(Call<TaskResponse> call, Throwable t) {
                Log.e(TAG, "Task request error: " + t.getMessage());
            }
        });
    }
    
    /**
     * 작업 실행
     */
    private void executeTask(TaskResponse taskResponse) {
        new Thread(() -> {
            boolean success = false;
            String log = "";
            
            try {
                // 비행기 모드로 IP 변경
                AirplaneModeManager.toggleAirplaneMode(this);
                
                // 작업 패턴 실행
                TaskExecutor executor = new TaskExecutor();
                executor.executePattern(taskResponse.getPattern());
                
                success = true;
                log = "Task completed successfully";
                Log.d(TAG, log);
                
            } catch (Exception e) {
                log = "Task failed: " + e.getMessage();
                Log.e(TAG, log, e);
            }
            
            // 결과 보고
            reportResult(taskResponse.getTaskId(), success, log);
            
        }).start();
    }
    
    /**
     * 작업 결과 보고
     */
    private void reportResult(String taskId, boolean success, String log) {
        TaskResultReport report = new TaskResultReport(
            botId,
            taskId,
            success ? "success" : "failed",
            log
        );
        
        api.reportResult(report).enqueue(new Callback<Void>() {
            @Override
            public void onResponse(Call<Void> call, Response<Void> response) {
                if (response.isSuccessful()) {
                    Log.d(TAG, "Result reported successfully");
                } else {
                    Log.e(TAG, "Result report failed: " + response.code());
                }
            }
            
            @Override
            public void onFailure(Call<Void> call, Throwable t) {
                Log.e(TAG, "Result report error: " + t.getMessage());
            }
        });
    }
}
