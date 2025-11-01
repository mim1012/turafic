package com.turafic.agent;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

import com.turafic.agent.service.BotService;
import com.turafic.agent.network.ApiClient;
import com.turafic.agent.utils.DeviceInfo;

/**
 * Turafic Android Agent - Main Activity
 * 
 * 사용자 인터페이스:
 * - 서버 URL 설정
 * - 서비스 시작/중지
 * - 봇 상태 표시
 */
public class MainActivity extends AppCompatActivity {
    
    private EditText serverUrlInput;
    private Button startServiceButton;
    private Button stopServiceButton;
    private TextView statusText;
    private TextView botIdText;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // UI 요소 초기화
        serverUrlInput = findViewById(R.id.server_url_input);
        startServiceButton = findViewById(R.id.start_service_button);
        stopServiceButton = findViewById(R.id.stop_service_button);
        statusText = findViewById(R.id.status_text);
        botIdText = findViewById(R.id.bot_id_text);
        
        // 기기 정보 표시
        displayDeviceInfo();
        
        // 서비스 시작 버튼
        startServiceButton.setOnClickListener(v -> {
            String serverUrl = serverUrlInput.getText().toString();
            if (!serverUrl.isEmpty()) {
                // 서버 URL 저장
                ApiClient.setBaseUrl(serverUrl);
                
                // 백그라운드 서비스 시작
                Intent serviceIntent = new Intent(this, BotService.class);
                startService(serviceIntent);
                
                statusText.setText("Status: Service Started");
            }
        });
        
        // 서비스 중지 버튼
        stopServiceButton.setOnClickListener(v -> {
            Intent serviceIntent = new Intent(this, BotService.class);
            stopService(serviceIntent);
            
            statusText.setText("Status: Service Stopped");
        });
    }
    
    /**
     * 기기 정보 표시
     */
    private void displayDeviceInfo() {
        String deviceModel = DeviceInfo.getDeviceModel();
        String androidVersion = DeviceInfo.getAndroidVersion();
        String screenResolution = DeviceInfo.getScreenResolution(this);
        String androidId = DeviceInfo.getAndroidId(this);
        
        String info = String.format(
            "Device: %s\nAndroid: %s\nResolution: %s\nAndroid ID: %s",
            deviceModel, androidVersion, screenResolution, androidId
        );
        
        botIdText.setText(info);
    }
}
