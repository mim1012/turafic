package com.turafic.agent.utils;

import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import android.util.Log;

/**
 * Airplane Mode Manager
 * 
 * 비행기 모드를 제어하여 IP 주소 변경
 * - 1 트래픽당 1회 IP 변경
 * - 비행기 모드 ON → 2초 대기 → OFF
 */
public class AirplaneModeManager {
    
    private static final String TAG = "AirplaneModeManager";
    
    /**
     * 비행기 모드 토글 (ON → OFF)
     * 
     * @param context 컨텍스트
     */
    public static void toggleAirplaneMode(Context context) {
        try {
            Log.d(TAG, "Toggling airplane mode to change IP...");
            
            // 1. 비행기 모드 ON
            setAirplaneMode(context, true);
            
            // 2. 2초 대기
            Thread.sleep(2000);
            
            // 3. 비행기 모드 OFF
            setAirplaneMode(context, false);
            
            // 4. 네트워크 재연결 대기
            Thread.sleep(5000);
            
            Log.d(TAG, "Airplane mode toggled successfully");
            
        } catch (Exception e) {
            Log.e(TAG, "Error toggling airplane mode", e);
        }
    }
    
    /**
     * 비행기 모드 설정
     * 
     * @param context 컨텍스트
     * @param enable true = ON, false = OFF
     */
    private static void setAirplaneMode(Context context, boolean enable) {
        try {
            // Settings.Global.AIRPLANE_MODE_ON 값 변경
            Settings.Global.putInt(
                context.getContentResolver(),
                Settings.Global.AIRPLANE_MODE_ON,
                enable ? 1 : 0
            );
            
            // 브로드캐스트 전송 (시스템에 변경 알림)
            Intent intent = new Intent(Intent.ACTION_AIRPLANE_MODE_CHANGED);
            intent.putExtra("state", enable);
            context.sendBroadcast(intent);
            
            Log.d(TAG, "Airplane mode " + (enable ? "enabled" : "disabled"));
            
        } catch (Exception e) {
            Log.e(TAG, "Error setting airplane mode", e);
        }
    }
    
    /**
     * 현재 비행기 모드 상태 확인
     * 
     * @param context 컨텍스트
     * @return true = ON, false = OFF
     */
    public static boolean isAirplaneModeOn(Context context) {
        return Settings.Global.getInt(
            context.getContentResolver(),
            Settings.Global.AIRPLANE_MODE_ON,
            0
        ) != 0;
    }
}
