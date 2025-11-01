package com.turafic.agent.utils;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import android.util.DisplayMetrics;
import android.view.WindowManager;

/**
 * Device Info Utility
 * 
 * 기기 정보 수집
 * - 기기 모델
 * - Android 버전
 * - 화면 해상도
 * - Android ID (고유 식별자)
 */
public class DeviceInfo {
    
    /**
     * 기기 모델 조회
     * 
     * @return 기기 모델 (예: "SM-G996N")
     */
    public static String getDeviceModel() {
        return Build.MODEL;
    }
    
    /**
     * Android 버전 조회
     * 
     * @return Android 버전 (예: "12")
     */
    public static String getAndroidVersion() {
        return String.valueOf(Build.VERSION.SDK_INT);
    }
    
    /**
     * 화면 해상도 조회
     * 
     * @param context 컨텍스트
     * @return 해상도 문자열 (예: "1080x2340")
     */
    public static String getScreenResolution(Context context) {
        WindowManager wm = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
        DisplayMetrics metrics = new DisplayMetrics();
        wm.getDefaultDisplay().getRealMetrics(metrics);
        
        int width = metrics.widthPixels;
        int height = metrics.heightPixels;
        
        return width + "x" + height;
    }
    
    /**
     * Android ID 조회 (기기 고유 식별자)
     * 
     * @param context 컨텍스트
     * @return Android ID
     */
    public static String getAndroidId(Context context) {
        return Settings.Secure.getString(
            context.getContentResolver(),
            Settings.Secure.ANDROID_ID
        );
    }
}
