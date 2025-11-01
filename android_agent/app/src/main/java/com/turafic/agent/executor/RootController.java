package com.turafic.agent.executor;

import android.util.Log;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;

/**
 * Root Controller
 * 
 * 루팅 기반 저수준 제어
 * - su 명령어로 루트 권한 획득
 * - input tap, input text 등 ADB 명령어 실행
 */
public class RootController {
    
    private static final String TAG = "RootController";
    
    /**
     * 루트 명령어 실행
     * 
     * @param command 실행할 명령어
     * @return 명령어 출력 결과
     */
    private static String executeRootCommand(String command) throws Exception {
        Process process = null;
        DataOutputStream os = null;
        BufferedReader reader = null;
        StringBuilder output = new StringBuilder();
        
        try {
            // su 프로세스 시작
            process = Runtime.getRuntime().exec("su");
            os = new DataOutputStream(process.getOutputStream());
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            // 명령어 실행
            os.writeBytes(command + "\n");
            os.flush();
            
            // 종료
            os.writeBytes("exit\n");
            os.flush();
            
            // 출력 읽기
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            // 프로세스 종료 대기
            process.waitFor();
            
            Log.d(TAG, "Command executed: " + command);
            
        } catch (Exception e) {
            Log.e(TAG, "Error executing command: " + command, e);
            throw e;
            
        } finally {
            if (os != null) os.close();
            if (reader != null) reader.close();
            if (process != null) process.destroy();
        }
        
        return output.toString();
    }
    
    /**
     * 화면 터치
     * 
     * @param x X 좌표
     * @param y Y 좌표
     */
    public static void tap(int x, int y) throws Exception {
        String command = "input tap " + x + " " + y;
        executeRootCommand(command);
        
        // 터치 후 짧은 대기 (자연스러운 동작)
        Thread.sleep(300);
    }
    
    /**
     * 텍스트 입력
     * 
     * @param text 입력할 텍스트
     */
    public static void inputText(String text) throws Exception {
        // 공백을 %s로 치환 (input text 명령어 제약)
        String escapedText = text.replace(" ", "%s");
        String command = "input text " + escapedText;
        executeRootCommand(command);
        
        // 입력 후 대기
        Thread.sleep(500);
    }
    
    /**
     * 뒤로 가기 버튼
     */
    public static void pressBack() throws Exception {
        executeRootCommand("input keyevent 4");  // KEYCODE_BACK = 4
        Thread.sleep(500);
    }
    
    /**
     * 홈 버튼
     */
    public static void pressHome() throws Exception {
        executeRootCommand("input keyevent 3");  // KEYCODE_HOME = 3
        Thread.sleep(500);
    }
    
    /**
     * 스크롤
     * 
     * @param direction 방향 ("up", "down", "left", "right")
     * @param distance 거리 (픽셀)
     */
    public static void scroll(String direction, int distance) throws Exception {
        // 화면 중앙 기준 스크롤
        int centerX = 540;  // TODO: 해상도에 따라 동적 계산
        int centerY = 1170;
        
        int startX = centerX;
        int startY = centerY;
        int endX = centerX;
        int endY = centerY;
        
        switch (direction) {
            case "down":
                endY = centerY - distance;
                break;
            case "up":
                endY = centerY + distance;
                break;
            case "left":
                endX = centerX + distance;
                break;
            case "right":
                endX = centerX - distance;
                break;
        }
        
        String command = String.format("input swipe %d %d %d %d 300", startX, startY, endX, endY);
        executeRootCommand(command);
        
        Thread.sleep(500);
    }
    
    /**
     * 앱 강제 종료
     * 
     * @param packageName 패키지 이름
     */
    public static void forceStopApp(String packageName) throws Exception {
        String command = "am force-stop " + packageName;
        executeRootCommand(command);
        
        Thread.sleep(1000);
    }
    
    /**
     * 앱 시작
     * 
     * @param packageName 패키지 이름
     */
    public static void startApp(String packageName) throws Exception {
        // monkey 명령어로 앱 시작 (간단한 방법)
        String command = "monkey -p " + packageName + " 1";
        executeRootCommand(command);
        
        Thread.sleep(2000);  // 앱 로딩 대기
    }
}
