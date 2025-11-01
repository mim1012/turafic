package com.turafic.agent.executor;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Task Executor
 * 
 * 서버로부터 받은 JSON 작업 패턴을 실행하는 엔진
 * 
 * 작업 패턴 예시:
 * [
 *   {"action": "kill", "target": "com.sec.android.app.sbrowser"},
 *   {"action": "wait", "duration": 2000},
 *   {"action": "tap", "x": 540, "y": 150},
 *   {"action": "text", "value": "단백질쉐이크"}
 * ]
 */
public class TaskExecutor {
    
    private static final String TAG = "TaskExecutor";
    
    /**
     * 작업 패턴 실행
     * 
     * @param pattern JSON 작업 패턴 (List of JSONObject)
     */
    public void executePattern(List<JSONObject> pattern) throws Exception {
        Log.d(TAG, "Executing pattern with " + pattern.size() + " steps");
        
        for (int i = 0; i < pattern.size(); i++) {
            JSONObject step = pattern.get(i);
            String action = step.getString("action");
            
            Log.d(TAG, "Step " + (i + 1) + ": " + action);
            
            switch (action) {
                case "kill":
                    executeKill(step);
                    break;
                    
                case "start":
                    executeStart(step);
                    break;
                    
                case "wait":
                    executeWait(step);
                    break;
                    
                case "tap":
                    executeTap(step);
                    break;
                    
                case "text":
                    executeText(step);
                    break;
                    
                case "back":
                    executeBack();
                    break;
                    
                case "scroll":
                    executeScroll(step);
                    break;
                    
                default:
                    Log.w(TAG, "Unknown action: " + action);
            }
        }
        
        Log.d(TAG, "Pattern execution completed");
    }
    
    /**
     * 앱 강제 종료
     */
    private void executeKill(JSONObject step) throws Exception {
        String target = step.getString("target");
        RootController.forceStopApp(target);
    }
    
    /**
     * 앱 시작
     */
    private void executeStart(JSONObject step) throws Exception {
        String target = step.getString("target");
        RootController.startApp(target);
    }
    
    /**
     * 대기
     */
    private void executeWait(JSONObject step) throws Exception {
        int duration = step.getInt("duration");
        Thread.sleep(duration);
    }
    
    /**
     * 화면 터치
     */
    private void executeTap(JSONObject step) throws Exception {
        int x = step.getInt("x");
        int y = step.getInt("y");
        RootController.tap(x, y);
    }
    
    /**
     * 텍스트 입력
     */
    private void executeText(JSONObject step) throws Exception {
        String value = step.getString("value");
        RootController.inputText(value);
    }
    
    /**
     * 뒤로 가기
     */
    private void executeBack() throws Exception {
        RootController.pressBack();
    }
    
    /**
     * 스크롤
     */
    private void executeScroll(JSONObject step) throws Exception {
        String direction = step.optString("direction", "down");
        int distance = step.optInt("distance", 500);
        
        RootController.scroll(direction, distance);
    }
}
