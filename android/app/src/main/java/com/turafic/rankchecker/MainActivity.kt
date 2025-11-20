package com.turafic.rankchecker

import android.os.Build
import android.os.Bundle
import android.util.Log
import android.webkit.WebView
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.turafic.rankchecker.checker.NaverHttpRankChecker
import com.turafic.rankchecker.network.TuraficApiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.*

/**
 * 메인 액티비티
 * 순위 체크 프로세스를 실행하고 관리합니다
 */
class MainActivity : AppCompatActivity() {

    private lateinit var apiClient: TuraficApiClient
    private lateinit var httpRankChecker: NaverHttpRankChecker
    private lateinit var statusTextView: TextView
    private lateinit var startButton: Button

    private var botId: Int = -1
    private val deviceId = "android-${UUID.randomUUID()}"
    private val loginId = "test_user"  // TODO: 실제 값으로 변경
    private val imei = "123456789012345"  // TODO: 실제 값으로 변경

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // UI 초기화
        statusTextView = findViewById(R.id.statusTextView)
        startButton = findViewById(R.id.startButton)

        // API 클라이언트 및 순위 체커 초기화
        apiClient = TuraficApiClient()
        httpRankChecker = NaverHttpRankChecker()

        // 버튼 클릭 리스너
        startButton.setOnClickListener {
            startRankCheck()
        }

        // 앱 시작 시 봇 등록
        registerBot()
    }

    /**
     * 봇 등록
     */
    private fun registerBot() {
        lifecycleScope.launch {
            updateStatus("봇 등록 중...")
            try {
                botId = withContext(Dispatchers.IO) {
                    apiClient.registerBot(deviceId, Build.MODEL)
                }
                updateStatus("봇 등록 완료 (ID: $botId)")
                Log.i(TAG, "Bot registered: botId=$botId")

                // 상태 업데이트
                withContext(Dispatchers.IO) {
                    apiClient.updateBotStatus(botId, "online")
                }
            } catch (e: Exception) {
                updateStatus("봇 등록 실패: ${e.message}")
                Log.e(TAG, "registerBot error", e)
            }
        }
    }

    /**
     * 순위 체크 시작
     */
    private fun startRankCheck() {
        if (botId == -1) {
            updateStatus("봇 등록이 필요합니다")
            return
        }

        lifecycleScope.launch {
            startButton.isEnabled = false
            updateStatus("작업 요청 중...")

            try {
                // 1. 작업 요청
                val task = withContext(Dispatchers.IO) {
                    apiClient.getTask(botId, loginId, imei)
                }

                if (task == null) {
                    updateStatus("작업 없음 (대기 중)")
                    startButton.isEnabled = true
                    return@launch
                }

                updateStatus("작업 수신: ${task.keyword}")
                Log.i(TAG, "Task received: ${task.taskId}")

                // 2. 순위 체크 실행
                val rank = performRankCheck(task)

                // 3. 결과 보고
                withContext(Dispatchers.IO) {
                    apiClient.reportRank(
                        taskId = task.taskId,
                        campaignId = task.campaignId,
                        rank = rank,
                        success = rank != -1,
                        errorMessage = if (rank == -1) "Product not found" else null
                    )
                }

                // 4. 작업 완료
                withContext(Dispatchers.IO) {
                    apiClient.finishTask(task.taskId, botId)
                }

                val statusMessage = if (rank != -1) {
                    "✅ 순위 $rank 발견!"
                } else {
                    "❌ 순위 못 찾음 (400개 검색)"
                }
                updateStatus(statusMessage)

            } catch (e: Exception) {
                updateStatus("에러: ${e.message}")
                Log.e(TAG, "startRankCheck error", e)
            } finally {
                startButton.isEnabled = true
            }
        }
    }

    /**
     * 순위 체크 실행 (HTTP 패킷 기반)
     *
     * WebView 대신 순수 HTTP 요청으로 순위를 체크합니다.
     * 실제 Android 디바이스에서 실행되므로 서버 기반보다 봇 탐지가 적습니다.
     *
     * @param task 순위 체크 작업
     * @return 순위 (못 찾으면 -1)
     */
    private suspend fun performRankCheck(task: com.turafic.rankchecker.models.RankCheckTask): Int {
        updateStatus("순위 체크 중 (HTTP 패킷)...")
        Log.i(TAG, "Using HTTP packet-based rank checker")

        return try {
            val rank = httpRankChecker.checkRank(task)
            Log.i(TAG, "Rank check completed: rank=$rank")
            rank
        } catch (e: Exception) {
            Log.e(TAG, "performRankCheck error", e)
            updateStatus("에러: ${e.message}")
            -1
        }
    }

    /**
     * 상태 메시지 업데이트
     */
    private fun updateStatus(message: String) {
        runOnUiThread {
            statusTextView.text = message
            Log.d(TAG, "Status: $message")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // 봇 상태 업데이트
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    apiClient.updateBotStatus(botId, "offline")
                }
            } catch (e: Exception) {
                Log.e(TAG, "updateBotStatus error", e)
            }
        }
    }

    companion object {
        private const val TAG = "MainActivity"
    }
}
