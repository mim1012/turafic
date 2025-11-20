package com.turafic.rankchecker.checker

import android.util.Log
import com.turafic.rankchecker.models.RankCheckTask
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

/**
 * HTTP 패킷 기반 순위 체크
 *
 * WebView 대신 순수 HTTP 요청으로 네이버 쇼핑 순위를 체크합니다.
 * zru12 APK와 동일한 방식으로 동작하여 봇 탐지를 우회합니다.
 *
 * 특징:
 * - OkHttp를 사용한 순수 HTTP 패킷 전송
 * - 10개 변수 시스템 완벽 지원
 * - Cookie 세션 관리
 * - 실제 Chrome Mobile과 동일한 헤더
 */
class NaverHttpRankChecker {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .cookieJar(SimpleCookieJar()) // Cookie 자동 관리
        .build()

    /**
     * 순위 체크 메인 로직
     * @param task 순위 체크 작업
     * @return 순위 (못 찾으면 -1)
     */
    suspend fun checkRank(task: RankCheckTask): Int = withContext(Dispatchers.IO) {
        Log.i(TAG, "=== HTTP PACKET RANK CHECK START ===")
        Log.i(TAG, "Keyword: ${task.keyword}")
        Log.i(TAG, "Product ID: ${task.productId}")
        Log.i(TAG, "Mode: Pure HTTP (No WebView)")

        try {
            // 페이지별 검색 (최대 10페이지 = 400개 상품)
            for (page in 1..MAX_PAGES) {
                Log.d(TAG, "--- Checking page $page/$MAX_PAGES ---")

                val url = buildSearchUrl(task.keyword, page)
                val headers = buildHeaders(task, page)

                Log.d(TAG, "URL: ${url.take(80)}...")
                Log.v(TAG, "User-Agent: ${headers["User-Agent"]?.take(50)}...")
                Log.v(TAG, "Referer: ${headers["Referer"] ?: "(none)"}")
                Log.v(TAG, "sec-fetch-site: ${headers["sec-fetch-site"]}")

                // HTTP 요청
                val request = Request.Builder()
                    .url(url)
                    .apply {
                        headers.forEach { (name, value) ->
                            addHeader(name, value)
                        }
                    }
                    .get()
                    .build()

                val response: Response = httpClient.newCall(request).execute()
                val statusCode = response.code
                val html = response.body?.string() ?: ""

                Log.d(TAG, "HTTP $statusCode (${html.length} bytes)")

                if (statusCode != 200) {
                    if (statusCode == 418) {
                        Log.w(TAG, "⚠️ HTTP 418 - Bot detected!")
                    }
                    continue
                }

                // nvMid로 상품 찾기
                val rank = findProductInHtml(html, task.productId, page)
                if (rank > 0) {
                    Log.i(TAG, "=== PRODUCT FOUND AT RANK $rank ===")
                    return@withContext rank
                }

                Log.d(TAG, "Product not found on page $page")

                // 페이지 간 딜레이 (lowDelay 변수 기반)
                val delayMs = calculateDelay(task.variables.lowDelay)
                delay(delayMs)
            }

            Log.w(TAG, "=== PRODUCT NOT FOUND (checked ${MAX_PAGES * PRODUCTS_PER_PAGE} products) ===")
            return@withContext -1

        } catch (e: Exception) {
            Log.e(TAG, "=== RANK CHECK ERROR ===", e)
            throw e
        }
    }

    /**
     * 검색 URL 생성
     */
    private fun buildSearchUrl(keyword: String, page: Int): String {
        val encodedKeyword = URLEncoder.encode(keyword, "UTF-8")
        return "https://msearch.shopping.naver.com/search/all" +
                "?query=$encodedKeyword" +
                "&pagingIndex=$page" +
                "&pagingSize=40" +
                "&sort=rel" +
                "&viewType=list" +
                "&productSet=total" +
                "&origQuery=$encodedKeyword" +
                "&adQuery=$encodedKeyword"
    }

    /**
     * HTTP 헤더 생성 (10개 변수 시스템)
     *
     * 실제 Chrome Mobile과 동일한 헤더 순서 및 값을 사용하여
     * 네이버 쇼핑 봇 탐지를 우회합니다.
     */
    private fun buildHeaders(task: RankCheckTask, page: Int): Map<String, String> {
        val headers = mutableMapOf<String, String>()
        val vars = task.variables

        // 1. sec-ch-ua (Chrome 버전 정보)
        headers["sec-ch-ua"] =
            "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\""

        // 2. sec-ch-ua-mobile (모바일 여부)
        when (vars.cookieStrategy) {
            "로그인쿠키", "비로그인쿠키" -> {
                headers["sec-ch-ua-mobile"] = "?1" // 모바일
                headers["sec-ch-ua-platform"] = "\"Android\""
            }
            else -> {
                headers["sec-ch-ua-mobile"] = "?0" // 데스크톱
                headers["sec-ch-ua-platform"] = "\"Windows\""
            }
        }

        // 3. upgrade-insecure-requests
        headers["upgrade-insecure-requests"] = "1"

        // 4. User-Agent (변수: user_agent)
        headers["User-Agent"] = when (vars.userAgent) {
            "UA58" -> "Mozilla/5.0 (Linux; Android 13; SM-S918N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
            "UA67" -> "Mozilla/5.0 (Linux; Android 14; SM-S926N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36"
            "UA71" -> "Mozilla/5.0 (Linux; Android 13; SM-G991N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
            else -> vars.userAgent // Zero API에서 받은 값
        }

        // 5. Accept
        headers["Accept"] =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"

        // 6. Sec-Fetch-Site (변수: entry_point + page 번호)
        headers["sec-fetch-site"] = when {
            page == 1 -> when (vars.entryPoint) {
                "쇼핑DI" -> "same-site"
                "광고DI" -> "same-origin"
                "통합검색" -> "cross-site"
                else -> "none"
            }
            else -> "same-origin" // 2페이지 이상은 same-origin
        }

        // 7. Sec-Fetch-Mode
        headers["sec-fetch-mode"] = "navigate"

        // 8. Sec-Fetch-User
        headers["sec-fetch-user"] = "?1"

        // 9. Sec-Fetch-Dest
        headers["sec-fetch-dest"] = "document"

        // 10. Referer (변수: entry_point)
        if (page > 1) {
            // 2페이지 이상: 이전 페이지를 Referer로
            headers["Referer"] = buildSearchUrl(task.keyword, page - 1)
        } else {
            // 1페이지: entry_point에 따라
            when (vars.entryPoint) {
                "쇼핑DI" -> headers["Referer"] = "https://m.shopping.naver.com/"
                "광고DI" -> headers["Referer"] = "https://msearch.shopping.naver.com/"
                "통합검색" -> headers["Referer"] = "https://m.search.naver.com/"
                // "직접입력"은 Referer 없음
            }
        }

        // 11. Accept-Encoding
        headers["accept-encoding"] = "gzip, deflate, br, zstd"

        // 12. Accept-Language
        headers["accept-language"] = "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"

        // 13. Cookie (변수: cookie_strategy)
        if (vars.cookieStrategy == "로그인쿠키" && task.cookies.isNotEmpty()) {
            headers["Cookie"] = task.cookies
        }

        return headers
    }

    /**
     * HTML에서 상품 찾기
     *
     * @param html HTML 응답
     * @param productId 찾을 상품 ID (nvMid)
     * @param page 현재 페이지
     * @return 순위 (못 찾으면 -1)
     */
    private fun findProductInHtml(html: String, productId: String, page: Int): Int {
        try {
            // nvMid 패턴으로 모든 상품 ID 추출
            val pattern = Regex("""nvMid=(\d+)""")
            val matches = pattern.findAll(html).toList()

            Log.v(TAG, "Found ${matches.size} nvMid links on page $page")

            // 타겟 상품의 위치 찾기
            for ((index, match) in matches.withIndex()) {
                val nvMid = match.groupValues[1]

                if (index < 3) {
                    Log.v(TAG, "  Product ${index + 1}: nvMid=$nvMid")
                }

                if (nvMid == productId) {
                    val rank = (page - 1) * PRODUCTS_PER_PAGE + index + 1
                    return rank
                }
            }

            return -1

        } catch (e: Exception) {
            Log.e(TAG, "findProductInHtml error", e)
            return -1
        }
    }

    /**
     * 딜레이 계산 (변수: delay_mode)
     *
     * @param delayMode "딜레이감소" 또는 "딜레이정상"
     * @return 딜레이 시간 (밀리초)
     */
    private fun calculateDelay(delayMode: String): Long {
        return when (delayMode) {
            "딜레이감소" -> 1000L // 1초
            "딜레이정상" -> 2000L // 2초
            else -> 1500L // 기본값
        }
    }

    companion object {
        private const val TAG = "NaverHttpRankChecker"
        private const val PRODUCTS_PER_PAGE = 40
        private const val MAX_PAGES = 10
    }
}

/**
 * 간단한 쿠키 저장소
 *
 * OkHttp의 CookieJar 인터페이스를 구현하여
 * Set-Cookie 응답을 자동으로 저장하고 재사용합니다.
 */
class SimpleCookieJar : okhttp3.CookieJar {
    private val cookieStore = mutableMapOf<String, List<okhttp3.Cookie>>()

    override fun saveFromResponse(url: okhttp3.HttpUrl, cookies: List<okhttp3.Cookie>) {
        cookieStore[url.host] = cookies
    }

    override fun loadForRequest(url: okhttp3.HttpUrl): List<okhttp3.Cookie> {
        return cookieStore[url.host] ?: emptyList()
    }
}
