/**
 * HTTP Header Generation Engine
 *
 * Generates realistic HTTP headers based on task variables
 * Emulates Android device behavior for rank checking
 *
 * Based on IMPLEMENTATION_PLAN.md Phase 5
 */

import { Task } from "../../drizzle/schema";
import { KeywordItem } from "./zeroApiClient";

/**
 * Generate HTTP headers for rank check requests
 *
 * Creates headers that match Android device patterns to avoid detection
 *
 * @param task Task with 10 variables
 * @param keywordData Keyword data from Zero API
 * @returns HTTP headers object
 */
export function generateHeaders(
  task: Task,
  keywordData: KeywordItem
): Record<string, string> {
  const headers: Record<string, string> = {
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    Connection: "keep-alive",
    "Upgrade-Insecure-Requests": "1",
  };

  // 1. User-Agent (variable: uaChange)
  if (task.uaChange === 1 && keywordData.user_agent) {
    headers["User-Agent"] = keywordData.user_agent;
  } else {
    // Default Android User-Agent
    headers["User-Agent"] =
      "Mozilla/5.0 (Linux; Android 13; SM-S918N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
  }

  // 2. Referer (variable: shopHome)
  const shopHomeUrls: (string | null)[] = [
    "https://m.naver.com/", // 0: 네이버 모바일 홈
    "https://msearch.shopping.naver.com/", // 1: 쇼핑 홈
    null, // 2: Referer 없음 (직접 접속)
    "https://msearch.shopping.naver.com/di/", // 3: 광고 DI
    "https://search.naver.com/search.naver", // 4: 통합 검색
  ];

  const referer = shopHomeUrls[task.shopHome];
  if (referer) {
    headers["Referer"] = referer;
  }

  // 3. Sec-Fetch-* headers (variable: secFetchSiteMode)
  const secFetchSites = ["none", "same-site", "same-origin"];
  headers["Sec-Fetch-Site"] = secFetchSites[task.secFetchSiteMode];
  headers["Sec-Fetch-Mode"] = "navigate";
  headers["Sec-Fetch-Dest"] = "document";
  headers["Sec-Fetch-User"] = "?1";

  // 4. sec-ch-ua headers (variable: cookieHomeMode)
  if (task.cookieHomeMode === 0) {
    // 모바일
    headers["sec-ch-ua-mobile"] = "?1";
    headers["sec-ch-ua-platform"] = '"Android"';
    headers["sec-ch-ua"] =
      '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"';
  } else if (task.cookieHomeMode === 1) {
    // 모바일 (갤럭시)
    headers["sec-ch-ua-mobile"] = "?1";
    headers["sec-ch-ua-platform"] = '"Android"';
    headers["sec-ch-ua"] =
      '"Not_A Brand";v="8", "Chromium";v="120", "Samsung Internet";v="23"';
  } else if (task.cookieHomeMode === 2) {
    // PC
    headers["sec-ch-ua-mobile"] = "?0";
    headers["sec-ch-ua-platform"] = '"Windows"';
    headers["sec-ch-ua"] =
      '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"';
  }

  // 5. Cookie (variable: useNid)
  if (task.useNid === 1) {
    // 로그인 쿠키 사용
    const cookies: string[] = [];

    if (keywordData.nnb) cookies.push(`NNB=${keywordData.nnb}`);
    if (keywordData.nid_aut) cookies.push(`NID_AUT=${keywordData.nid_aut}`);
    if (keywordData.nid_ses) cookies.push(`NID_SES=${keywordData.nid_ses}`);

    if (cookies.length > 0) {
      headers["Cookie"] = cookies.join("; ");
    }
  } else {
    // 비로그인 쿠키 (NNB만)
    if (keywordData.nnb) {
      headers["Cookie"] = `NNB=${keywordData.nnb}`;
    }
  }

  return headers;
}

/**
 * Generate search URL with parameters
 *
 * @param keyword Search keyword
 * @param page Page number (1-based)
 * @returns Full search URL
 */
export function buildSearchUrl(keyword: string, page: number): string {
  const params = new URLSearchParams({
    query: keyword,
    sort: "rel", // 관련도순
    pagingIndex: page.toString(),
    pagingSize: "40",
    viewType: "list",
    productSet: "total",
    origQuery: keyword,
    adQuery: keyword,
  });

  return `https://msearch.shopping.naver.com/search/all?${params}`;
}

/**
 * Calculate delay based on lowDelay variable
 *
 * @param lowDelay Delay mode (1-10)
 * @returns Delay in milliseconds
 */
export function calculateDelay(lowDelay: number): number {
  // lowDelay = 1: 매우 짧음 (500ms)
  // lowDelay = 5: 보통 (2500ms)
  // lowDelay = 10: 매우 길음 (5000ms)
  const baseDelay = 500;
  const increment = 450;

  return baseDelay + lowDelay * increment;
}

/**
 * Generate random click coordinates within element bounds
 *
 * Used for simulating human-like clicks
 *
 * @param element Element selector
 * @returns Click coordinates { x, y }
 */
export function generateClickCoordinates(element: {
  x: number;
  y: number;
  width: number;
  height: number;
}): { x: number; y: number } {
  // Click in center with slight randomness
  const x = element.x + element.width / 2 + (Math.random() - 0.5) * 20;
  const y = element.y + element.height / 2 + (Math.random() - 0.5) * 20;

  return { x, y };
}
