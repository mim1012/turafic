/**
 * Advanced HTTP Engine
 *
 * 실제 Chrome Mobile 브라우저와 동일한 HTTP 헤더를 생성하여
 * 네이버 쇼핑 봇 탐지를 우회합니다.
 *
 * 기존 httpEngine.ts보다 더 정교한 헤더 순서와 값을 사용합니다.
 */

import { Task } from "../../drizzle/schema";
import { KeywordItem } from "./zeroApiClient";

/**
 * 실제 Chrome Mobile 헤더 생성
 *
 * 헤더 순서가 매우 중요합니다. 실제 브라우저와 동일한 순서를 유지해야 합니다.
 */
export function generateAdvancedHeaders(
  task: Task,
  keywordData: KeywordItem
): Record<string, string> {
  const headers: Record<string, string> = {};

  // 1. sec-ch-ua 헤더 (Chrome 버전 정보)
  headers["sec-ch-ua"] =
    '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"';

  // 2. sec-ch-ua-mobile (모바일 표시)
  if (task.cookieHomeMode === 1) {
    headers["sec-ch-ua-mobile"] = "?1"; // 모바일
    headers["sec-ch-ua-platform"] = '"Android"';
  } else {
    headers["sec-ch-ua-mobile"] = "?0"; // 데스크톱
    headers["sec-ch-ua-platform"] = '"Windows"';
  }

  // 3. upgrade-insecure-requests
  headers["upgrade-insecure-requests"] = "1";

  // 4. User-Agent (task.uaChange에 따라)
  if (task.uaChange === 1 && keywordData.user_agent) {
    headers["user-agent"] = keywordData.user_agent;
  } else {
    // 기본 Chrome Mobile User-Agent (Android 13, Chrome 122)
    headers["user-agent"] =
      "Mozilla/5.0 (Linux; Android 13; SM-S918N Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.64 Mobile Safari/537.36";
  }

  // 5. Accept 헤더 (정확한 순서)
  headers["accept"] =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";

  // 6. Sec-Fetch-Site (task.secFetchSiteMode에 따라)
  switch (task.secFetchSiteMode) {
    case 1:
      headers["sec-fetch-site"] = "none"; // 직접 입력
      break;
    case 2:
      headers["sec-fetch-site"] = "same-site"; // 네이버 내부 이동
      break;
    case 3:
      headers["sec-fetch-site"] = "same-origin"; // 동일 도메인
      break;
    default:
      headers["sec-fetch-site"] = "cross-site"; // 외부에서 접근
  }

  // 7. Sec-Fetch-Mode
  headers["sec-fetch-mode"] = "navigate";

  // 8. Sec-Fetch-User (사용자 액션)
  headers["sec-fetch-user"] = "?1";

  // 9. Sec-Fetch-Dest
  headers["sec-fetch-dest"] = "document";

  // 10. Referer (task.shopHome에 따라)
  switch (task.shopHome) {
    case 1:
      headers["referer"] = "https://m.naver.com/"; // 네이버 모바일 홈
      break;
    case 2:
      headers["referer"] = "https://msearch.shopping.naver.com/"; // 쇼핑 홈
      break;
    case 3:
      // referer 없음
      break;
    case 4:
      headers["referer"] = "https://m.shopping.naver.com/"; // DI
      break;
    case 5:
      headers["referer"] = "https://m.search.naver.com/"; // 통합 검색
      break;
  }

  // 11. Accept-Encoding
  headers["accept-encoding"] = "gzip, deflate, br, zstd";

  // 12. Accept-Language
  headers["accept-language"] = "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7";

  // 13. Cookie (task.useNid에 따라)
  if (task.useNid === 1 && keywordData.nnb) {
    const cookies = [`NNB=${keywordData.nnb}`];

    if (keywordData.nid_aut) {
      cookies.push(`NID_AUT=${keywordData.nid_aut}`);
    }

    if (keywordData.nid_ses) {
      cookies.push(`NID_SES=${keywordData.nid_ses}`);
    }

    headers["cookie"] = cookies.join("; ");
  }

  return headers;
}

/**
 * 검색 URL 생성 (기존 buildSearchUrl과 동일)
 */
export function buildAdvancedSearchUrl(keyword: string, page: number): string {
  const params = new URLSearchParams({
    query: keyword,
    sort: "rel",
    pagingIndex: page.toString(),
    pagingSize: "40",
    viewType: "list",
    productSet: "total",
    origQuery: keyword,
    adQuery: keyword,
  });

  return `https://msearch.shopping.naver.com/search/all?${params.toString()}`;
}

/**
 * Delay 계산 (기존 calculateDelay와 동일)
 */
export function calculateAdvancedDelay(lowDelay: number): number {
  // lowDelay: 1-10 → delay: 500ms-5000ms
  if (lowDelay >= 1 && lowDelay <= 10) {
    return lowDelay * 500;
  }

  return 2000; // 기본값
}
