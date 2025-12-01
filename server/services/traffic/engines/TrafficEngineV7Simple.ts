/**
 * v7 Simple Engine - Samsung Galaxy S23 프로필 적용
 */
import { connect } from "puppeteer-real-browser";
import type { Browser, Page } from "puppeteer-core";
import { findAccurateRank, type RankResult } from '../../../../rank-check/accurate-rank-checker';
import { ProfileApplier } from '../shared/fingerprint/ProfileApplier';
import { getFailureLogger, type FailReason } from '../../failureLogger';
import v7Profile from '../profiles/v7-samsung-s23.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

export interface SimpleTrafficProduct {
  nvMid: string;
  productName: string;
  keyword: string;
  taskId?: number;   // 실패 로깅용
  slotId?: number;   // 실패 로깅용
}

export interface SimpleTrafficResult {
  success: boolean;
  version: string;
  blocked: boolean;
  bridgeDetected: boolean;
  midClicked: boolean;
  error?: string;
  duration?: number;
  foundMids?: string[];    // 검색 결과에서 발견된 MID 목록
  foundCount?: number;     // 발견된 총 상품 수
}

const BRIDGE_PATTERNS = [
  "cr.shopping.naver.com/bridge",
  "cr2.shopping.naver.com/bridge",
  "cr3.shopping.naver.com/bridge",
  "cr4.shopping.naver.com/bridge",
  "shopping.naver.com/bridge",
  "naver.com/v2/bridge",
  "/bridge?"
];

// 프로필 타입 캐스팅
const profile = v7Profile as FingerprintProfile;

export class TrafficEngineV7Simple {
  private browser: Browser | null = null;
  private page: Page | null = null;

  async init(): Promise<void> {
    const { browser, page } = await connect({
      headless: false,
      turnstile: true,
      // fingerprint: true,  // 모바일 프로필 비활성화 - m.smartstore CAPTCHA 회피
      // args: ProfileApplier.getConnectArgs(profile),
    });

    this.browser = browser as Browser;
    this.page = page as Page;

    // 프로필 적용 비활성화 - 모바일 프로필 때문에 m.smartstore로 리다이렉트되어 CAPTCHA 발생
    // await ProfileApplier.apply(this.page as any, profile);

    this.page.setDefaultTimeout(30000);
    this.page.setDefaultNavigationTimeout(30000);

    console.log(`[v7-simple] No profile applied (PC mode)`);
  }

  async close(): Promise<void> {
    try {
      if (this.page) await this.page.close().catch(() => {});
      if (this.browser) await this.browser.close().catch(() => {});
    } catch {}
    this.browser = null;
    this.page = null;
  }

  async execute(product: SimpleTrafficProduct): Promise<SimpleTrafficResult> {
    const startTime = Date.now();

    if (!this.page) {
      return {
        success: false,
        version: "v7-simple",
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: "Browser not initialized",
      };
    }

    try {
      // 1. 네이버 모바일 메인
      await this.page.goto("https://m.naver.com/", { waitUntil: "domcontentloaded" });
      await this.delay(1500 + Math.random() * 1000);

      // 2. 풀네임 검색
      const searchQuery = product.productName.substring(0, 50);

      const searchFound = await this.page.evaluate((searchTerm: string) => {
        const input = document.querySelector('input[type="search"], input[name="query"]') as HTMLInputElement;
        if (input) {
          input.value = searchTerm;
          input.dispatchEvent(new Event('input', { bubbles: true }));
          const form = input.closest('form');
          if (form) {
            form.submit();
            return true;
          }
        }
        return false;
      }, searchQuery);

      if (!searchFound) {
        return {
          success: false,
          version: "v7-simple",
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: "Search input not found",
        };
      }

      await this.page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => {});
      await this.delay(2500 + Math.random() * 1000);

      // 3. CAPTCHA 체크
      const captchaDetected = await this.checkCaptcha();
      if (captchaDetected) {
        // CAPTCHA 실패 로깅
        const failureLogger = getFailureLogger();
        await failureLogger.logCaptcha({
          taskId: product.taskId,
          slotId: product.slotId,
          keyword: product.keyword || product.productName,
          targetMid: product.nvMid,
          searchUrl: this.page.url(),
          engineVersion: 'v7-simple',
          errorMessage: '통합검색 CAPTCHA 감지',
        });

        return {
          success: false,
          version: "v7-simple",
          blocked: true,
          bridgeDetected: false,
          midClicked: false,
          error: "통합검색 CAPTCHA",
          duration: Date.now() - startTime,
        };
      }

      // 4. 스크롤 (최소한만)
      for (let s = 0; s < 3; s++) {
        await this.page.evaluate(() => window.scrollBy(0, 400));
        await this.delay(500);
      }

      // 5. MID 클릭 (v6 방식)
      let clicked = await this.clickDirectSmartStore(product.nvMid);
      console.log(`[v7-simple] clickDirectSmartStore: ${clicked}`);

      if (!clicked) {
        clicked = await this.findAndClickMid(product.nvMid);
        console.log(`[v7-simple] findAndClickMid: ${clicked}`);
      }

      // 6. Fallback: 쇼핑 탭 전략
      let usedFallback = false;
      if (!clicked) {
        console.log("[v7-simple] 1차 시도 실패 → Fallback 전략 시작");
        clicked = await this.tryShoppingTabFallback(product);
        usedFallback = true;
        console.log(`[v7-simple] Fallback result: ${clicked}`);
      }

      if (!clicked) {
        // MID 못 찾았을 때 - 검색 결과에서 발견된 MID들 수집
        const { mids: foundMids, count: foundCount } = await this.collectFoundMids();

        // 실패 로깅 (DB + JSON 파일)
        const failureLogger = getFailureLogger();
        await failureLogger.logMidNotFound({
          taskId: product.taskId,
          slotId: product.slotId,
          keyword: product.keyword || product.productName,
          targetMid: product.nvMid,
          searchUrl: this.page.url(),
          foundMids,
          foundCount,
          engineVersion: 'v7-simple',
        });

        return {
          success: false,
          version: "v7-simple",
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: `MID ${product.nvMid} not found (both strategies failed)`,
          duration: Date.now() - startTime,
          foundMids,
          foundCount,
        };
      }

      // 7. 페이지 로딩 대기 (1차 시도 성공한 경우만 - Fallback은 자체적으로 처리)
      if (!usedFallback) {
        // navigation 이벤트 대기
        try {
          await this.page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 10000 });
        } catch {}

        await this.delay(3000);

        // 브릿지 URL 체크 및 리다이렉트 대기
        let finalUrl = this.page.url();
        console.log(`[v7-simple] Current URL after navigation: ${finalUrl.substring(0, 100)}`);

        if (this.isBridgeUrl(finalUrl)) {
          console.log("[v7-simple] Bridge URL detected, waiting for redirect...");
          for (let i = 0; i < 10; i++) {
            await this.delay(1000);
            finalUrl = this.page.url();
            if (!this.isBridgeUrl(finalUrl)) {
              console.log(`[v7-simple] Redirect completed to: ${finalUrl.substring(0, 80)}`);
              break;
            }
          }
        }
      }

      // 8. 최종 검증 (정확한 MID 상품인지 DOM에서 확인)
      await this.delay(1000);
      const finalUrl = this.page.url();
      console.log(`[v7-simple] Final URL for validation: ${finalUrl.substring(0, 100)}`);
      const isProduct = finalUrl.includes("/catalog/") ||
                       finalUrl.includes("/products/") ||
                       finalUrl.includes("smartstore.naver.com") ||
                       finalUrl.includes("brand.naver.com");

      if (!isProduct) {
        return {
          success: false,
          version: "v7-simple",
          blocked: false,
          bridgeDetected: false,
          midClicked: true,
          error: "Not a product page",
          duration: Date.now() - startTime,
        };
      }

      // DOM에서 MID 확인 (URL 또는 data 속성)
      const midVerification = await this.page.evaluate((targetMid: string) => {
        const url = window.location.href;

        // 1. URL에 MID 포함
        if (url.includes(targetMid)) return { found: true, method: 'URL', url };

        // 2. data-nv-mid 속성 확인
        const elements = document.querySelectorAll('[data-nv-mid], [data-nvmid], [data-product-id]');
        for (const el of Array.from(elements)) {
          const mid = el.getAttribute('data-nv-mid') ||
                     el.getAttribute('data-nvmid') ||
                     el.getAttribute('data-product-id');
          if (mid === targetMid) return { found: true, method: 'data-attr', url };
        }

        // 3. meta 태그 확인
        const metaTags = document.querySelectorAll('meta[property*="product"], meta[name*="product"]');
        for (const meta of Array.from(metaTags)) {
          const content = meta.getAttribute('content') || '';
          if (content.includes(targetMid)) return { found: true, method: 'meta', url };
        }

        // 차단 페이지인지 확인
        const bodyText = document.body.innerText;
        const isBlocked = bodyText.includes("보안 확인") ||
                         bodyText.includes("일시적으로 제한") ||
                         bodyText.includes("비정상적인 접근");

        return { found: false, url, bodyPreview: bodyText.substring(0, 200), isBlocked };
      }, product.nvMid);

      const midVerified = midVerification.found;

      // 차단 페이지 체크만 수행 (MID 불일치는 허용)
      if (midVerification.isBlocked) {
        // 차단 실패 로깅
        const failureLogger = getFailureLogger();
        await failureLogger.logBlocked({
          taskId: product.taskId,
          slotId: product.slotId,
          keyword: product.keyword || product.productName,
          targetMid: product.nvMid,
          searchUrl: this.page.url(),
          engineVersion: 'v7-simple',
          errorMessage: `Blocked after click - ${midVerification.bodyPreview?.substring(0, 100)}`,
        });

        return {
          success: false,
          version: "v7-simple",
          blocked: true,
          bridgeDetected: false,
          midClicked: true,
          error: `Blocked after click - ${midVerification.bodyPreview?.substring(0, 50)}`,
          duration: Date.now() - startTime,
        };
      }

      // MID 검증은 경고만 출력
      if (!midVerified) {
        console.log(`[v7-simple] WARNING: MID mismatch - expected ${product.nvMid}, got ${midVerification.url?.substring(0, 80)}`);
      }

      // 체류
      await this.delay(2000);

      return {
        success: true,
        version: "v7-simple",
        blocked: false,
        bridgeDetected: false,
        midClicked: true,
        duration: Date.now() - startTime,
      };

    } catch (e: any) {
      return {
        success: false,
        version: "v7-simple",
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: e.message,
        duration: Date.now() - startTime,
      };
    }
  }

  private async checkCaptcha(): Promise<boolean> {
    try {
      return await this.page!.evaluate(() => {
        const bodyText = document.body.innerText;

        // 다양한 차단 메시지 패턴
        const blockPatterns = [
          "보안 확인",
          "일시적으로 제한",
          "보안 확인을 완료해 주세요",
          "쇼핑 서비스 접속이 일시적으로 제한",
          "실제 사용자임을 확인",
          "자동입력 방지",
          "보안문자",
          "자동등록방지",
          "비정상적인 접근",
        ];

        for (const pattern of blockPatterns) {
          if (bodyText.includes(pattern)) return true;
        }

        // HTML에서 captcha 관련 요소
        if (document.querySelector('[id*="captcha"], [class*="captcha"]')) {
          return true;
        }

        return false;
      });
    } catch {
      return false;
    }
  }

  private async clickDirectSmartStore(mid: string): Promise<boolean> {
    return await this.page!.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll("a"));
      for (const link of links) {
        const href = link.href || "";
        if (href.includes("/bridge") || href.includes("cr.shopping") ||
            href.includes("cr2.shopping") || href.includes("cr3.shopping") ||
            href.includes("cr4.shopping")) {
          continue;
        }
        if (href.includes("smartstore.naver.com") && href.includes("/products/")) {
          if (href.includes(targetMid)) {
            (link as HTMLElement).click();
            return true;
          }
        }
        if (href.includes("brand.naver.com") && href.includes("/products/")) {
          if (href.includes(targetMid)) {
            (link as HTMLElement).click();
            return true;
          }
        }
      }
      return false;
    }, mid);
  }

  private async findAndClickMid(mid: string): Promise<boolean> {
    const midLink = await this.page!.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll("a"));
      for (const link of links) {
        const href = link.href || "";
        if (href.includes(targetMid) || href.includes(`nvMid=${targetMid}`)) {
          return { found: true, href };
        }
        const dataMid = link.getAttribute("data-nv-mid") || link.getAttribute("data-nvmid");
        if (dataMid === targetMid) {
          return { found: true, href };
        }
      }
      return { found: false };
    }, mid);

    console.log(`[v7-simple] findAndClickMid result:`, midLink);

    if (!midLink.found) return false;

    // Bridge URL이든 직접 링크든 그냥 클릭 (Bridge가 리다이렉트 해줌)
    if (this.isBridgeUrl(midLink.href!)) {
      console.log(`[v7-simple] Bridge URL 감지, 직접 클릭 (리다이렉트 대기)`);
    }

    // 링크 클릭
    await this.page!.evaluate((href: string) => {
      const link = Array.from(document.querySelectorAll("a")).find((a) => a.href === href);
      if (link) (link as HTMLElement).click();
    }, midLink.href!);

    return true;
  }

  /**
   * Catalog URL로 DOM 조작을 통해 이동 (Bridge URL 우회)
   */
  private async navigateViaCatalogUrl(mid: string): Promise<boolean> {
    const catalogUrl = `https://search.shopping.naver.com/catalog/${mid}`;

    const navigated = await this.page!.evaluate((url: string) => {
      try {
        const link = document.createElement("a");
        link.href = url;
        link.target = "_self";
        document.body.appendChild(link);
        link.click();
        return true;
      } catch (e: any) {
        return false;
      }
    }, catalogUrl);

    if (navigated) {
      console.log(`[v7-simple] ✅ Catalog URL로 이동: ${catalogUrl}`);
      await this.delay(3000);
    }

    return navigated;
  }

  private isBridgeUrl(url: string): boolean {
    return BRIDGE_PATTERNS.some(pattern => url.includes(pattern));
  }

  private async avoidBridgeAndRetry(mid: string): Promise<{ success: boolean; detected: boolean }> {
    const MAX_RETRY = 3;

    for (let i = 0; i < MAX_RETRY; i++) {
      await this.delay(800);
      const url = this.page!.url();

      if (this.isBridgeUrl(url)) {
        console.log(`[v7-simple] 브릿지 감지 (${i + 1}/${MAX_RETRY})`);

        await this.page!.evaluate(() => window.stop());
        try {
          await this.page!.goBack({ waitUntil: "domcontentloaded" });
        } catch {}
        await this.delay(1000);

        const direct = await this.clickDirectSmartStore(mid);
        if (direct) {
          await this.delay(1500);
          const newUrl = this.page!.url();
          if (!this.isBridgeUrl(newUrl)) {
            return { success: true, detected: true };
          }
        }

        const fallback = await this.findAndClickMid(mid);
        if (fallback) {
          await this.delay(1500);
        }
      } else {
        return { success: true, detected: false };
      }
    }

    return { success: false, detected: true };
  }

  private delay(ms: number): Promise<void> {
    return new Promise(r => setTimeout(r, ms));
  }

  /**
   * 검색 결과에서 발견된 MID 목록 수집 (실패 분석용)
   */
  private async collectFoundMids(): Promise<{ mids: string[]; count: number }> {
    if (!this.page) return { mids: [], count: 0 };

    try {
      return await this.page.evaluate(() => {
        const mids: string[] = [];
        const links = Array.from(document.querySelectorAll('a'));

        for (const link of links) {
          const href = link.href || '';

          // products/12345 패턴에서 MID 추출
          const productMatch = href.match(/products\/(\d+)/);
          if (productMatch && !mids.includes(productMatch[1])) {
            mids.push(productMatch[1]);
          }

          // catalog/12345 패턴에서 MID 추출
          const catalogMatch = href.match(/catalog\/(\d+)/);
          if (catalogMatch && !mids.includes(catalogMatch[1])) {
            mids.push(catalogMatch[1]);
          }

          // data-nv-mid 속성 체크
          const dataMid = link.getAttribute('data-nv-mid');
          if (dataMid && !mids.includes(dataMid)) {
            mids.push(dataMid);
          }

          // data-nvmid 속성 체크
          const dataNvMid = link.getAttribute('data-nvmid');
          if (dataNvMid && !mids.includes(dataNvMid)) {
            mids.push(dataNvMid);
          }
        }

        return {
          mids: mids.slice(0, 20),  // 최대 20개
          count: mids.length,
        };
      });
    } catch (error) {
      console.error('[v7-simple] collectFoundMids error:', error);
      return { mids: [], count: 0 };
    }
  }

  /**
   * 쇼핑 탭 Fallback 전략
   * - 메인 키워드 검색
   * - 여러 페이지 스캔 (1-5페이지)
   * - MID 발견 시 클릭
   */
  /**
   * 쇼핑 탭 Fallback 전략 (순위 체크 로직 재사용)
   * - findAccurateRank()로 MID가 몇 페이지에 있는지 찾기
   * - 해당 페이지로 이동
   * - MID 클릭 → 상세페이지 진입
   */
  private async tryShoppingTabFallback(product: SimpleTrafficProduct): Promise<boolean> {
    if (!this.page) return false;

    try {
      console.log("[v7-simple] Fallback: 순위 체크 시스템으로 MID 검색");

      // 1. 순위 체크 로직으로 MID 찾기 (최대 10페이지)
      const rankResult: RankResult | null = await findAccurateRank(
        this.page,
        product.keyword,
        product.nvMid,
        10  // 최대 10페이지 스캔
      );

      if (!rankResult || !rankResult.found) {
        console.log(`[v7-simple] MID ${product.nvMid} not found in shopping tab (10 pages)`);
        return false;
      }

      console.log(`[v7-simple] MID found: Page ${rankResult.page}, Rank ${rankResult.totalRank}`);

      // 2. findAccurateRank()가 완료되면 이미 해당 페이지에 머물러 있음
      // 페이지 이동 불필요, 바로 MID 클릭 시도
      console.log(`[v7-simple] Already on page ${rankResult.page}, attempting to click MID...`);

      // 페이지 로딩 안정화를 위한 짧은 대기
      await this.delay(2000);

      // 3. MID로 직접 상품 페이지 진입 (DOM 조작 방식)
      console.log(`[v7-simple] Creating catalog link for MID ${product.nvMid}...`);

      // PC search.shopping.naver.com URL 사용 (기존 shoppingDiCategory 로직)
      const catalogUrl = `https://search.shopping.naver.com/catalog/${product.nvMid}`;

      const navigated = await this.page.evaluate((url: string) => {
        try {
          const link = document.createElement("a");
          link.href = url;
          link.target = "_self";
          document.body.appendChild(link);
          link.click();
          return true;
        } catch (e: any) {
          return false;
        }
      }, catalogUrl);

      if (!navigated) {
        console.log(`[v7-simple] Failed to create/click catalog link`);
        return false;
      }

      console.log(`[v7-simple] ✅ Catalog link clicked, waiting for navigation...`);
      await this.delay(4000);

      const currentUrl = this.page.url();
      console.log(`[v7-simple] ✅ Fallback success: Final URL: ${currentUrl.substring(0, 80)}`);
      return true;

    } catch (error: any) {
      console.log(`[v7-simple] Fallback error: ${error.message}`);
      return false;
    }
  }
}
