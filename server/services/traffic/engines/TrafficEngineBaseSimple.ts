/**
 * Base Simple Engine - 공통 로직을 담은 추상 베이스 클래스
 * 각 버전(v7-v20)은 이 클래스를 상속받아 프로필만 다르게 적용
 */
import { connect } from "puppeteer-real-browser";
import type { Browser, Page } from "puppeteer-core";
import { findAccurateRank, type RankResult } from '../../../../rank-check/accurate-rank-checker';
import { ProfileApplier } from '../shared/fingerprint/ProfileApplier';
import type { FingerprintProfile } from '../shared/fingerprint/types';
import { ReceiptCaptchaSolver } from '../shared/captcha/ReceiptCaptchaSolver';

export interface SimpleTrafficProduct {
  nvMid: string;
  productName: string;
  keyword: string;
}

export interface SimpleTrafficResult {
  success: boolean;
  version: string;
  blocked: boolean;
  bridgeDetected: boolean;
  midClicked: boolean;
  error?: string;
  duration?: number;
}

export type SearchMode = '통검' | '쇼검';

const BRIDGE_PATTERNS = [
  "cr.shopping.naver.com/bridge",
  "cr2.shopping.naver.com/bridge",
  "cr3.shopping.naver.com/bridge",
  "cr4.shopping.naver.com/bridge",
  "shopping.naver.com/bridge",
  "naver.com/v2/bridge",
  "/bridge?"
];

export abstract class TrafficEngineBaseSimple {
  protected browser: Browser | null = null;
  protected page: Page | null = null;
  protected captchaSolver: ReceiptCaptchaSolver;

  // 각 버전에서 구현해야 할 추상 속성
  protected abstract get profile(): FingerprintProfile;
  protected abstract get versionString(): string;

  constructor() {
    this.captchaSolver = new ReceiptCaptchaSolver();
  }

  async init(): Promise<void> {
    // 프로필 적용 제거 - PRB 기본값 사용 (봇 탐지 회피)
    // 모바일 프로필(viewport, WebGL, navigator 조작)이 오히려 봇 탐지를 트리거함
    const { browser, page } = await connect({
      headless: false,
      turnstile: true,
      // fingerprint, args, ProfileApplier 모두 제거 → PRB가 알아서 진짜 브라우저처럼 동작
    });

    this.browser = browser as Browser;
    this.page = page as Page;

    // ===== 네이버 최적화 뷰포트 강제 적용 (2025.12 실전 최적값) =====
    // PRB 기본값 800x600은 봇 탐지 위험, 1366x768이 CAPTCHA 발생률 최저
    await this.page.setViewport({
      width: 1366,
      height: 768,
      deviceScaleFactor: 1,
      isMobile: false,
      hasTouch: false,
    });

    // ===== 네이버 통검+쇼검 모두 통과하는 완벽 지문 동기화 (2025.12 실전 최적화) =====
    await this.page.evaluateOnNewDocument(() => {
      // 1. CDC 디버그 완전 제거 (Chrome DevTools Protocol 흔적)
      delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Array;
      delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Object;
      delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Promise;

      // 2. 외부/내부 창 크기 완벽 동기화 (네이버 쇼핑 필수)
      Object.defineProperty(window, 'outerWidth',  { value: 1366, configurable: false });
      Object.defineProperty(window, 'outerHeight', { value: 768, configurable: false });
      Object.defineProperty(window, 'innerWidth',  { value: 1366, configurable: false });
      Object.defineProperty(window, 'innerHeight', { value: 768, configurable: false });

      // 3. screen 완벽 동기화
      Object.defineProperties(screen, {
        availWidth:  { value: 1366, configurable: false },
        availHeight: { value: 728, configurable: false },  // 윈도우 작업표시줄 고려 -40px
        width:       { value: 1366, configurable: false },
        height:      { value: 768, configurable: false },
      });

      // 4. User-Agent + Client Hints 완벽 한국 1위 조합 (Chrome 130, Win10/11)
      const realUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
      Object.defineProperty(navigator, 'userAgent', { value: realUA, configurable: false });
      Object.defineProperty(navigator, 'platform', { value: 'Win32' });

      // SEC-CH-UA 강제 주입 (네이버 쇼핑이 이거까지 체크함)
      Object.defineProperty(navigator, 'userAgentData', {
        value: {
          brands: [
            { brand: "Google Chrome", version: "130" },
            { brand: "Chromium", version: "130" },
            { brand: "Not=A?Brand", version: "99" }
          ],
          platform: "Windows",
          mobile: false,
        },
        configurable: false
      });

      // 5. WebGL Renderer 한국 1위 (Intel UHD Graphics 630/620)
      const getParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(parameter: number) {
        if (parameter === 37445) return "Intel Inc.";                    // UNMASKED_VENDOR_WEBGL
        if (parameter === 37446) return "Intel(R) UHD Graphics 630";     // UNMASKED_RENDERER_WEBGL
        return getParameter.call(this, parameter);
      };
    });

    this.page.setDefaultTimeout(30000);
    this.page.setDefaultNavigationTimeout(30000);

    console.log(`[${this.versionString}] Browser initialized (1366x768 perfect match, no stealth)`);
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
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: "Browser not initialized",
      };
    }

    try {
      // 1. 네이버 모바일 메인
      await this.page.goto("https://m.naver.com/", { waitUntil: "domcontentloaded" });
      await this.delay(500);

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
          version: this.versionString,
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: "Search input not found",
        };
      }

      await this.page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => {});
      await this.delay(1000);

      // 3. CAPTCHA 체크
      const captchaDetected = await this.checkCaptcha();
      if (captchaDetected) {
        return {
          success: false,
          version: this.versionString,
          blocked: true,
          bridgeDetected: false,
          midClicked: false,
          error: "통합검색 CAPTCHA",
          duration: Date.now() - startTime,
        };
      }

      // 4. 스크롤 (최소한만)
      for (let s = 0; s < 2; s++) {
        await this.page.evaluate(() => window.scrollBy(0, 400));
        await this.delay(200);
      }

      // 5. MID 클릭
      let clicked = await this.clickDirectSmartStore(product.nvMid);
      console.log(`[${this.versionString}] clickDirectSmartStore: ${clicked}`);

      if (!clicked) {
        clicked = await this.findAndClickMid(product.nvMid);
        console.log(`[${this.versionString}] findAndClickMid: ${clicked}`);
      }

      // 6. Fallback: 쇼핑 탭 전략
      let usedFallback = false;
      if (!clicked) {
        console.log(`[${this.versionString}] 1차 시도 실패 → Fallback 전략 시작`);
        clicked = await this.tryShoppingTabFallback(product);
        usedFallback = true;
        console.log(`[${this.versionString}] Fallback result: ${clicked}`);
      }

      if (!clicked) {
        return {
          success: false,
          version: this.versionString,
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: `MID ${product.nvMid} not found (both strategies failed)`,
          duration: Date.now() - startTime,
        };
      }

      // 7. 페이지 로딩 대기 (최적화: 10초 목표)
      if (!usedFallback) {
        try {
          await this.page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 8000 });
        } catch {}

        await this.delay(1500);

        let finalUrl = this.page.url();
        console.log(`[${this.versionString}] Current URL after navigation: ${finalUrl.substring(0, 100)}`);

        if (this.isBridgeUrl(finalUrl)) {
          console.log(`[${this.versionString}] Bridge URL detected, waiting for redirect...`);
          for (let i = 0; i < 5; i++) {
            await this.delay(500);
            finalUrl = this.page.url();
            if (!this.isBridgeUrl(finalUrl)) {
              console.log(`[${this.versionString}] Redirect completed to: ${finalUrl.substring(0, 80)}`);
              break;
            }
          }
        }
      }

      // 8. 최종 검증
      await this.delay(500);
      const finalUrl = this.page.url();
      console.log(`[${this.versionString}] Final URL for validation: ${finalUrl.substring(0, 100)}`);
      const isProduct = finalUrl.includes("/catalog/") ||
                       finalUrl.includes("/products/") ||
                       finalUrl.includes("smartstore.naver.com") ||
                       finalUrl.includes("brand.naver.com");

      if (!isProduct) {
        return {
          success: false,
          version: this.versionString,
          blocked: false,
          bridgeDetected: false,
          midClicked: true,
          error: "Not a product page",
          duration: Date.now() - startTime,
        };
      }

      // DOM에서 MID 확인
      const midVerification = await this.page.evaluate((targetMid: string) => {
        const url = window.location.href;
        if (url.includes(targetMid)) return { found: true, method: 'URL', url };

        const elements = document.querySelectorAll('[data-nv-mid], [data-nvmid], [data-product-id]');
        for (const el of Array.from(elements)) {
          const mid = el.getAttribute('data-nv-mid') ||
                     el.getAttribute('data-nvmid') ||
                     el.getAttribute('data-product-id');
          if (mid === targetMid) return { found: true, method: 'data-attr', url };
        }

        const metaTags = document.querySelectorAll('meta[property*="product"], meta[name*="product"]');
        for (const meta of Array.from(metaTags)) {
          const content = meta.getAttribute('content') || '';
          if (content.includes(targetMid)) return { found: true, method: 'meta', url };
        }

        const bodyText = document.body.innerText;
        const isBlocked = bodyText.includes("보안 확인") ||
                         bodyText.includes("일시적으로 제한") ||
                         bodyText.includes("비정상적인 접근");

        return { found: false, url, bodyPreview: bodyText.substring(0, 200), isBlocked };
      }, product.nvMid);

      if (midVerification.isBlocked) {
        return {
          success: false,
          version: this.versionString,
          blocked: true,
          bridgeDetected: false,
          midClicked: true,
          error: `Blocked after click - ${midVerification.bodyPreview?.substring(0, 50)}`,
          duration: Date.now() - startTime,
        };
      }

      if (!midVerification.found) {
        console.log(`[${this.versionString}] WARNING: MID mismatch - expected ${product.nvMid}, got ${midVerification.url?.substring(0, 80)}`);
      }

      await this.delay(2000);

      return {
        success: true,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: true,
        duration: Date.now() - startTime,
      };

    } catch (e: any) {
      return {
        success: false,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: e.message,
        duration: Date.now() - startTime,
      };
    }
  }

  protected async checkCaptcha(): Promise<boolean> {
    try {
      return await this.page!.evaluate(() => {
        const bodyText = document.body.innerText;
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

        if (document.querySelector('[id*="captcha"], [class*="captcha"]')) {
          return true;
        }

        return false;
      });
    } catch {
      return false;
    }
  }

  /**
   * CAPTCHA 감지 + 자동 해결 시도
   * @returns true if CAPTCHA was present and solved, false otherwise
   */
  protected async checkAndSolveCaptcha(): Promise<{
    hadCaptcha: boolean;
    solved: boolean;
  }> {
    if (!this.page) return { hadCaptcha: false, solved: false };

    const hasCaptcha = await this.checkCaptcha();
    if (!hasCaptcha) {
      return { hadCaptcha: false, solved: false };
    }

    console.log(`[${this.versionString}] CAPTCHA 감지! 자동 해결 시도...`);

    try {
      const solved = await this.captchaSolver.solve(this.page);
      if (solved) {
        console.log(`[${this.versionString}] CAPTCHA 해결 성공!`);
        return { hadCaptcha: true, solved: true };
      } else {
        console.log(`[${this.versionString}] CAPTCHA 해결 실패`);
        return { hadCaptcha: true, solved: false };
      }
    } catch (error) {
      console.error(`[${this.versionString}] CAPTCHA 해결 중 에러:`, error);
      return { hadCaptcha: true, solved: false };
    }
  }

  protected async clickDirectSmartStore(mid: string): Promise<boolean> {
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

  protected async findAndClickMid(mid: string): Promise<boolean> {
    // v7-simple과 동일한 방식: MID 링크를 찾고, Bridge URL이면 catalog로 우회
    const midLink = await this.page!.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll("a"));

      // 1순위: smartstore/brand 직접 링크 (가장 좋음)
      for (const link of links) {
        const href = link.href || "";
        // Bridge URL 건너뛰기 (나중에 처리)
        if (href.includes('/bridge') || href.includes('cr.shopping') ||
            href.includes('cr2.shopping') || href.includes('cr3.shopping') ||
            href.includes('cr4.shopping')) {
          continue;
        }
        // smartstore 또는 brand 직접 링크
        if ((href.includes('smartstore.naver.com/') || href.includes('brand.naver.com/')) &&
            href.includes('/products/')) {
          if (href.includes(targetMid)) {
            return { found: true, href, type: 'smartstore-direct' };
          }
          const dataMid = link.getAttribute("data-nv-mid") || link.getAttribute("data-nvmid");
          if (dataMid === targetMid) {
            return { found: true, href, type: 'smartstore-data' };
          }
        }
      }

      // 2순위: MID가 포함된 모든 링크 (Bridge URL 포함!)
      // Bridge URL이면 catalog로 우회할 것임
      for (const link of links) {
        const href = link.href || "";
        if (href.includes(targetMid) || href.includes(`nvMid=${targetMid}`)) {
          return { found: true, href, type: 'mid-in-url' };
        }
        const dataMid = link.getAttribute("data-nv-mid") || link.getAttribute("data-nvmid");
        if (dataMid === targetMid) {
          return { found: true, href, type: 'data-attr' };
        }
      }

      return { found: false, href: '', type: '' };
    }, mid);

    console.log(`[${this.versionString}] findAndClickMid result:`, midLink);

    if (!midLink.found) return false;

    // Bridge URL이든 아니든 직접 클릭 (catalog URL 우회는 순위에 영향 없음!)
    // CAPTCHA가 뜨면 Claude Vision으로 해결
    const isBridge = this.isBridgeUrl(midLink.href!);
    if (isBridge) {
      console.log(`[${this.versionString}] Bridge URL 감지 → 직접 클릭 (트래킹을 위해)`);
    }

    await this.page!.evaluate((href: string) => {
      const link = Array.from(document.querySelectorAll("a")).find((a) => a.href === href);
      if (link) (link as HTMLElement).click();
    }, midLink.href!);

    // Bridge URL 클릭 후 CAPTCHA 체크 및 해결 (최적화: 10초 목표)
    if (isBridge) {
      await this.delay(1500);
      const captchaResult = await this.checkAndSolveCaptcha();
      if (captchaResult.hadCaptcha && !captchaResult.solved) {
        console.log(`[${this.versionString}] Bridge URL CAPTCHA 해결 실패`);
        // CAPTCHA 해결 실패해도 일단 진행 (이후 validateFinalPage에서 처리)
      }
    }

    return true;
  }

  protected async navigateViaCatalogUrl(mid: string): Promise<boolean> {
    const catalogUrl = `https://search.shopping.naver.com/catalog/${mid}`;

    const navigated = await this.page!.evaluate((url: string) => {
      try {
        const link = document.createElement("a");
        link.href = url;
        link.target = "_self";
        document.body.appendChild(link);
        link.click();
        return true;
      } catch {
        return false;
      }
    }, catalogUrl);

    if (navigated) {
      console.log(`[${this.versionString}] ✅ Catalog URL로 이동: ${catalogUrl}`);
      await this.delay(1500);
    }

    return navigated;
  }

  protected isBridgeUrl(url: string): boolean {
    return BRIDGE_PATTERNS.some(pattern => url.includes(pattern));
  }

  protected async tryShoppingTabFallback(product: SimpleTrafficProduct): Promise<boolean> {
    if (!this.page) return false;

    try {
      console.log(`[${this.versionString}] Fallback: 순위 체크 시스템으로 MID 검색`);

      const rankResult: RankResult | null = await findAccurateRank(
        this.page,
        product.keyword,
        product.nvMid,
        10
      );

      if (!rankResult || !rankResult.found) {
        console.log(`[${this.versionString}] MID ${product.nvMid} not found in shopping tab (10 pages)`);
        return false;
      }

      console.log(`[${this.versionString}] MID found: Page ${rankResult.page}, Rank ${rankResult.totalRank}`);

      await this.delay(2000);

      const catalogUrl = `https://search.shopping.naver.com/catalog/${product.nvMid}`;

      const navigated = await this.page.evaluate((url: string) => {
        try {
          const link = document.createElement("a");
          link.href = url;
          link.target = "_self";
          document.body.appendChild(link);
          link.click();
          return true;
        } catch {
          return false;
        }
      }, catalogUrl);

      if (!navigated) {
        console.log(`[${this.versionString}] Failed to create/click catalog link`);
        return false;
      }

      console.log(`[${this.versionString}] ✅ Catalog link clicked, waiting for navigation...`);
      await this.delay(4000);

      const currentUrl = this.page.url();
      console.log(`[${this.versionString}] ✅ Fallback success: Final URL: ${currentUrl.substring(0, 80)}`);
      return true;

    } catch (error: any) {
      console.log(`[${this.versionString}] Fallback error: ${error.message}`);
      return false;
    }
  }

  protected delay(ms: number): Promise<void> {
    return new Promise(r => setTimeout(r, ms));
  }

  /**
   * 통검/쇼검 모드 분기 실행
   * - 통검: 통합검색 → smartstore 직접 클릭
   * - 쇼검: 쇼핑탭 → 마우스 클릭 → 새 탭 (봇 탐지 회피)
   */
  async executeFullname(
    product: SimpleTrafficProduct,
    mode: SearchMode = '통검'
  ): Promise<SimpleTrafficResult> {
    const startTime = Date.now();

    if (!this.page) {
      return {
        success: false,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: "Browser not initialized",
      };
    }

    try {
      // 1. 네이버 메인 접속 (모드별 다른 URL 사용)
      // - 통검: 모바일 (m.naver.com) - 기존 방식, 잘 작동함
      // - 쇼검: PC (www.naver.com) - msearch.shopping은 봇 탐지 심함, search.shopping은 통과
      const naverUrl = mode === '쇼검' ? "https://www.naver.com/" : "https://m.naver.com/";
      await this.page.goto(naverUrl, { waitUntil: "domcontentloaded" });
      await this.delay(500);

      // 2. 풀네임 검색 (PC/모바일 공통 셀렉터)
      const searchQuery = product.productName.substring(0, 50);

      const searchFound = await this.page.evaluate((searchTerm: string) => {
        // PC: #query, 모바일: input[type="search"], input[name="query"]
        const input = document.querySelector('#query, input[type="search"], input[name="query"]') as HTMLInputElement;
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
          version: this.versionString,
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: "Search input not found",
        };
      }

      await this.page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 10000 }).catch(() => {});
      await this.delay(1500);

      // 3. 통합검색 CAPTCHA 체크
      const captchaDetected = await this.checkCaptcha();
      if (captchaDetected) {
        return {
          success: false,
          version: this.versionString,
          blocked: true,
          bridgeDetected: false,
          midClicked: false,
          error: "통합검색 CAPTCHA",
          duration: Date.now() - startTime,
        };
      }

      // =============================================
      // 모드별 분기
      // =============================================
      if (mode === '통검') {
        return await this.executeUnifiedSearchMode(product, startTime);
      } else {
        return await this.executeShoppingTabMode(product, startTime);
      }

    } catch (e: any) {
      return {
        success: false,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: e.message,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * 통검 모드: 통합검색 결과에서 smartstore 링크 직접 클릭
   */
  protected async executeUnifiedSearchMode(
    product: SimpleTrafficProduct,
    startTime: number
  ): Promise<SimpleTrafficResult> {
    if (!this.page) throw new Error("Page not initialized");

    // 스크롤 (최소한만)
    for (let s = 0; s < 2; s++) {
      await this.page.evaluate(() => window.scrollBy(0, 400));
      await this.delay(500);
    }

    // MID 클릭
    let clicked = await this.clickDirectSmartStore(product.nvMid);
    console.log(`[${this.versionString}] 통검 clickDirectSmartStore: ${clicked}`);

    if (!clicked) {
      clicked = await this.findAndClickMid(product.nvMid);
      console.log(`[${this.versionString}] 통검 findAndClickMid: ${clicked}`);
    }

    if (!clicked) {
      return {
        success: false,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: `MID ${product.nvMid} not found (통검)`,
        duration: Date.now() - startTime,
      };
    }

    // 페이지 로딩 대기
    try {
      await this.page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 10000 });
    } catch {}

    await this.delay(1500);

    // Bridge URL 대기
    let finalUrl = this.page.url();
    if (this.isBridgeUrl(finalUrl)) {
      console.log(`[${this.versionString}] Bridge URL detected, waiting...`);
      for (let i = 0; i < 3; i++) {
        await this.delay(800);
        finalUrl = this.page.url();
        if (!this.isBridgeUrl(finalUrl)) break;
      }
    }

    // 최종 검증
    return await this.validateFinalPage(product.nvMid, startTime);
  }

  /**
   * 쇼검 모드: 새 탭 방식 (실제 사용자 행동 모방, 10초 이내)
   *
   * 흐름: 통합검색 → 쇼핑탭 클릭 (새 탭) → MID 상품 클릭 (새 탭) → 스크롤
   */
  protected async executeShoppingTabMode(
    product: SimpleTrafficProduct,
    startTime: number
  ): Promise<SimpleTrafficResult> {
    if (!this.page || !this.browser) throw new Error("Browser not initialized");

    // 1. 쇼핑탭 찾기
    const shoppingTab = await this.page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('a'));
      for (const link of links) {
        if ((link.textContent || '').trim() === '쇼핑' && link.href.includes('shopping')) {
          const rect = link.getBoundingClientRect();
          return { found: true, x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
        }
      }
      return { found: false, x: 0, y: 0 };
    });

    if (!shoppingTab.found) {
      return {
        success: false,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: "쇼핑탭 not found",
        duration: Date.now() - startTime,
      };
    }

    // 2. 쇼핑탭 클릭 (새 탭으로 열림)
    let pagesBefore = (await this.browser.pages()).length;
    console.log(`[${this.versionString}] 쇼검: 쇼핑탭 클릭 (${Math.round(shoppingTab.x)}, ${Math.round(shoppingTab.y)})`);
    await this.page.mouse.click(shoppingTab.x, shoppingTab.y);
    await this.delay(1500);

    // 3. 새 탭 전환
    let pages = await this.browser.pages();
    if (pages.length <= pagesBefore) {
      return {
        success: false,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: "쇼핑탭 새 탭 없음",
        duration: Date.now() - startTime,
      };
    }

    const shoppingPage = pages[pages.length - 1] as Page;
    await shoppingPage.bringToFront();
    await shoppingPage.setViewport({ width: 1366, height: 768, deviceScaleFactor: 1, isMobile: false, hasTouch: false });
    await this.delay(1000);

    console.log(`[${this.versionString}] 쇼검: Shopping URL: ${shoppingPage.url().substring(0, 60)}`);

    // 4. 쇼핑 페이지 CAPTCHA 체크
    const captcha1 = await shoppingPage.evaluate(() => document.body.innerText.includes("보안 확인"));
    if (captcha1) {
      await shoppingPage.close();
      return {
        success: false,
        version: this.versionString,
        blocked: true,
        bridgeDetected: false,
        midClicked: false,
        error: "쇼핑검색 CAPTCHA",
        duration: Date.now() - startTime,
      };
    }

    // 5. MID 상품 찾기 + 클릭
    let midFound = false;
    for (let scroll = 0; scroll < 5 && !midFound; scroll++) {
      const midInfo = await shoppingPage.evaluate((mid: string) => {
        const links = Array.from(document.querySelectorAll('a'));
        for (const link of links) {
          const href = link.href || '';
          if (href.includes(`nv_mid=${mid}`) || href.includes(mid)) {
            const rect = link.getBoundingClientRect();
            if (rect.width > 0 && rect.height > 0 && rect.top > 0 && rect.top < window.innerHeight) {
              return { found: true, x: rect.left + rect.width / 2, y: rect.top + rect.height / 2, href };
            }
          }
        }
        return { found: false, x: 0, y: 0, href: '' };
      }, product.nvMid);

      if (midInfo.found) {
        console.log(`[${this.versionString}] 쇼검: MID 발견! 클릭...`);
        pagesBefore = (await this.browser.pages()).length;
        await shoppingPage.mouse.click(midInfo.x, midInfo.y);
        midFound = true;
      } else {
        await shoppingPage.evaluate(() => window.scrollBy(0, 400));
        await this.delay(200);
      }
    }

    if (!midFound) {
      await shoppingPage.close();
      return {
        success: false,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: `MID not found (쇼검)`,
        duration: Date.now() - startTime,
      };
    }

    await this.delay(1500);

    // 6. 상품 페이지 새 탭
    pages = await this.browser.pages();
    if (pages.length <= pagesBefore) {
      // 새 탭 없으면 같은 탭에서 이동한 것
      const currentUrl = shoppingPage.url();
      console.log(`[${this.versionString}] 쇼검: 같은 탭 이동 - ${currentUrl.substring(0, 60)}`);

      const isProduct = currentUrl.includes("/products/") || currentUrl.includes("smartstore.naver.com");
      if (isProduct) {
        // 스크롤
        for (let s = 0; s < 3; s++) {
          await shoppingPage.evaluate(() => window.scrollBy(0, 300));
          await this.delay(300);
        }
        return {
          success: true,
          version: this.versionString,
          blocked: false,
          bridgeDetected: false,
          midClicked: true,
          duration: Date.now() - startTime,
        };
      }
    }

    const productPage = pages[pages.length - 1] as Page;
    await productPage.bringToFront();
    await productPage.setViewport({ width: 1366, height: 768, deviceScaleFactor: 1, isMobile: false, hasTouch: false });
    await this.delay(1000);

    const productUrl = productPage.url();
    console.log(`[${this.versionString}] 쇼검: 상품 페이지: ${productUrl.substring(0, 60)}`);

    // 7. 상품 페이지 상태 체크
    const status = await productPage.evaluate(() => {
      const bodyText = document.body.innerText;
      const hasError = bodyText.includes("존재하지 않는") || bodyText.includes("보안 확인") ||
                      bodyText.includes("판매종료") || bodyText.includes("삭제된") ||
                      bodyText.includes("일시적으로 제한");
      return { hasError, preview: bodyText.substring(0, 200) };
    });

    if (status.hasError) {
      console.log(`[${this.versionString}] 쇼검: 오류 - ${status.preview.substring(0, 80)}`);
      await productPage.close();
      await shoppingPage.close();
      return {
        success: false,
        version: this.versionString,
        blocked: status.preview.includes("보안") || status.preview.includes("제한"),
        bridgeDetected: false,
        midClicked: true,
        error: status.preview.substring(0, 50),
        duration: Date.now() - startTime,
      };
    }

    // 8. 스크롤 (체류 시뮬레이션)
    console.log(`[${this.versionString}] 쇼검: 스크롤...`);
    for (let s = 0; s < 2; s++) {
      await productPage.evaluate(() => window.scrollBy(0, 300));
      await this.delay(200);
    }

    // 9. 탭 정리
    await productPage.close();
    await shoppingPage.close();

    return {
      success: true,
      version: this.versionString,
      blocked: false,
      bridgeDetected: false,
      midClicked: true,
      duration: Date.now() - startTime,
    };
  }

  /**
   * 최종 페이지 검증 (공통)
   */
  protected async validateFinalPage(
    nvMid: string,
    startTime: number
  ): Promise<SimpleTrafficResult> {
    if (!this.page) throw new Error("Page not initialized");

    await this.delay(300);
    const finalUrl = this.page.url();
    console.log(`[${this.versionString}] Final URL: ${finalUrl.substring(0, 100)}`);

    const isProduct = finalUrl.includes("/catalog/") ||
                     finalUrl.includes("/products/") ||
                     finalUrl.includes("smartstore.naver.com") ||
                     finalUrl.includes("brand.naver.com");

    if (!isProduct) {
      return {
        success: false,
        version: this.versionString,
        blocked: false,
        bridgeDetected: false,
        midClicked: true,
        error: "Not a product page",
        duration: Date.now() - startTime,
      };
    }

    // CAPTCHA 체크 (상세 메시지 로깅)
    const captchaCheck = await this.page.evaluate(() => {
      const bodyText = document.body?.innerText || '';
      const patterns = [
        '보안 확인을 완료해 주세요',
        '보안 확인',
        '일시적으로 제한',
        '비정상적인 접근',
        '자동입력 방지',
        '실제 사용자임을 확인'
      ];
      for (const pattern of patterns) {
        if (bodyText.includes(pattern)) {
          return { blocked: true, pattern, preview: bodyText.substring(0, 200) };
        }
      }
      return { blocked: false, pattern: '', preview: '' };
    });

    if (captchaCheck.blocked) {
      console.log(`[${this.versionString}] CAPTCHA detected: "${captchaCheck.pattern}"`);
      console.log(`[${this.versionString}] Page preview: ${captchaCheck.preview.substring(0, 100)}`);

      // 영수증 CAPTCHA 자동 해결 시도
      console.log(`[${this.versionString}] 영수증 CAPTCHA 자동 해결 시도...`);
      try {
        const solved = await this.captchaSolver.solve(this.page);
        if (solved) {
          console.log(`[${this.versionString}] ✅ CAPTCHA 해결 성공! 페이지 재검증...`);
          await this.delay(2000);

          // 해결 후 다시 검증
          const recheck = await this.page.evaluate(() => {
            const bodyText = document.body?.innerText || '';
            return !bodyText.includes('보안 확인') &&
                   !bodyText.includes('영수증') &&
                   !bodyText.includes('[?]');
          });

          if (recheck) {
            return {
              success: true,
              version: this.versionString,
              blocked: false,
              bridgeDetected: false,
              midClicked: true,
              duration: Date.now() - startTime,
            };
          }
        }
        console.log(`[${this.versionString}] CAPTCHA 해결 실패`);
      } catch (e: any) {
        console.log(`[${this.versionString}] CAPTCHA 해결 에러: ${e.message}`);
      }

      return {
        success: false,
        version: this.versionString,
        blocked: true,
        bridgeDetected: false,
        midClicked: true,
        error: `상품페이지 CAPTCHA (${captchaCheck.pattern})`,
        duration: Date.now() - startTime,
      };
    }

    await this.delay(500);

    return {
      success: true,
      version: this.versionString,
      blocked: false,
      bridgeDetected: false,
      midClicked: true,
      duration: Date.now() - startTime,
    };
  }
}
