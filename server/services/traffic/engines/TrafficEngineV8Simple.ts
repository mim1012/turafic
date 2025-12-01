/**
 * v8 Simple Engine - iPhone 15 Pro 프로필 적용
 */
import { connect } from "puppeteer-real-browser";
import type { Browser, Page } from "puppeteer-core";
import { ProfileApplier } from '../shared/fingerprint/ProfileApplier';
import v8Profile from '../profiles/v8-iphone-15-pro.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

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

const BRIDGE_PATTERNS = [
  "cr.shopping.naver.com/bridge",
  "cr2.shopping.naver.com/bridge",
  "cr3.shopping.naver.com/bridge",
  "cr4.shopping.naver.com/bridge",
  "shopping.naver.com/bridge",
  "naver.com/v2/bridge",
  "/bridge?"
];

const profile = v8Profile as FingerprintProfile;

export class TrafficEngineV8Simple {
  private browser: Browser | null = null;
  private page: Page | null = null;

  async init(): Promise<void> {
    const { browser, page } = await connect({
      headless: false,
      turnstile: true,
      fingerprint: true,
      args: ProfileApplier.getConnectArgs(profile),
    });

    this.browser = browser as Browser;
    this.page = page as Page;

    await ProfileApplier.apply(this.page as any, profile);

    this.page.setDefaultTimeout(30000);
    this.page.setDefaultNavigationTimeout(30000);

    console.log(`[v8-simple] Profile applied: ${profile.deviceName}`);
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
        version: "v8-simple",
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
          version: "v8-simple",
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
        return {
          success: false,
          version: "v8-simple",
          blocked: true,
          bridgeDetected: false,
          midClicked: false,
          error: "통합검색 CAPTCHA",
          duration: Date.now() - startTime,
        };
      }

      // 4. 스크롤 (3회, v7 검증된 패턴)
      for (let s = 0; s < 3; s++) {
        await this.page.evaluate(() => window.scrollBy(0, 400));
        await this.delay(500);
      }

      // 5. MID 클릭
      let clicked = await this.clickDirectSmartStore(product.nvMid);
      console.log(`[v8-simple] clickDirectSmartStore: ${clicked}`);

      if (!clicked) {
        clicked = await this.findAndClickMid(product.nvMid);
        console.log(`[v8-simple] findAndClickMid: ${clicked}`);
      }

      if (!clicked) {
        return {
          success: false,
          version: "v8-simple",
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: `MID ${product.nvMid} not found`,
          duration: Date.now() - startTime,
        };
      }

      // 6. 페이지 로딩 대기 (브릿지 리다이렉트)
      try {
        await this.page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 10000 });
      } catch {}

      await this.delay(3000);

      // 7. 최종 검증
      await this.delay(1000);
      const finalUrl = this.page.url();
      const isProduct = finalUrl.includes("/catalog/") ||
                       finalUrl.includes("/products/") ||
                       finalUrl.includes("smartstore.naver.com") ||
                       finalUrl.includes("brand.naver.com");

      if (!isProduct) {
        return {
          success: false,
          version: "v8-simple",
          blocked: false,
          bridgeDetected: false,
          midClicked: true,
          error: "Not a product page",
          duration: Date.now() - startTime,
        };
      }

      // MID 검증 (완화 버전)
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
        return {
          success: false,
          version: "v8-simple",
          blocked: true,
          bridgeDetected: false,
          midClicked: true,
          error: `Blocked after click - ${midVerification.bodyPreview?.substring(0, 50)}`,
          duration: Date.now() - startTime,
        };
      }

      // MID 검증은 경고만 출력
      if (!midVerified) {
        console.log(`[v8-simple] WARNING: MID mismatch - expected ${product.nvMid}, got ${midVerification.url?.substring(0, 80)}`);
      }

      // 체류
      await this.delay(2000);

      return {
        success: true,
        version: "v8-simple",
        blocked: false,
        bridgeDetected: false,
        midClicked: true,
        duration: Date.now() - startTime,
      };

    } catch (e: any) {
      return {
        success: false,
        version: "v8-simple",
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

    console.log(`[v8-simple] findAndClickMid result:`, midLink);

    if (!midLink.found) return false;

    await this.page!.evaluate((href: string) => {
      const link = Array.from(document.querySelectorAll("a")).find((a) => a.href === href);
      if (link) (link as HTMLElement).click();
    }, midLink.href!);

    return true;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(r => setTimeout(r, ms));
  }
}
