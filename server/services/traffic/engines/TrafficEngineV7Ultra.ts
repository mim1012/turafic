/**
 * v7 Ultra-flat - 모든 로직을 execute() 메서드 안에 인라인으로
 */
import { connect } from "puppeteer-real-browser";
import type { Browser, Page } from "puppeteer-core";

export interface UltraTrafficProduct {
  nvMid: string;
  productName: string;
  keyword: string;
}

export interface UltraTrafficResult {
  success: boolean;
  version: string;
  blocked: boolean;
  bridgeDetected: boolean;
  midClicked: boolean;
  error?: string;
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

export class TrafficEngineV7Ultra {
  private browser: Browser | null = null;
  private page: Page | null = null;

  async init(): Promise<void> {
    const { browser, page } = await connect({
      headless: false,
      turnstile: true,
      fingerprint: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-blink-features=AutomationControlled",
      ],
    });
    this.browser = browser as Browser;
    this.page = page as Page;
    this.page.setDefaultTimeout(30000);
    this.page.setDefaultNavigationTimeout(30000);
  }

  async close(): Promise<void> {
    try {
      if (this.page) await this.page.close().catch(() => {});
      if (this.browser) await this.browser.close().catch(() => {});
    } catch {}
    this.browser = null;
    this.page = null;
  }

  async execute(product: UltraTrafficProduct): Promise<UltraTrafficResult> {
    if (!this.page) {
      return {
        success: false,
        version: "v7-ultra",
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: "Browser not initialized",
      };
    }

    try {
      // === 1. 네이버 모바일 메인 ===
      await this.page.goto("https://m.naver.com/", { waitUntil: "domcontentloaded" });
      await new Promise(r => setTimeout(r, 1500 + Math.random() * 1000));

      // === 2. 풀네임 검색 (인라인) ===
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
          version: "v7-ultra",
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: "Search input not found",
        };
      }

      await this.page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => {});
      await new Promise(r => setTimeout(r, 2500 + Math.random() * 1000));

      // === 3. CAPTCHA 체크 (강화) ===
      const captchaDetected = await this.page.evaluate(() => {
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

      if (captchaDetected) {
        return {
          success: false,
          version: "v7-ultra",
          blocked: true,
          bridgeDetected: false,
          midClicked: false,
          error: "통합검색 CAPTCHA",
        };
      }

      // === 4. 스크롤 (최소한만) ===
      for (let s = 0; s < 3; s++) {
        await this.page.evaluate(() => window.scrollBy(0, 400));
        await new Promise(r => setTimeout(r, 500));
      }

      // === 5. MID 클릭 (인라인) ===
      let clicked = await this.page.evaluate((targetMid: string) => {
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
      }, product.nvMid);

      if (!clicked) {
        const midLink = await this.page.evaluate((targetMid: string) => {
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
        }, product.nvMid);

        if (!midLink.found) {
          return {
            success: false,
            version: "v7-ultra",
            blocked: false,
            bridgeDetected: false,
            midClicked: false,
            error: `MID ${product.nvMid} not found`,
          };
        }

        await this.page.evaluate((href: string) => {
          const link = Array.from(document.querySelectorAll("a")).find((a) => a.href === href);
          if (link) (link as HTMLElement).click();
        }, midLink.href!);

        clicked = true;
      }

      // === 6. 페이지 로딩 대기 (브릿지 리다이렉트 자연스럽게 따라감) ===
      await new Promise(r => setTimeout(r, 5000));

      // === 7. 최종 검증 (정확한 MID 상품인지 DOM에서 확인) ===
      await new Promise(r => setTimeout(r, 1000));
      const finalUrl = this.page.url();
      const isProduct = finalUrl.includes("/catalog/") ||
                       finalUrl.includes("/products/") ||
                       finalUrl.includes("smartstore.naver.com") ||
                       finalUrl.includes("brand.naver.com");

      if (!isProduct) {
        return {
          success: false,
          version: "v7-ultra",
          blocked: false,
          bridgeDetected: false,
          midClicked: true,
          error: "Not a product page",
        };
      }

      // DOM에서 MID 확인 (URL 또는 data 속성)
      const midVerified = await this.page.evaluate((targetMid: string) => {
        // 1. URL에 MID 포함
        if (window.location.href.includes(targetMid)) return true;

        // 2. data-nv-mid 속성 확인
        const elements = document.querySelectorAll('[data-nv-mid], [data-nvmid], [data-product-id]');
        for (const el of Array.from(elements)) {
          const mid = el.getAttribute('data-nv-mid') ||
                     el.getAttribute('data-nvmid') ||
                     el.getAttribute('data-product-id');
          if (mid === targetMid) return true;
        }

        // 3. meta 태그 확인
        const metaTags = document.querySelectorAll('meta[property*="product"], meta[name*="product"]');
        for (const meta of Array.from(metaTags)) {
          const content = meta.getAttribute('content') || '';
          if (content.includes(targetMid)) return true;
        }

        return false;
      }, product.nvMid);

      if (!midVerified) {
        return {
          success: false,
          version: "v7-ultra",
          blocked: false,
          bridgeDetected: false,
          midClicked: true,
          error: `Wrong product - MID ${product.nvMid} not found in page`,
        };
      }

      // 체류
      await new Promise(r => setTimeout(r, 2000));

      return {
        success: true,
        version: "v7-ultra",
        blocked: false,
        bridgeDetected: false,
        midClicked: true,
      };

    } catch (e: any) {
      return {
        success: false,
        version: "v7-ultra",
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: e.message,
      };
    }
  }
}
