/**
 * Naver Shopping Bot
 *
 * Automated rank checking bot for Naver Shopping
 * Supports both Puppeteer (headless browser) and HTTP-only modes
 *
 * Based on IMPLEMENTATION_PLAN.md Phase 5
 *
 * NOTE: Puppeteer is an optional dependency. Install with:
 *   pnpm add puppeteer
 */

import { Task, Campaign } from "../../drizzle/schema";
import { KeywordItem } from "./zeroApiClient";
import { generateHeaders, buildSearchUrl, calculateDelay } from "./httpEngine";

// Optional Puppeteer import
let puppeteer: any = null;
try {
  puppeteer = require("puppeteer");
} catch (e) {
  console.warn("Puppeteer not installed. Using HTTP-only mode.");
}

type Browser = any;
type Page = any;

/**
 * Naver Shopping Bot
 *
 * Performs rank checking with realistic browser behavior
 */
export class NaverShoppingBot {
  private browser: Browser | null = null;
  private page: Page | null = null;
  private usePuppeteer: boolean = false;

  constructor(usePuppeteer: boolean = false) {
    this.usePuppeteer = usePuppeteer && puppeteer !== null;
  }

  /**
   * Initialize bot (Puppeteer mode only)
   */
  async init(): Promise<void> {
    if (!this.usePuppeteer || !puppeteer) {
      console.log("NaverBot initialized in HTTP-only mode");
      return;
    }

    this.browser = await puppeteer.launch({
      headless: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-accelerated-2d-canvas",
        "--disable-gpu",
        "--window-size=360,640",
      ],
    });

    this.page = await this.browser.newPage();

    // Mobile viewport
    await this.page.setViewport({
      width: 360,
      height: 640,
      isMobile: true,
      hasTouch: true,
    });

    console.log("NaverBot initialized with Puppeteer");
  }

  /**
   * Check product rank for given campaign
   *
   * @param task Task with 10 variables
   * @param campaign Campaign details
   * @param keywordData Keyword data from Zero API
   * @returns Rank (1-400) or -1 if not found
   */
  async checkRank(
    task: Task,
    campaign: Campaign,
    keywordData: KeywordItem
  ): Promise<number> {
    if (this.usePuppeteer && this.page) {
      return this.checkRankWithPuppeteer(task, campaign, keywordData);
    } else {
      return this.checkRankWithHttp(task, campaign, keywordData);
    }
  }

  /**
   * Check rank using Puppeteer (full browser emulation)
   */
  private async checkRankWithPuppeteer(
    task: Task,
    campaign: Campaign,
    keywordData: KeywordItem
  ): Promise<number> {
    if (!this.page) throw new Error("Puppeteer page not initialized");

    // Set headers
    const headers = generateHeaders(task, keywordData);
    await this.page.setExtraHTTPHeaders(headers);

    // Set User-Agent
    if (task.uaChange === 1 && keywordData.user_agent) {
      await this.page.setUserAgent(keywordData.user_agent);
    }

    // Image loading control
    if (task.useImage === 0) {
      await this.page.setRequestInterception(true);
      this.page.on("request", (req: any) => {
        if (req.resourceType() === "image") {
          req.abort();
        } else {
          req.continue();
        }
      });
    }

    // Search pages
    let currentPage = 1;
    const maxPages = 10;

    while (currentPage <= maxPages) {
      const searchUrl = buildSearchUrl(campaign.keyword, currentPage);
      await this.page.goto(searchUrl, { waitUntil: "networkidle2" });

      // Delay based on lowDelay variable
      await this.delay(calculateDelay(task.lowDelay));

      // Find product rank
      const rank = await this.findProductRankInPage(campaign.productId, currentPage);

      if (rank > 0) {
        return rank;
      }

      // Check if next page exists
      const hasNext = await this.hasNextPage();
      if (!hasNext) {
        break;
      }

      currentPage++;
    }

    return -1; // Not found
  }

  /**
   * Check rank using HTTP requests (Android APK method)
   *
   * This simulates what the Android APK does
   */
  private async checkRankWithHttp(
    task: Task,
    campaign: Campaign,
    keywordData: KeywordItem
  ): Promise<number> {
    // Note: In production, this would use the actual Android APK
    // For now, return a mock result
    console.log(`HTTP-only rank check for: ${campaign.keyword}`);
    console.log(`Product ID: ${campaign.productId}`);
    console.log(`Variables: uaChange=${task.uaChange}, shopHome=${task.shopHome}`);

    // Mock rank (would be replaced by actual Android APK call)
    return -1;
  }

  /**
   * Find product rank within current page (Puppeteer)
   */
  private async findProductRankInPage(
    productId: string,
    currentPage: number
  ): Promise<number> {
    if (!this.page) return -1;

    const position = await this.page.evaluate((pid: string) => {
      // Multiple selector patterns for product ID
      const selectors = [
        `[data-product-id="${pid}"]`,
        `[data-nv-mid="${pid}"]`,
        `a[href*="nvMid=${pid}"]`,
        `a[href*="mid=${pid}"]`,
      ];

      // Try each selector
      for (const selector of selectors) {
        const productNode = document.querySelector(selector);

        if (productNode) {
          // Find all product items
          const allProducts = document.querySelectorAll(
            ".product_item, .product__item, [class*='product']"
          );

          // Find position
          for (let i = 0; i < allProducts.length; i++) {
            if (allProducts[i].contains(productNode)) {
              return i + 1; // 1-based index
            }
          }
        }
      }

      return -1;
    }, productId);

    if (position > 0) {
      // Calculate absolute rank across pages
      return (currentPage - 1) * 40 + position;
    }

    return -1;
  }

  /**
   * Check if next page button exists (Puppeteer)
   */
  private async hasNextPage(): Promise<boolean> {
    if (!this.page) return false;

    return this.page.evaluate(() => {
      const nextButton = document.querySelector(
        ".paginator_btn_next:not(.paginator_disabled), .pagination_next:not(.disabled)"
      );
      return nextButton !== null;
    });
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Close browser (Puppeteer mode only)
   */
  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
    }
  }
}

/**
 * Create bot instance
 *
 * @param usePuppeteer Whether to use Puppeteer (requires installation)
 * @returns NaverShoppingBot instance
 */
export async function createNaverBot(
  usePuppeteer: boolean = false
): Promise<NaverShoppingBot> {
  const bot = new NaverShoppingBot(usePuppeteer);
  await bot.init();
  return bot;
}
