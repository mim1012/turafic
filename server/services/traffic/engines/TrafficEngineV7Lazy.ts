/**
 * v7 Lazy Engine - Test if lazy initialization avoids detection
 */
import { FingerprintProfile } from "../shared/fingerprint/types";
import { BrowserManager } from "../shared/browser/BrowserManager";
import { NavigationOps } from "../shared/browser/NavigationOps";
import { InputOps } from "../shared/browser/InputOps";
import { BlockDetector } from "../shared/detection/BlockDetector";
import { BridgeDetector } from "../shared/detection/BridgeDetector";
import { MidMatcher } from "../shared/browser/MidMatcher";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v7Profile from "../profiles/v7-samsung-s23.json";

export interface LazyTrafficProduct {
  nvMid: string;
  productName: string;
  keyword: string;
}

export interface LazyTrafficResult {
  success: boolean;
  version: string;
  blocked: boolean;
  bridgeDetected: boolean;
  midClicked: boolean;
  error?: string;
}

export class TrafficEngineV7Lazy {
  private profile: FingerprintProfile;

  // NULL 초기화 - 브라우저 연결 후에만 생성
  private browserManager: BrowserManager | null = null;
  private navigationOps: NavigationOps | null = null;
  private inputOps: InputOps | null = null;
  private blockDetector: BlockDetector | null = null;
  private bridgeDetector: BridgeDetector | null = null;
  private midMatcher: MidMatcher | null = null;

  constructor() {
    this.profile = ProfileLoader.load(v7Profile);
  }

  async init(): Promise<void> {
    // 1. 먼저 브라우저 연결
    this.browserManager = new BrowserManager(this.profile);
    await this.browserManager.init();

    // 2. 브라우저 연결 후 헬퍼 클래스들 생성
    this.navigationOps = new NavigationOps(this.browserManager);
    this.inputOps = new InputOps(this.browserManager);
    this.blockDetector = new BlockDetector(this.browserManager);
    this.bridgeDetector = new BridgeDetector(this.browserManager);
    this.midMatcher = new MidMatcher(this.browserManager);
  }

  async execute(product: LazyTrafficProduct): Promise<LazyTrafficResult> {
    if (!this.browserManager || !this.navigationOps || !this.inputOps ||
        !this.blockDetector || !this.bridgeDetector || !this.midMatcher) {
      return {
        success: false,
        version: "v7-lazy",
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: "Not initialized",
      };
    }

    try {
      const page = this.browserManager.getPage();

      // 1. 네이버 홈
      await this.navigationOps.gotoNaverHome();
      await this.delay(1500 + Math.random() * 1000);

      // 2. 검색
      await this.inputOps.typeSearch(product.productName);
      await this.delay(2500 + Math.random() * 1000);

      // 3. 차단 체크
      const blocked = await this.blockDetector.isBlocked();
      if (blocked) {
        return {
          success: false,
          version: "v7-lazy",
          blocked: true,
          bridgeDetected: false,
          midClicked: false,
          error: "CAPTCHA detected",
        };
      }

      // 4. 스크롤
      for (let i = 0; i < 5; i++) {
        await page.evaluate(() => window.scrollBy(0, 400));
        await this.delay(500);
      }

      // 5. MID 클릭
      const midClicked = await this.midMatcher.clickByMid(product.nvMid);
      if (!midClicked) {
        return {
          success: false,
          version: "v7-lazy",
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: "MID not found",
        };
      }

      await this.delay(1500);

      // 6. 브릿지 우회
      const currentUrl = page.url();
      const bridgeDetected = this.bridgeDetector.isBridgeUrl(currentUrl);

      if (bridgeDetected) {
        const avoided = await this.bridgeDetector.avoidIfDetected(product.nvMid);
        if (!avoided) {
          return {
            success: false,
            version: "v7-lazy",
            blocked: false,
            bridgeDetected: true,
            midClicked: true,
            error: "Bridge avoidance failed",
          };
        }
      }

      // 7. 체류
      await this.delay(5000 + Math.random() * 1000);

      return {
        success: true,
        version: "v7-lazy",
        blocked: false,
        bridgeDetected,
        midClicked: true,
      };

    } catch (e: any) {
      return {
        success: false,
        version: "v7-lazy",
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: e.message,
      };
    }
  }

  async close(): Promise<void> {
    if (this.browserManager) {
      await this.browserManager.close();
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(r => setTimeout(r, ms));
  }
}
