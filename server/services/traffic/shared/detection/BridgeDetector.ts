import { BrowserManager } from "../browser/BrowserManager";
import { MidMatcher } from "../browser/MidMatcher";

const BRIDGE_PATTERNS = [
  "cr.shopping.naver.com/bridge",
  "cr2.shopping.naver.com/bridge",
  "cr3.shopping.naver.com/bridge",
  "cr4.shopping.naver.com/bridge",
  "shopping.naver.com/bridge",
  "naver.com/v2/bridge",
  "/bridge?"
];

export class BridgeDetector {
  private midMatcher: MidMatcher;

  constructor(private browserManager: BrowserManager) {
    this.midMatcher = new MidMatcher(browserManager);
  }

  isBridgeUrl(url: string): boolean {
    return BRIDGE_PATTERNS.some((pattern) => url.includes(pattern));
  }

  /**
   * V5 방식: 브릿지 우회 및 재시도 (최대 3회)
   */
  async avoidIfDetected(mid: string): Promise<boolean> {
    const MAX_RETRY = 3;
    const page = this.browserManager.getPage();

    for (let i = 0; i < MAX_RETRY; i++) {
      await this.delay(800);

      const url = page.url();

      if (this.isBridgeUrl(url)) {
        console.log(`[BridgeDetector] 브릿지 감지 (${i + 1}/${MAX_RETRY}): ${url.substring(0, 50)}...`);

        // 페이지 로딩 중지
        await page.evaluate(() => {
          window.stop();
        });

        // 뒤로가기
        try {
          await page.goBack({ waitUntil: "domcontentloaded" });
        } catch {}

        await this.delay(1000);

        // 1. 먼저 스마트스토어 직접 링크 시도
        const direct = await this.midMatcher.clickDirectSmartStore(mid);
        if (direct) {
          await this.delay(1500);
          const newUrl = page.url();
          if (!this.isBridgeUrl(newUrl)) {
            console.log(`[BridgeDetector] ✅ 브릿지 우회 성공 (직접 링크)`);
            return true;
          }
        }

        // 2. 일반 MID 매칭 시도
        const fallback = await this.midMatcher.clickByMid(mid);
        if (fallback) {
          await this.delay(1500);
        }
      } else {
        console.log(`[BridgeDetector] ✅ 브릿지 없음`);
        return true;
      }
    }

    console.warn(`[BridgeDetector] ❌ 브릿지 우회 실패 (${MAX_RETRY}회 시도)`);
    return false;
  }

  private delay(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }
}
