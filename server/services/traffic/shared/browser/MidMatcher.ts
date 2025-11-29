import { BrowserManager } from "./BrowserManager";

export class MidMatcher {
  constructor(private browserManager: BrowserManager) {}

  /**
   * V5 방식: 먼저 스마트스토어 직접 링크 시도 (브릿지 제외)
   */
  async clickDirectSmartStore(mid: string): Promise<boolean> {
    const page = this.browserManager.getPage();

    return await page.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll("a"));

      for (const link of links) {
        const href = link.href || "";

        // 브릿지 URL은 제외
        if (href.includes("/bridge") || href.includes("cr.shopping") ||
            href.includes("cr2.shopping") || href.includes("cr3.shopping") ||
            href.includes("cr4.shopping")) {
          continue;
        }

        // 스마트스토어 직접 링크
        if (href.includes("smartstore.naver.com") && href.includes("/products/")) {
          if (href.includes(targetMid)) {
            console.log(`[MidMatcher] Direct smartstore: ${href.substring(0, 80)}`);
            (link as HTMLElement).click();
            return true;
          }
        }

        // 브랜드스토어 직접 링크
        if (href.includes("brand.naver.com") && href.includes("/products/")) {
          if (href.includes(targetMid)) {
            console.log(`[MidMatcher] Direct brand: ${href.substring(0, 80)}`);
            (link as HTMLElement).click();
            return true;
          }
        }
      }

      return false;
    }, mid);
  }

  /**
   * V5 방식: MID 매칭 (브릿지 포함)
   */
  async clickByMid(mid: string): Promise<boolean> {
    const page = this.browserManager.getPage();

    // 1. 먼저 스마트스토어 직접 링크 시도
    const directClicked = await this.clickDirectSmartStore(mid);
    if (directClicked) {
      console.log(`[MidMatcher] ✅ Direct link clicked: ${mid}`);
      return true;
    }

    // 2. 일반 MID 매칭 (V5 방식)
    const midLink = await page.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll("a"));

      for (const link of links) {
        const href = link.href || "";

        // href에 MID 포함
        if (href.includes(targetMid) || href.includes(`nvMid=${targetMid}`)) {
          return { found: true, href };
        }

        // data 속성 체크
        const dataMid = link.getAttribute("data-nv-mid") || link.getAttribute("data-nvmid");
        if (dataMid === targetMid) {
          return { found: true, href };
        }
      }

      return { found: false };
    }, mid);

    if (!midLink.found) {
      console.warn(`[MidMatcher] ❌ MID not found: ${mid}`);
      return false;
    }

    // 클릭
    await page.evaluate((href: string) => {
      const link = Array.from(document.querySelectorAll("a")).find((a) => a.href === href);
      if (link) {
        console.log(`[MidMatcher] Clicking MID link: ${href.substring(0, 80)}`);
        (link as HTMLElement).click();
      }
    }, midLink.href!);

    console.log(`[MidMatcher] ✅ MID link clicked: ${mid}`);
    return true;
  }

  private delay(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }
}
