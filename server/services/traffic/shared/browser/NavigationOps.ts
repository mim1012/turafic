import { BrowserManager } from "./BrowserManager";

export class NavigationOps {
  constructor(private browserManager: BrowserManager) {}

  async goto(url: string): Promise<void> {
    const page = this.browserManager.getPage();
    await page.goto(url, { waitUntil: "domcontentloaded" });
  }

  async gotoNaverHome(): Promise<void> {
    await this.goto("https://m.naver.com/");
    await this.delay(2000);
  }

  async delay(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }
}
