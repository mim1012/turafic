import { BrowserManager } from "./BrowserManager";

export class InputOps {
  constructor(private browserManager: BrowserManager) {}

  async typeSearch(keyword: string): Promise<void> {
    const page = this.browserManager.getPage();

    // V5 방식: page.evaluate()로 직접 값 설정 및 form submit
    const searchSuccess = await page.evaluate((searchTerm: string) => {
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
    }, keyword);

    if (!searchSuccess) {
      throw new Error("Search input not found");
    }

    // 네비게이션 대기
    try {
      await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 20000 });
    } catch (error) {
      // 타임아웃은 무시 (페이지가 이미 로드되었을 수 있음)
    }

    await this.delay(2500 + Math.random() * 1000);
  }

  private naturalDelay(baseMs: number): Promise<void> {
    const randomMs = baseMs + Math.random() * 500; // ±500ms 랜덤
    return new Promise((r) => setTimeout(r, randomMs));
  }

  private delay(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }
}
