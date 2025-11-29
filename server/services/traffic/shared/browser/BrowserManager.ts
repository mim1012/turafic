import { connect } from "puppeteer-real-browser";
import { FingerprintProfile } from "../fingerprint/types";
import { ProfileApplier } from "../fingerprint/ProfileApplier";

export class BrowserManager {
  private browser: any = null;
  private page: any = null;

  constructor(
    private profile: FingerprintProfile,
    private userDataDir?: string  // 프로필 디렉토리 (선택)
  ) {}

  async init(): Promise<void> {
    // PBR 연결 옵션
    const connectOptions: any = {
      headless: false,
      turnstile: true,
      fingerprint: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--start-maximized",  // 창 최대화 - screenRatio 정상화
      ],
    };

    // userDataDir이 있으면 프로필 디렉토리 사용
    if (this.userDataDir) {
      connectOptions.userDataDir = this.userDataDir;
      console.log(`[BrowserManager] Using profile: ${this.userDataDir}`);
    }

    const connection = await connect(connectOptions);

    this.browser = connection.browser;
    this.page = connection.page;

    this.page.setDefaultTimeout(30000);
    this.page.setDefaultNavigationTimeout(30000);
  }

  getPage(): any {
    if (!this.page) throw new Error("Browser not initialized");
    return this.page;
  }

  setPage(page: any): void {
    this.page = page;
  }

  getBrowser(): any {
    if (!this.browser) throw new Error("Browser not initialized");
    return this.browser;
  }

  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
    }
  }
}
