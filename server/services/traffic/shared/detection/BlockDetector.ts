import { BrowserManager } from "../browser/BrowserManager";

export class BlockDetector {
  constructor(private browserManager: BrowserManager) {}

  async isBlocked(): Promise<boolean> {
    try {
      const page = this.browserManager.getPage();

      const blocked = await page.evaluate(() => {
        const bodyText = document.body.innerText;
        const html = document.documentElement.innerHTML;

        // 1. 일시적 제한 메시지
        if (bodyText.includes("일시적으로 제한")) {
          console.log("[BlockDetector] Detected: 일시적으로 제한");
          return true;
        }

        // 2. 캡챠 감지 (영수증 캡챠)
        if (bodyText.includes("자동입력 방지") ||
            bodyText.includes("보안문자") ||
            bodyText.includes("자동등록방지") ||
            html.includes("captcha") ||
            html.includes("Captcha") ||
            html.includes("CAPTCHA")) {
          console.log("[BlockDetector] Detected: CAPTCHA");
          return true;
        }

        // 3. 캡챠 이미지/폼 요소 존재 확인
        const captchaElements = [
          document.querySelector('img[src*="captcha"]'),
          document.querySelector('[id*="captcha"]'),
          document.querySelector('[class*="captcha"]'),
          document.querySelector('input[name*="captcha"]'),
        ];

        if (captchaElements.some(el => el !== null)) {
          console.log("[BlockDetector] Detected: CAPTCHA element found");
          return true;
        }

        // 4. 로봇 확인 메시지
        if (bodyText.includes("로봇이 아닙니다") ||
            bodyText.includes("robot") ||
            bodyText.includes("Robot")) {
          console.log("[BlockDetector] Detected: Robot verification");
          return true;
        }

        return false;
      });

      if (blocked) {
        console.log("[BlockDetector] ⚠️ Page is blocked or has CAPTCHA");
      }

      return blocked;
    } catch (error) {
      console.error("[BlockDetector] Error checking block status:", error);
      return false;
    }
  }
}
