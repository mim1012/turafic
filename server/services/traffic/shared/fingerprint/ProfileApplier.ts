import { FingerprintProfile } from "./types";
import type { Page } from "puppeteer";

export class ProfileApplier {
  static async apply(page: Page, profile: FingerprintProfile): Promise<void> {
    await page.evaluateOnNewDocument((p: FingerprintProfile) => {
      // Platform 오버라이드
      Object.defineProperty(navigator, "platform", {
        get: () => p.platform,
      });

      // Hardware 오버라이드
      Object.defineProperty(navigator, "hardwareConcurrency", {
        get: () => p.hardwareConcurrency,
      });

      Object.defineProperty(navigator, "deviceMemory", {
        get: () => p.deviceMemory,
      });

      Object.defineProperty(navigator, "maxTouchPoints", {
        get: () => p.maxTouchPoints,
      });

      // WebGL 지문 스푸핑
      const getParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function (param) {
        if (param === 37445) return p.webgl.vendor;
        if (param === 37446) return p.webgl.renderer;
        return getParameter.call(this, param);
      };
    }, profile);
  }
}
