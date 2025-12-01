/**
 * 프로필 적용 없이 테스트 (PC 기본)
 */
import * as dotenv from "dotenv";
dotenv.config();

import { connect } from "puppeteer-real-browser";

const product = {
  nvMid: "86683606603",
  productName: "디월트 충전 전기톱 20V 체인톱 200mm 무선 전동 DCMPS520N 베어툴",
};

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  console.log("🧪 프로필 없이 테스트 (PC 기본)\n");

  // 프로필 적용 없이 연결
  const { browser, page } = await connect({
    headless: false,
    turnstile: true,
    // fingerprint: true,  // 프로필 적용 안 함
  });

  try {
    // PC 네이버
    console.log("[1] PC 네이버 메인...");
    await page.goto("https://www.naver.com/", { waitUntil: "domcontentloaded" });
    await delay(2000);

    // 검색
    console.log("[2] 풀네임 검색...");
    await page.evaluate((term: string) => {
      const input = document.querySelector('input[name="query"]') as HTMLInputElement;
      if (input) {
        input.value = term;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const form = input.closest('form');
        if (form) form.submit();
      }
    }, product.productName.substring(0, 50));

    await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => {});
    await delay(3000);

    // 스크롤
    for (let s = 0; s < 3; s++) {
      await page.evaluate(() => window.scrollBy(0, 400));
      await delay(500);
    }

    // MID 클릭
    console.log("[3] MID 클릭...");
    const clicked = await page.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll("a"));
      for (const link of links) {
        const href = link.href || "";
        if (href.includes(targetMid)) {
          (link as HTMLElement).click();
          return { clicked: true, href };
        }
      }
      return { clicked: false, href: "" };
    }, product.nvMid);

    console.log(`  클릭: ${clicked.clicked}`);
    console.log(`  URL: ${clicked.href.substring(0, 80)}`);

    if (!clicked.clicked) {
      console.log("❌ 클릭 실패");
      await browser.close();
      return;
    }

    // 리다이렉트 대기
    try {
      await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 15000 });
    } catch {}
    await delay(3000);

    const finalUrl = page.url();
    const pageTitle = await page.title();

    console.log("\n📊 결과:");
    console.log(`  URL: ${finalUrl}`);
    console.log(`  Title: ${pageTitle.substring(0, 60)}`);

    const bodyText = await page.evaluate(() => document.body.innerText.substring(0, 300));
    if (bodyText.includes("보안") || bodyText.includes("제한")) {
      console.log("❌ 차단됨");
    } else {
      console.log("✅ 성공!");
    }

    await delay(3000);
  } finally {
    await browser.close();
  }
}

main().catch(console.error);
