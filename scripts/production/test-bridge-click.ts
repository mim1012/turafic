/**
 * Bridge URL 직접 클릭 테스트
 * - catalog URL 우회 대신 Bridge URL을 그대로 클릭
 * - 네이버가 리다이렉트해주는 대로 따라감
 */
import * as dotenv from "dotenv";
dotenv.config();

import { connect } from "puppeteer-real-browser";

// 테스트할 상품
const product = {
  nvMid: "86683606603",
  productName: "디월트 충전 전기톱 20V 체인톱 200mm 무선 전동 DCMPS520N 베어툴",
  keyword: "전기톱",
};

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  console.log("🧪 Bridge URL 직접 클릭 테스트\n");
  console.log("📦 상품:", product.productName.substring(0, 50));
  console.log("🔗 MID:", product.nvMid);
  console.log("");

  const { browser, page } = await connect({
    headless: false,
    turnstile: true,
    fingerprint: true,
  });

  try {
    // 1. 네이버 모바일 메인
    console.log("[1] 네이버 모바일 메인...");
    await page.goto("https://m.naver.com/", { waitUntil: "domcontentloaded" });
    await delay(2000);

    // 2. 풀네임 검색
    console.log("[2] 풀네임 검색...");
    const searchQuery = product.productName.substring(0, 50);

    await page.evaluate((term: string) => {
      const input = document.querySelector('input[type="search"], input[name="query"]') as HTMLInputElement;
      if (input) {
        input.value = term;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const form = input.closest('form');
        if (form) form.submit();
      }
    }, searchQuery);

    await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => {});
    await delay(3000);

    // 3. 스크롤
    console.log("[3] 스크롤...");
    for (let s = 0; s < 3; s++) {
      await page.evaluate(() => window.scrollBy(0, 400));
      await delay(500);
    }

    // 4. MID 포함된 링크 찾기 (Bridge든 뭐든)
    console.log("[4] MID 포함 링크 찾아서 직접 클릭...");

    const clickResult = await page.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll("a"));

      // 1차: smartstore 직접 링크 (MID 포함)
      for (const link of links) {
        const href = link.href || "";
        if (href.includes("smartstore.naver.com") && href.includes("/products/") && href.includes(targetMid)) {
          console.log("Found smartstore direct link:", href);
          (link as HTMLElement).click();
          return { clicked: true, type: "smartstore", href };
        }
      }

      // 2차: MID 포함된 아무 링크 (Bridge 포함)
      for (const link of links) {
        const href = link.href || "";
        if (href.includes(targetMid)) {
          console.log("Found MID link:", href);
          (link as HTMLElement).click();
          return { clicked: true, type: "mid-link", href };
        }
        const dataMid = link.getAttribute("data-nv-mid") || link.getAttribute("data-nvmid");
        if (dataMid === targetMid) {
          console.log("Found data-mid link:", href);
          (link as HTMLElement).click();
          return { clicked: true, type: "data-mid", href };
        }
      }

      return { clicked: false, type: "none", href: "" };
    }, product.nvMid);

    console.log(`  클릭 결과: ${clickResult.clicked ? "성공" : "실패"}`);
    console.log(`  타입: ${clickResult.type}`);
    console.log(`  URL: ${clickResult.href.substring(0, 80)}...`);

    if (!clickResult.clicked) {
      console.log("\n❌ MID 링크를 찾지 못함");
      await browser.close();
      return;
    }

    // 5. 리다이렉트 대기 (Bridge URL인 경우 자동 리다이렉트)
    console.log("\n[5] 리다이렉트 대기...");

    // 첫 번째 navigation 대기
    try {
      await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 15000 });
    } catch {}

    await delay(2000);
    let currentUrl = page.url();
    console.log(`  현재 URL: ${currentUrl.substring(0, 80)}`);

    // Bridge URL이면 추가 대기 (리다이렉트 진행 중)
    if (currentUrl.includes("/bridge")) {
      console.log("  Bridge 리다이렉트 진행 중, 추가 대기...");
      for (let i = 0; i < 10; i++) {
        await delay(1000);
        currentUrl = page.url();
        console.log(`  [${i+1}] URL: ${currentUrl.substring(0, 60)}`);
        if (!currentUrl.includes("/bridge")) {
          break;
        }
      }
    }

    // 6. 최종 결과 확인
    await delay(2000);
    const finalUrl = page.url();
    const pageTitle = await page.title();

    console.log("\n📊 최종 결과:");
    console.log(`  URL: ${finalUrl}`);
    console.log(`  Title: ${pageTitle.substring(0, 60)}`);

    // 차단 체크
    const bodyText = await page.evaluate(() => document.body.innerText.substring(0, 500));

    if (bodyText.includes("보안 확인") || bodyText.includes("일시적으로 제한") || bodyText.includes("비정상적인 접근")) {
      console.log("\n❌ 차단됨!");
      console.log(bodyText.substring(0, 150));
    } else if (finalUrl.includes("smartstore") || finalUrl.includes("brand.naver")) {
      console.log("\n✅ 스마트스토어 상세페이지 진입 성공!");

      // MID 확인
      if (finalUrl.includes(product.nvMid)) {
        console.log("✅ MID 일치!");
      } else {
        console.log("⚠️ MID 불일치 - 다른 상품 페이지일 수 있음");
      }
    } else if (finalUrl.includes("catalog") || finalUrl.includes("search.shopping")) {
      console.log("\n⚠️ 쇼핑 카탈로그 페이지");
    } else {
      console.log("\n⚠️ 알 수 없는 상태");
      console.log("Body preview:", bodyText.substring(0, 200));
    }

    await delay(3000);
  } finally {
    await browser.close();
  }
}

main().catch(console.error);
