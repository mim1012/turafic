/**
 * MID로 스마트스토어 URL 찾기
 *
 * 통합검색에서 MID로 검색하여 스마트스토어 링크 추출
 *
 * 사용법:
 *   npx tsx get-smartstore-url.ts <mid>
 */

import "dotenv/config";
import { connect } from "puppeteer-real-browser";

async function getSmartStoreUrl(mid: string) {
  console.log(`\nMID: ${mid} → 스마트스토어 URL 찾기\n`);

  const { browser, page } = await connect({
    headless: false,
    turnstile: true,
  });

  let smartstoreUrl: string | null = null;

  try {
    // 1. 네이버 메인
    console.log("1. 네이버 메인...");
    await page.goto("https://www.naver.com/", { waitUntil: "domcontentloaded" });
    await new Promise(r => setTimeout(r, 1500));

    // 2. MID로 통합검색
    console.log("2. MID로 통합검색...");
    await page.goto(`https://search.naver.com/search.naver?query=${mid}`, {
      waitUntil: "domcontentloaded",
    });
    await new Promise(r => setTimeout(r, 2500));

    // 3. 스마트스토어 링크 찾기
    console.log("3. 스마트스토어 링크 찾기...");
    smartstoreUrl = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll("a"));
      const smartstoreLink = links.find(a =>
        a.href.includes("smartstore.naver.com") &&
        a.href.includes("/products/")
      );
      return smartstoreLink?.href || null;
    });

    if (smartstoreUrl) {
      console.log(`\n✅ 스마트스토어 URL 발견:`);
      console.log(smartstoreUrl);
    } else {
      // 쇼핑 탭 클릭해서 다시 시도
      console.log("4. 쇼핑 탭에서 찾기...");
      const shopTab = await page.$('a[href*="search.shopping.naver.com"]');
      if (shopTab) {
        await shopTab.click();
        await new Promise(r => setTimeout(r, 3000));

        // 카탈로그 페이지에서 스마트스토어 링크 찾기
        smartstoreUrl = await page.evaluate(() => {
          const links = Array.from(document.querySelectorAll("a"));
          const link = links.find(a =>
            a.href.includes("smartstore.naver.com") &&
            a.href.includes("/products/")
          );
          return link?.href || null;
        });

        if (smartstoreUrl) {
          console.log(`\n✅ 스마트스토어 URL 발견 (쇼핑탭):`);
          console.log(smartstoreUrl);
        }
      }

      if (!smartstoreUrl) {
        console.log("\n❌ 스마트스토어 URL을 찾을 수 없습니다");
        console.log("   - 카탈로그 상품일 수 있음 (여러 판매처)");
        console.log("   - 스마트스토어가 아닌 외부몰 상품일 수 있음");
      }
    }
  } catch (e: any) {
    console.log("에러:", e.message);
  }

  await browser.close();

  if (smartstoreUrl) {
    console.log("\n트래픽 실행:");
    console.log(`npx tsx run-smartstore-traffic.ts "${smartstoreUrl}" 10 5000`);
  }

  process.exit(0);
}

// CLI
const args = process.argv.slice(2);
if (args.length < 1) {
  console.log("사용법: npx tsx get-smartstore-url.ts <mid>");
  console.log("");
  console.log("예시:");
  console.log("  npx tsx get-smartstore-url.ts 80917167574");
  process.exit(1);
}

getSmartStoreUrl(args[0]);
