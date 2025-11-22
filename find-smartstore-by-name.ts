/**
 * 상품명으로 스마트스토어 URL 찾기
 *
 * 상품명 검색 → 스마트스토어 링크 추출 → 트래픽 실행
 *
 * 사용법:
 *   npx tsx find-smartstore-by-name.ts "상품명" [count] [dwell]
 */

import "dotenv/config";
import { connect } from "puppeteer-real-browser";

async function findAndRunTraffic(productName: string, count: number, dwellTime: number) {
  console.log(`\n상품명으로 스마트스토어 찾기`);
  console.log(`상품명: ${productName}`);
  console.log(`횟수: ${count} | 체류: ${dwellTime}ms\n`);

  const { browser, page } = await connect({
    headless: false,
    turnstile: true,
    args: ["--disable-blink-features=AutomationControlled"],
  });

  let smartstoreUrl: string | null = null;
  let success = 0;
  let failed = 0;
  const startTime = Date.now();

  try {
    // 1. 네이버 메인
    console.log("1. 네이버 메인...");
    await page.goto("https://www.naver.com/", { waitUntil: "domcontentloaded" });
    await new Promise(r => setTimeout(r, 1500));

    // 2. 상품명으로 통합검색
    console.log("2. 상품명 검색...");
    await page.goto(
      `https://search.naver.com/search.naver?query=${encodeURIComponent(productName)}`,
      { waitUntil: "domcontentloaded" }
    );
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

    if (!smartstoreUrl) {
      // 쇼핑 탭에서 찾기
      console.log("4. 쇼핑 탭에서 찾기...");
      const shopTab = await page.$('a[href*="search.shopping.naver.com"]');
      if (shopTab) {
        await shopTab.click();
        await new Promise(r => setTimeout(r, 3000));

        smartstoreUrl = await page.evaluate(() => {
          const links = Array.from(document.querySelectorAll("a"));
          const link = links.find(a =>
            a.href.includes("smartstore.naver.com") &&
            a.href.includes("/products/")
          );
          return link?.href || null;
        });
      }
    }

    if (!smartstoreUrl) {
      console.log("\n❌ 스마트스토어 URL을 찾을 수 없습니다");
      await browser.close();
      process.exit(1);
    }

    console.log(`\n✅ 스마트스토어 URL 발견:`);
    console.log(smartstoreUrl);
    console.log("\n트래픽 실행 시작...\n");

    // 트래픽 실행
    for (let i = 0; i < count; i++) {
      const iterStart = Date.now();

      try {
        // 네이버 메인
        await page.goto("https://www.naver.com/", { waitUntil: "domcontentloaded" });
        await new Promise(r => setTimeout(r, 1000));

        // 스마트스토어 직접 접근
        await page.goto(smartstoreUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
        await new Promise(r => setTimeout(r, 2000));

        const currentUrl = page.url();
        const title = await page.title();

        if (currentUrl.includes("smartstore.naver.com") && !title.includes("오류")) {
          success++;

          // 체류
          if (dwellTime > 0) {
            await page.evaluate(() => window.scrollTo(0, 300));
            await new Promise(r => setTimeout(r, dwellTime));
          }

          const elapsed = ((Date.now() - iterStart) / 1000).toFixed(1);
          console.log(`  ${i + 1}/${count} ✅ 성공 (${elapsed}초)`);
        } else {
          failed++;
          console.log(`  ${i + 1}/${count} ❌ 실패`);
        }
      } catch (e: any) {
        failed++;
        console.log(`  ${i + 1}/${count} ❌ 에러`);
      }
    }
  } catch (e: any) {
    console.log("에러:", e.message);
  }

  await browser.close();

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);
  const perTime = count > 0 ? (parseFloat(totalTime) / count).toFixed(1) : "0";

  console.log("\n====================================");
  console.log(`URL: ${smartstoreUrl}`);
  console.log(`결과: ${success}/${count} (${count > 0 ? ((success/count)*100).toFixed(1) : 0}%)`);
  console.log(`시간: ${totalTime}초 (${perTime}초/회)`);
  console.log("====================================");

  process.exit(0);
}

// CLI
const args = process.argv.slice(2);
if (args.length < 1) {
  console.log("사용법: npx tsx find-smartstore-by-name.ts \"상품명\" [count] [dwell]");
  console.log("");
  console.log("예시:");
  console.log('  npx tsx find-smartstore-by-name.ts "아이폰 케이스" 10 5000');
  process.exit(1);
}

const productName = args[0];
const count = parseInt(args[1]) || 5;
const dwellTime = parseInt(args[2]) || 5000;

findAndRunTraffic(productName, count, dwellTime);
