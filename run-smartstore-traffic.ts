/**
 * 스마트스토어 URL 직접 트래픽
 *
 * 쇼핑 검색이 차단되어도 스마트스토어 직접 접근은 작동함
 *
 * 사용법:
 *   npx tsx run-smartstore-traffic.ts <smartstore_url> [count] [dwell]
 *
 * 예시:
 *   npx tsx run-smartstore-traffic.ts "https://smartstore.naver.com/xxx/products/123" 10 5000
 */

import "dotenv/config";
import { connect } from "puppeteer-real-browser";

async function runSmartstoreTraffic(url: string, count: number, dwellTime: number) {
  console.log(`\n스마트스토어 트래픽 실행`);
  console.log(`URL: ${url}`);
  console.log(`횟수: ${count} | 체류: ${dwellTime}ms\n`);

  const { browser, page } = await connect({
    headless: false,
    turnstile: true,
    args: ["--disable-blink-features=AutomationControlled"],
  });

  let success = 0;
  let failed = 0;
  const startTime = Date.now();

  try {
    // 1. 네이버 메인으로 세션 초기화
    console.log("세션 초기화...");
    await page.goto("https://www.naver.com/", { waitUntil: "domcontentloaded" });
    await new Promise(r => setTimeout(r, 1500));

    for (let i = 0; i < count; i++) {
      const iterStart = Date.now();

      try {
        // 스마트스토어 직접 접근
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
        await new Promise(r => setTimeout(r, 2000));

        const currentUrl = page.url();
        const title = await page.title();

        // 성공 여부 확인
        if (currentUrl.includes("smartstore.naver.com") && !title.includes("오류")) {
          success++;

          // 체류 시간
          if (dwellTime > 0) {
            // 스크롤 동작
            await page.evaluate(() => {
              window.scrollTo(0, 300);
            });
            await new Promise(r => setTimeout(r, dwellTime));
          }

          const elapsed = ((Date.now() - iterStart) / 1000).toFixed(1);
          console.log(`  ${i + 1}/${count} ✅ 성공 (${elapsed}초)`);
        } else {
          failed++;
          console.log(`  ${i + 1}/${count} ❌ 실패 - ${title}`);
        }

        // 네이버 메인으로 복귀
        await page.goto("https://www.naver.com/", { waitUntil: "domcontentloaded" });
        await new Promise(r => setTimeout(r, 1000));

      } catch (e: any) {
        failed++;
        console.log(`  ${i + 1}/${count} ❌ 에러 - ${e.message.slice(0, 50)}`);
      }
    }
  } catch (e: any) {
    console.log("초기화 에러:", e.message);
  }

  await browser.close();

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);
  const perTime = (parseFloat(totalTime) / count).toFixed(1);

  console.log("\n====================================");
  console.log(`결과: ${success}/${count} (${((success/count)*100).toFixed(1)}%)`);
  console.log(`시간: ${totalTime}초 (${perTime}초/회)`);
  console.log("====================================");

  process.exit(0);
}

// CLI
const args = process.argv.slice(2);
if (args.length < 1) {
  console.log("사용법: npx tsx run-smartstore-traffic.ts <smartstore_url> [count] [dwell]");
  console.log("");
  console.log("예시:");
  console.log('  npx tsx run-smartstore-traffic.ts "https://smartstore.naver.com/xxx/products/123" 10 5000');
  process.exit(1);
}

const url = args[0];
const count = parseInt(args[1]) || 5;
const dwellTime = parseInt(args[2]) || 5000;

if (!url.includes("smartstore.naver.com")) {
  console.log("❌ 스마트스토어 URL이 아닙니다");
  process.exit(1);
}

runSmartstoreTraffic(url, count, dwellTime);
