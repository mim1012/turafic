/**
 * 태그 버전(v2.0.0)과 동일한 로직으로 테스트
 * - smartstore 직접 링크 클릭 우선
 * - MID 매칭 필수
 */
import * as dotenv from "dotenv";
dotenv.config();

import { connect } from "puppeteer-real-browser";

// 테스트할 상품 (slot_naver에서 가져온 것)
const product = {
  nvMid: "86683606603",
  productName: "디월트 충전 전기톱 20V 체인톱 200mm 무선 전동 DCMPS520N 베어툴",
  keyword: "전기톱",
};

const BRIDGE_PATTERNS = [
  "cr.shopping.naver.com/bridge",
  "cr2.shopping.naver.com/bridge",
  "cr3.shopping.naver.com/bridge",
  "cr4.shopping.naver.com/bridge",
  "shopping.naver.com/bridge",
  "naver.com/v2/bridge",
  "/bridge?"
];

function isBridgeUrl(url: string): boolean {
  return BRIDGE_PATTERNS.some(p => url.includes(p));
}

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  console.log("🧪 태그 버전 로직 직접 테스트\n");
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

    // 4. 페이지의 모든 링크 분석
    console.log("\n[4] 페이지 링크 분석...");
    const linkAnalysis = await page.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll('a'));
      const result = {
        smartstoreWithMid: [] as string[],
        smartstoreWithoutMid: [] as string[],
        bridgeUrls: [] as string[],
        otherWithMid: [] as string[],
      };

      for (const link of links) {
        const href = link.href || '';

        if (href.includes('smartstore.naver.com') && href.includes('/products/')) {
          if (href.includes(targetMid)) {
            result.smartstoreWithMid.push(href.substring(0, 100));
          } else {
            result.smartstoreWithoutMid.push(href.substring(0, 100));
          }
        } else if (href.includes('/bridge')) {
          if (href.includes(targetMid)) {
            result.bridgeUrls.push(href.substring(0, 100));
          }
        } else if (href.includes(targetMid)) {
          result.otherWithMid.push(href.substring(0, 100));
        }
      }

      return result;
    }, product.nvMid);

    console.log("\n📊 링크 분석 결과:");
    console.log(`  ✅ smartstore + MID 포함: ${linkAnalysis.smartstoreWithMid.length}개`);
    linkAnalysis.smartstoreWithMid.forEach(url => console.log(`     ${url}`));

    console.log(`  ⚠️ smartstore (MID 없음): ${linkAnalysis.smartstoreWithoutMid.length}개`);
    linkAnalysis.smartstoreWithoutMid.slice(0, 3).forEach(url => console.log(`     ${url}`));

    console.log(`  🔗 Bridge URL + MID: ${linkAnalysis.bridgeUrls.length}개`);
    linkAnalysis.bridgeUrls.slice(0, 3).forEach(url => console.log(`     ${url}`));

    console.log(`  📦 기타 MID 포함: ${linkAnalysis.otherWithMid.length}개`);
    linkAnalysis.otherWithMid.slice(0, 3).forEach(url => console.log(`     ${url}`));

    // 5. 태그 버전 로직대로 클릭 시도
    console.log("\n[5] 태그 버전 로직으로 클릭 시도...");

    // clickDirectSmartStore 로직
    let clicked = await page.evaluate((targetMid: string) => {
      const links = Array.from(document.querySelectorAll("a"));
      for (const link of links) {
        const href = link.href || "";
        // Bridge URL 스킵
        if (href.includes("/bridge") || href.includes("cr.shopping") ||
            href.includes("cr2.shopping") || href.includes("cr3.shopping") ||
            href.includes("cr4.shopping")) {
          continue;
        }
        // smartstore + MID
        if (href.includes("smartstore.naver.com") && href.includes("/products/")) {
          if (href.includes(targetMid)) {
            console.log("Clicking smartstore product:", href);
            (link as HTMLElement).click();
            return true;
          }
        }
        // brand.naver.com + MID
        if (href.includes("brand.naver.com") && href.includes("/products/")) {
          if (href.includes(targetMid)) {
            console.log("Clicking brand product:", href);
            (link as HTMLElement).click();
            return true;
          }
        }
      }
      return false;
    }, product.nvMid);

    console.log(`  clickDirectSmartStore: ${clicked}`);

    if (!clicked) {
      // findAndClickMid 로직
      const midLink = await page.evaluate((targetMid: string) => {
        const links = Array.from(document.querySelectorAll("a"));
        for (const link of links) {
          const href = link.href || "";
          if (href.includes(targetMid) || href.includes(`nvMid=${targetMid}`)) {
            return { found: true, href };
          }
          const dataMid = link.getAttribute("data-nv-mid") || link.getAttribute("data-nvmid");
          if (dataMid === targetMid) {
            return { found: true, href };
          }
        }
        return { found: false, href: '' };
      }, product.nvMid);

      console.log(`  findAndClickMid: found=${midLink.found}`);
      if (midLink.found) {
        console.log(`    URL: ${midLink.href.substring(0, 80)}...`);

        if (isBridgeUrl(midLink.href)) {
          console.log("  ❌ Bridge URL이므로 우회 필요");

          // catalog URL로 우회
          const catalogUrl = `https://search.shopping.naver.com/catalog/${product.nvMid}`;
          console.log(`  → Catalog URL로 이동: ${catalogUrl}`);

          clicked = await page.evaluate((url: string) => {
            const link = document.createElement("a");
            link.href = url;
            link.target = "_self";
            document.body.appendChild(link);
            link.click();
            return true;
          }, catalogUrl);
        } else {
          // 직접 클릭
          await page.evaluate((href: string) => {
            const link = Array.from(document.querySelectorAll("a")).find((a) => a.href === href);
            if (link) (link as HTMLElement).click();
          }, midLink.href);
          clicked = true;
        }
      }
    }

    if (!clicked) {
      console.log("\n❌ MID 클릭 실패 - 모든 전략 실패");
      await browser.close();
      return;
    }

    // 6. 페이지 로딩 대기
    console.log("\n[6] 페이지 로딩 대기...");
    try {
      await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 10000 });
    } catch {}
    await delay(4000);

    // 7. 결과 확인
    const finalUrl = page.url();
    const pageTitle = await page.title();

    console.log("\n📊 결과:");
    console.log(`  URL: ${finalUrl.substring(0, 80)}`);
    console.log(`  Title: ${pageTitle.substring(0, 50)}`);

    // 차단 체크
    const bodyText = await page.evaluate(() => document.body.innerText.substring(0, 500));
    if (bodyText.includes("보안 확인") || bodyText.includes("일시적으로 제한") || bodyText.includes("비정상적인 접근")) {
      console.log("\n❌ 차단됨:", bodyText.substring(0, 100));
    } else if (finalUrl.includes("smartstore") || finalUrl.includes("catalog") || finalUrl.includes("brand.naver")) {
      console.log("\n✅ 상세페이지 진입 성공!");
    } else {
      console.log("\n⚠️ 알 수 없는 상태");
    }

    await delay(3000);
  } finally {
    await browser.close();
  }
}

main().catch(console.error);
