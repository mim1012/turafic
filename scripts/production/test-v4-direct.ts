/**
 * v4 로직 직접 테스트 (DB 없이)
 */
import * as dotenv from "dotenv";
dotenv.config();

const product = {
  productName: "[켈슨] 무선 전기톱 15cm 충전식 소형 체인톱 전동 배터리1개 풀세트",
  productId: "8164781277",
};

const USER_AGENTS = [
  "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
];

async function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function randomDelay(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

async function main() {
  console.log("🧪 v4 직접 테스트\n");
  console.log("📦 상품:", product.productName);
  console.log("🔗 MID:", product.productId);
  console.log("");

  const { connect } = await import("puppeteer-real-browser");

  const ua = USER_AGENTS[0];
  console.log(`[테스트] 브라우저 시작 (UA: ${ua.substring(0, 50)}...)`);

  const { page, browser } = await connect({
    headless: false,
    turnstile: true,
    fingerprint: true,
  });

  await page.setUserAgent(ua);

  try {
    // 1. 네이버 메인
    console.log("[1] 네이버 메인 진입...");
    await page.goto("https://m.naver.com", {
      waitUntil: "domcontentloaded",
      timeout: 20000,
    });
    await delay(randomDelay(1500, 2500));

    // 2. 풀네임 검색
    console.log("[2] 풀네임 검색...");
    await page.evaluate((searchTerm: string) => {
      const input = document.querySelector(
        'input[type="search"], input[name="query"]'
      ) as HTMLInputElement;
      if (input) {
        input.value = searchTerm;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        const form = input.closest("form");
        if (form) form.submit();
      }
    }, product.productName);

    await page
      .waitForNavigation({ waitUntil: "domcontentloaded", timeout: 20000 })
      .catch(() => {});
    await delay(randomDelay(2500, 3500));

    // 3. 스마트스토어 직접 링크 우선 클릭 (v4 핵심!)
    console.log("[3] 스마트스토어 링크 찾기...");
    let clicked = false;

    for (let scroll = 0; scroll < 5 && !clicked; scroll++) {
      clicked = await page.evaluate(() => {
        const links = document.querySelectorAll("a");
        for (const link of links) {
          const href = link.href || "";
          // 스마트스토어 상품 페이지 직접 링크 (브릿지 아님!)
          if (
            href.includes("smartstore.naver.com") &&
            href.includes("/products/")
          ) {
            if (
              !href.includes("/main/stores/") &&
              !href.endsWith("smartstore.naver.com/")
            ) {
              console.log("Clicking smartstore product:", href);
              (link as HTMLElement).click();
              return true;
            }
          }
        }
        return false;
      });

      if (!clicked) {
        await page.evaluate(() => window.scrollBy(0, 350));
        await delay(600);
      }
    }

    // 스마트스토어 못 찾으면 MID로 찾기
    if (!clicked) {
      console.log("[3-1] 스마트스토어 못 찾음, MID로 찾기...");
      clicked = await page.evaluate((targetId: string) => {
        const links = document.querySelectorAll("a");
        for (const link of links) {
          const href = link.href || "";
          if (href.includes(targetId) && !href.includes("/search/all")) {
            console.log("Clicking target link:", href);
            (link as HTMLElement).click();
            return true;
          }
        }
        return false;
      }, product.productId);
    }

    if (!clicked) {
      console.log("❌ 상품 링크 없음");
      await browser.close();
      return;
    }

    console.log("[4] 상품 페이지로 이동...");
    // 네비게이션 대기
    await page
      .waitForNavigation({ waitUntil: "networkidle2", timeout: 25000 })
      .catch(() => {});
    await delay(randomDelay(2000, 3500));

    // 결과 확인
    const pageTitle = await page.title();
    const pageUrl = page.url();

    console.log("\n📊 결과:");
    console.log("   URL:", pageUrl.substring(0, 80));
    console.log("   Title:", pageTitle.substring(0, 50));

    if (pageTitle.includes("보안") || pageUrl.includes("captcha")) {
      console.log("❌ CAPTCHA 감지!");
    } else if (pageTitle.length > 5) {
      console.log("✅ 성공!");
    } else {
      console.log("❌ 빈 페이지 또는 실패");
    }

    // 잠시 대기 (확인용)
    await delay(3000);
  } catch (error: any) {
    console.log("❌ 에러:", error.message);
  } finally {
    await browser.close();
  }
}

main().catch(console.error);
