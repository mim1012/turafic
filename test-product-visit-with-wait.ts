/**
 * 상품 페이지 진입 테스트 (자동 대기 포함)
 *
 * Rate limit 해제를 기다렸다가 자동으로 테스트 실행
 */

async function testProductVisitWithWait() {
  console.log("\n=== 상품 페이지 진입 테스트 (자동 대기) ===\n");
  console.log("=".repeat(60));

  const WAIT_TIME = 180; // 3분 대기
  const testData = {
    keyword: "장난감",
    productId: "28812663612",
    expectedRank: 41,
  };

  console.log(`\n⏳ Rate limit 해제 대기 중... (${WAIT_TIME}초)\n`);
  console.log("네이버가 IP를 일시적으로 차단했습니다.");
  console.log("일반적으로 5-30분 후 자동 해제됩니다.\n");

  // Countdown
  for (let i = WAIT_TIME; i > 0; i--) {
    if (i % 10 === 0 || i <= 10) {
      process.stdout.write(`\r⏳ ${i}초 남음...  `);
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  console.log(`\r✓ 대기 완료!                    \n`);

  console.log("=".repeat(60));
  console.log("테스트 시작\n");

  console.log("Test Info:");
  console.log(`  - Keyword: "${testData.keyword}"`);
  console.log(`  - Product ID: ${testData.productId}`);
  console.log(`  - Expected Rank: ${testData.expectedRank}\n`);

  try {
    const puppeteer = (await import("puppeteer")).default;

    const browser = await puppeteer.launch({
      headless: false, // 브라우저 창 보이기
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });

    const page = await browser.newPage();

    // Request interception (폰트/미디어만 차단)
    await page.setRequestInterception(true);
    page.on("request", (req) => {
      const resourceType = req.resourceType();
      if (["font", "media"].includes(resourceType)) {
        req.abort();
      } else {
        req.continue();
      }
    });

    await page.setViewport({ width: 360, height: 640, isMobile: true, hasTouch: true });
    await page.setUserAgent(
      "Mozilla/5.0 (Linux; Android 13; SM-S918N Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.64 Mobile Safari/537.36"
    );

    const startTime = Date.now();

    // Step 1: 검색에서 상품 찾기
    console.log("Step 1: 검색 페이지에서 상품 찾기\n");

    let rank = -1;
    let productUrl = "";

    for (let currentPage = 1; currentPage <= 10; currentPage++) {
      const searchUrl = `https://msearch.shopping.naver.com/search/all?query=${encodeURIComponent(
        testData.keyword
      )}&pagingIndex=${currentPage}&pagingSize=40&sort=rel&viewType=list&productSet=total`;

      console.log(`[Page ${currentPage}/10] 검색 중...`);

      await page.goto(searchUrl, { waitUntil: "domcontentloaded", timeout: 10000 });

      try {
        await page.waitForSelector('a[href*="nvMid="]', { timeout: 2000 });
      } catch (e) {
        // Continue
      }

      await new Promise((resolve) => setTimeout(resolve, 300));

      // Rate limit 체크
      const bodyText = await page.evaluate(() => document.body.innerText);
      if (bodyText.includes("쇼핑 서비스 접속이 일시적으로 제한")) {
        console.log(`  ❌ 여전히 차단됨! 더 기다려야 합니다.\n`);
        console.log("💡 해결 방법:");
        console.log("   1. 라우터를 재시작하여 IP 변경");
        console.log("   2. 또는 10-20분 더 대기 후 재시도\n");
        await browser.close();
        return;
      }

      // 상품 찾기
      const foundProduct = await page.evaluate((productId) => {
        const links = Array.from(document.querySelectorAll('a[href*="nvMid="]'));
        for (let i = 0; i < links.length; i++) {
          const link = links[i] as HTMLAnchorElement;
          if (link.href.includes(`nvMid=${productId}`)) {
            return {
              found: true,
              position: i,
              url: link.href,
              text: link.innerText?.substring(0, 50) || "",
            };
          }
        }
        return { found: false, position: -1, url: "", text: "" };
      }, testData.productId);

      if (foundProduct.found) {
        rank = (currentPage - 1) * 40 + foundProduct.position + 1;
        productUrl = foundProduct.url;
        console.log(`  ✅ 상품 발견!`);
        console.log(`     순위: ${rank}위`);
        console.log(`     링크: ${productUrl.substring(0, 60)}...\n`);
        break;
      } else {
        console.log(`  ❌ ${currentPage}페이지에 없음`);
      }
    }

    if (rank === -1) {
      console.log("\n❌ 상품을 찾지 못했습니다.\n");
      await browser.close();
      return;
    }

    const searchTime = Date.now() - startTime;

    // Step 2: 상품 페이지로 이동
    console.log("=".repeat(60));
    console.log("Step 2: 상품 페이지로 이동\n");

    const clickTime = Date.now();
    console.log(`상품 페이지로 이동 중...\n`);

    await page.goto(productUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const pageLoadTime = Date.now() - clickTime;

    // 페이지 정보 추출
    const pageInfo = await page.evaluate(() => {
      const title = document.title;

      let productName = "";
      const nameSelectors = ["h1", "h2", '[class*="product"]'];
      for (const selector of nameSelectors) {
        const elem = document.querySelector(selector);
        if (elem && elem.textContent) {
          productName = elem.textContent.trim();
          if (productName.length > 0) break;
        }
      }

      let price = "";
      const priceSelectors = ['[class*="price"]', "strong em"];
      for (const selector of priceSelectors) {
        const elem = document.querySelector(selector);
        if (elem && elem.textContent) {
          const text = elem.textContent.trim();
          if (text.includes("원") || /\d{3,}/.test(text)) {
            price = text;
            break;
          }
        }
      }

      return {
        title,
        productName,
        price,
        url: window.location.href,
      };
    });

    console.log("✅ 상품 페이지 로드 완료!\n");
    console.log("페이지 정보:");
    console.log(`  - 제목: ${pageInfo.title}`);
    console.log(`  - 상품명: ${pageInfo.productName || "(추출 실패)"}`);
    console.log(`  - 가격: ${pageInfo.price || "(추출 실패)"}`);
    console.log(`  - URL: ${pageInfo.url.substring(0, 70)}...\n`);

    // 스크린샷
    const screenshotPath = `screenshots/product-${testData.productId}-${Date.now()}.png`;
    await page.screenshot({ path: screenshotPath });
    console.log(`📸 스크린샷 저장: ${screenshotPath}\n`);

    const totalTime = Date.now() - startTime;

    console.log("=".repeat(60));
    console.log("✅ 테스트 성공!\n");
    console.log("📊 결과:");
    console.log(`  - 키워드: "${testData.keyword}"`);
    console.log(`  - 상품 ID: ${testData.productId}`);
    console.log(`  - 찾은 순위: ${rank}위 (예상: ${testData.expectedRank}위)`);
    console.log(`  - 순위 정확도: ${rank === testData.expectedRank ? "✅ 정확" : `⚠️  차이: ${Math.abs(rank - testData.expectedRank)}위`}`);
    console.log(`\n⏱️  성능:`);
    console.log(`  - 검색 시간: ${searchTime}ms`);
    console.log(`  - 페이지 로드: ${pageLoadTime}ms`);
    console.log(`  - 총 시간: ${totalTime}ms`);
    console.log(`\n✅ 검증:`);
    console.log(`  - 검색 페이지: ✅`);
    console.log(`  - 순위 발견: ✅ (${rank}위)`);
    console.log(`  - 상품 클릭: ✅`);
    console.log(`  - 상품 페이지 로드: ✅`);
    console.log(`  - 정보 추출: ${pageInfo.productName ? "✅" : "⚠️"}`);

    console.log("\n🎉 5초 후 브라우저가 닫힙니다...");
    await new Promise((resolve) => setTimeout(resolve, 5000));

    await browser.close();
    console.log("\n테스트 완료.");
  } catch (error: any) {
    console.error("\nERROR:", error.message);
    console.error(error);
  }
}

// Run
testProductVisitWithWait()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("\nFATAL ERROR:", error);
    process.exit(1);
  });
