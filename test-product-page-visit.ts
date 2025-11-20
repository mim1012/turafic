/**
 * Test: 실제 상품 페이지에 진입하는지 확인
 *
 * 플로우:
 * 1. 검색 페이지에서 순위 찾기
 * 2. 해당 상품 링크 클릭
 * 3. 상품 페이지 로드 확인
 * 4. 페이지 정보 추출 (제목, 가격 등)
 */

async function testProductPageVisit() {
  console.log("\n=== 상품 페이지 실제 진입 테스트 ===\n");
  console.log("=".repeat(60));

  const testData = {
    keyword: "장난감",
    productId: "28812663612", // 테스트할 상품 ID
    expectedRank: 41, // 예상 순위
  };

  console.log("\nTest Info:");
  console.log(`  - Keyword: "${testData.keyword}"`);
  console.log(`  - Product ID: ${testData.productId}`);
  console.log(`  - Expected Rank: ${testData.expectedRank}`);
  console.log("\nTest Flow:");
  console.log("  1️⃣  검색 페이지 로드");
  console.log("  2️⃣  상품 순위 찾기");
  console.log("  3️⃣  상품 링크 클릭");
  console.log("  4️⃣  상품 페이지 로드 확인");
  console.log("  5️⃣  페이지 정보 추출\n");

  try {
    const puppeteer = (await import("puppeteer")).default;

    console.log("Starting Puppeteer...");

    const browser = await puppeteer.launch({
      headless: false, // 실제 브라우저 창을 띄워서 확인
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
      ],
    });

    const page = await browser.newPage();

    // Request interception (속도 최적화)
    await page.setRequestInterception(true);
    page.on("request", (req) => {
      const resourceType = req.resourceType();
      if (["font", "media"].includes(resourceType)) {
        req.abort(); // 폰트/미디어만 차단 (이미지는 상품 확인용으로 허용)
      } else {
        req.continue();
      }
    });

    // 모바일 뷰포트
    await page.setViewport({
      width: 360,
      height: 640,
      isMobile: true,
      hasTouch: true,
    });

    // User-Agent
    await page.setUserAgent(
      "Mozilla/5.0 (Linux; Android 13; SM-S918N Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.64 Mobile Safari/537.36"
    );

    console.log("Browser initialized\n");

    const startTime = Date.now();

    // Step 1: 검색 페이지에서 상품 찾기
    console.log("=".repeat(60));
    console.log("Step 1: 검색 페이지에서 상품 찾기\n");

    const productsPerPage = 40;
    let rank = -1;
    let productUrl = "";

    for (let currentPage = 1; currentPage <= 10; currentPage++) {
      const searchUrl = `https://msearch.shopping.naver.com/search/all?query=${encodeURIComponent(
        testData.keyword
      )}&pagingIndex=${currentPage}&pagingSize=40&sort=rel&viewType=list&productSet=total`;

      console.log(`[Page ${currentPage}/10] Loading search page...`);

      try {
        await page.goto(searchUrl, {
          waitUntil: "domcontentloaded",
          timeout: 10000,
        });

        // Wait for products
        try {
          await page.waitForSelector('a[href*="nvMid="]', { timeout: 2000 });
        } catch (e) {
          console.log(`  ⚠️  Selector timeout`);
        }

        // 짧은 딜레이
        await new Promise((resolve) => setTimeout(resolve, 300));

        // Rate limit 체크
        const bodyText = await page.evaluate(() => document.body.innerText);
        if (bodyText.includes("쇼핑 서비스 접속이 일시적으로 제한")) {
          console.log(`  ❌ Rate limited! 잠시 후 다시 시도하세요.\n`);
          await browser.close();
          return;
        }

        // nvMid로 상품 찾기
        const foundProduct = await page.evaluate((productId) => {
          const links = Array.from(
            document.querySelectorAll('a[href*="nvMid="]')
          );

          for (let i = 0; i < links.length; i++) {
            const link = links[i] as HTMLAnchorElement;
            const href = link.href;

            if (href.includes(`nvMid=${productId}`)) {
              return {
                found: true,
                position: i,
                url: href,
                text: link.innerText?.substring(0, 50) || "",
              };
            }
          }

          return { found: false, position: -1, url: "", text: "" };
        }, testData.productId);

        if (foundProduct.found) {
          rank = (currentPage - 1) * productsPerPage + foundProduct.position + 1;
          productUrl = foundProduct.url;

          console.log(`  ✅ Found product!`);
          console.log(`     - Rank: ${rank}`);
          console.log(`     - Position on page: ${foundProduct.position + 1}`);
          console.log(`     - Link text: ${foundProduct.text}`);
          console.log(`     - URL: ${productUrl.substring(0, 80)}...\n`);
          break;
        } else {
          console.log(`  ❌ Not found on page ${currentPage}\n`);
        }
      } catch (error: any) {
        console.log(`  ⚠️  Error: ${error.message}\n`);
      }
    }

    if (rank === -1) {
      console.log("=".repeat(60));
      console.log("❌ FAILED: Product not found in top 400\n");
      await browser.close();
      return;
    }

    const searchTime = Date.now() - startTime;
    console.log(`⏱️  Search completed in ${searchTime}ms\n`);

    // Step 2: 상품 페이지로 이동
    console.log("=".repeat(60));
    console.log("Step 2: 상품 페이지로 이동\n");

    const clickTime = Date.now();

    console.log(`Navigating to product page...`);
    console.log(`URL: ${productUrl.substring(0, 100)}...\n`);

    try {
      // 상품 페이지로 이동
      await page.goto(productUrl, {
        waitUntil: "domcontentloaded",
        timeout: 15000,
      });

      // 페이지 로드 대기
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const pageLoadTime = Date.now() - clickTime;

      console.log(`✅ Page loaded in ${pageLoadTime}ms\n`);

      // Step 3: 상품 페이지 정보 추출
      console.log("=".repeat(60));
      console.log("Step 3: 상품 페이지 정보 추출\n");

      const pageInfo = await page.evaluate(() => {
        // 페이지 타이틀
        const title = document.title;

        // 상품명 추출 시도 (여러 선택자)
        let productName = "";
        const nameSelectors = [
          'h1[class*="product"]',
          'h2[class*="product"]',
          '[class*="productName"]',
          '[class*="product-name"]',
          "h1",
          "h2",
        ];

        for (const selector of nameSelectors) {
          const elem = document.querySelector(selector);
          if (elem && elem.textContent) {
            productName = elem.textContent.trim();
            if (productName.length > 0) break;
          }
        }

        // 가격 추출 시도
        let price = "";
        const priceSelectors = [
          '[class*="price"]',
          '[class*="Price"]',
          "strong em",
          ".price_num",
        ];

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

        // HTML 샘플
        const bodyText = document.body.innerText.substring(0, 500);

        return {
          title,
          productName,
          price,
          url: window.location.href,
          bodyTextSample: bodyText,
        };
      });

      console.log("Page Information:");
      console.log(`  - Page Title: ${pageInfo.title}`);
      console.log(`  - Product Name: ${pageInfo.productName || "(추출 실패)"}`);
      console.log(`  - Price: ${pageInfo.price || "(추출 실패)"}`);
      console.log(`  - Final URL: ${pageInfo.url.substring(0, 80)}...`);
      console.log(`\nPage Text Sample:`);
      console.log(`${pageInfo.bodyTextSample.substring(0, 200)}...\n`);

      const totalTime = Date.now() - startTime;

      // Screenshot 찍기
      const screenshotPath = `D:\\Project\\Navertrafic\\screenshots\\product-${testData.productId}-${Date.now()}.png`;
      await page.screenshot({ path: screenshotPath, fullPage: false });
      console.log(`📸 Screenshot saved: ${screenshotPath}\n`);

      console.log("=".repeat(60));
      console.log("✅ SUCCESS: 상품 페이지 진입 성공!\n");

      console.log("📊 Final Results:");
      console.log(`  - Keyword: "${testData.keyword}"`);
      console.log(`  - Product ID: ${testData.productId}`);
      console.log(`  - Rank Found: ${rank} (expected: ${testData.expectedRank})`);
      console.log(`  - Rank Accuracy: ${rank === testData.expectedRank ? "✅ EXACT" : `⚠️  Diff: ${Math.abs(rank - testData.expectedRank)}`}`);
      console.log(`\n⏱️  Performance:`);
      console.log(`  - Search time: ${searchTime}ms`);
      console.log(`  - Page load time: ${pageLoadTime}ms`);
      console.log(`  - Total time: ${totalTime}ms`);
      console.log(`\n✅ Verification:`);
      console.log(`  - Search page: ✅ Loaded`);
      console.log(`  - Rank found: ✅ Found at rank ${rank}`);
      console.log(`  - Product clicked: ✅ Navigated`);
      console.log(`  - Product page: ✅ Loaded`);
      console.log(`  - Page info extracted: ${pageInfo.productName ? "✅" : "⚠️"} ${pageInfo.productName ? "Success" : "Partial"}`);

      console.log("\n🎉 Test complete. Browser will close in 5 seconds...");
      await new Promise((resolve) => setTimeout(resolve, 5000));

      await browser.close();
    } catch (error: any) {
      console.log(`❌ ERROR navigating to product page: ${error.message}\n`);
      await browser.close();
    }
  } catch (error: any) {
    console.error("\nFATAL ERROR:", error.message);
    console.error(error);
  }
}

// Run
testProductPageVisit()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("\nFATAL ERROR:", error);
    process.exit(1);
  });
