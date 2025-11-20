/**
 * 트래픽 전용 테스트 (순위 체크와 분리)
 *
 * 상품 페이지 접근만 테스트:
 * - 검색 없이 상품 URL로 직접 접근
 * - 상품 상세 페이지 로드 확인
 * - 체류 시간 시뮬레이션
 * - 리뷰 페이지 접근 (옵션)
 */

async function testTrafficOnly() {
  console.log("\n=== 트래픽 전용 테스트 (순위 체크 제외) ===\n");
  console.log("=".repeat(60));

  const testData = {
    productId: "28812663612",
    // 네이버 쇼핑 상품 URL 형식들
    productUrls: [
      // Gate URL (가장 일반적)
      `https://search.shopping.naver.com/gate.nhn?id=28812663612`,
      // Catalog URL
      `https://search.shopping.naver.com/catalog/28812663612`,
      // Search 결과에서 사용하는 형식
      `https://msearch.shopping.naver.com/product/28812663612`,
    ],
    workType: "검색+클릭+체류", // work_type
    dwellTime: 5000, // 체류 시간 (ms)
  };

  console.log("\nTest Info:");
  console.log(`  - Product ID: ${testData.productId}`);
  console.log(`  - Work Type: ${testData.workType}`);
  console.log(`  - Dwell Time: ${testData.dwellTime}ms`);
  console.log(`  - Test Mode: 트래픽만 (순위 체크 없음)\n`);

  try {
    const puppeteer = (await import("puppeteer")).default;

    console.log("Starting Puppeteer...\n");

    const browser = await puppeteer.launch({
      headless: false, // 브라우저 창 보기
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });

    const page = await browser.newPage();

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

    // 각 URL 형식 시도
    for (let i = 0; i < testData.productUrls.length; i++) {
      const productUrl = testData.productUrls[i];

      console.log("=".repeat(60));
      console.log(`Test ${i + 1}/${testData.productUrls.length}\n`);
      console.log(`URL: ${productUrl}\n`);

      try {
        const startTime = Date.now();

        // Step 1: 상품 페이지로 이동
        console.log("Step 1: 상품 페이지 접근...");
        await page.goto(productUrl, {
          waitUntil: "domcontentloaded",
          timeout: 15000,
        });

        await new Promise((resolve) => setTimeout(resolve, 2000));

        const loadTime = Date.now() - startTime;

        // Step 2: 페이지 분석
        const pageInfo = await page.evaluate(() => {
          const title = document.title;
          const url = window.location.href;
          const bodyText = document.body.innerText;

          // Rate limit 체크
          const isRateLimited = bodyText.includes("쇼핑 서비스 접속이 일시적으로 제한");

          // 404 체크
          const is404 =
            bodyText.includes("404") ||
            bodyText.includes("찾을 수 없") ||
            bodyText.includes("페이지 없음");

          // 상품명 추출
          let productName = "";
          const nameSelectors = [
            'h1[class*="product"]',
            'h2[class*="product"]',
            "h1",
            "h2",
            '[class*="productName"]',
            '[class*="productTitle"]',
          ];

          for (const selector of nameSelectors) {
            const elem = document.querySelector(selector);
            if (elem && elem.textContent) {
              const text = elem.textContent.trim();
              if (text.length > 0 && text.length < 200) {
                productName = text;
                break;
              }
            }
          }

          // 가격 추출
          let price = "";
          const priceSelectors = [
            '[class*="price"]',
            '[class*="Price"]',
            "strong em",
            "em",
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

          // 리뷰 링크 찾기
          const reviewLink = Array.from(document.querySelectorAll("a"))
            .find((a) => a.textContent?.includes("리뷰") || a.href?.includes("review"))
            ?.getAttribute("href");

          return {
            title,
            url,
            isRateLimited,
            is404,
            productName,
            price,
            reviewLink,
            bodyTextSample: bodyText.substring(0, 300),
          };
        });

        console.log(`✅ 로드 완료 (${loadTime}ms)\n`);

        console.log("페이지 정보:");
        console.log(`  - Title: ${pageInfo.title}`);
        console.log(`  - Final URL: ${pageInfo.url.substring(0, 80)}...`);
        console.log(`  - Rate Limited: ${pageInfo.isRateLimited ? "❌ YES" : "✅ NO"}`);
        console.log(`  - 404 Error: ${pageInfo.is404 ? "❌ YES" : "✅ NO"}`);
        console.log(`  - 상품명: ${pageInfo.productName || "(없음)"}`);
        console.log(`  - 가격: ${pageInfo.price || "(없음)"}`);
        console.log(`  - 리뷰 링크: ${pageInfo.reviewLink ? "✅ 있음" : "❌ 없음"}\n`);

        if (pageInfo.isRateLimited) {
          console.log("⚠️  Rate limited. 다음 URL 시도...\n");
          continue;
        }

        if (pageInfo.is404) {
          console.log("⚠️  404 Error. 다음 URL 시도...\n");
          continue;
        }

        if (!pageInfo.productName && !pageInfo.price) {
          console.log("⚠️  상품 정보 없음. 다음 URL 시도...\n");
          console.log(`페이지 텍스트 샘플:\n${pageInfo.bodyTextSample}\n`);
          continue;
        }

        // Step 3: 트래픽 시뮬레이션
        console.log("Step 2: 트래픽 시뮬레이션...");

        // 체류 시간
        console.log(`  - 체류 시간: ${testData.dwellTime}ms 대기 중...`);
        await new Promise((resolve) => setTimeout(resolve, testData.dwellTime));
        console.log(`  ✅ 체류 완료\n`);

        // 스크린샷
        const screenshotPath = `screenshots/traffic-${testData.productId}-${Date.now()}.png`;
        await page.screenshot({ path: screenshotPath, fullPage: false });
        console.log(`📸 스크린샷: ${screenshotPath}\n`);

        // Step 4 (옵션): 리뷰 페이지 접근
        if (pageInfo.reviewLink && testData.workType.includes("리뷰")) {
          console.log("Step 3: 리뷰 페이지 접근...");
          console.log(`  URL: ${pageInfo.reviewLink.substring(0, 60)}...\n`);

          try {
            await page.goto(pageInfo.reviewLink, {
              waitUntil: "domcontentloaded",
              timeout: 10000,
            });
            await new Promise((resolve) => setTimeout(resolve, 2000));
            console.log(`  ✅ 리뷰 페이지 로드 완료\n`);

            const reviewScreenshot = `screenshots/review-${testData.productId}-${Date.now()}.png`;
            await page.screenshot({ path: reviewScreenshot, fullPage: false });
            console.log(`  📸 리뷰 스크린샷: ${reviewScreenshot}\n`);
          } catch (error: any) {
            console.log(`  ⚠️  리뷰 페이지 로드 실패: ${error.message}\n`);
          }
        }

        const totalTime = Date.now() - startTime;

        console.log("=".repeat(60));
        console.log("✅ 트래픽 테스트 성공!\n");
        console.log("📊 결과:");
        console.log(`  - 상품 ID: ${testData.productId}`);
        console.log(`  - 상품명: ${pageInfo.productName}`);
        console.log(`  - 가격: ${pageInfo.price}`);
        console.log(`  - 성공 URL: ${productUrl}`);
        console.log(`\n⏱️  성능:`);
        console.log(`  - 페이지 로드: ${loadTime}ms`);
        console.log(`  - 체류 시간: ${testData.dwellTime}ms`);
        console.log(`  - 총 시간: ${totalTime}ms`);
        console.log(`\n✅ 검증:`);
        console.log(`  - 상품 페이지 접근: ✅`);
        console.log(`  - 페이지 로드: ✅`);
        console.log(`  - 정보 추출: ✅`);
        console.log(`  - 체류: ✅`);
        console.log(`  - 리뷰 접근: ${pageInfo.reviewLink ? "✅" : "⚠️  (링크 없음)"}`);

        console.log("\n🎉 5초 후 브라우저가 닫힙니다...");
        await new Promise((resolve) => setTimeout(resolve, 5000));

        await browser.close();
        return;

      } catch (error: any) {
        console.log(`❌ 에러: ${error.message}\n`);
      }
    }

    console.log("=".repeat(60));
    console.log("\n❌ 모든 URL 형식 실패\n");

    await browser.close();

  } catch (error: any) {
    console.error("\nFATAL ERROR:", error.message);
    console.error(error);
  }
}

// Run
testTrafficOnly()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("\nFATAL ERROR:", error);
    process.exit(1);
  });
