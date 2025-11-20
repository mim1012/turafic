/**
 * 상품 페이지 직접 접근 테스트
 *
 * 검색을 거치지 않고 상품 URL로 바로 접근
 * (검색 API는 차단되었어도 상품 페이지는 접근 가능할 수 있음)
 */

async function testDirectProductUrl() {
  console.log("\n=== 상품 페이지 직접 접근 테스트 ===\n");
  console.log("=".repeat(60));

  const testData = {
    productId: "28812663612",
    // 가능한 상품 URL 형식들
    urls: [
      `https://shopping.naver.com/products/${28812663612}`,
      `https://msearch.shopping.naver.com/product/${28812663612}`,
      `https://search.shopping.naver.com/catalog/${28812663612}`,
    ],
  };

  console.log("\nTest Info:");
  console.log(`  - Product ID: ${testData.productId}`);
  console.log(`  - Strategy: 검색 우회, 직접 URL 접근`);
  console.log(`  - Test URLs: ${testData.urls.length}개\n`);

  try {
    const puppeteer = (await import("puppeteer")).default;

    const browser = await puppeteer.launch({
      headless: false,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });

    const page = await browser.newPage();

    await page.setViewport({ width: 360, height: 640, isMobile: true, hasTouch: true });
    await page.setUserAgent(
      "Mozilla/5.0 (Linux; Android 13; SM-S918N Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.64 Mobile Safari/537.36"
    );

    console.log("Browser initialized\n");

    // 각 URL 형식 시도
    for (let i = 0; i < testData.urls.length; i++) {
      const url = testData.urls[i];

      console.log("=".repeat(60));
      console.log(`Test ${i + 1}/${testData.urls.length}\n`);
      console.log(`시도 URL: ${url}\n`);

      try {
        const startTime = Date.now();

        console.log("페이지 로딩 중...");
        await page.goto(url, {
          waitUntil: "domcontentloaded",
          timeout: 15000,
        });

        await new Promise((resolve) => setTimeout(resolve, 2000));

        const loadTime = Date.now() - startTime;

        // 페이지 정보 추출
        const pageInfo = await page.evaluate(() => {
          const title = document.title;
          const url = window.location.href;
          const bodyText = document.body.innerText;

          // Rate limit 체크
          const isRateLimited = bodyText.includes("쇼핑 서비스 접속이 일시적으로 제한");
          const is404 = bodyText.includes("404") || bodyText.includes("찾을 수 없");

          // 상품명 추출
          let productName = "";
          const nameSelectors = [
            "h1",
            "h2",
            '[class*="product"]',
            '[class*="title"]',
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
          const priceSelectors = ['[class*="price"]', "strong em", "em"];
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

          // nvMid 확인
          const hasNvMid = bodyText.includes("nvMid") || url.includes("nvMid");

          return {
            title,
            url,
            isRateLimited,
            is404,
            productName,
            price,
            hasNvMid,
            bodyTextSample: bodyText.substring(0, 500),
          };
        });

        console.log(`✅ 로드 완료 (${loadTime}ms)\n`);

        console.log("페이지 분석:");
        console.log(`  - Title: ${pageInfo.title}`);
        console.log(`  - Final URL: ${pageInfo.url.substring(0, 80)}...`);
        console.log(`  - Rate Limited: ${pageInfo.isRateLimited ? "❌ YES" : "✅ NO"}`);
        console.log(`  - 404 Error: ${pageInfo.is404 ? "❌ YES" : "✅ NO"}`);
        console.log(`  - 상품명: ${pageInfo.productName || "(없음)"}`);
        console.log(`  - 가격: ${pageInfo.price || "(없음)"}`);
        console.log(`  - nvMid 포함: ${pageInfo.hasNvMid ? "✅" : "❌"}`);

        if (pageInfo.isRateLimited) {
          console.log(`\n⚠️  이 URL도 차단되었습니다.`);
          continue;
        }

        if (pageInfo.is404) {
          console.log(`\n⚠️  404 - 잘못된 URL 형식입니다.`);
          continue;
        }

        if (pageInfo.productName || pageInfo.price) {
          console.log(`\n✅ SUCCESS! 상품 페이지 접근 성공!`);

          // 스크린샷
          const screenshotPath = `screenshots/direct-access-${testData.productId}-${Date.now()}.png`;
          await page.screenshot({ path: screenshotPath, fullPage: false });
          console.log(`\n📸 스크린샷 저장: ${screenshotPath}`);

          console.log(`\n페이지 내용 샘플:`);
          console.log(pageInfo.bodyTextSample.substring(0, 300) + "...");

          console.log(`\n🎉 테스트 성공! 5초 후 브라우저가 닫힙니다...`);
          await new Promise((resolve) => setTimeout(resolve, 5000));

          await browser.close();
          return;
        }

        console.log(`\n⚠️  상품 정보를 찾을 수 없습니다.`);
        console.log(`\n페이지 텍스트 샘플:`);
        console.log(pageInfo.bodyTextSample.substring(0, 300) + "...");

      } catch (error: any) {
        console.log(`❌ 에러: ${error.message}`);
      }

      console.log();
    }

    console.log("=".repeat(60));
    console.log("\n❌ 모든 URL 형식 실패\n");
    console.log("결론:");
    console.log("  - 검색 API: 차단됨");
    console.log("  - 상품 URL 직접 접근: 차단됨 또는 잘못된 URL");
    console.log("\n해결 방법:");
    console.log("  1. IP 변경 (라우터 재시작)");
    console.log("  2. 10-30분 대기");
    console.log("  3. 다른 네트워크 사용\n");

    await browser.close();

  } catch (error: any) {
    console.error("\nFATAL ERROR:", error.message);
    console.error(error);
  }
}

// Run
testDirectProductUrl()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("\nFATAL ERROR:", error);
    process.exit(1);
  });
