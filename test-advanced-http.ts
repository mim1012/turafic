/**
 * Advanced HTTP 모드 테스트
 *
 * 더 정교한 HTTP 헤더로 봇 탐지를 우회하는지 테스트합니다.
 */

import { createNaverBot } from "./server/services/naverBot";

async function testAdvancedHttp() {
  console.log("\n🧪 Advanced HTTP 모드 테스트\n");
  console.log("=".repeat(60));

  // 테스트 데이터
  const testData = {
    keyword: "장난감",
    productId: "28812663612", // 2페이지 첫 상품 (rank 41 예상)
  };

  console.log("\n📋 테스트 정보:");
  console.log(`  - 키워드: "${testData.keyword}"`);
  console.log(`  - 상품 ID: ${testData.productId}`);
  console.log(`  - 모드: Advanced HTTP (정교한 헤더)`);

  // 10개 변수 (기본값 사용)
  const task = {
    uaChange: 1,
    cookieHomeMode: 1,
    shopHome: 1,
    useNid: 0,
    useImage: 1,
    workType: 3,
    randomClickCount: 2,
    workMore: 1,
    secFetchSiteMode: 1,
    lowDelay: 2,
  };

  console.log("\n🔧 10개 변수 (zru12 기본값):");
  console.log(`  1. ua_change: ${task.uaChange}`);
  console.log(`  2. cookie_home_mode: ${task.cookieHomeMode}`);
  console.log(`  3. shop_home: ${task.shopHome}`);
  console.log(`  4. use_nid: ${task.useNid}`);
  console.log(`  5. use_image: ${task.useImage}`);
  console.log(`  6. work_type: ${task.workType}`);
  console.log(`  7. random_click_count: ${task.randomClickCount}`);
  console.log(`  8. work_more: ${task.workMore}`);
  console.log(`  9. sec_fetch_site_mode: ${task.secFetchSiteMode}`);
  console.log(` 10. low_delay: ${task.lowDelay}`);

  try {
    console.log("\n🚀 순위 체크 시작...");
    console.log("  (Advanced HTTP 모드 - 정교한 헤더)");

    const bot = await createNaverBot(false); // Puppeteer 없음
    bot.setMode("advanced-http"); // Advanced HTTP 모드 설정

    const mockCampaign = {
      keyword: testData.keyword,
      productId: testData.productId,
    };

    const mockKeywordData = {
      user_agent:
        "Mozilla/5.0 (Linux; Android 13; SM-S918N Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.64 Mobile Safari/537.36",
      nnb: "",
      nid_aut: "",
      nid_ses: "",
    };

    const startTime = Date.now();
    const rank = await bot.checkRank(task as any, mockCampaign as any, mockKeywordData);
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    await bot.close();

    console.log("\n" + "=".repeat(60));

    if (rank > 0) {
      console.log("✅ 순위 발견!");
      console.log(`\n📊 결과:`);
      console.log(`  - 키워드: "${testData.keyword}"`);
      console.log(`  - 상품 ID: ${testData.productId}`);
      console.log(`  - 순위: ${rank}위`);
      console.log(`  - 예상 순위: 41위`);
      console.log(`  - 정확도: ${rank === 41 ? "✅ 정확!" : "❌ 불일치"}`);
      console.log(`  - 소요 시간: ${duration}초`);
      console.log(`\n🎉 Advanced HTTP 모드로 순위 체크 성공!`);
      console.log(`   (기존 HTTP 모드는 HTTP 418로 차단되었지만, Advanced 모드는 성공!)`);
    } else {
      console.log("❌ 순위를 찾을 수 없습니다");
      console.log(`\n📊 결과:`);
      console.log(`  - 키워드: "${testData.keyword}"`);
      console.log(`  - 상품 ID: ${testData.productId}`);
      console.log(`  - 순위: 400위 이내 없음`);
      console.log(`  - 소요 시간: ${duration}초`);
      console.log(`\n💡 힌트:`);
      console.log(`  1. 로그에서 HTTP 418 (봇 탐지) 여부 확인`);
      console.log(`  2. HTTP 200이면 성공, 418이면 여전히 차단됨`);
      console.log(`  3. 차단되었다면 Proxy/VPN 또는 Android SDK 고려`);
    }

    console.log("\n✅ 테스트 완료");
  } catch (error: any) {
    console.error("\n❌ 에러 발생:", error.message);
    console.error("\n상세 에러:");
    console.error(error);
  }
}

// 테스트 실행
testAdvancedHttp()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("\n❌ 치명적 에러:", error);
    process.exit(1);
  });
