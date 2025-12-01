/**
 * Production 네이버쇼핑 트래픽 Runner
 * 참조: adpang_coupang_click/traffic-click-processor.js
 *
 * 실행: npx tsx scripts/production/naver-traffic-runner.ts
 *
 * 환경변수 필수:
 * - SUPABASE_PRODUCTION_URL
 * - SUPABASE_PRODUCTION_KEY
 */

import * as dotenv from "dotenv";
dotenv.config();

import {
  NaverTrafficClient,
  NaverTrafficTask,
} from "../../server/services/naverTrafficClient";
import {
  EngineRouter,
  EngineVersion,
} from "../../server/services/traffic/engineRouter";
import config from "./config";

// 통계
interface RunnerStats {
  total: number;
  success: number;
  failed: number;
  captcha: number;
  startTime: Date;
}

const stats: RunnerStats = {
  total: 0,
  success: 0,
  failed: 0,
  captcha: 0,
  startTime: new Date(),
};

// URL에서 nvMid 추출
function extractMidFromUrl(url: string): string {
  // smartstore.naver.com/xxx/products/12345678
  const match = url.match(/products\/(\d+)/);
  return match ? match[1] : "";
}

// 휴식
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// 성공/실패 판정
// 성공: result.success === true && CAPTCHA 없음 && HTTP 418 없음
function isSuccessResult(result: {
  success: boolean;
  error?: string;
}): boolean {
  if (!result.success) return false;
  if (result.error?.includes("CAPTCHA")) return false;
  if (result.error?.includes("418")) return false;
  return true;
}

// 통계 출력
function printStats(): void {
  const elapsed = Math.floor(
    (Date.now() - stats.startTime.getTime()) / 1000 / 60
  );
  const successRate =
    stats.total > 0 ? ((stats.success / stats.total) * 100).toFixed(1) : "0";

  console.log("\n📊 현재 통계:");
  console.log(`   총 처리: ${stats.total}`);
  console.log(`   성공: ${stats.success} (${successRate}%)`);
  console.log(`   실패: ${stats.failed}`);
  console.log(`   캡챠: ${stats.captcha}`);
  console.log(`   경과 시간: ${elapsed}분\n`);
}

// 메인 실행
async function main() {
  console.log("🚀 네이버쇼핑 트래픽 Runner 시작");
  console.log(`📋 설정: 엔진=${config.engineMode}, 검색=${config.searchType}`);

  // 클라이언트 초기화
  const client = new NaverTrafficClient();

  // 연결 테스트
  const connected = await client.testConnection();
  if (!connected) {
    console.error("❌ Production Supabase 연결 실패. 환경변수를 확인하세요.");
    process.exit(1);
  }

  // 대기 작업 조회
  const tasks = await client.getAllPendingTrafficTasks();
  console.log(`📋 대기 작업: ${tasks.length}개`);

  if (tasks.length === 0) {
    console.log("✅ 처리할 작업이 없습니다.");
    return;
  }

  let consecutiveFailures = 0;
  let processedInBatch = 0;

  // 각 작업 순차 처리
  for (let i = 0; i < tasks.length; i++) {
    const task = tasks[i];

    try {
      // 엔진 선택
      const version: EngineVersion =
        config.engineMode === "rotation"
          ? EngineRouter.getRandomVersion()
          : config.singleEngine;

      const engine = EngineRouter.getEngine(version);

      console.log(
        `\n🔄 [${i + 1}/${tasks.length}] 작업 ${task.id}: ${task.keyword} (엔진: ${version})`
      );

      // slot_naver에서 product_name, mid 가져오기
      let productName = task.product_name;
      let nvMid = task.product_id || extractMidFromUrl(task.link_url);

      if (task.slot_id && (!productName || !nvMid)) {
        const slotInfo = await client.getSlotProductInfo(task.slot_id);
        if (slotInfo.productName && !productName) {
          productName = slotInfo.productName;
          console.log(`   📦 slot_naver에서 상품명 가져옴: ${productName}`);
        }
        if (slotInfo.mid && !nvMid) {
          nvMid = slotInfo.mid;
          console.log(`   📦 slot_naver에서 MID 가져옴: ${nvMid}`);
        }
      }

      // 트래픽 실행
      await engine.init();

      const result = await engine.execute({
        nvMid: nvMid,
        productName: productName || task.keyword,
        keyword: task.keyword,
      });

      await engine.close();

      // 성공/실패 판정
      const isSuccess = isSuccessResult(result);
      stats.total++;

      if (isSuccess) {
        stats.success++;
        consecutiveFailures = 0;
        console.log(`✅ 성공: ${task.keyword}`);
      } else {
        stats.failed++;
        consecutiveFailures++;

        if (result.error?.includes("CAPTCHA")) {
          stats.captcha++;
          console.log(`❌ 캡챠 감지: ${task.keyword} (${result.error})`);
        } else {
          console.log(
            `❌ 실패: ${task.keyword}${result.error ? ` (${result.error})` : ""}`
          );
        }
      }

      // slot_naver 매칭 및 결과 업데이트
      const slotId = task.slot_id || (await client.findSlotNaver(task));
      if (slotId) {
        await client.updateSlotResult(slotId, isSuccess);
      } else {
        console.warn(`⚠️ slot_naver 매칭 실패: task ${task.id}`);
      }
    } catch (error) {
      console.error(`❌ 작업 ${task.id} 예외:`, error);
      stats.failed++;
      stats.total++;
      consecutiveFailures++;

      // 실패 카운터 증가
      const slotId = task.slot_id || (await client.findSlotNaver(task));
      if (slotId) {
        try {
          await client.updateSlotResult(slotId, false);
        } catch (updateError) {
          console.error("slot_naver 업데이트 실패:", updateError);
        }
      }
    } finally {
      // traffic_navershopping에서 삭제 (성공/실패 관계없이 항상 실행)
      try {
        await client.deleteProcessedTraffic(task.id);
      } catch (deleteError) {
        console.error("트래픽 삭제 실패:", deleteError);
      }
    }

    // 연속 실패 체크
    if (consecutiveFailures >= config.maxConsecutiveFailures) {
      console.log(
        `\n⚠️ ${consecutiveFailures}회 연속 실패. ${config.failurePauseInterval / 1000}초 대기...`
      );
      printStats();
      await sleep(config.failurePauseInterval);
      consecutiveFailures = 0;
    }

    // 배치 처리 체크
    processedInBatch++;
    if (processedInBatch >= config.batchSize) {
      console.log(`\n⏸️ ${config.batchSize}건 완료. 배치 휴식...`);
      printStats();
      await sleep(config.batchRestInterval);
      processedInBatch = 0;
    } else {
      // 작업 간 휴식
      await sleep(config.taskRestInterval);
    }
  }

  // 최종 통계
  console.log("\n🏁 네이버쇼핑 트래픽 Runner 완료");
  printStats();
}

// 실행
main().catch((error) => {
  console.error("Runner 오류:", error);
  process.exit(1);
});
