/**
 * Production 배치 트래픽 테스트
 *
 * 실행: npx tsx scripts/production/test-batch.ts --count=5
 *
 * 옵션:
 *   --count=N       처리할 작업 수 (기본: 5)
 *   --engine=v7     특정 엔진 사용 (기본: 로테이션)
 *   --dry-run       실제 실행 없이 작업 조회만
 *   --rest=5000     작업 간 휴식 시간 ms (기본: 5000)
 */

import * as dotenv from "dotenv";
dotenv.config();

import { NaverTrafficClient } from "../../server/services/naverTrafficClient";
import {
  EngineRouter,
  EngineVersion,
} from "../../server/services/traffic/engineRouter";

// 인자 파싱
const args = process.argv.slice(2);
const countArg = args.find((a) => a.startsWith("--count="));
const engineArg = args.find((a) => a.startsWith("--engine="));
const restArg = args.find((a) => a.startsWith("--rest="));
const dryRun = args.includes("--dry-run");

const count = countArg ? parseInt(countArg.split("=")[1]) : 5;
const fixedEngine = engineArg
  ? (engineArg.split("=")[1] as EngineVersion)
  : null;
const restInterval = restArg ? parseInt(restArg.split("=")[1]) : 5000;

// 통계
let success = 0;
let failed = 0;
let captcha = 0;

// URL에서 nvMid 추출
function extractMidFromUrl(url: string): string {
  const match = url.match(/products\/(\d+)/);
  return match ? match[1] : "";
}

// 휴식
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  console.log("🧪 Production 배치 트래픽 테스트");
  console.log(
    `📋 작업 수: ${count}, 엔진: ${fixedEngine || "로테이션"}, 휴식: ${restInterval}ms, Dry-run: ${dryRun}`
  );

  // 클라이언트 초기화
  const client = new NaverTrafficClient();

  // 연결 테스트
  const connected = await client.testConnection();
  if (!connected) {
    console.error("❌ Production Supabase 연결 실패");
    process.exit(1);
  }

  // 대기 작업 조회
  const tasks = await client.getPendingTrafficTasks(count);
  console.log(`📋 조회된 작업: ${tasks.length}개`);

  if (tasks.length === 0) {
    console.log("✅ 처리할 작업이 없습니다.");
    return;
  }

  if (dryRun) {
    console.log("\n📋 작업 목록:");
    tasks.forEach((task, i) => {
      console.log(`   ${i + 1}. ID=${task.id}, 키워드="${task.keyword}"`);
    });
    console.log("\n⏹️ Dry-run 모드 - 실제 실행 없이 종료");
    return;
  }

  console.log("\n🚀 배치 실행 시작...\n");

  for (let i = 0; i < tasks.length; i++) {
    const task = tasks[i];
    const engineVersion: EngineVersion =
      fixedEngine || EngineRouter.getRandomVersion();

    console.log(
      `[${i + 1}/${tasks.length}] 작업 ${task.id}: ${task.keyword} (엔진: ${engineVersion})`
    );

    try {
      // 엔진 초기화 및 실행
      const engine = EngineRouter.getEngine(engineVersion);
      await engine.init();

      const result = await engine.execute({
        nvMid: task.product_id || extractMidFromUrl(task.link_url),
        productName: task.product_name || task.keyword,
        keyword: task.keyword,
      });

      await engine.close();

      // 성공/실패 판정
      const isSuccess =
        result.success &&
        !result.error?.includes("CAPTCHA") &&
        !result.error?.includes("418");

      if (isSuccess) {
        success++;
        console.log(`   ✅ 성공`);
      } else {
        failed++;
        if (result.error?.includes("CAPTCHA")) {
          captcha++;
          console.log(`   ❌ 캡챠: ${result.error}`);
        } else {
          console.log(`   ❌ 실패: ${result.error || "알 수 없음"}`);
        }
      }

      // slot_naver 업데이트
      const slotId = task.slot_id || (await client.findSlotNaver(task));
      if (slotId) {
        await client.updateSlotResult(slotId, isSuccess);
      }
    } catch (error) {
      failed++;
      console.log(`   ❌ 예외: ${error}`);

      // 실패 기록
      const slotId = task.slot_id || (await client.findSlotNaver(task));
      if (slotId) {
        try {
          await client.updateSlotResult(slotId, false);
        } catch {}
      }
    } finally {
      // traffic 삭제
      try {
        await client.deleteProcessedTraffic(task.id);
      } catch {}
    }

    // 마지막 작업이 아니면 휴식
    if (i < tasks.length - 1) {
      await sleep(restInterval);
    }
  }

  // 최종 통계
  const total = success + failed;
  const successRate = total > 0 ? ((success / total) * 100).toFixed(1) : "0";

  console.log("\n📊 최종 통계:");
  console.log(`   총 처리: ${total}`);
  console.log(`   성공: ${success} (${successRate}%)`);
  console.log(`   실패: ${failed}`);
  console.log(`   캡챠: ${captcha}`);
}

main().catch(console.error);
