/**
 * Production 단일 트래픽 테스트
 *
 * 실행: npx tsx scripts/production/test-single.ts
 *
 * 옵션:
 *   --engine=v7     특정 엔진 사용 (기본: v7)
 *   --dry-run       실제 실행 없이 작업 조회만
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
const engineArg = args.find((a) => a.startsWith("--engine="));
const dryRun = args.includes("--dry-run");

const engineVersion: EngineVersion = engineArg
  ? (engineArg.split("=")[1] as EngineVersion)
  : "v7";

// URL에서 nvMid 추출
function extractMidFromUrl(url: string): string {
  const match = url.match(/products\/(\d+)/);
  return match ? match[1] : "";
}

async function main() {
  console.log("🧪 Production 단일 트래픽 테스트");
  console.log(`📋 엔진: ${engineVersion}, Dry-run: ${dryRun}`);

  // 클라이언트 초기화
  const client = new NaverTrafficClient();

  // 연결 테스트
  const connected = await client.testConnection();
  if (!connected) {
    console.error("❌ Production Supabase 연결 실패");
    process.exit(1);
  }

  // 대기 작업 1개 조회
  const tasks = await client.getPendingTrafficTasks(1);

  if (tasks.length === 0) {
    console.log("✅ 처리할 작업이 없습니다.");
    return;
  }

  const task = tasks[0];
  console.log("\n📋 작업 정보:");
  console.log(`   ID: ${task.id}`);
  console.log(`   키워드: ${task.keyword}`);
  console.log(`   URL: ${task.link_url}`);
  console.log(`   상품ID: ${task.product_id || extractMidFromUrl(task.link_url)}`);
  console.log(`   상품명: ${task.product_name || "(없음)"}`);
  console.log(`   slot_id: ${task.slot_id}`);

  if (dryRun) {
    console.log("\n⏹️ Dry-run 모드 - 실제 실행 없이 종료");
    return;
  }

  console.log(`\n🚀 트래픽 실행 시작 (엔진: ${engineVersion})...`);

  try {
    // 엔진 초기화
    const engine = EngineRouter.getEngine(engineVersion);
    await engine.init();

    // 트래픽 실행
    const result = await engine.execute({
      nvMid: task.product_id || extractMidFromUrl(task.link_url),
      productName: task.product_name || task.keyword,
      keyword: task.keyword,
    });

    await engine.close();

    // 결과 출력
    console.log("\n📊 실행 결과:");
    console.log(`   성공: ${result.success}`);
    console.log(`   에러: ${result.error || "(없음)"}`);
    console.log(`   소요시간: ${result.duration || 0}ms`);

    // 성공/실패 판정
    const isSuccess =
      result.success &&
      !result.error?.includes("CAPTCHA") &&
      !result.error?.includes("418");

    console.log(`\n${isSuccess ? "✅ 최종 판정: 성공" : "❌ 최종 판정: 실패"}`);

    // slot_naver 업데이트
    const slotId = task.slot_id || (await client.findSlotNaver(task));
    if (slotId) {
      await client.updateSlotResult(slotId, isSuccess);
      console.log(`📊 slot_naver[${slotId}] 업데이트 완료`);
    } else {
      console.warn(`⚠️ slot_naver 매칭 실패`);
    }

    // traffic 삭제
    await client.deleteProcessedTraffic(task.id);
  } catch (error) {
    console.error("\n❌ 실행 오류:", error);

    // 실패 기록
    const slotId = task.slot_id || (await client.findSlotNaver(task));
    if (slotId) {
      await client.updateSlotResult(slotId, false);
    }

    // traffic 삭제 (실패해도 삭제)
    await client.deleteProcessedTraffic(task.id);
  }
}

main().catch(console.error);
