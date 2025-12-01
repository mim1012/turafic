/**
 * slot_naver에서 product_name + mid가 있는 슬롯을 직접 테스트
 */
import * as dotenv from "dotenv";
dotenv.config();

import { createClient } from "@supabase/supabase-js";
import { EngineRouter } from "../../server/services/traffic/engineRouter";

const supabase = createClient(
  process.env.SUPABASE_PRODUCTION_URL!,
  process.env.SUPABASE_PRODUCTION_KEY!
);

async function main() {
  console.log("🔍 slot_naver에서 product_name + mid가 있는 슬롯 조회\n");

  // product_name과 mid가 모두 있는 슬롯 조회
  const { data: slots, error } = await supabase
    .from("slot_naver")
    .select("id, keyword, product_name, mid, link_url, success_count, fail_count")
    .not("product_name", "is", null)
    .not("mid", "is", null)
    .limit(10);

  if (error) {
    console.error("❌ 조회 오류:", error);
    return;
  }

  if (!slots || slots.length === 0) {
    console.log("⚠️ product_name과 mid가 있는 슬롯이 없습니다.");
    return;
  }

  console.log(`📋 발견된 슬롯: ${slots.length}개\n`);

  for (const slot of slots) {
    console.log(`[ID: ${slot.id}]`);
    console.log(`  키워드: ${slot.keyword}`);
    console.log(`  상품명: ${slot.product_name?.substring(0, 50)}...`);
    console.log(`  MID: ${slot.mid}`);
    console.log(`  URL: ${slot.link_url?.substring(0, 60)}...`);
    console.log(`  성공/실패: ${slot.success_count}/${slot.fail_count}`);
    console.log("");
  }

  // 첫 번째 슬롯으로 테스트 실행
  const testSlot = slots[0];
  console.log("=".repeat(60));
  console.log(`🧪 테스트 실행: ${testSlot.product_name?.substring(0, 40)}...\n`);

  const engine = EngineRouter.getEngine("v7");
  await engine.init();

  const result = await engine.execute({
    nvMid: testSlot.mid!,
    productName: testSlot.product_name!,
    keyword: testSlot.keyword,
    taskId: undefined,
    slotId: testSlot.id,
  });

  await engine.close();

  console.log("\n📊 결과:");
  console.log("  성공:", result.success);
  console.log("  MID 클릭:", result.midClicked);
  console.log("  차단:", result.blocked);
  console.log("  에러:", result.error || "(없음)");
  console.log("  소요시간:", result.duration, "ms");

  if (result.foundMids && result.foundMids.length > 0) {
    console.log("\n  🔍 검색 결과에서 발견된 MID들:");
    result.foundMids.slice(0, 5).forEach((mid, i) => {
      console.log(`    ${i + 1}. ${mid}`);
    });
    console.log(`    ... 총 ${result.foundCount}개`);
  }
}

main().catch(console.error);
