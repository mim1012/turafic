/**
 * Production DB 연결 테스트
 *
 * 실행: npx tsx scripts/production/test-connection.ts
 *
 * 테스트 항목:
 * 1. Supabase 연결
 * 2. traffic_navershopping 테이블 접근
 * 3. slot_naver 테이블 접근
 */

import * as dotenv from "dotenv";
dotenv.config();

import { createClient } from "@supabase/supabase-js";

async function main() {
  console.log("🧪 Production DB 연결 테스트\n");

  // 환경변수 확인
  const url = process.env.SUPABASE_PRODUCTION_URL;
  const key = process.env.SUPABASE_PRODUCTION_KEY;

  console.log("1️⃣ 환경변수 확인:");
  console.log(`   SUPABASE_PRODUCTION_URL: ${url ? "✅ 설정됨" : "❌ 없음"}`);
  console.log(`   SUPABASE_PRODUCTION_KEY: ${key ? "✅ 설정됨" : "❌ 없음"}`);

  if (!url || !key) {
    console.error("\n❌ 환경변수가 설정되지 않았습니다.");
    console.log("\n.env 파일에 다음을 추가하세요:");
    console.log("SUPABASE_PRODUCTION_URL=https://xxx.supabase.co");
    console.log("SUPABASE_PRODUCTION_KEY=your-service-role-key");
    process.exit(1);
  }

  // Supabase 연결
  console.log("\n2️⃣ Supabase 연결 시도...");
  const supabase = createClient(url, key);

  // traffic_navershopping 테이블 테스트
  console.log("\n3️⃣ traffic_navershopping 테이블:");
  try {
    const { data: trafficData, error: trafficError, count: trafficCount } =
      await supabase
        .from("traffic_navershopping")
        .select("*", { count: "exact", head: false })
        .limit(5);

    if (trafficError) {
      console.log(`   ❌ 오류: ${trafficError.message}`);
    } else {
      console.log(`   ✅ 접근 성공`);
      console.log(`   📊 대기 작업 수: ${trafficCount || 0}개`);

      if (trafficData && trafficData.length > 0) {
        console.log(`   📋 샘플 컬럼: ${Object.keys(trafficData[0]).join(", ")}`);
      }
    }
  } catch (err) {
    console.log(`   ❌ 예외: ${err}`);
  }

  // slot_naver 테이블 테스트
  console.log("\n4️⃣ slot_naver 테이블:");
  try {
    const { data: slotData, error: slotError, count: slotCount } =
      await supabase
        .from("slot_naver")
        .select("*", { count: "exact", head: false })
        .limit(5);

    if (slotError) {
      console.log(`   ❌ 오류: ${slotError.message}`);
    } else {
      console.log(`   ✅ 접근 성공`);
      console.log(`   📊 총 슬롯 수: ${slotCount || 0}개`);

      if (slotData && slotData.length > 0) {
        console.log(`   📋 샘플 컬럼: ${Object.keys(slotData[0]).join(", ")}`);

        // success_count, fail_count 컬럼 확인
        const hasSuccessCount = "success_count" in slotData[0];
        const hasFailCount = "fail_count" in slotData[0];
        console.log(
          `   📊 success_count 컬럼: ${hasSuccessCount ? "✅ 있음" : "❌ 없음"}`
        );
        console.log(
          `   📊 fail_count 컬럼: ${hasFailCount ? "✅ 있음" : "❌ 없음"}`
        );
      }
    }
  } catch (err) {
    console.log(`   ❌ 예외: ${err}`);
  }

  console.log("\n✅ 연결 테스트 완료");
}

main().catch(console.error);
