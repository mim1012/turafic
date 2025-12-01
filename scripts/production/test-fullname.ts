/**
 * 풀네임 키워드 직접 테스트
 */
import * as dotenv from "dotenv";
dotenv.config();

import { EngineRouter } from "../../server/services/traffic/engineRouter";

async function main() {
  console.log("🧪 풀네임 키워드 직접 테스트\n");

  const product = {
    nvMid: "8164781277",
    productName: "[켈슨] 무선 전기톱 15cm 충전식 소형 체인톱 전동 배터리1개 풀세트",
    keyword: "[켈슨] 무선 전기톱 15cm 충전식 소형 체인톱 전동 배터리1개 풀세트",
  };

  console.log("📦 상품:", product.productName);
  console.log("🔗 MID:", product.nvMid);
  console.log("");

  const engine = EngineRouter.getEngine("v7");
  await engine.init();

  const result = await engine.execute(product);

  await engine.close();

  console.log("\n📊 결과:");
  console.log("   성공:", result.success);
  console.log("   에러:", result.error || "(없음)");
  console.log("   소요시간:", result.duration, "ms");
}

main().catch(console.error);
