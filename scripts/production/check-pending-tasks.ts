/**
 * Production DB에서 대기 작업 확인
 */
import * as dotenv from "dotenv";
dotenv.config();

import { NaverTrafficClient } from "../../server/services/naverTrafficClient";

async function main() {
  const client = new NaverTrafficClient();
  const tasks = await client.getPendingTrafficTasks(5);

  console.log("대기 작업 (첫 5개):\n");

  tasks.forEach((t, i) => {
    console.log(`[${i + 1}] ID=${t.id}, slot_id=${t.slot_id}`);
    console.log(`    keyword: ${t.keyword?.substring(0, 60) || "(없음)"}`);
    console.log(`    product_name: ${t.product_name?.substring(0, 60) || "(없음)"}`);
    console.log(`    product_id: ${t.product_id || "(없음)"}`);
    console.log(`    link_url: ${t.link_url?.substring(0, 70) || "(없음)"}`);
    console.log("");
  });
}

main().catch(console.error);
