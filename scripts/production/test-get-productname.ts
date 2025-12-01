/**
 * 상품명 추출 테스트
 */
import * as dotenv from "dotenv";
dotenv.config();

import { getProductNameFromSmartstore } from "../../rank-check/utils/get-product-name-from-url";

async function main() {
  const url = "https://m.smartstore.naver.com/goldtraderscor/products/8058076323";
  console.log("URL:", url);

  const productName = await getProductNameFromSmartstore(url);
  console.log("상품명:", productName);
}

main().catch(console.error);
