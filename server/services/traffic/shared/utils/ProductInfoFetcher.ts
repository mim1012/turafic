/**
 * URL 또는 MID로부터 상품 정보를 조회하는 유틸리티
 */

export interface ProductInfo {
  nvMid: string;
  productName: string;
  url: string;
}

export class ProductInfoFetcher {
  /**
   * URL에서 MID 추출
   * 예: https://search.shopping.naver.com/catalog/53373673663 → 53373673663
   */
  static extractMidFromUrl(url: string): string | null {
    const patterns = [
      /catalog\/(\d+)/,           // catalog/MID
      /products\/(\d+)/,          // products/MID
      /nvMid=(\d+)/,              // nvMid=MID
    ];

    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) return match[1];
    }

    return null;
  }

  /**
   * MID로 puppeteer를 사용해 실제 상품명 조회
   */
  static async fetchProductName(mid: string): Promise<string | null> {
    const { connect } = await import("puppeteer-real-browser");

    let browser: any = null;
    try {
      const catalogUrl = `https://search.shopping.naver.com/catalog/${mid}`;

      console.log(`[ProductInfoFetcher] Fetching product name from: ${catalogUrl}`);

      const connection = await connect({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      });

      browser = connection.browser;
      const page = connection.page;

      await page.goto(catalogUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await new Promise(r => setTimeout(r, 2000));

      // 상품명 추출 (여러 셀렉터 시도)
      const selectors = [
        'h1.top_summary_title__HfauO',      // 네이버 쇼핑 상품명 h1
        '.product_title',
        'h2.product_title',
        'h1',
        '.top_summary_title'
      ];

      for (const selector of selectors) {
        try {
          const productName = await page.$eval(selector, (el: any) => el.textContent?.trim());
          if (productName && productName !== '네이버쇼핑' && productName.length > 2) {
            console.log(`[ProductInfoFetcher] Found product name: ${productName}`);
            await browser.close();
            return productName;
          }
        } catch (e) {
          continue;
        }
      }

      await browser.close();
      return null;
    } catch (error) {
      console.error(`[ProductInfoFetcher] Failed to fetch product name for MID ${mid}:`, error);
      if (browser) await browser.close();
      return null;
    }
  }

  /**
   * URL에서 전체 상품 정보 추출
   */
  static async getProductInfo(url: string): Promise<ProductInfo | null> {
    const mid = this.extractMidFromUrl(url);
    if (!mid) {
      console.error('[ProductInfoFetcher] Failed to extract MID from URL');
      return null;
    }

    const productName = await this.fetchProductName(mid);
    if (!productName) {
      console.error('[ProductInfoFetcher] Failed to fetch product name');
      return null;
    }

    return {
      nvMid: mid,
      productName,
      url,
    };
  }
}
