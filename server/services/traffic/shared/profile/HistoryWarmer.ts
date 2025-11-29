/**
 * HistoryWarmer - 프로필 히스토리 워밍업
 *
 * 각 프로필에 3~5분간 네이버 사용 히스토리 누적
 * - 뉴스 2~3개 방문
 * - 카페 1~2개 방문
 * - 쇼핑 홈 + 카테고리 브라우징
 */

import { BrowserManager } from '../browser/BrowserManager';
import { ProfileData } from './ProfileManager';

export class HistoryWarmer {
  private browserManager: BrowserManager | null = null;

  /**
   * 프로필 워밍업 실행 (3~5분)
   */
  async warmUp(profileData: ProfileData): Promise<boolean> {
    console.log(`[HistoryWarmer] Starting warmup for ${profileData.id}`);

    try {
      // 브라우저 초기화 (프로필 디렉토리 사용)
      this.browserManager = new BrowserManager(
        profileData.fingerprint,
        profileData.userDataDir
      );
      await this.browserManager.init();

      const page = this.browserManager.getPage();

      // 1. 네이버 뉴스 방문 (2~3개, 각 30~60초)
      await this.visitNews(page);

      // 2. 네이버 카페 방문 (1~2개, 각 30~60초)
      await this.visitCafe(page);

      // 3. 네이버 쇼핑 홈 방문 (60~90초)
      await this.visitShoppingHome(page);

      // 4. 쇼핑 카테고리 브라우징 (1~2개, 각 30~60초)
      await this.browseShopping(page);

      console.log(`[HistoryWarmer] Warmup completed for ${profileData.id}`);
      return true;

    } catch (error: any) {
      console.error(`[HistoryWarmer] Warmup failed for ${profileData.id}:`, error.message);
      return false;

    } finally {
      await this.close();
    }
  }

  /**
   * 네이버 뉴스 방문
   */
  private async visitNews(page: any): Promise<void> {
    const newsUrls = [
      'https://news.naver.com/',
      'https://entertain.naver.com/',
      'https://sports.news.naver.com/'
    ];

    // 2~3개 랜덤 선택
    const count = 2 + Math.floor(Math.random() * 2);
    const shuffled = newsUrls.sort(() => Math.random() - 0.5).slice(0, count);

    for (const url of shuffled) {
      console.log(`[HistoryWarmer] Visiting: ${url.substring(8, 35)}...`);

      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await this.delay(2000 + Math.random() * 2000);

      // 스크롤 + 마우스 이동
      await this.naturalBrowsing(page);

      // 30~60초 체류
      await this.delay(30000 + Math.random() * 30000);
    }
  }

  /**
   * 네이버 카페 방문
   */
  private async visitCafe(page: any): Promise<void> {
    const cafeUrls = [
      'https://cafe.naver.com/',
      'https://section.cafe.naver.com/'
    ];

    // 1~2개 랜덤 선택
    const count = 1 + Math.floor(Math.random() * 2);
    const shuffled = cafeUrls.sort(() => Math.random() - 0.5).slice(0, count);

    for (const url of shuffled) {
      console.log(`[HistoryWarmer] Visiting: ${url.substring(8, 35)}...`);

      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await this.delay(2000 + Math.random() * 2000);

      await this.naturalBrowsing(page);

      // 30~60초 체류
      await this.delay(30000 + Math.random() * 30000);
    }
  }

  /**
   * 네이버 쇼핑 홈 방문
   */
  private async visitShoppingHome(page: any): Promise<void> {
    console.log(`[HistoryWarmer] Visiting: shopping.naver.com`);

    await page.goto('https://shopping.naver.com/', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await this.delay(3000 + Math.random() * 2000);

    // 스크롤 여러 번
    for (let i = 0; i < 3; i++) {
      await page.evaluate(() => window.scrollBy(0, 300 + Math.random() * 200));
      await this.delay(1000 + Math.random() * 1000);
    }

    // 마우스 이동
    await this.randomMouseMove(page);

    // 60~90초 체류
    await this.delay(60000 + Math.random() * 30000);
  }

  /**
   * 쇼핑 카테고리 브라우징
   */
  private async browseShopping(page: any): Promise<void> {
    const categories = [
      'https://shopping.naver.com/ns/home?cat=50000000',  // 패션의류
      'https://shopping.naver.com/ns/home?cat=50000001',  // 패션잡화
      'https://shopping.naver.com/ns/home?cat=50000002',  // 화장품/미용
      'https://shopping.naver.com/ns/home?cat=50000003',  // 디지털/가전
      'https://shopping.naver.com/ns/home?cat=50000004',  // 가구/인테리어
    ];

    // 1~2개 랜덤 선택
    const count = 1 + Math.floor(Math.random() * 2);
    const shuffled = categories.sort(() => Math.random() - 0.5).slice(0, count);

    for (const url of shuffled) {
      console.log(`[HistoryWarmer] Browsing category...`);

      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await this.delay(2000 + Math.random() * 2000);

      await this.naturalBrowsing(page);

      // 30~60초 체류
      await this.delay(30000 + Math.random() * 30000);
    }
  }

  /**
   * 자연스러운 브라우징 동작 (스크롤 + 마우스)
   */
  private async naturalBrowsing(page: any): Promise<void> {
    // 스크롤 2~3회
    const scrollCount = 2 + Math.floor(Math.random() * 2);
    for (let i = 0; i < scrollCount; i++) {
      const scrollAmount = 200 + Math.floor(Math.random() * 300);
      await page.evaluate((amt: number) => window.scrollBy(0, amt), scrollAmount);
      await this.delay(500 + Math.random() * 1000);
    }

    // 마우스 이동
    await this.randomMouseMove(page);
  }

  /**
   * 랜덤 마우스 이동
   */
  private async randomMouseMove(page: any): Promise<void> {
    const x = 100 + Math.random() * 500;
    const y = 200 + Math.random() * 400;
    await page.mouse.move(x, y);
    await this.delay(300 + Math.random() * 500);

    // 추가 이동
    const x2 = x + (Math.random() - 0.5) * 200;
    const y2 = y + (Math.random() - 0.5) * 200;
    await page.mouse.move(x2, y2);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async close(): Promise<void> {
    if (this.browserManager) {
      await this.browserManager.close();
      this.browserManager = null;
    }
  }
}

/**
 * 여러 프로필 일괄 워밍업
 */
export async function warmUpProfiles(profiles: ProfileData[]): Promise<number> {
  const warmer = new HistoryWarmer();
  let successCount = 0;

  for (let i = 0; i < profiles.length; i++) {
    const profile = profiles[i];
    console.log(`\n[WarmUp] Profile ${i + 1}/${profiles.length}: ${profile.id}`);

    const success = await warmer.warmUp(profile);
    if (success) {
      successCount++;
    }

    // 프로필 간 5초 휴식
    if (i < profiles.length - 1) {
      console.log('[WarmUp] Resting 5 seconds...');
      await new Promise(r => setTimeout(r, 5000));
    }
  }

  console.log(`\n[WarmUp] Completed: ${successCount}/${profiles.length} profiles warmed up`);
  return successCount;
}
