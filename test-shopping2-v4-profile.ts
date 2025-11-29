/**
 * 쇼검2 v4 테스트 - 멀티 프로필 + Fingerprint 최적화
 *
 * v4 핵심 변경사항:
 * - 워밍업된 프로필 사용 (히스토리 + 쿠키 누적)
 * - MID 쿼터 시스템 (프로필당 동일 MID 2회 제한)
 * - 창 최대화 (screenRatio 정상화)
 * - Fingerprint 진단 통과 상태
 *
 * 목표: CAPTCHA 회피율 95%~99%
 */

import { connect } from 'puppeteer-real-browser';
import { getProfileManager, ProfileData } from './server/services/traffic/shared/profile/ProfileManager';

const TEST_PRODUCT = {
  nvMid: '92254376653',
  productName: '또봇V 미니 킹포트란 마스터v 세트 변신 로봇 자동차 장난감',
  keyword: '또봇 미니'
};

const TEST_COUNT = 5;

interface TestResult {
  run: number;
  profileId: string;
  success: boolean;
  error?: string;
  duration: number;
  captcha: boolean;
}

async function runSingleTest(run: number, profile: ProfileData): Promise<TestResult> {
  const startTime = Date.now();
  let browser: any = null;

  try {
    console.log(`\n[${'='.repeat(60)}]`);
    console.log(`[Run ${run}/${TEST_COUNT}] 쇼검2 v4 - 프로필 기반 테스트`);
    console.log(`[Profile] ${profile.id} (${profile.fingerprint.version})`);
    console.log(`[${'='.repeat(60)}]`);

    // PBR 브라우저 연결 (프로필 사용)
    const connectResult = await connect({
      headless: false,
      turnstile: true,
      fingerprint: true,
      userDataDir: profile.userDataDir,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-blink-features=AutomationControlled',
        '--start-maximized',
      ],
    });

    browser = connectResult.browser;
    const page = connectResult.page;

    page.setDefaultTimeout(30000);
    page.setDefaultNavigationTimeout(30000);

    // 1. 네이버 쇼핑 접속
    console.log('[Step 1] 네이버 쇼핑 접속...');
    await page.goto('https://shopping.naver.com/', {
      waitUntil: 'domcontentloaded',
      timeout: 30000
    });
    await delay(2000 + Math.random() * 1000);

    // 2. 검색 (전체 상품명)
    console.log('[Step 2] 상품명 검색...');
    const searchInput = await page.waitForSelector('input[type="search"], input[name="query"]');
    if (!searchInput) throw new Error('Search input not found');

    // 자연스러운 타이핑
    await searchInput.click();
    await delay(300 + Math.random() * 200);

    for (const char of TEST_PRODUCT.productName) {
      await page.keyboard.type(char);
      await delay(50 + Math.random() * 100);
    }
    await delay(500 + Math.random() * 500);
    await page.keyboard.press('Enter');

    // 3. 검색 결과 대기 및 CAPTCHA 체크
    console.log('[Step 3] 검색 결과 대기...');
    await delay(3000 + Math.random() * 2000);

    // CAPTCHA 체크
    const pageContent = await page.content();
    if (pageContent.includes('캡차') || pageContent.includes('CAPTCHA') ||
        pageContent.includes('자동입력방지') || pageContent.includes('보안 확인')) {
      throw new Error('CAPTCHA detected');
    }

    // 4. MID 찾기
    console.log('[Step 4] MID 찾기...');
    const productLinks = await page.$$('a[href*="smartstore.naver.com"]');
    let found = false;

    for (const link of productLinks) {
      const href = await link.evaluate((el: Element) => el.getAttribute('href'));
      if (href && href.includes(TEST_PRODUCT.nvMid)) {
        console.log(`[Found] MID ${TEST_PRODUCT.nvMid} 발견!`);

        // 스크롤하여 보이게
        await link.evaluate((el: Element) => el.scrollIntoView({ behavior: 'smooth', block: 'center' }));
        await delay(500 + Math.random() * 500);

        // 클릭
        await link.click();
        found = true;
        break;
      }
    }

    if (!found) {
      throw new Error('MID not found in search results');
    }

    // 5. 상품 상세 페이지 대기
    console.log('[Step 5] 상품 상세 페이지 로딩...');
    await delay(5000 + Math.random() * 2000);

    // 성공 확인
    const currentUrl = page.url();
    if (currentUrl.includes('smartstore.naver.com') && currentUrl.includes(TEST_PRODUCT.nvMid)) {
      const duration = Date.now() - startTime;
      console.log(`[SUCCESS] 상품 상세 페이지 도착! (${duration}ms)`);

      return {
        run,
        profileId: profile.id,
        success: true,
        duration,
        captcha: false
      };
    } else {
      throw new Error('Failed to reach product detail page');
    }

  } catch (error: any) {
    const duration = Date.now() - startTime;
    const isCaptcha = error.message.includes('CAPTCHA');
    console.log(`[${isCaptcha ? 'CAPTCHA' : 'FAILED'}] ${error.message} (${duration}ms)`);

    return {
      run,
      profileId: profile.id,
      success: false,
      error: error.message,
      duration,
      captcha: isCaptcha
    };
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  console.log('');
  console.log('============================================================');
  console.log('  쇼검2 v4 테스트 - 멀티 프로필 + Fingerprint 최적화');
  console.log('============================================================');
  console.log(`테스트 상품: ${TEST_PRODUCT.productName.substring(0, 30)}...`);
  console.log(`MID: ${TEST_PRODUCT.nvMid}`);
  console.log(`테스트 횟수: ${TEST_COUNT}회`);
  console.log('');
  console.log('v4 핵심 변경사항:');
  console.log('  - 워밍업된 프로필 사용 (히스토리 + 쿠키)');
  console.log('  - MID 쿼터 시스템 (프로필당 2회 제한)');
  console.log('  - 창 최대화 (screenRatio 정상화)');
  console.log('  - Fingerprint 진단 통과 상태');
  console.log('');

  // 프로필 매니저 초기화
  const pm = getProfileManager();
  await pm.loadProfiles();

  const warmedProfiles = pm.getProfiles().filter(p => p.warmedUp);
  console.log(`워밍업 완료 프로필: ${warmedProfiles.length}개`);

  if (warmedProfiles.length === 0) {
    console.error('워밍업된 프로필이 없습니다. test-profile-warmup.ts를 먼저 실행하세요.');
    return;
  }

  const results: TestResult[] = [];

  for (let i = 1; i <= TEST_COUNT; i++) {
    // 사용 가능한 프로필 선택
    const profile = pm.getAvailableProfile(TEST_PRODUCT.nvMid);

    if (!profile) {
      console.log(`[Run ${i}] 사용 가능한 프로필 없음 - 스킵`);
      continue;
    }

    const result = await runSingleTest(i, profile);
    results.push(result);

    // MID 사용 기록
    if (result.success) {
      pm.recordMidUsage(profile.id, TEST_PRODUCT.nvMid);
    }

    // 브라우저 간 휴식
    if (i < TEST_COUNT) {
      console.log(`\n[휴식] 5초 대기...\n`);
      await delay(5000);
    }
  }

  // 결과 요약
  console.log('\n');
  console.log('============================================================');
  console.log('  테스트 결과 요약 (v4 - 멀티 프로필)');
  console.log('============================================================');

  const successCount = results.filter(r => r.success).length;
  const failedCount = results.filter(r => !r.success).length;
  const captchaCount = results.filter(r => r.captcha).length;
  const midNotFoundCount = results.filter(r => r.error?.includes('MID not found')).length;
  const avgDuration = results.length > 0
    ? Math.round(results.reduce((sum, r) => sum + r.duration, 0) / results.length)
    : 0;

  console.log(`성공: ${successCount}/${results.length} (${results.length > 0 ? (successCount / results.length * 100).toFixed(1) : 0}%)`);
  console.log(`실패: ${failedCount}/${results.length}`);
  console.log(`  - CAPTCHA: ${captchaCount}회`);
  console.log(`  - MID not found: ${midNotFoundCount}회`);
  console.log(`평균 시간: ${avgDuration}ms`);
  console.log('');

  // 프로필별 결과
  console.log('프로필별 결과:');
  const profileResults = new Map<string, { success: number; total: number }>();
  results.forEach(r => {
    const curr = profileResults.get(r.profileId) || { success: 0, total: 0 };
    curr.total++;
    if (r.success) curr.success++;
    profileResults.set(r.profileId, curr);
  });
  profileResults.forEach((stats, profileId) => {
    console.log(`  ${profileId}: ${stats.success}/${stats.total} 성공`);
  });

  // 상세 결과
  console.log('\n상세 결과:');
  results.forEach(r => {
    const status = r.success ? 'SUCCESS' : (r.captcha ? 'CAPTCHA' : 'FAILED');
    console.log(`  [${r.run}] ${r.profileId} - ${status} - ${r.error || 'OK'} - ${r.duration}ms`);
  });

  console.log('\n============================================================');
  const successRate = results.length > 0 ? (successCount / results.length) * 100 : 0;
  if (successRate >= 95) {
    console.log(`  v4 목표 달성! CAPTCHA 회피율 ${successRate.toFixed(1)}%`);
  } else if (successRate >= 70) {
    console.log(`  양호 - CAPTCHA 회피율 ${successRate.toFixed(1)}%`);
  } else if (successRate >= 50) {
    console.log(`  개선 필요 - CAPTCHA 회피율 ${successRate.toFixed(1)}%`);
  } else {
    console.log(`  추가 최적화 필요 - CAPTCHA 회피율 ${successRate.toFixed(1)}%`);
  }
  console.log('============================================================');
}

main().catch(console.error);
