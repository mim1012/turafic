/**
 * Fingerprint 진단 스크립트
 *
 * PBR 브라우저 환경이 정상인지 진단
 * - Fingerprint Top 10 항목 체크
 * - Pre-filter 12 항목 체크
 *
 * 목적: 우회가 아닌, 현재 환경의 비정상 패턴 발견
 */

import { connect } from 'puppeteer-real-browser';
import { getProfileManager } from './server/services/traffic/shared/profile/ProfileManager';

interface DiagnosticResult {
  profile: string;
  fingerprint: {
    webdriver: boolean;
    plugins: boolean;
    mimeTypes: boolean;
    hardwareConcurrency: boolean;
    deviceMemory: boolean;
    languages: boolean;
    webglRenderer: string;
    webglVendor: string;
    dpr: number;
    screenRatio: boolean;
    audioContext: boolean;
  };
  prefilter: {
    permissionsOK: boolean;
    connectionType: string;
    domReady: number;
    loadTime: number;
    firstPaint: number | null;
    timing: {
      connectEnd: number;
      responseEnd: number;
      domInteractive: number;
    };
    windowScreenRatio: {
      deltaW: number;
      deltaH: number;
    };
  };
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  riskItems: string[];
}

async function runDiagnostic(profileId?: string): Promise<DiagnosticResult> {
  console.log('\n============================================================');
  console.log('  PBR 환경 진단 시작');
  console.log('============================================================\n');

  let userDataDir: string | undefined;

  // 프로필 지정 시 해당 프로필 사용
  if (profileId) {
    const pm = getProfileManager();
    await pm.loadProfiles();
    const profile = pm.getProfile(profileId);
    if (profile) {
      userDataDir = profile.userDataDir;
      console.log(`[Profile] ${profileId} 사용`);
      console.log(`[UserDataDir] ${userDataDir}\n`);
    }
  }

  // PBR 브라우저 연결
  const connectOptions: any = {
    headless: false,
    turnstile: true,
    fingerprint: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-blink-features=AutomationControlled',
      '--start-maximized',  // 창 최대화 - screenRatio 정상화
    ],
  };

  if (userDataDir) {
    connectOptions.userDataDir = userDataDir;
  }

  console.log('[Browser] PBR 연결 중...');
  const { browser, page } = await connect(connectOptions);

  // 네이버 쇼핑 접속 (실제 환경에서 테스트)
  console.log('[Navigate] shopping.naver.com 접속...');
  await page.goto('https://shopping.naver.com/', {
    waitUntil: 'domcontentloaded',
    timeout: 30000
  });
  await new Promise(r => setTimeout(r, 3000));

  // Fingerprint 진단 스크립트 실행
  console.log('\n[Diagnostic] Fingerprint Top 10 체크...');
  const fingerprint = await page.evaluate(() => {
    const result: any = {};

    // 1. webdriver
    result.webdriver = navigator.webdriver === false;

    // 2. plugins
    result.plugins = navigator.plugins.length > 0;

    // 3. mimeTypes
    result.mimeTypes = navigator.mimeTypes.length > 0;

    // 4. hardwareConcurrency
    result.hardwareConcurrency = [2, 4, 8, 12, 16].includes(navigator.hardwareConcurrency);

    // 5. deviceMemory
    result.deviceMemory = [2, 4, 8, 12, 16].includes((navigator as any).deviceMemory);

    // 6. languages
    result.languages = navigator.languages && navigator.languages.length >= 2;

    // 7-8. WebGL renderer/vendor 체크
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          result.webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          result.webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
        } else {
          result.webglRenderer = 'no-debug-info';
          result.webglVendor = 'no-debug-info';
        }
      } else {
        result.webglRenderer = 'no-webgl';
        result.webglVendor = 'no-webgl';
      }
    } catch {
      result.webglRenderer = 'error';
      result.webglVendor = 'error';
    }

    // 9. devicePixelRatio
    result.dpr = window.devicePixelRatio;

    // 10. screen/window 비율
    result.screenRatio = (
      Math.abs(window.outerWidth - screen.width) <= 50 &&
      Math.abs(window.outerHeight - screen.height) <= 100
    );

    // 11. AudioContext
    result.audioContext = !!(window.AudioContext || (window as any).webkitAudioContext);

    return result;
  });

  // Pre-filter 진단 스크립트 실행
  console.log('[Diagnostic] Pre-filter 12항목 체크...');
  const prefilter = await page.evaluate(async () => {
    const my: any = {};

    // 1. Permissions 체크
    try {
      const perm = await navigator.permissions.query({ name: 'geolocation' as PermissionName });
      my.permissionsOK = perm.state !== 'denied';
    } catch {
      my.permissionsOK = false;
    }

    // 2. connection.effectiveType
    my.connectionType = (navigator as any).connection?.effectiveType || 'unknown';

    // 3-4. Timing 정보
    const timing = performance.timing;
    my.domReady = timing.domContentLoadedEventEnd - timing.navigationStart;
    my.loadTime = timing.loadEventEnd - timing.navigationStart;

    // 5. first paint
    try {
      const fp = performance.getEntriesByName('first-paint')[0];
      my.firstPaint = fp ? fp.startTime : null;
    } catch {
      my.firstPaint = null;
    }

    // 6. Navigation Timing
    my.timing = {
      connectEnd: timing.connectEnd - timing.navigationStart,
      responseEnd: timing.responseEnd - timing.navigationStart,
      domInteractive: timing.domInteractive - timing.navigationStart,
    };

    // 7. window / screen 비율
    my.windowScreenRatio = {
      deltaW: window.outerWidth - screen.width,
      deltaH: window.outerHeight - screen.height
    };

    return my;
  });

  // 브라우저 종료
  await browser.close();

  // 리스크 분석
  const riskItems: string[] = [];

  // Fingerprint 리스크 체크
  if (!fingerprint.webdriver) riskItems.push('webdriver 탐지됨');
  if (!fingerprint.plugins) riskItems.push('plugins 없음');
  if (!fingerprint.mimeTypes) riskItems.push('mimeTypes 없음');
  if (!fingerprint.hardwareConcurrency) riskItems.push('hardwareConcurrency 비정상');
  if (!fingerprint.deviceMemory) riskItems.push('deviceMemory 비정상');
  if (!fingerprint.languages) riskItems.push('languages 부족');
  if (fingerprint.webglRenderer === 'no-webgl' || fingerprint.webglRenderer === 'error') {
    riskItems.push('WebGL 비정상');
  }
  if (!fingerprint.screenRatio) riskItems.push('screen/window 비율 비정상');
  if (!fingerprint.audioContext) riskItems.push('AudioContext 없음');

  // Pre-filter 리스크 체크
  if (!prefilter.permissionsOK) riskItems.push('Permissions API 실패');
  if (prefilter.connectionType === 'unknown') riskItems.push('connection.effectiveType 없음');
  if (prefilter.domReady < 100) riskItems.push('DOMContentLoaded 너무 빠름');
  if (Math.abs(prefilter.windowScreenRatio.deltaW) > 50) riskItems.push('window/screen width 차이 큼');
  if (Math.abs(prefilter.windowScreenRatio.deltaH) > 100) riskItems.push('window/screen height 차이 큼');

  // 리스크 레벨 결정
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  if (riskItems.length >= 5) riskLevel = 'HIGH';
  else if (riskItems.length >= 2) riskLevel = 'MEDIUM';

  const result: DiagnosticResult = {
    profile: profileId || 'default',
    fingerprint,
    prefilter,
    riskLevel,
    riskItems
  };

  // 결과 출력
  console.log('\n============================================================');
  console.log('  진단 결과');
  console.log('============================================================\n');

  console.log('📌 Fingerprint Top 10:');
  console.log(`  [${fingerprint.webdriver ? '✅' : '❌'}] webdriver: ${fingerprint.webdriver}`);
  console.log(`  [${fingerprint.plugins ? '✅' : '❌'}] plugins: ${fingerprint.plugins}`);
  console.log(`  [${fingerprint.mimeTypes ? '✅' : '❌'}] mimeTypes: ${fingerprint.mimeTypes}`);
  console.log(`  [${fingerprint.hardwareConcurrency ? '✅' : '❌'}] hardwareConcurrency: ${fingerprint.hardwareConcurrency}`);
  console.log(`  [${fingerprint.deviceMemory ? '✅' : '❌'}] deviceMemory: ${fingerprint.deviceMemory}`);
  console.log(`  [${fingerprint.languages ? '✅' : '❌'}] languages: ${fingerprint.languages}`);
  console.log(`  [ℹ️] WebGL Vendor: ${fingerprint.webglVendor}`);
  console.log(`  [ℹ️] WebGL Renderer: ${fingerprint.webglRenderer}`);
  console.log(`  [ℹ️] DPR: ${fingerprint.dpr}`);
  console.log(`  [${fingerprint.screenRatio ? '✅' : '❌'}] screenRatio: ${fingerprint.screenRatio}`);
  console.log(`  [${fingerprint.audioContext ? '✅' : '❌'}] audioContext: ${fingerprint.audioContext}`);

  console.log('\n📌 Pre-filter 항목:');
  console.log(`  [${prefilter.permissionsOK ? '✅' : '❌'}] Permissions: ${prefilter.permissionsOK}`);
  console.log(`  [ℹ️] Connection Type: ${prefilter.connectionType}`);
  console.log(`  [ℹ️] DOM Ready: ${prefilter.domReady}ms`);
  console.log(`  [ℹ️] Load Time: ${prefilter.loadTime}ms`);
  console.log(`  [ℹ️] First Paint: ${prefilter.firstPaint}ms`);
  console.log(`  [ℹ️] Window/Screen Delta: W=${prefilter.windowScreenRatio.deltaW}, H=${prefilter.windowScreenRatio.deltaH}`);

  console.log('\n============================================================');
  console.log(`  리스크 레벨: ${riskLevel}`);
  console.log('============================================================');

  if (riskItems.length > 0) {
    console.log('\n⚠️ 리스크 항목:');
    riskItems.forEach((item, i) => console.log(`  ${i + 1}. ${item}`));
  } else {
    console.log('\n✅ 리스크 항목 없음');
  }

  console.log('\n');

  return result;
}

// CLI 실행
const profileId = process.argv[2];
runDiagnostic(profileId).catch(console.error);
