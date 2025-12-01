import { FingerprintProfile } from "../shared/fingerprint/types";
import { BrowserManager } from "../shared/browser/BrowserManager";
import { NavigationOps } from "../shared/browser/NavigationOps";
import { InputOps } from "../shared/browser/InputOps";
import { BlockDetector } from "../shared/detection/BlockDetector";
import { BridgeDetector } from "../shared/detection/BridgeDetector";
import { MidMatcher } from "../shared/browser/MidMatcher";
import { Logger } from "../shared/utils/Logger";

export interface TrafficProduct {
  nvMid: string;
  productName: string;
  keyword: string;
}

export interface TrafficResult {
  success: boolean;
  version: string;
  blocked: boolean;
  bridgeDetected: boolean;
  midClicked: boolean;
  error?: string;
}

export class TrafficEngineBase {
  private browserManager: BrowserManager;
  private navigationOps: NavigationOps;
  private inputOps: InputOps;
  private blockDetector: BlockDetector;
  private bridgeDetector: BridgeDetector;
  private midMatcher: MidMatcher;
  private logger: Logger;

  constructor(protected profile: FingerprintProfile) {
    this.browserManager = new BrowserManager(profile);
    this.navigationOps = new NavigationOps(this.browserManager);
    this.inputOps = new InputOps(this.browserManager);
    this.blockDetector = new BlockDetector(this.browserManager);
    this.bridgeDetector = new BridgeDetector(this.browserManager);
    this.midMatcher = new MidMatcher(this.browserManager);
    this.logger = new Logger(profile.version);
  }

  async init(): Promise<void> {
    this.logger.info("Initializing traffic engine");
    await this.browserManager.init();
  }

  async execute(product: TrafficProduct): Promise<TrafficResult> {
    this.logger.info(`Executing traffic for ${product.productName}`);

    try {
      const page = this.browserManager.getPage();

      // 1. 네이버 홈 이동 (V5 방식)
      await this.navigationOps.gotoNaverHome();
      this.logger.info("Navigated to Naver home");
      await this.delay(1500 + Math.random() * 1000); // V5: 1.5~2.5초

      // 2. 상품명으로 검색 (통검) - V5 방식
      await this.inputOps.typeSearch(product.productName);
      this.logger.info(`Searched for: ${product.productName}`);
      await this.delay(2500 + Math.random() * 1000); // V5: 2.5~3.5초

      // 3. 차단 감지
      const blocked = await this.blockDetector.isBlocked();
      if (blocked) {
        this.logger.warn("Traffic blocked by Naver");
        return {
          success: false,
          version: this.profile.version,
          blocked: true,
          bridgeDetected: false,
          midClicked: false,
          error: "Naver blocked traffic",
        };
      }

      // 4. 스크롤 다운 (자연스럽게)
      this.logger.info("Scrolling search results...");
      for (let i = 0; i < 5; i++) {
        await page.evaluate(() => window.scrollBy(0, 400));
        await this.delay(500);
      }

      // 5. MID 매칭해서 클릭 (V5 방식: 쇼핑 탭 클릭 안 함!)
      const midClicked = await this.midMatcher.clickByMid(product.nvMid);
      if (!midClicked) {
        this.logger.warn("Failed to click MID");
        return {
          success: false,
          version: this.profile.version,
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: "MID not found in search results",
        };
      }

      this.logger.info("MID clicked successfully");
      await this.naturalDelay(1500); // 1.5-2.5초 대기

      // 6. 브릿지 우회 (V5 방식)
      const currentUrl = page.url();
      const bridgeDetected = this.bridgeDetector.isBridgeUrl(currentUrl);

      if (bridgeDetected) {
        this.logger.warn("Bridge URL detected, avoiding...");
        const avoided = await this.bridgeDetector.avoidIfDetected(product.nvMid);
        if (!avoided) {
          return {
            success: false,
            version: this.profile.version,
            blocked: false,
            bridgeDetected: true,
            midClicked: true,
            error: "Bridge avoidance failed",
          };
        }
      }

      // 7. 상품 페이지 체류 (5-6초 랜덤)
      this.logger.info("Dwelling on product page...");
      await this.naturalDelay(5000);

      this.logger.success("Traffic executed successfully");
      return {
        success: true,
        version: this.profile.version,
        blocked: false,
        bridgeDetected,
        midClicked: true,
      };
    } catch (error: any) {
      this.logger.error("Traffic execution failed", error);
      return {
        success: false,
        version: this.profile.version,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: error.message,
      };
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }

  /**
   * 자연스러운 랜덤 딜레이 (사람처럼)
   */
  private naturalDelay(baseMs: number): Promise<void> {
    const randomMs = baseMs + Math.random() * 1000; // ±1초 랜덤
    return new Promise((r) => setTimeout(r, randomMs));
  }

  /**
   * 네이버 히스토리 쌓기 (trust score 상승)
   * - 뉴스 2개 + 쇼핑탭 1개 방문
   */
  private async buildNaverHistory(): Promise<void> {
    const page = this.browserManager.getPage();
    this.logger.info("히스토리 쌓기 시작 (뉴스 2개 + 쇼핑 1개)");

    // 1. 네이버 뉴스 방문
    const newsUrls = [
      'https://news.naver.com/',
      'https://entertain.naver.com/'
    ];

    for (const url of newsUrls) {
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      this.logger.info(`히스토리: ${url.substring(8, 30)}...`);
      await this.delay(2000 + Math.random() * 2000);

      // 스크롤 + 마우스 이동
      await page.evaluate(() => window.scrollBy(0, 300 + Math.random() * 200));
      await this.delay(500 + Math.random() * 500);
      await this.microMouseJitter(400 + Math.random() * 200, 300 + Math.random() * 100);
      await this.delay(1000 + Math.random() * 1000);
    }

    // 2. 쇼핑탭 방문
    await page.goto('https://shopping.naver.com/', { waitUntil: 'domcontentloaded' });
    this.logger.info("히스토리: shopping.naver.com");
    await this.delay(2000 + Math.random() * 2000);
    await page.evaluate(() => window.scrollBy(0, 400 + Math.random() * 200));
    await this.microMouseJitter(350 + Math.random() * 200, 250 + Math.random() * 100);
    await this.delay(1500 + Math.random() * 1000);

    this.logger.info("히스토리 쌓기 완료");
  }

  /**
   * 실수 행동 삽입 (35% 확률)
   * - bot score 절반 감소 효과
   */
  private async mistakeAction(currentX: number, currentY: number): Promise<{x: number, y: number}> {
    const page = this.browserManager.getPage();

    if (Math.random() < 0.35) {
      // 30~60px 범위 내 랜덤 이동
      const offsetX = (Math.random() - 0.5) * 60 + (Math.random() > 0.5 ? 30 : -30);
      const offsetY = (Math.random() - 0.5) * 60 + (Math.random() > 0.5 ? 30 : -30);
      const mistakeX = currentX + offsetX;
      const mistakeY = currentY + offsetY;

      this.logger.info(`실수 행동: (${Math.round(currentX)}, ${Math.round(currentY)}) → (${Math.round(mistakeX)}, ${Math.round(mistakeY)})`);

      await this.moveMouseBezier(currentX, currentY, mistakeX, mistakeY);
      await this.delay(300 + Math.random() * 500);

      return { x: mistakeX, y: mistakeY };
    }

    return { x: currentX, y: currentY };
  }

  /**
   * 베지어 곡선 + 흔들림 마우스 이동 (쇼검2 최적화)
   */
  private async moveMouseBezier(
    startX: number, startY: number,
    endX: number, endY: number
  ): Promise<void> {
    const page = this.browserManager.getPage();
    const steps = 20 + Math.floor(Math.random() * 10); // 20~30 스텝

    // 랜덤 컨트롤 포인트 (곡선 생성)
    const cp1x = startX + (endX - startX) * 0.3 + (Math.random() - 0.5) * 100;
    const cp1y = startY + (endY - startY) * 0.3 + (Math.random() - 0.5) * 100;
    const cp2x = startX + (endX - startX) * 0.7 + (Math.random() - 0.5) * 100;
    const cp2y = startY + (endY - startY) * 0.7 + (Math.random() - 0.5) * 100;

    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      const x = Math.pow(1-t, 3) * startX +
                3 * Math.pow(1-t, 2) * t * cp1x +
                3 * (1-t) * Math.pow(t, 2) * cp2x +
                Math.pow(t, 3) * endX;
      const y = Math.pow(1-t, 3) * startY +
                3 * Math.pow(1-t, 2) * t * cp1y +
                3 * (1-t) * Math.pow(t, 2) * cp2y +
                Math.pow(t, 3) * endY;

      // 흔들림 3~6px
      const jitterX = x + (Math.random() - 0.5) * (3 + Math.random() * 3);
      const jitterY = y + (Math.random() - 0.5) * (3 + Math.random() * 3);

      await page.mouse.move(jitterX, jitterY);
      await this.delay(10 + Math.random() * 15);
    }
  }

  /**
   * 스크롤 후 미세 마우스 흔들림 (쇼검2 최적화)
   */
  private async microMouseJitter(baseX: number, baseY: number): Promise<void> {
    const page = this.browserManager.getPage();
    const jitterCount = 2 + Math.floor(Math.random() * 2); // 2~3회
    for (let i = 0; i < jitterCount; i++) {
      const jitterX = baseX + (Math.random() - 0.5) * 30; // ±15px
      const jitterY = baseY + (Math.random() - 0.5) * 30;
      await page.mouse.move(jitterX, jitterY);
      await this.delay(50 + Math.random() * 100);
    }
  }

  /**
   * 랜덤 상품 요소 위치 반환 (쇼검2: 상위 10개 중)
   */
  private async getRandomProductElement(): Promise<{x: number, y: number} | null> {
    const page = this.browserManager.getPage();
    return await page.evaluate(() => {
      const products = document.querySelectorAll('[data-shp-contents-id]');
      if (products.length === 0) return null;

      // 상위 10개 중 선택
      const randomIdx = Math.floor(Math.random() * Math.min(products.length, 10));
      const elem = products[randomIdx];
      const rect = elem.getBoundingClientRect();

      // 정중앙 대신 ±20px 오차
      return {
        x: rect.left + rect.width / 2 + (Math.random() - 0.5) * 40,
        y: rect.top + rect.height / 2 + (Math.random() - 0.5) * 40
      };
    });
  }

  /**
   * 목표 상품 위치 반환 (쇼검2: 좌표 오차 추가)
   */
  private async findTargetProductPosition(targetMid: string): Promise<{x: number, y: number, url: string} | null> {
    const page = this.browserManager.getPage();
    return await page.evaluate((mid: string) => {
      const products = document.querySelectorAll('[data-shp-contents-id]');
      for (const elem of products) {
        const catalogMid = elem.getAttribute('data-shp-contents-id');
        if (catalogMid === mid) {
          const rect = elem.getBoundingClientRect();
          const anchor = elem.closest('a') || elem.querySelector('a');
          // ±20px 오차
          return {
            x: rect.left + rect.width / 2 + (Math.random() - 0.5) * 40,
            y: rect.top + rect.height / 2 + (Math.random() - 0.5) * 40,
            url: (anchor as HTMLAnchorElement)?.href || ''
          };
        }
      }
      return null;
    }, targetMid);
  }

  /**
   * 쇼검2 최적화 시나리오 v3 (Behavior Engine v2.0)
   * CAPTCHA 회피율 95%~99% 목표
   */
  private async executeShopping2Scenario(product: TrafficProduct): Promise<TrafficResult> {
    const page = this.browserManager.getPage();

    // Step 1: 페이지 로드 후 초기 멈춤 (1.4~2.4초)
    this.logger.info("v3 Step 1: 초기 멈춤 1.4~2.4초");
    await this.delay(1400 + Math.random() * 1000);

    // Step 2: 랜덤 곡선 이동 (초기 마우스, jitter 5~8px)
    const startX = 100 + Math.random() * 300;
    const startY = 50 + Math.random() * 50;
    let currentX = 200 + Math.random() * 400;
    let currentY = 150 + Math.random() * 100;
    this.logger.info("v3 Step 2: 초기 마우스 곡선 이동");
    await this.moveMouseBezier(startX, startY, currentX, currentY);
    await this.delay(400 + Math.random() * 500);

    // Step 3: 스크롤 패턴 (의무 2회 + 20~30% 확률로 3회)
    this.logger.info("v3 Step 3: 스크롤 2~3회");

    // 스크롤 1
    const scroll1 = 180 + Math.floor(Math.random() * 80);
    await page.evaluate((amt) => window.scrollBy(0, amt), scroll1);
    await this.delay(350 + Math.random() * 350);

    // 스크롤 2
    const scroll2 = 200 + Math.floor(Math.random() * 130);
    await page.evaluate((amt) => window.scrollBy(0, amt), scroll2);
    await this.delay(500 + Math.random() * 400);

    // 20~30% 확률로 스크롤 3
    if (Math.random() < 0.25) {
      const scroll3 = 120 + Math.floor(Math.random() * 100);
      this.logger.info(`v3 Step 3: 추가 스크롤 ${scroll3}px`);
      await page.evaluate((amt) => window.scrollBy(0, amt), scroll3);
      await this.delay(300 + Math.random() * 300);
    }

    // Step 4: 실수 행동 삽입 (35% 확률)
    const afterMistake = await this.mistakeAction(currentX, currentY);
    currentX = afterMistake.x;
    currentY = afterMistake.y;

    // Step 5: 랜덤 상품 hover (상위 10개)
    const fakeProduct = await this.getRandomProductElement();
    if (fakeProduct) {
      this.logger.info("v3 Step 5: 랜덤 상품 hover");
      await this.moveMouseBezier(currentX, currentY, fakeProduct.x, fakeProduct.y);
      await this.delay(500 + Math.random() * 600);
      currentX = fakeProduct.x;
      currentY = fakeProduct.y;
    }

    // Step 6: 목표 상품 이동 (jitter 4~6px)
    const targetProduct = await this.findTargetProductPosition(product.nvMid);
    if (!targetProduct) {
      this.logger.warn("v3: MID not found");
      return {
        success: false,
        version: this.profile.version,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: 'MID not found (v3)'
      };
    }
    this.logger.info("v3 Step 6: 목표 상품으로 이동");
    await this.moveMouseBezier(currentX, currentY, targetProduct.x, targetProduct.y);
    await this.delay(500 + Math.random() * 400);

    // Step 7: 클릭 (좌표 오차 ±25px + 딜레이 30~90ms)
    const clickX = targetProduct.x + (Math.random() - 0.5) * 50;
    const clickY = targetProduct.y + (Math.random() - 0.5) * 50;
    const clickDelay = 30 + Math.floor(Math.random() * 60);
    this.logger.info(`v3 Step 7: 클릭 (${Math.round(clickX)}, ${Math.round(clickY)}) delay=${clickDelay}ms`);
    await page.mouse.click(clickX, clickY, { delay: clickDelay });
    await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});

    // Step 8: 상세페이지 대기 (0.9~1.8초)
    this.logger.info("v3 Step 8: 상세페이지 대기");
    await this.delay(900 + Math.random() * 900);

    // Step 9: 상세페이지 스크롤 (2~4회, 220~420px)
    const detailScrollCount = 2 + Math.floor(Math.random() * 3);
    this.logger.info(`v3 Step 9: 상세페이지 스크롤 ${detailScrollCount}회`);
    for (let i = 0; i < detailScrollCount; i++) {
      const scrollAmt = 220 + Math.floor(Math.random() * 200);
      await page.evaluate((amt) => window.scrollBy(0, amt), scrollAmt);
      await this.delay(400 + Math.random() * 500);
    }

    // Step 10: 마지막 체류 (1.4~2.6초) - 뒤로가기 금지
    this.logger.info("v3 Step 10: 마지막 체류 1.4~2.6초");
    await this.delay(1400 + Math.random() * 1200);

    this.logger.success("v3 시나리오 완료");
    return {
      success: true,
      version: this.profile.version,
      blocked: false,
      bridgeDetected: false,
      midClicked: true
    };
  }

  /**
   * Fullname 트래픽 실행 (통검/쇼검/쇼검2 통합 - mode 파라미터 기반)
   *
   * 통검: 네이버 메인 → 통합검색 → 상품 클릭 (100% 성공률)
   * 쇼검: 네이버 메인 → 통합검색 → 쇼핑 링크 클릭 → 상품 클릭
   * 쇼검2: 네이버 쇼핑 직접 진입 → 검색 → 상품 클릭
   */
  async executeFullname(
    product: TrafficProduct,
    mode: '통검' | '쇼검' | '쇼검2' = '통검'
  ): Promise<TrafficResult> {
    this.logger.info(`Executing fullname traffic (${mode}) for ${product.productName}`);

    try {
      let page = this.browserManager.getPage();

      // v3: 쇼검2는 히스토리 쌓기 먼저 (trust score 상승)
      if (mode === '쇼검2') {
        await this.buildNaverHistory();
      }

      // 1. 초기 진입 (mode 분기)
      // 모든 모드: 네이버 메인 진입
      await page.goto("https://www.naver.com/", { waitUntil: "domcontentloaded" });
      this.logger.info("Navigated to Naver home (PC)");
      await this.delay(mode === '쇼검' ? 800 : 1500);

      if (mode === '쇼검2') {
        // 쇼검2: 스토어 링크 URL 추출 → page.goto()로 이동
        const storeUrl = await page.evaluate(() => {
          // 방법 1: span.service_icon.type_shopping 아이콘을 포함한 링크
          const shoppingIcon = document.querySelector('span.service_icon.type_shopping');
          if (shoppingIcon) {
            const parentLink = shoppingIcon.closest('a');
            if (parentLink && parentLink.href) {
              return parentLink.href;
            }
          }

          // 방법 2: 상단 메뉴에서 스토어 링크 찾기
          const storeLink = document.querySelector('a[href*="shopping.naver.com/ns/home"]') as HTMLAnchorElement;
          if (storeLink) {
            return storeLink.href;
          }

          // 방법 3: 스토어 텍스트로 찾기
          const links = Array.from(document.querySelectorAll('a'));
          for (const link of links) {
            if (link.innerText.trim() === '스토어' && link.href.includes('shopping')) {
              return link.href;
            }
          }

          return null;
        });

        if (storeUrl) {
          this.logger.info(`Found store URL: ${storeUrl.substring(0, 60)}`);
          const referer = page.url();
          await page.goto(storeUrl, {
            waitUntil: 'domcontentloaded',
            timeout: 15000,
            referer: referer
          });
        } else {
          this.logger.warn("Store button not found, falling back to direct URL");
          await page.goto("https://shopping.naver.com/ns/home", { waitUntil: "domcontentloaded" });
        }

        // 쇼검2: 스토어 홈에서 사전 동작 (CAPTCHA 회피)
        this.logger.info("쇼검2: 스토어 홈 사전 동작 시작");

        // 1. 스토어 홈 체류 (5~8초)
        await this.delay(5000 + Math.random() * 3000);

        // 2. 마우스 이동 (화면 중앙 → 상단으로)
        const startMouseX = 400 + Math.random() * 200;
        const startMouseY = 400 + Math.random() * 100;
        await this.moveMouseBezier(startMouseX, startMouseY, 300 + Math.random() * 200, 150 + Math.random() * 50);

        // 3. 스크롤 다운 (200~350px)
        const homeScroll = 200 + Math.floor(Math.random() * 150);
        await page.evaluate((amt) => window.scrollBy(0, amt), homeScroll);
        this.logger.info(`쇼검2: 스토어 홈 스크롤 ${homeScroll}px`);
        await this.delay(800 + Math.random() * 400);

        // 4. 스크롤 업 (원위치)
        await page.evaluate((amt) => window.scrollBy(0, -amt), homeScroll);
        await this.delay(600 + Math.random() * 300);

        // 5. 마우스 흔들림
        await this.microMouseJitter(350 + Math.random() * 100, 100 + Math.random() * 50);

        this.logger.info(`Now at: ${page.url()}`);
      }

      // 2. 검색 진입 (mode 분기)
      this.logger.info(`Searching fullname (${mode}): ${product.productName.substring(0, 50)}...`);

      let searchSuccess = false;

      if (mode === '쇼검2') {
        // 쇼검2: 네이버 쇼핑 검색창에 클릭 후 타이핑 (CAPTCHA 회피 최적화)
        const inputSelector = 'input#input_text, input[name="query"]';

        // 검색창 위치 찾기
        const inputBox = await page.evaluate(() => {
          const input = document.querySelector('input#input_text, input[name="query"]');
          if (input) {
            const rect = input.getBoundingClientRect();
            return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
          }
          return null;
        });

        if (!inputBox) {
          return {
            success: false,
            version: this.profile.version,
            blocked: false,
            bridgeDetected: false,
            midClicked: false,
            error: "Shopping search input not found (position)"
          };
        }

        // 검색창으로 마우스 이동 (베지어 곡선)
        this.logger.info("쇼검2: 검색창으로 마우스 이동");
        await this.moveMouseBezier(350, 150, inputBox.x, inputBox.y);
        await this.delay(400 + Math.random() * 300);

        // 검색창 클릭
        try {
          await page.mouse.click(inputBox.x, inputBox.y);
          this.logger.info("쇼검2: 검색창 클릭");
          await this.delay(500 + Math.random() * 300);

          // 타이핑 (느리게: 80~150ms 간격)
          this.logger.info("쇼검2: 타이핑 시작 (느린 속도)");
          await page.type(inputSelector, product.productName, { delay: 80 + Math.random() * 70 });
          await this.delay(600 + Math.random() * 400);

          // 검색 버튼 위치 찾기
          const searchBtnPos = await page.evaluate(() => {
            const btns = Array.from(document.querySelectorAll('button'));
            for (const btn of btns) {
              if (btn.className.includes('_searchInput_button_search_') ||
                  (btn.innerText.trim() === '검색' && btn.type === 'button')) {
                const rect = btn.getBoundingClientRect();
                return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
              }
            }
            return null;
          });

          if (searchBtnPos) {
            // 검색 버튼으로 마우스 이동 (베지어 곡선)
            this.logger.info("쇼검2: 검색 버튼으로 마우스 이동");
            await this.moveMouseBezier(inputBox.x, inputBox.y, searchBtnPos.x, searchBtnPos.y);
            await this.delay(300 + Math.random() * 200);

            // 마우스 클릭
            await page.mouse.click(searchBtnPos.x, searchBtnPos.y);
            this.logger.info("쇼검2: 검색 버튼 클릭");
            searchSuccess = true;
          } else {
            // 폴백: Enter 키
            this.logger.info("쇼검2: 검색 버튼 없음, Enter 키 사용");
            await page.keyboard.press('Enter');
            searchSuccess = true;
          }
        } catch (e) {
          this.logger.warn("Shopping search input click/type failed");
          searchSuccess = false;
        }

        if (!searchSuccess) {
          return {
            success: false,
            version: this.profile.version,
            blocked: false,
            bridgeDetected: false,
            midClicked: false,
            error: "Shopping search input not found"
          };
        }

        await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
        await this.delay(2500 + Math.random() * 500);

        // CAPTCHA 체크
        const blocked = await page.evaluate(() => {
          const bodyText = document.body?.innerText || '';
          return bodyText.includes('일시적으로 제한') ||
                 bodyText.includes('보안 확인을 완료해 주세요') ||
                 bodyText.includes('자동입력 방지') ||
                 bodyText.includes('영수증');
        });

        if (blocked) {
          this.logger.warn("Shopping CAPTCHA detected (쇼검2)");
          return {
            success: false,
            version: this.profile.version,
            blocked: true,
            bridgeDetected: false,
            midClicked: false,
            error: "CAPTCHA at shopping search (쇼검2)"
          };
        }

        // 쇼검2 최적화 시나리오 실행 (12단계) - CAPTCHA 회피율 95% 목표
        this.logger.info("쇼검2: 최적화 시나리오 시작 (12단계)");
        return await this.executeShopping2Scenario(product);

      } else if (mode === '통검') {
        // 통합검색
        searchSuccess = await page.evaluate((query: string) => {
          const input = document.querySelector('input.search_input, input#query') as HTMLInputElement;
          if (input) {
            input.value = query;
            input.focus();
            input.dispatchEvent(new Event('input', { bubbles: true }));
            const btn = document.querySelector('button.btn_search, button.bt_search');
            if (btn) {
              (btn as HTMLElement).click();
              return true;
            }
          }
          return false;
        }, product.productName);

      } else {
        // 쇼검: 통합검색 → 쇼핑 영역 링크 클릭 (이전 성공 방식)
        searchSuccess = await page.evaluate((query: string) => {
          const input = document.querySelector('input.search_input, input#query') as HTMLInputElement;
          if (input) {
            input.value = query;
            input.focus();
            input.dispatchEvent(new Event('input', { bubbles: true }));
            const btn = document.querySelector('button.btn_search, button.bt_search');
            if (btn) {
              (btn as HTMLElement).click();
              return true;
            }
          }
          return false;
        }, product.productName);

        if (!searchSuccess) {
          return {
            success: false,
            version: this.profile.version,
            blocked: false,
            bridgeDetected: false,
            midClicked: false,
            error: "Unified search failed"
          };
        }

        await page.waitForNavigation({ waitUntil: 'domcontentloaded' }).catch(() => {});
        await this.delay(2000);  // 원래대로 복원

        // 쇼핑 영역 링크 URL 추출
        const shoppingUrl = await page.evaluate(() => {
          const links = Array.from(document.querySelectorAll('a'));
          for (const link of links) {
            const href = link.getAttribute('href') || '';
            if (href.includes('search.shopping.naver.com/search')) {
              return href;
            }
          }
          return null;
        });

        if (!shoppingUrl) {
          return {
            success: false,
            version: this.profile.version,
            blocked: false,
            bridgeDetected: false,
            midClicked: false,
            error: "Shopping link not found"
          };
        }

        // 쇼핑 검색 페이지로 직접 이동 (Referer 설정)
        const unifiedUrl = page.url();
        await page.goto(shoppingUrl, {
          waitUntil: 'networkidle0',  // 네트워크 완전 대기
          timeout: 30000,
          referer: unifiedUrl
        });
        await this.delay(5000);  // 상품 렌더링 대기 (SPA)

        // 쇼검 CAPTCHA 체크 (쇼핑 검색 페이지에서)
        const shoppingBlocked = await page.evaluate(() => {
          const bodyText = document.body?.innerText || '';
          return bodyText.includes('보안 확인을 완료해 주세요') ||
                 bodyText.includes('일시적으로 제한') ||
                 bodyText.includes('자동입력 방지') ||
                 bodyText.includes('실제 사용자임을 확인');
        });

        if (shoppingBlocked) {
          this.logger.warn("CAPTCHA detected at shopping search (쇼검)");
          return {
            success: false,
            version: this.profile.version,
            blocked: true,
            bridgeDetected: false,
            midClicked: false,
            error: "CAPTCHA at shopping search"
          };
        }

        searchSuccess = true;
      }

      if (!searchSuccess) {
        return {
          success: false,
          version: this.profile.version,
          blocked: false,
          bridgeDetected: false,
          midClicked: false,
          error: "Search input not found"
        };
      }

      // 통검은 추가 navigation 대기 필요
      if (mode === '통검') {
        await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => {});
        await this.naturalDelay(2000);

        // CAPTCHA 체크
        const blocked = await page.evaluate(() => {
          const bodyText = document.body?.innerText || '';
          return bodyText.includes('일시적으로 제한') ||
                 bodyText.includes('보안 확인') ||
                 bodyText.includes('자동입력 방지');
        });

        if (blocked) {
          this.logger.warn("CAPTCHA detected");
          return {
            success: false,
            version: this.profile.version,
            blocked: true,
            bridgeDetected: false,
            midClicked: false,
            error: "CAPTCHA at unified search"
          };
        }
      }

      // 4. Reach Pattern 실행 (통검만 적용)
      if (mode === '통검') {
        const { EngineConfigLoader } = await import('../shared/config/EngineConfigLoader');
        const config = await EngineConfigLoader.loadFromFile(this.profile.version);
        const reachPattern = await EngineConfigLoader.getPatternDefinition(config.reach);

        this.logger.info(`Pattern: ${config.reach} + ${config.dwell}초`);

        if (reachPattern.scrollBeforeClick) {
          // B2: 스크롤 후 클릭
          this.logger.info(`B2: Scroll ${reachPattern.scrollAmount}px before click`);
          await page.evaluate((amount: number) => window.scrollBy(0, amount), reachPattern.scrollAmount);
          await this.delay(reachPattern.scrollDelay);
        } else {
          // B1: 바로 클릭
          this.logger.info(`B1: Direct click`);
        }
      } else {
        // 쇼검/쇼검2: 바로 클릭 (패턴 미적용)
        this.logger.info(`${mode}: Direct click (no pattern)`);
      }

      // 5. MID 매칭 (통검/쇼검 분기)
      this.logger.info(`Finding MID ${product.nvMid} in search results...`);

      if (mode === '통검') {
        // 통검: URL 추출 → page.goto()
        // 참고: smartstore MID와 검색 결과 catalog MID가 다를 수 있음!
        // 전략: 1) 정확한 MID 매치 시도 → 2) 실패시 첫 번째 smartstore 링크 클릭
        const productUrl = await page.evaluate((targetMid: string) => {
          const links = Array.from(document.querySelectorAll("a"));

          // 1단계: 정확한 MID 매치 시도
          for (const link of links) {
            const href = link.href || "";

            if (href.includes(`smartstore.naver.com`) && href.includes(`/products/${targetMid}`)) {
              console.log(`[Found Exact] smartstore: ${href}`);
              return href;
            }
            if (href.includes(`brand.naver.com`) && href.includes(`/products/${targetMid}`)) {
              console.log(`[Found Exact] brand: ${href}`);
              return href;
            }
            if (href.includes(`/catalog/${targetMid}`)) {
              console.log(`[Found Exact] catalog: ${href}`);
              return href;
            }
          }

          // nv_mid 파라미터로 찾기 (bridge/searchGate URL)
          for (const link of links) {
            const href = link.href || "";
            // Naver uses nv_mid (with underscore) in bridge URLs
            const nvMidMatch = href.match(/[?&]nv_mid=(\d+)/i);
            if (nvMidMatch && nvMidMatch[1] === targetMid) {
              console.log(`[Found Exact] nv_mid param: ${href}`);
              return href;
            }
          }

          // 2단계: 정확한 MID 없음 → 첫 번째 smartstore/brand 상품 링크 클릭
          // (전체 상품명으로 검색했으므로 첫 번째 결과가 대상 상품일 가능성 높음)
          console.log(`[Fallback] Exact MID ${targetMid} not found, using first product link...`);

          for (const link of links) {
            const href = link.href || "";

            // smartstore.naver.com/main/products/XXX 또는 smartstore.naver.com/xxx/products/XXX
            if (href.includes(`smartstore.naver.com`) && href.includes(`/products/`)) {
              // outlink 제외 (리다이렉트 링크)
              if (!href.includes('/outlink/')) {
                console.log(`[Fallback] First smartstore product: ${href}`);
                return href;
              }
            }

            // brand.naver.com/xxx/products/XXX
            if (href.includes(`brand.naver.com`) && href.includes(`/products/`)) {
              console.log(`[Fallback] First brand product: ${href}`);
              return href;
            }
          }

          // 3단계: catalog 링크 시도
          for (const link of links) {
            const href = link.href || "";
            if (href.includes(`/catalog/`) && href.includes('shopping.naver.com')) {
              console.log(`[Fallback] First catalog: ${href}`);
              return href;
            }
          }

          console.log(`[Debug] No product links found. Total links: ${links.length}`);
          return null;
        }, product.nvMid);

        if (!productUrl) {
          this.logger.warn("MID not found in unified search results");
          return {
            success: false,
            version: this.profile.version,
            blocked: false,
            bridgeDetected: false,
            midClicked: false,
            error: "MID not found (통검)"
          };
        }

        this.logger.info(`Found product URL: ${productUrl.substring(0, 60)}...`);
        // 상품 페이지로 이동
        const currentUrl = page.url();
        await page.goto(productUrl, {
          waitUntil: 'domcontentloaded',
          timeout: 15000,
          referer: currentUrl
        });
        await this.delay(1000);

      } else {
        // 쇼검: 마우스 클릭 → 새 탭 방식 (봇 탐지 회피)
        // page.goto() 직접 이동은 봇으로 감지됨!

        // 1. MID 매칭되는 상품 요소 찾아서 클릭
        const clickResult = await page.evaluate((targetMid: string) => {
          // data-shp-contents-id로 찾기
          const elements = document.querySelectorAll('[data-shp-contents-id]');
          for (const elem of elements) {
            const catalogMid = elem.getAttribute('data-shp-contents-id');
            if (catalogMid === targetMid) {
              const anchor = elem.tagName === 'A' ? elem : (elem.closest('a') || elem.querySelector('a'));
              if (anchor) {
                const rect = anchor.getBoundingClientRect();
                return {
                  found: true,
                  x: rect.left + rect.width / 2,
                  y: rect.top + rect.height / 2,
                  href: (anchor as HTMLAnchorElement).href
                };
              }
            }
          }

          // href에서 MID 찾기
          const links = Array.from(document.querySelectorAll("a"));
          for (const link of links) {
            const href = link.href || "";
            const nvMidMatch = href.match(/[?&]nv_mid=(\d+)/i);
            if (nvMidMatch && nvMidMatch[1] === targetMid) {
              const rect = link.getBoundingClientRect();
              return {
                found: true,
                x: rect.left + rect.width / 2,
                y: rect.top + rect.height / 2,
                href
              };
            }
            if (href.includes(`/products/${targetMid}`) || href.includes(`/catalog/${targetMid}`)) {
              const rect = link.getBoundingClientRect();
              return {
                found: true,
                x: rect.left + rect.width / 2,
                y: rect.top + rect.height / 2,
                href
              };
            }
          }

          return { found: false, x: 0, y: 0, href: '' };
        }, product.nvMid);

        if (!clickResult.found) {
          return {
            success: false,
            version: this.profile.version,
            blocked: false,
            bridgeDetected: false,
            midClicked: false,
            error: `MID not found (${mode})`
          };
        }

        this.logger.info(`Found product URL (쇼검): ${clickResult.href.substring(0, 60)}...`);

        // 2. 새 탭 열림 감지 준비
        const browser = page.browser();
        const pagesBefore = (await browser.pages()).length;

        // 3. 마우스 클릭으로 상품 클릭 (자연스러운 행동)
        await page.mouse.click(clickResult.x, clickResult.y);
        await this.delay(2000);

        // 4. 새 탭이 열렸는지 확인
        const pagesAfter = await browser.pages();
        if (pagesAfter.length > pagesBefore) {
          // 새 탭이 열림 → 새 탭으로 이동
          const newPage = pagesAfter[pagesAfter.length - 1];
          await newPage.bringToFront();
          await newPage.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});

          // 기존 page를 새 탭으로 교체하여 이후 로직 진행
          // (여기서는 page 변수를 교체할 수 없으므로, 새 탭의 URL을 확인하고 성공 처리)
          const newUrl = newPage.url();
          const isProductPage = newUrl.includes("/catalog/") ||
                               newUrl.includes("/products/") ||
                               newUrl.includes("smartstore.naver.com") ||
                               newUrl.includes("brand.naver.com");

          // 새 탭 CAPTCHA 체크
          const newPageBlocked = await newPage.evaluate(() => {
            const bodyText = document.body?.innerText || '';
            return bodyText.includes('보안 확인을 완료해 주세요') ||
                   bodyText.includes('일시적으로 제한');
          });

          // 새 탭 닫기
          await newPage.close();

          if (newPageBlocked) {
            this.logger.warn("Product page CAPTCHA detected (new tab)");
            return {
              success: false,
              version: this.profile.version,
              blocked: true,
              bridgeDetected: false,
              midClicked: true,
              error: "Product page CAPTCHA (new tab)"
            };
          }

          if (isProductPage) {
            // 체류 시간
            this.logger.info(`Dwell (쇼검): 1.0초`);
            await this.delay(1000);

            return {
              success: true,
              version: this.profile.version,
              blocked: false,
              bridgeDetected: false,
              midClicked: true
            };
          }
        }

        // 새 탭이 안 열린 경우 - 같은 페이지에서 이동했을 수 있음
        await this.delay(1000);
      }

      // 7. 상품 페이지 CAPTCHA 체크
      const productPageBlocked = await page.evaluate(() => {
        const bodyText = document.body?.innerText || '';
        const title = document.title || '';

        // CAPTCHA 감지 - "보안 확인을 완료해 주세요" 메시지가 있으면 차단
        // (영수증 캡챠 또는 "실제 사용자임을 확인" 캡챠 모두 감지)
        if (bodyText.includes('보안 확인을 완료해 주세요')) {
          return true;
        }

        // title에 "보안 확인"이 있으면 CAPTCHA 페이지
        if (title.includes('보안 확인')) {
          return true;
        }

        // 일시적 제한 페이지
        if (bodyText.includes('일시적으로 제한')) {
          return true;
        }

        return false;
      });

      if (productPageBlocked) {
        this.logger.warn("Product page CAPTCHA detected");
        return {
          success: false,
          version: this.profile.version,
          blocked: true,
          bridgeDetected: false,
          midClicked: true,
          error: "Product page CAPTCHA"
        };
      }

      // 8. 최종 URL 검증
      const finalUrl = page.url();
      const isProductPage = finalUrl.includes("/catalog/") ||
                           finalUrl.includes("/products/") ||
                           finalUrl.includes("smartstore.naver.com") ||
                           finalUrl.includes("brand.naver.com");

      if (!isProductPage) {
        return {
          success: false,
          version: this.profile.version,
          blocked: false,
          bridgeDetected: false,
          midClicked: true,
          error: "Not a product page"
        };
      }

      // 8. 체류 (통검: C Pattern, 쇼검/쇼검2: 1초 고정)
      if (mode === '통검') {
        const { EngineConfigLoader } = await import('../shared/config/EngineConfigLoader');
        const config = await EngineConfigLoader.loadFromFile(this.profile.version);
        const dwellMs = config.dwell * 1000;  // 1.2초 → 1200ms
        this.logger.info(`Dwell (통검): ${config.dwell}초`);
        await this.delay(dwellMs);
      } else {
        // 쇼검/쇼검2: 1초 (빠른 속도)
        this.logger.info(`Dwell (${mode}): 1.0초`);
        await this.delay(1000);
      }

      this.logger.success("Fullname traffic executed successfully");
      return {
        success: true,
        version: this.profile.version,
        blocked: false,
        bridgeDetected: false,
        midClicked: true
      };

    } catch (error: any) {
      this.logger.error("Fullname traffic execution failed", error);
      return {
        success: false,
        version: this.profile.version,
        blocked: false,
        bridgeDetected: false,
        midClicked: false,
        error: error.message
      };
    }
  }

  async close(): Promise<void> {
    this.logger.info("Closing browser");
    await this.browserManager.close();
  }
}
