/**
 * JSON Config 기반 전략 실행기
 *
 * JSON 설정을 읽고 실제 브라우저 동작으로 변환
 */

import type { Page } from 'puppeteer-core';
import type { StrategyConfig } from './StrategyLoader';

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

export class StrategyExecutor {
  /**
   * Input 전략 실행
   */
  static async executeInput(page: Page, text: string, config: StrategyConfig): Promise<boolean> {
    const { method } = config.config;

    if (method === 'evaluate') {
      // 복붙 방식 (page.evaluate 사용)
      await delay(config.config.preDelay || 0);

      const success = await page.evaluate(
        (selector: string, value: string, submitSelector: string) => {
          const input = document.querySelector(selector) as HTMLInputElement;
          if (!input) return false;

          input.value = value;
          input.focus();
          input.dispatchEvent(new Event('input', { bubbles: true }));

          const btn = document.querySelector(submitSelector);
          if (btn) {
            (btn as HTMLElement).click();
            return true;
          }
          return false;
        },
        config.config.selector,
        text,
        config.config.submitSelector
      );

      await delay(config.config.postDelay || 0);
      return success;

    } else if (method === 'keyboard') {
      // 타이핑 방식 (keyboard API 사용)
      const input = await page.$(config.config.selector);
      if (!input) return false;

      await delay(config.config.preClickDelay || 0);
      await input.click();

      // 한 글자씩 타이핑
      for (const char of text) {
        const charDelay =
          config.config.delayPerChar + Math.random() * (config.config.delayVariation || 0);
        await page.keyboard.type(char, { delay: charDelay });
      }

      await delay(config.config.postTypeDelay || 0);

      if (config.config.submitMethod === 'enter') {
        await page.keyboard.press('Enter');
      }

      return true;
    }

    throw new Error(`Unsupported input method: ${method}`);
  }

  /**
   * Scroll 전략 실행
   */
  static async executeScroll(page: Page, config: StrategyConfig): Promise<void> {
    if (config.config.pattern) {
      // Pattern 기반 (자연스러운 스크롤)
      for (const step of config.config.pattern) {
        const amount = step.direction === 'down' ? step.amount : -step.amount;

        for (let i = 0; i < step.repeat; i++) {
          await page.evaluate((scrollAmount: number) => {
            window.scrollBy(0, scrollAmount);
          }, amount);
          await delay(step.delay);
        }
      }

    } else if (config.config.iterationsMin !== undefined) {
      // Random 기반
      const iterations =
        config.config.iterationsMin +
        Math.floor(
          Math.random() * (config.config.iterationsMax - config.config.iterationsMin)
        );

      for (let i = 0; i < iterations; i++) {
        const scrollAmount =
          config.config.scrollAmountMin +
          Math.random() * (config.config.scrollAmountMax - config.config.scrollAmountMin);

        await page.evaluate((amount: number) => window.scrollBy(0, amount), scrollAmount);

        const delayTime =
          config.config.delayMin + Math.random() * (config.config.delayMax - config.config.delayMin);
        await delay(delayTime);
      }

    } else {
      // Fixed 기반
      for (let i = 0; i < config.config.iterations; i++) {
        const amount =
          config.config.direction === 'down'
            ? config.config.scrollAmount
            : -config.config.scrollAmount;

        await page.evaluate((scrollAmount: number) => window.scrollBy(0, scrollAmount), amount);
        await delay(config.config.delayBetween);
      }
    }
  }

  /**
   * Dwell 전략 실행
   */
  static async executeDwell(page: Page, config: StrategyConfig): Promise<void> {
    const duration =
      config.config.durationMin +
      Math.random() * (config.config.durationMax - config.config.durationMin);

    if (config.config.scrollWhileDwell) {
      // 스크롤하면서 체류
      const scrollCount = Math.floor(duration / config.config.scrollInterval);

      for (let i = 0; i < scrollCount; i++) {
        await page.evaluate(
          (amount: number) => window.scrollBy(0, amount),
          config.config.scrollAmount
        );
        await delay(config.config.scrollInterval);
      }
    } else {
      // 단순 대기
      await delay(duration);
    }
  }
}
