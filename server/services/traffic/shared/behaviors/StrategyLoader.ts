/**
 * JSON Config 기반 전략 로더
 *
 * strategies/ 폴더의 JSON 파일을 동적으로 로드
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface StrategyConfig {
  id: string;
  name: string;
  type: 'input' | 'scroll' | 'dwell';
  enabled: boolean;
  config: Record<string, any>;
}

export class StrategyLoader {
  private static cache = new Map<string, StrategyConfig>();

  /**
   * 특정 전략 로드
   */
  static async load(type: 'input' | 'scroll' | 'dwell', id: string): Promise<StrategyConfig> {
    const cacheKey = `${type}/${id}`;

    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey)!;
    }

    const filePath = path.join(__dirname, `../../strategies/${type}/${id}.json`);

    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const config: StrategyConfig = JSON.parse(content);

      if (!config.enabled) {
        throw new Error(`Strategy ${type}/${id} is disabled`);
      }

      this.cache.set(cacheKey, config);
      return config;
    } catch (error: any) {
      throw new Error(`Failed to load strategy ${type}/${id}: ${error.message}`);
    }
  }

  /**
   * 전략 타입의 모든 활성화된 전략 로드
   */
  static async loadAll(type: 'input' | 'scroll' | 'dwell'): Promise<StrategyConfig[]> {
    const dirPath = path.join(__dirname, `../../strategies/${type}`);

    try {
      const files = await fs.readdir(dirPath);
      const configs: StrategyConfig[] = [];

      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(dirPath, file), 'utf-8');
          const config: StrategyConfig = JSON.parse(content);

          if (config.enabled) {
            configs.push(config);
          }
        }
      }

      return configs;
    } catch (error: any) {
      console.error(`Failed to load strategies from ${type}:`, error.message);
      return [];
    }
  }

  /**
   * 랜덤 전략 선택
   */
  static async loadRandom(type: 'input' | 'scroll' | 'dwell'): Promise<StrategyConfig> {
    const allConfigs = await this.loadAll(type);

    if (allConfigs.length === 0) {
      throw new Error(`No enabled strategies found for type: ${type}`);
    }

    const randomIndex = Math.floor(Math.random() * allConfigs.length);
    return allConfigs[randomIndex];
  }

  /**
   * 캐시 클리어 (테스트 또는 재로드 시)
   */
  static clearCache(): void {
    this.cache.clear();
  }
}
