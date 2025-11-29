/**
 * 엔진 버전별 B+C Pattern Config 로더
 *
 * engine-patterns.json에서 각 엔진의 도달 방식(Reach)과 체류 시간(Dwell) 로드
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface EngineConfig {
  reach: 'B1' | 'B2';
  dwell: number;  // 초 단위 (1.2, 1.7, 2.0, 2.4)
}

export interface ReachPatternDefinition {
  name: string;
  description: string;
  scrollBeforeClick: boolean;
  scrollAmount?: number;
  scrollDelay?: number;
}

export class EngineConfigLoader {
  private static cache: Record<string, EngineConfig> = {};
  private static patternCache: Record<string, ReachPatternDefinition> = {};

  /**
   * JSON 파일에서 엔진 Config 로드
   */
  static async loadFromFile(version: string): Promise<EngineConfig> {
    if (this.cache[version]) {
      return this.cache[version];
    }

    try {
      const filePath = path.join(__dirname, '../../engine-patterns.json');
      const content = await fs.readFile(filePath, 'utf-8');
      const data = JSON.parse(content);

      const config = data.engine_config[version];
      if (!config) {
        throw new Error(`No config found for engine ${version}`);
      }

      this.cache[version] = {
        reach: config.reach,
        dwell: config.dwell
      };

      return this.cache[version];
    } catch (error: any) {
      throw new Error(`Failed to load config for ${version}: ${error.message}`);
    }
  }

  /**
   * Reach Pattern 정의 로드 (B1, B2)
   */
  static async getPatternDefinition(patternId: 'B1' | 'B2'): Promise<ReachPatternDefinition> {
    if (this.patternCache[patternId]) {
      return this.patternCache[patternId];
    }

    try {
      const filePath = path.join(__dirname, '../../engine-patterns.json');
      const content = await fs.readFile(filePath, 'utf-8');
      const data = JSON.parse(content);

      const pattern = data.patterns[patternId];
      if (!pattern) {
        throw new Error(`No pattern definition found for ${patternId}`);
      }

      this.patternCache[patternId] = pattern;
      return pattern;
    } catch (error: any) {
      throw new Error(`Failed to load pattern ${patternId}: ${error.message}`);
    }
  }

  /**
   * 캐시 클리어 (Config 변경 시)
   */
  static clearCache(): void {
    this.cache = {};
    this.patternCache = {};
  }

  /**
   * 모든 엔진의 Config 로드
   */
  static async loadAllConfigs(): Promise<Record<string, EngineConfig>> {
    const filePath = path.join(__dirname, '../../engine-patterns.json');
    const content = await fs.readFile(filePath, 'utf-8');
    const data = JSON.parse(content);

    return data.engine_config;
  }
}
