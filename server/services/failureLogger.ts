/**
 * MID 매칭 실패 및 트래픽 실패 로깅 시스템
 *
 * DB (Supabase traffic_failures 테이블) + JSON 파일 (logs/*.jsonl) 두 가지 방식으로 기록
 */

import * as fs from 'fs';
import * as path from 'path';
import { NaverTrafficClient } from './naverTrafficClient';

export type FailReason = 'MID_NOT_FOUND' | 'CAPTCHA' | 'BLOCKED' | 'TIMEOUT' | 'OTHER';

export interface FailureRecord {
  taskId?: number;
  slotId?: number;
  keyword: string;
  targetMid: string;
  failReason: FailReason;
  searchUrl?: string;
  foundMids?: string[];
  foundCount?: number;
  engineVersion?: string;
  errorMessage?: string;
}

export interface FailureLogRecord extends FailureRecord {
  timestamp: string;
}

export class FailureLogger {
  private logDir: string;
  private client: NaverTrafficClient | null = null;
  private dbEnabled: boolean = true;

  constructor(options?: { dbEnabled?: boolean }) {
    this.logDir = path.join(process.cwd(), 'logs');
    this.dbEnabled = options?.dbEnabled ?? true;
    this.ensureLogDir();

    if (this.dbEnabled) {
      try {
        this.client = new NaverTrafficClient();
      } catch (error) {
        console.warn('[FailureLogger] DB 클라이언트 초기화 실패, 파일 로깅만 사용:', error);
        this.dbEnabled = false;
      }
    }
  }

  private ensureLogDir(): void {
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
      console.log(`📁 로그 디렉토리 생성: ${this.logDir}`);
    }
  }

  /**
   * 실패 기록 (DB + JSON 파일 둘 다)
   */
  async logFailure(record: FailureRecord): Promise<void> {
    const timestamp = new Date().toISOString();
    const fullRecord: FailureLogRecord = { timestamp, ...record };

    // 1. JSON 파일에 기록 (동기, 빠름, 항상 실행)
    this.appendToJsonl(fullRecord);

    // 2. DB에 기록 (비동기, 실패해도 계속)
    if (this.dbEnabled && this.client) {
      try {
        await this.insertToDb(fullRecord);
      } catch (error) {
        console.error('[FailureLogger] DB 저장 실패:', error);
      }
    }
  }

  /**
   * MID_NOT_FOUND 실패 기록 (편의 메서드)
   */
  async logMidNotFound(params: {
    taskId?: number;
    slotId?: number;
    keyword: string;
    targetMid: string;
    searchUrl?: string;
    foundMids?: string[];
    foundCount?: number;
    engineVersion?: string;
  }): Promise<void> {
    await this.logFailure({
      ...params,
      failReason: 'MID_NOT_FOUND',
      errorMessage: `MID ${params.targetMid} not found in search results`,
    });
  }

  /**
   * CAPTCHA 실패 기록 (편의 메서드)
   */
  async logCaptcha(params: {
    taskId?: number;
    slotId?: number;
    keyword: string;
    targetMid: string;
    searchUrl?: string;
    engineVersion?: string;
    errorMessage?: string;
  }): Promise<void> {
    await this.logFailure({
      ...params,
      failReason: 'CAPTCHA',
    });
  }

  /**
   * BLOCKED 실패 기록 (편의 메서드)
   */
  async logBlocked(params: {
    taskId?: number;
    slotId?: number;
    keyword: string;
    targetMid: string;
    searchUrl?: string;
    engineVersion?: string;
    errorMessage?: string;
  }): Promise<void> {
    await this.logFailure({
      ...params,
      failReason: 'BLOCKED',
    });
  }

  private appendToJsonl(record: FailureLogRecord): void {
    try {
      const filename = this.getFilename(record.failReason);
      const filepath = path.join(this.logDir, filename);
      const line = JSON.stringify(record) + '\n';
      fs.appendFileSync(filepath, line, 'utf-8');

      // 전체 로그에도 기록
      const allFilepath = path.join(this.logDir, 'all-failures.jsonl');
      fs.appendFileSync(allFilepath, line, 'utf-8');

      console.log(`📝 [${record.failReason}] ${record.keyword} → ${filename}`);
    } catch (error) {
      console.error('[FailureLogger] 파일 저장 실패:', error);
    }
  }

  private getFilename(failReason: FailReason): string {
    switch (failReason) {
      case 'MID_NOT_FOUND': return 'mid-not-found.jsonl';
      case 'CAPTCHA': return 'captcha-failures.jsonl';
      case 'BLOCKED': return 'blocked-failures.jsonl';
      case 'TIMEOUT': return 'timeout-failures.jsonl';
      default: return 'other-failures.jsonl';
    }
  }

  private async insertToDb(record: FailureLogRecord): Promise<void> {
    if (!this.client) return;

    await this.client.insertFailure({
      task_id: record.taskId,
      slot_id: record.slotId,
      keyword: record.keyword,
      target_mid: record.targetMid,
      fail_reason: record.failReason,
      search_url: record.searchUrl,
      found_mids: record.foundMids,
      found_count: record.foundCount,
      engine_version: record.engineVersion,
      error_message: record.errorMessage,
    });
  }

  /**
   * 로그 파일 읽기 (분석용)
   */
  readLogs(failReason?: FailReason): FailureLogRecord[] {
    const filename = failReason
      ? this.getFilename(failReason)
      : 'all-failures.jsonl';
    const filepath = path.join(this.logDir, filename);

    if (!fs.existsSync(filepath)) {
      return [];
    }

    const content = fs.readFileSync(filepath, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);

    return lines.map(line => {
      try {
        return JSON.parse(line) as FailureLogRecord;
      } catch {
        return null;
      }
    }).filter((r): r is FailureLogRecord => r !== null);
  }

  /**
   * 통계 조회
   */
  getStats(): { [key in FailReason]?: number } & { total: number } {
    const all = this.readLogs();
    const stats: { [key: string]: number } = { total: all.length };

    for (const record of all) {
      stats[record.failReason] = (stats[record.failReason] || 0) + 1;
    }

    return stats as any;
  }
}

// 싱글톤 인스턴스 (선택적 사용)
let _instance: FailureLogger | null = null;

export function getFailureLogger(): FailureLogger {
  if (!_instance) {
    _instance = new FailureLogger();
  }
  return _instance;
}
