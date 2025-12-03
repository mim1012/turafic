#!/usr/bin/env npx tsx
/**
 * Parallel IP Rotation Traffic Worker
 *
 * 병렬 3개 브라우저 + IP 로테이션 방식
 * - 3개 다른 상품 동시 처리
 * - 완료 후 USB 테더링으로 IP 변경
 * - IP 변경 확인 후 다음 배치
 *
 * 환경변수:
 *   - SUPABASE_PRODUCTION_URL (필수)
 *   - SUPABASE_PRODUCTION_KEY (필수)
 *   - TETHERING_ADAPTER: 테더링 어댑터 이름 (자동 감지)
 *   - PARALLEL_COUNT: 병렬 실행 수 (기본: 3)
 */

import * as dotenv from "dotenv";
dotenv.config();

import os from "os";
import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { EngineRouter, EngineVersion } from "../../server/services/traffic/engineRouter";
import {
  getCurrentIP,
  getTetheringAdapter,
  rotateIP,
} from "../../server/services/traffic/ipRotation";

// ============ 설정 ============
const NODE_ID = process.env.NODE_ID || `parallel-${os.hostname()}`;
const PARALLEL_COUNT = parseInt(process.env.PARALLEL_COUNT || "3");
const TETHERING_ADAPTER = process.env.TETHERING_ADAPTER || undefined;
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL || "10") * 1000;
const TASK_TIMEOUT = 60 * 1000;  // 1분 타임아웃

// ============ Supabase 클라이언트 ============
let supabase: SupabaseClient;

function initSupabase(): SupabaseClient {
  const url = process.env.SUPABASE_PRODUCTION_URL;
  const key = process.env.SUPABASE_PRODUCTION_KEY;

  if (!url || !key) {
    console.error("[ERROR] SUPABASE_PRODUCTION_URL and SUPABASE_PRODUCTION_KEY required");
    process.exit(1);
  }

  return createClient(url, key);
}

// ============ 타입 ============
interface TrafficTask {
  id: number;
  keyword: string;
  link_url: string;
  slot_id: number;
  slot_sequence: number;
  product_id?: string;
  product_name?: string;
}

interface TaskResult {
  taskId: number;
  success: boolean;
  captcha: boolean;
  error?: string;
  engineVersion: string;
  productName: string;
  nvMid: string;
}

// ============ 통계 ============
const stats = {
  total: 0,
  success: 0,
  failed: 0,
  captcha: 0,
  ipRotations: 0,
  startTime: new Date(),
};

let isRunning = true;
let currentAdapter: string | null = null;

// ============ 유틸 ============
function log(msg: string, level: "info" | "warn" | "error" = "info") {
  const time = new Date().toISOString();
  const prefix = { info: "[INFO]", warn: "[WARN]", error: "[ERROR]" }[level];
  console.log(`[${time}] ${prefix} ${msg}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function extractMidFromUrl(url: string): string {
  const match = url.match(/products\/(\d+)/);
  return match ? match[1] : "";
}

function printStats() {
  const elapsed = Math.floor((Date.now() - stats.startTime.getTime()) / 1000 / 60);
  const rate = stats.total > 0 ? ((stats.success / stats.total) * 100).toFixed(1) : "0";
  log(`Stats: Total=${stats.total} Success=${stats.success}(${rate}%) Failed=${stats.failed} Captcha=${stats.captcha} IPRotations=${stats.ipRotations} Time=${elapsed}min`);
}

// ============ DB 함수 ============
async function getNextTasks(count: number): Promise<TrafficTask[]> {
  const validTasks: TrafficTask[] = [];

  // 여러 작업 가져오기
  const { data: tasks, error } = await supabase
    .from("traffic_navershopping")
    .select("*")
    .order("id", { ascending: true })
    .limit(count * 2);  // 여유있게 가져오기

  if (error || !tasks) return [];

  for (const task of tasks) {
    if (validTasks.length >= count) break;

    if (!task.slot_id) {
      await deleteProcessedTraffic(task.id);
      continue;
    }

    // slot_naver에서 정보 확인
    const slotInfo = await getSlotProductInfo(task.slot_id);
    if (slotInfo.productName && slotInfo.mid) {
      validTasks.push(task as TrafficTask);
    } else {
      log(`Skipping task #${task.id}: missing product_name or mid`, "warn");
      await deleteProcessedTraffic(task.id);
    }
  }

  return validTasks;
}

async function getSlotProductInfo(slotId: number): Promise<{ productName: string | null; mid: string | null }> {
  const { data } = await supabase
    .from("slot_naver")
    .select("product_name, mid")
    .eq("id", slotId)
    .single();

  return {
    productName: data?.product_name || null,
    mid: data?.mid || null,
  };
}

async function updateSlotResult(slotId: number, success: boolean): Promise<void> {
  const column = success ? "success_count" : "fail_count";

  const { data: current } = await supabase
    .from("slot_naver")
    .select(column)
    .eq("id", slotId)
    .single();

  const currentValue = (current as any)?.[column] || 0;

  await supabase
    .from("slot_naver")
    .update({ [column]: currentValue + 1 })
    .eq("id", slotId);
}

async function deleteProcessedTraffic(taskId: number): Promise<void> {
  await supabase
    .from("traffic_navershopping")
    .delete()
    .eq("id", taskId);
}

async function getPendingCount(): Promise<number> {
  const { count } = await supabase
    .from("traffic_navershopping")
    .select("*", { count: "exact", head: true });
  return count || 0;
}

// ============ 트래픽 실행 (타임아웃 포함) ============
async function executeTrafficWithTimeout(task: TrafficTask): Promise<TaskResult> {
  return new Promise(async (resolve) => {
    const timeout = setTimeout(() => {
      resolve({
        taskId: task.id,
        success: false,
        captcha: false,
        error: "Timeout",
        engineVersion: "unknown",
        productName: task.keyword,
        nvMid: "",
      });
    }, TASK_TIMEOUT);

    try {
      const result = await executeTraffic(task);
      clearTimeout(timeout);
      resolve(result);
    } catch (error: any) {
      clearTimeout(timeout);
      resolve({
        taskId: task.id,
        success: false,
        captcha: false,
        error: error.message,
        engineVersion: "unknown",
        productName: task.keyword,
        nvMid: "",
      });
    }
  });
}

async function executeTraffic(task: TrafficTask): Promise<TaskResult> {
  const version: EngineVersion = EngineRouter.getRandomVersion();
  let productName = "";
  let nvMid = "";

  try {
    const engine = EngineRouter.getEngine(version);

    // slot_naver에서 정보 가져오기
    if (task.slot_id) {
      const slotInfo = await getSlotProductInfo(task.slot_id);
      if (slotInfo.mid) nvMid = slotInfo.mid;
      if (slotInfo.productName) productName = slotInfo.productName;
    }

    if (!nvMid) {
      nvMid = task.product_id || extractMidFromUrl(task.link_url);
    }

    if (!productName) {
      productName = task.keyword;
    }

    log(`[${task.id}] Executing: ${productName.substring(0, 30)}... (${version})`);

    await engine.init();
    const result = await engine.execute({
      nvMid: nvMid,
      productName: productName,
      keyword: task.keyword,
    });
    await engine.close();

    const isSuccess = result.success && !result.error?.includes("CAPTCHA") && !result.error?.includes("418");
    const isCaptcha = result.error?.includes("CAPTCHA") || false;

    return {
      taskId: task.id,
      success: isSuccess,
      captcha: isCaptcha,
      error: result.error,
      engineVersion: version,
      productName,
      nvMid,
    };
  } catch (error: any) {
    return {
      taskId: task.id,
      success: false,
      captcha: false,
      error: error.message,
      engineVersion: version,
      productName,
      nvMid,
    };
  }
}

// ============ 메인 루프 ============
async function main() {
  log("========================================");
  log("  TURAFIC Parallel IP Rotation Worker");
  log("========================================");
  log(`  Node ID: ${NODE_ID}`);
  log(`  Parallel: ${PARALLEL_COUNT} browsers`);
  log(`  Engine: v7-v20 rotation`);
  log("========================================");

  // Supabase 초기화
  supabase = initSupabase();

  // 연결 테스트
  try {
    const count = await getPendingCount();
    log(`Connected! Pending tasks: ${count}`);
  } catch (error: any) {
    log(`Connection failed: ${error.message}`, "error");
    process.exit(1);
  }

  // 테더링 어댑터 감지
  log("Detecting tethering adapter...");
  currentAdapter = TETHERING_ADAPTER || await getTetheringAdapter();
  if (!currentAdapter) {
    log("WARNING: No tethering adapter found. IP rotation disabled.", "warn");
    log("Connect USB tethering and restart.", "warn");
  } else {
    log(`Tethering adapter: ${currentAdapter}`);
  }

  // 현재 IP 확인
  try {
    const ip = await getCurrentIP();
    log(`Current IP: ${ip}`);
  } catch {
    log("Could not get current IP", "warn");
  }

  // 종료 시그널
  process.on("SIGINT", () => {
    log("Shutdown signal received...");
    isRunning = false;
    printStats();
  });

  // 메인 루프
  while (isRunning) {
    // 1. 작업 가져오기
    const tasks = await getNextTasks(PARALLEL_COUNT);

    if (tasks.length === 0) {
      const count = await getPendingCount();
      if (count === 0) {
        log("No pending tasks. Waiting...");
      }
      await sleep(POLL_INTERVAL);
      continue;
    }

    // 2. 현재 IP 확인
    let currentIP = "";
    try {
      currentIP = await getCurrentIP();
      log(`Current IP: ${currentIP}`);
    } catch {
      log("Could not get current IP", "warn");
    }

    // 3. 병렬 실행
    log(`========================================`);
    log(`Starting parallel batch: ${tasks.length} tasks`);
    log(`========================================`);

    const startTime = Date.now();
    const results = await Promise.all(
      tasks.map(task => executeTrafficWithTimeout(task))
    );
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    // 4. 결과 처리
    let batchSuccess = 0;
    let batchFailed = 0;
    let batchCaptcha = 0;

    for (const result of results) {
      stats.total++;

      if (result.success) {
        stats.success++;
        batchSuccess++;
      } else {
        stats.failed++;
        batchFailed++;
        if (result.captcha) {
          stats.captcha++;
          batchCaptcha++;
        }
      }

      // slot_naver 업데이트
      const task = tasks.find(t => t.id === result.taskId);
      if (task?.slot_id) {
        try {
          await updateSlotResult(task.slot_id, result.success);
        } catch (e) {
          log(`slot_naver update failed: ${e}`, "warn");
        }
      }

      // 완료된 작업 삭제
      try {
        await deleteProcessedTraffic(result.taskId);
      } catch (e) {
        log(`traffic delete failed: ${e}`, "warn");
      }

      const status = result.success ? "OK" : (result.captcha ? "CAPTCHA" : "FAIL");
      log(`[${result.taskId}] ${status} - ${result.productName.substring(0, 25)}...`);
    }

    log(`----------------------------------------`);
    log(`Batch completed in ${elapsed}s: ${batchSuccess} success, ${batchFailed} failed, ${batchCaptcha} captcha`);

    // 5. IP 로테이션 (테더링 어댑터가 있는 경우)
    if (currentAdapter && isRunning) {
      log(`IP rotation starting...`);
      const rotationResult = await rotateIP(currentAdapter);

      if (rotationResult.success) {
        stats.ipRotations++;
        log(`IP changed: ${rotationResult.oldIP} -> ${rotationResult.newIP}`);
      } else {
        log(`IP rotation failed: ${rotationResult.error}`, "warn");
        // 실패해도 계속 진행 (다음 배치에서 재시도)
      }
    }

    printStats();
    log(``);
  }

  log("Worker stopped");
  printStats();
}

// 실행
main().catch((error) => {
  log(`Fatal error: ${error.message}`, "error");
  process.exit(1);
});
