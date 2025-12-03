/**
 * IP Rotation Module
 *
 * USB 테더링을 통한 IP 로테이션 기능
 * - 현재 IP 확인
 * - 테더링 어댑터 자동 감지
 * - 테더링 ON/OFF로 IP 변경
 */

import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// ============ 설정 ============
const TETHERING_OFF_DELAY = 3000;  // 3초
const TETHERING_ON_DELAY = 5000;   // 5초
const IP_CHECK_RETRY = 3;
const IP_CHECK_RETRY_DELAY = 2000;

// ============ IP 확인 ============
export async function getCurrentIP(): Promise<string> {
  try {
    const response = await fetch("https://api.ipify.org?format=json");
    const data = await response.json() as { ip: string };
    return data.ip;
  } catch (error) {
    // 백업 API
    try {
      const response = await fetch("https://ifconfig.me/ip");
      return (await response.text()).trim();
    } catch {
      throw new Error("IP 확인 실패: 네트워크 연결 확인 필요");
    }
  }
}

// ============ 테더링 어댑터 감지 ============
export async function getTetheringAdapter(): Promise<string | null> {
  try {
    // Windows 네트워크 어댑터 목록 가져오기
    const { stdout } = await execAsync("netsh interface show interface", { encoding: "utf8" });

    const lines = stdout.split("\n");

    // USB 테더링 관련 어댑터 찾기
    const tetheringKeywords = [
      "Remote NDIS",
      "USB 테더링",
      "USB Tethering",
      "Android USB",
      "RNDIS",
      "iPhone USB",
      "Apple Mobile Device Ethernet",
    ];

    for (const line of lines) {
      for (const keyword of tetheringKeywords) {
        if (line.toLowerCase().includes(keyword.toLowerCase())) {
          // 어댑터 이름 추출 (마지막 컬럼)
          const parts = line.trim().split(/\s{2,}/);
          if (parts.length >= 4) {
            const adapterName = parts[parts.length - 1];
            console.log(`[IPRotation] 테더링 어댑터 감지: ${adapterName}`);
            return adapterName;
          }
        }
      }
    }

    console.log("[IPRotation] 테더링 어댑터를 찾을 수 없음");
    console.log("[IPRotation] 연결된 어댑터 목록:");
    console.log(stdout);
    return null;
  } catch (error: any) {
    console.error(`[IPRotation] 어댑터 감지 실패: ${error.message}`);
    return null;
  }
}

// ============ 테더링 제어 ============
export async function disableTethering(adapterName: string): Promise<void> {
  try {
    console.log(`[IPRotation] 테더링 비활성화: ${adapterName}`);
    await execAsync(`netsh interface set interface "${adapterName}" disable`);
  } catch (error: any) {
    // 이미 비활성화된 경우 무시
    if (!error.message.includes("already")) {
      throw new Error(`테더링 비활성화 실패: ${error.message}`);
    }
  }
}

export async function enableTethering(adapterName: string): Promise<void> {
  try {
    console.log(`[IPRotation] 테더링 활성화: ${adapterName}`);
    await execAsync(`netsh interface set interface "${adapterName}" enable`);
  } catch (error: any) {
    // 이미 활성화된 경우 무시
    if (!error.message.includes("already")) {
      throw new Error(`테더링 활성화 실패: ${error.message}`);
    }
  }
}

// ============ IP 로테이션 ============
export interface IPRotationResult {
  success: boolean;
  oldIP: string;
  newIP: string;
  error?: string;
}

export async function rotateIP(adapterName?: string): Promise<IPRotationResult> {
  // 1. 어댑터 이름 확인
  const adapter = adapterName || await getTetheringAdapter();
  if (!adapter) {
    return {
      success: false,
      oldIP: "",
      newIP: "",
      error: "테더링 어댑터를 찾을 수 없음",
    };
  }

  // 2. 현재 IP 확인
  let oldIP: string;
  try {
    oldIP = await getCurrentIP();
    console.log(`[IPRotation] 현재 IP: ${oldIP}`);
  } catch (error: any) {
    return {
      success: false,
      oldIP: "",
      newIP: "",
      error: `현재 IP 확인 실패: ${error.message}`,
    };
  }

  // 3. 테더링 비활성화
  try {
    await disableTethering(adapter);
    console.log(`[IPRotation] ${TETHERING_OFF_DELAY / 1000}초 대기...`);
    await sleep(TETHERING_OFF_DELAY);
  } catch (error: any) {
    return {
      success: false,
      oldIP,
      newIP: "",
      error: `테더링 비활성화 실패: ${error.message}`,
    };
  }

  // 4. 테더링 활성화
  try {
    await enableTethering(adapter);
    console.log(`[IPRotation] ${TETHERING_ON_DELAY / 1000}초 대기 (재연결)...`);
    await sleep(TETHERING_ON_DELAY);
  } catch (error: any) {
    return {
      success: false,
      oldIP,
      newIP: "",
      error: `테더링 활성화 실패: ${error.message}`,
    };
  }

  // 5. 새 IP 확인 (재시도 포함)
  let newIP = "";
  for (let i = 0; i < IP_CHECK_RETRY; i++) {
    try {
      newIP = await getCurrentIP();
      break;
    } catch {
      console.log(`[IPRotation] IP 확인 재시도 ${i + 1}/${IP_CHECK_RETRY}...`);
      await sleep(IP_CHECK_RETRY_DELAY);
    }
  }

  if (!newIP) {
    return {
      success: false,
      oldIP,
      newIP: "",
      error: "새 IP 확인 실패: 네트워크 재연결 실패",
    };
  }

  // 6. IP 변경 확인
  if (oldIP === newIP) {
    console.log(`[IPRotation] 경고: IP가 변경되지 않음 (${oldIP})`);
    return {
      success: false,
      oldIP,
      newIP,
      error: "IP가 변경되지 않음",
    };
  }

  console.log(`[IPRotation] IP 변경 성공: ${oldIP} → ${newIP}`);
  return {
    success: true,
    oldIP,
    newIP,
  };
}

// ============ 유틸 ============
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============ 테스트 함수 ============
export async function testIPRotation(): Promise<void> {
  console.log("========================================");
  console.log("  IP Rotation 테스트");
  console.log("========================================");

  // 1. 현재 IP 확인
  console.log("\n[1] 현재 IP 확인...");
  try {
    const ip = await getCurrentIP();
    console.log(`  현재 IP: ${ip}`);
  } catch (error: any) {
    console.error(`  실패: ${error.message}`);
    return;
  }

  // 2. 테더링 어댑터 감지
  console.log("\n[2] 테더링 어댑터 감지...");
  const adapter = await getTetheringAdapter();
  if (!adapter) {
    console.error("  테더링 어댑터를 찾을 수 없음");
    console.log("  USB 테더링이 연결되어 있는지 확인하세요");
    return;
  }
  console.log(`  어댑터: ${adapter}`);

  // 3. IP 로테이션 테스트
  console.log("\n[3] IP 로테이션 실행...");
  const result = await rotateIP(adapter);

  if (result.success) {
    console.log(`  성공! ${result.oldIP} → ${result.newIP}`);
  } else {
    console.error(`  실패: ${result.error}`);
  }

  console.log("\n========================================");
  console.log("  테스트 완료");
  console.log("========================================");
}

// 직접 실행 시 테스트
if (require.main === module) {
  testIPRotation().catch(console.error);
}
