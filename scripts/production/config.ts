/**
 * Production 트래픽 실행 설정
 */

export type SearchType = "통검" | "쇼검";
export type EngineMode = "rotation" | "single";
export type EngineVersion =
  | "v7"
  | "v8"
  | "v9"
  | "v10"
  | "v11"
  | "v12"
  | "v13"
  | "v14"
  | "v15"
  | "v16"
  | "v17"
  | "v18"
  | "v19"
  | "v20";

export const config = {
  // 검색 타입 (통검 → 쇼검으로 변경 가능)
  searchType: "통검" as SearchType,

  // 엔진 선택 모드
  // - 'rotation': v7-v20 중 랜덤 선택
  // - 'single': 특정 엔진만 사용
  engineMode: "rotation" as EngineMode,

  // engineMode가 'single'일 때 사용할 엔진
  singleEngine: "v7" as EngineVersion,

  // 작업 간 휴식 시간 (ms)
  // 봇 탐지 회피를 위해 적절한 간격 유지
  taskRestInterval: 5000,

  // 배치 간 휴식 시간 (ms)
  // 10건마다 더 긴 휴식
  batchRestInterval: 60000,

  // 한 배치당 작업 수
  batchSize: 10,

  // 슬롯 타입 필터
  slotType: "네이버쇼핑",

  // 브라우저 재시작 주기 (작업 수)
  // 메모리 누수 방지
  browserRestartInterval: 10,

  // 최대 연속 실패 횟수
  // 이 횟수 이상 연속 실패 시 일시 중지
  maxConsecutiveFailures: 5,

  // 연속 실패 시 대기 시간 (ms)
  failurePauseInterval: 300000, // 5분

  // 로그 레벨
  logLevel: "info" as "debug" | "info" | "warn" | "error",
};

export default config;
