/**
 * Variable Combinations Service
 * L18 직교배열표 기반 초기 생성 + 유전 알고리즘 진화
 */

import { getDb } from "../db";
import { variableCombinations, type InsertVariableCombination } from "../../drizzle/schema";
import { eq, gte, and, desc } from "drizzle-orm";

// ========================================
// 1. 변수 정의 및 L18 직교배열표
// ========================================

export interface Variables {
  user_agent: string;
  cw_mode: string;
  entry_point: string;
  cookie_strategy: string;
  image_loading: string;
  input_method: string;
  random_clicks: number;
  more_button: string;
  x_with_header: string;
  delay_mode: string;
  // AdPang 통합 신규 변수 (2개)
  work_type: string;
  sec_fetch_site_mode: string;
}

export const VARIABLE_CONFIG = {
  user_agent: ['UA58', 'UA67', 'UA71'],
  cw_mode: ['CW해제', 'CW유지'],
  entry_point: ['쇼핑DI', '광고DI', '통합검색'],
  cookie_strategy: ['로그인쿠키', '비로그인쿠키'],
  image_loading: ['이미지패스', '이미지로드'],
  input_method: ['복붙', '타이핑'],
  random_clicks: [0, 3, 6],
  more_button: ['더보기패스', '더보기클릭'],
  x_with_header: ['x-with삼성', 'x-with갤럭시'],
  delay_mode: ['딜레이감소', '딜레이정상'],
  // AdPang 통합 신규 변수 (2개)
  work_type: ['검색만', '검색+클릭', '검색+클릭+체류', '리뷰조회'],
  sec_fetch_site_mode: ['same-origin', 'same-site', 'cross-site', 'none'],
} as const;

// L18(2^1 × 3^7) 직교배열 행렬
const L18_MATRIX = [
  [0, 0, 0, 0, 0, 0, 0, 0],
  [0, 1, 1, 1, 1, 1, 1, 1],
  [0, 2, 2, 2, 2, 2, 2, 2],
  [1, 0, 0, 1, 1, 2, 2, 2],
  [1, 1, 1, 2, 2, 0, 0, 0],
  [1, 2, 2, 0, 0, 1, 1, 1],
  [2, 0, 1, 0, 2, 0, 2, 1],
  [2, 1, 2, 1, 0, 1, 0, 2],
  [2, 2, 0, 2, 1, 2, 1, 0],
  [0, 0, 2, 2, 1, 1, 0, 2],
  [0, 1, 0, 0, 2, 2, 1, 0],
  [0, 2, 1, 1, 0, 0, 2, 1],
  [1, 0, 1, 2, 0, 2, 1, 2],
  [1, 1, 2, 0, 1, 0, 2, 0],
  [1, 2, 0, 1, 2, 1, 0, 1],
  [2, 0, 2, 1, 2, 1, 2, 0],
  [2, 1, 0, 2, 0, 2, 0, 1],
  [2, 2, 1, 0, 1, 0, 1, 2],
];

// ========================================
// 2. L18 초기 조합 생성
// ========================================

export function generateInitialCombinations(): InsertVariableCombination[] {
  return L18_MATRIX.map((row, rowIdx) => {
    const c8Value = row[7]; // 0, 1, 2

    const variables: Variables = {
      user_agent: VARIABLE_CONFIG.user_agent[row[0]],
      entry_point: VARIABLE_CONFIG.entry_point[row[1] % 3],
      random_clicks: VARIABLE_CONFIG.random_clicks[row[2] % 3],

      // 2수준 변수들 - C8 값과 행 인덱스로 분배
      cw_mode: VARIABLE_CONFIG.cw_mode[c8Value % 2],
      cookie_strategy: VARIABLE_CONFIG.cookie_strategy[Math.floor(c8Value / 2) % 2],
      image_loading: VARIABLE_CONFIG.image_loading[(rowIdx % 3) % 2],
      input_method: VARIABLE_CONFIG.input_method[(rowIdx % 5) % 2],
      more_button: VARIABLE_CONFIG.more_button[(rowIdx % 7) % 2],
      x_with_header: VARIABLE_CONFIG.x_with_header[(rowIdx % 11) % 2],
      delay_mode: VARIABLE_CONFIG.delay_mode[(rowIdx % 13) % 2],

      // AdPang 통합 신규 변수 (2개) - 행 인덱스로 분배
      work_type: VARIABLE_CONFIG.work_type[rowIdx % 4],
      sec_fetch_site_mode: VARIABLE_CONFIG.sec_fetch_site_mode[Math.floor(rowIdx / 4) % 4],
    };

    return {
      variables: JSON.stringify(variables),
      status: 'new',
      generation: 0,
      performanceScore: 0,
      avgRank: null,
      successRate: null,
      captchaAvoidRate: null,
    };
  });
}

// ========================================
// 3. 성능 점수 계산
// ========================================

export function calculatePerformanceScore(metrics: {
  successRate: number;      // 0-100
  avgRank: number;          // 1-100
  captchaAvoidRate: number; // 0-100
  consistencyScore: number; // 0-100
}): number {
  const score = (
    0.4 * metrics.successRate +
    0.3 * (100 - metrics.avgRank) +
    0.2 * metrics.captchaAvoidRate +
    0.1 * metrics.consistencyScore
  ) * 100; // 0-10000 스케일

  return Math.round(score);
}

// ========================================
// 4. 등급 자동 분류
// ========================================

export function classifyByPerformance(
  performanceScore: number,
  testCount: number
): 'new' | 'testing' | 'elite' | 'significant' | 'deprecated' {
  // 최소 테스트 횟수 미충족 시 testing 상태 유지
  if (testCount < 10) return 'testing';

  // 성능 점수 기준 분류
  if (performanceScore >= 8000) {
    return 'elite';          // 상위 10% (8000-10000)
  } else if (performanceScore >= 5000) {
    return 'significant';    // 중간 40% (5000-7999)
  } else {
    return 'deprecated';     // 하위 50% (0-4999)
  }
}

// ========================================
// 5. 유전 알고리즘 - 선택 (Selection)
// ========================================

export async function selectElites(generation: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  // 해당 세대의 조합 조회
  const currentPopulation = await db
    .select()
    .from(variableCombinations)
    .where(eq(variableCombinations.generation, generation))
    .orderBy(desc(variableCombinations.performanceScore));

  // 상위 10% 선택
  const eliteCount = Math.ceil(currentPopulation.length * 0.1);
  const elites = currentPopulation.slice(0, eliteCount);

  // Elite 상태 업데이트
  for (const elite of elites) {
    await db
      .update(variableCombinations)
      .set({ status: 'elite' })
      .where(eq(variableCombinations.id, elite.id));
  }

  return elites;
}

// ========================================
// 6. 유전 알고리즘 - 교차 (Crossover)
// ========================================

export function crossover(parent1: Variables, parent2: Variables): Variables {
  const keys = Object.keys(parent1) as Array<keyof Variables>;
  const splitPoint = Math.floor(Math.random() * keys.length);

  const child: any = {};

  keys.forEach((key, idx) => {
    child[key] = idx < splitPoint ? parent1[key] : parent2[key];
  });

  return child as Variables;
}

// ========================================
// 7. 유전 알고리즘 - 변이 (Mutation)
// ========================================

export function mutate(variables: Variables): Variables {
  const mutated = { ...variables };
  const keys = Object.keys(VARIABLE_CONFIG) as Array<keyof typeof VARIABLE_CONFIG>;

  // 변이 개수 결정 (1-2개)
  const mutateCount = Math.random() < 0.5 ? 1 : 2;

  for (let i = 0; i < mutateCount; i++) {
    const randomKey = keys[Math.floor(Math.random() * keys.length)];
    const options = VARIABLE_CONFIG[randomKey];
    const newValue = options[Math.floor(Math.random() * options.length)];

    (mutated as any)[randomKey] = newValue;
  }

  return mutated;
}

// ========================================
// 8. 완전 랜덤 조합 생성
// ========================================

export function generateRandomCombination(generation: number): InsertVariableCombination {
  const variables: Variables = {
    user_agent: VARIABLE_CONFIG.user_agent[Math.floor(Math.random() * 3)],
    cw_mode: VARIABLE_CONFIG.cw_mode[Math.floor(Math.random() * 2)],
    entry_point: VARIABLE_CONFIG.entry_point[Math.floor(Math.random() * 3)],
    cookie_strategy: VARIABLE_CONFIG.cookie_strategy[Math.floor(Math.random() * 2)],
    image_loading: VARIABLE_CONFIG.image_loading[Math.floor(Math.random() * 2)],
    input_method: VARIABLE_CONFIG.input_method[Math.floor(Math.random() * 2)],
    random_clicks: VARIABLE_CONFIG.random_clicks[Math.floor(Math.random() * 3)],
    more_button: VARIABLE_CONFIG.more_button[Math.floor(Math.random() * 2)],
    x_with_header: VARIABLE_CONFIG.x_with_header[Math.floor(Math.random() * 2)],
    delay_mode: VARIABLE_CONFIG.delay_mode[Math.floor(Math.random() * 2)],
    // AdPang 통합 신규 변수 (2개)
    work_type: VARIABLE_CONFIG.work_type[Math.floor(Math.random() * 4)],
    sec_fetch_site_mode: VARIABLE_CONFIG.sec_fetch_site_mode[Math.floor(Math.random() * 4)],
  };

  return {
    variables: JSON.stringify(variables),
    status: 'new',
    generation,
    performanceScore: 0,
    avgRank: null,
    successRate: null,
    captchaAvoidRate: null,
  };
}

// ========================================
// 9. 다음 세대 진화 (메인 로직)
// ========================================

export async function evolveGeneration(
  currentGen: number,
  populationSize = 50
): Promise<InsertVariableCombination[]> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  // 1. 엘리트 선택
  const elites = await selectElites(currentGen);

  if (elites.length === 0) {
    throw new Error(`No elites found for generation ${currentGen}`);
  }

  const eliteCount = elites.length;
  const nextGeneration: InsertVariableCombination[] = [];

  // 2. 엘리트 유지 (10%)
  nextGeneration.push(
    ...elites.map(e => ({
      variables: e.variables,
      status: 'elite' as const,
      generation: currentGen + 1,
      performanceScore: 0,
      avgRank: null,
      successRate: null,
      captchaAvoidRate: null,
    }))
  );

  // 3. 교차로 생성 (40%)
  const crossoverCount = Math.floor(populationSize * 0.4);
  for (let i = 0; i < crossoverCount; i++) {
    const p1 = elites[Math.floor(Math.random() * eliteCount)];
    const p2 = elites[Math.floor(Math.random() * eliteCount)];

    const parent1: Variables = JSON.parse(p1.variables);
    const parent2: Variables = JSON.parse(p2.variables);

    nextGeneration.push({
      variables: JSON.stringify(crossover(parent1, parent2)),
      status: 'new',
      generation: currentGen + 1,
      performanceScore: 0,
      avgRank: null,
      successRate: null,
      captchaAvoidRate: null,
    });
  }

  // 4. 변이로 생성 (40%)
  const mutationCount = Math.floor(populationSize * 0.4);
  for (let i = 0; i < mutationCount; i++) {
    const parent = elites[Math.floor(Math.random() * eliteCount)];
    const parentVars: Variables = JSON.parse(parent.variables);

    nextGeneration.push({
      variables: JSON.stringify(mutate(parentVars)),
      status: 'new',
      generation: currentGen + 1,
      performanceScore: 0,
      avgRank: null,
      successRate: null,
      captchaAvoidRate: null,
    });
  }

  // 5. 랜덤 탐색 (10%)
  const randomCount = populationSize - nextGeneration.length;
  for (let i = 0; i < randomCount; i++) {
    nextGeneration.push(generateRandomCombination(currentGen + 1));
  }

  // 6. DB 저장
  await db.insert(variableCombinations).values(nextGeneration);

  return nextGeneration;
}

// ========================================
// 10. 환경 변화 감지
// ========================================

export async function detectEnvironmentChange(): Promise<boolean> {
  const db = await getDb();
  if (!db) return false;

  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  // 최근 7일간 업데이트된 엘리트 조합 조회
  const elites = await db
    .select()
    .from(variableCombinations)
    .where(
      and(
        eq(variableCombinations.status, 'elite'),
        gte(variableCombinations.createdAt, sevenDaysAgo)
      )
    );

  if (elites.length === 0) return false;

  // 20% 이상 성능 하락한 엘리트 수 계산
  // (실제로는 historicalBestScore 필드가 필요하지만, 현재는 단순화)
  let significantDropCount = 0;
  const threshold = 8000; // Elite 최소 점수

  for (const elite of elites) {
    if (elite.performanceScore && elite.performanceScore < threshold * 0.8) {
      significantDropCount++;
    }
  }

  // 30% 이상의 엘리트가 성능 하락 → 환경 변화
  return (significantDropCount / elites.length) >= 0.3;
}
