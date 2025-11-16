/**
 * Variable Converter
 * AdPang <-> Turafic 변수 변환 유틸리티
 */

import type { Variables } from './variableCombinations';

// ========================================
// AdPang 변수 타입 정의
// ========================================

export interface AdPangVariables {
  ua_change: boolean;
  cookie_home_mode: string;
  shop_home: boolean;
  use_nid: boolean;
  use_image: boolean;
  work_type: string;
  random_click_count: number;
  work_more: boolean;
  sec_fetch_site_mode: string;
  low_delay: boolean;
}

// ========================================
// AdPang → Turafic 변환
// ========================================

export function convertAdPangToTurafic(adpangVars: AdPangVariables): Variables {
  return {
    // 1. ua_change → user_agent
    // true면 최신 UA(UA71), false면 기본 UA(UA58)
    user_agent: adpangVars.ua_change ? 'UA71' : 'UA58',

    // 2. cookie_home_mode → cookie_strategy
    // 'login' 또는 'nologin'으로 가정
    cookie_strategy: adpangVars.cookie_home_mode === 'login'
      ? '로그인쿠키'
      : '비로그인쿠키',

    // 3. shop_home → entry_point
    // true면 쇼핑홈 진입, false면 광고 진입
    entry_point: adpangVars.shop_home ? '쇼핑DI' : '광고DI',

    // 4. use_image → image_loading
    // true면 이미지 로드, false면 이미지 패스
    image_loading: adpangVars.use_image ? '이미지로드' : '이미지패스',

    // 5. work_type → work_type (직접 매핑)
    work_type: adpangVars.work_type || '검색+클릭+체류',

    // 6. random_click_count → random_clicks
    // AdPang의 값을 가장 가까운 Turafic 옵션으로 매핑
    random_clicks: mapRandomClicks(adpangVars.random_click_count),

    // 7. work_more → more_button
    // true면 더보기 클릭, false면 패스
    more_button: adpangVars.work_more ? '더보기클릭' : '더보기패스',

    // 8. sec_fetch_site_mode → sec_fetch_site_mode (직접 매핑)
    sec_fetch_site_mode: adpangVars.sec_fetch_site_mode || 'same-site',

    // 9. low_delay → delay_mode
    // true면 딜레이 감소, false면 정상
    delay_mode: adpangVars.low_delay ? '딜레이감소' : '딜레이정상',

    // Turafic 전용 변수 (기본값 설정)
    cw_mode: 'CW해제',
    input_method: '복붙',
    x_with_header: 'x-with삼성',
  };
}

// ========================================
// Turafic → AdPang 변환
// ========================================

export function convertTuraficToAdPang(turaficVars: Variables): AdPangVariables {
  return {
    // 1. user_agent → ua_change
    // UA71이면 true (변경됨), 아니면 false
    ua_change: turaficVars.user_agent === 'UA71',

    // 2. cookie_strategy → cookie_home_mode
    cookie_home_mode: turaficVars.cookie_strategy === '로그인쿠키'
      ? 'login'
      : 'nologin',

    // 3. entry_point → shop_home
    shop_home: turaficVars.entry_point === '쇼핑DI',

    // 4. use_nid (기본값: 로그인 쿠키 사용 시 true)
    use_nid: turaficVars.cookie_strategy === '로그인쿠키',

    // 5. image_loading → use_image
    use_image: turaficVars.image_loading === '이미지로드',

    // 6. work_type → work_type (직접 매핑)
    work_type: turaficVars.work_type,

    // 7. random_clicks → random_click_count
    random_click_count: turaficVars.random_clicks,

    // 8. more_button → work_more
    work_more: turaficVars.more_button === '더보기클릭',

    // 9. sec_fetch_site_mode → sec_fetch_site_mode (직접 매핑)
    sec_fetch_site_mode: turaficVars.sec_fetch_site_mode,

    // 10. delay_mode → low_delay
    low_delay: turaficVars.delay_mode === '딜레이감소',
  };
}

// ========================================
// 헬퍼 함수
// ========================================

/**
 * AdPang의 random_click_count를 Turafic의 random_clicks 옵션으로 매핑
 * Turafic 옵션: [0, 3, 6]
 */
function mapRandomClicks(count: number): number {
  if (count === 0) return 0;
  if (count <= 3) return 3;
  return 6;
}

// ========================================
// 변환 검증
// ========================================

/**
 * 변환된 변수가 유효한지 검증
 */
export function validateTuraficVariables(vars: Variables): boolean {
  try {
    // 각 변수가 VARIABLE_CONFIG의 옵션 중 하나인지 확인
    const validUserAgents = ['UA58', 'UA67', 'UA71'];
    const validCwModes = ['CW해제', 'CW유지'];
    const validEntryPoints = ['쇼핑DI', '광고DI', '통합검색'];
    // ... 추가 검증 로직

    if (!validUserAgents.includes(vars.user_agent)) return false;
    if (!validCwModes.includes(vars.cw_mode)) return false;
    if (!validEntryPoints.includes(vars.entry_point)) return false;

    return true;
  } catch (error) {
    return false;
  }
}

// ========================================
// 배치 변환
// ========================================

/**
 * 여러 AdPang 변수를 한 번에 Turafic으로 변환
 */
export function batchConvertAdPangToTurafic(
  adpangVarsList: AdPangVariables[]
): Variables[] {
  return adpangVarsList.map(convertAdPangToTurafic);
}

/**
 * 여러 Turafic 변수를 한 번에 AdPang으로 변환
 */
export function batchConvertTuraficToAdPang(
  turaficVarsList: Variables[]
): AdPangVariables[] {
  return turaficVarsList.map(convertTuraficToAdPang);
}
