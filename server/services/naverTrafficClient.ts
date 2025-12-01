/**
 * Production DB 전용 네이버쇼핑 트래픽 클라이언트
 * 참조: adpang_coupang_click/supabase/client.js
 */

import { createClient, SupabaseClient } from "@supabase/supabase-js";

// traffic_navershopping 테이블 타입
export interface NaverTrafficTask {
  id: number;
  keyword: string; // 검색 키워드
  link_url: string; // 상품 URL (smartstore.naver.com/...)
  slot_id: number; // slot_naver 테이블 참조
  slot_sequence: number; // 슬롯 내 순서
  product_id?: string; // 상품 ID (nvMid)
  product_name?: string; // 상품명 (fullname 검색용)
  slot_type?: string; // 슬롯 타입
  created_at?: string;
}

// slot_naver 테이블 타입 (결과 저장용)
export interface SlotNaver {
  id: number;
  slot_type: string; // '네이버쇼핑'
  keyword: string;
  link_url: string;
  slot_sequence: number;
  success_count: number; // 성공 횟수
  fail_count: number; // 실패 횟수
  target_count?: number; // 목표 횟수 (있는 경우)
  status?: string; // 'pending' | 'running' | 'completed'
}

export class NaverTrafficClient {
  private supabase: SupabaseClient;

  constructor() {
    const url = process.env.SUPABASE_PRODUCTION_URL;
    const key = process.env.SUPABASE_PRODUCTION_KEY;

    if (!url || !key) {
      throw new Error(
        "SUPABASE_PRODUCTION_URL and SUPABASE_PRODUCTION_KEY must be set"
      );
    }

    this.supabase = createClient(url, key);
  }

  /**
   * traffic_navershopping에서 대기 작업 전체 조회
   * (쿠팡의 getAllPendingTrafficTasks 참조)
   */
  async getAllPendingTrafficTasks(): Promise<NaverTrafficTask[]> {
    const { data, error } = await this.supabase
      .from("traffic_navershopping")
      .select("*")
      .order("id", { ascending: true });

    if (error) {
      console.error("트래픽 조회 오류:", error);
      throw error;
    }

    return data || [];
  }

  /**
   * traffic_navershopping에서 제한된 수의 작업 조회
   */
  async getPendingTrafficTasks(limit: number): Promise<NaverTrafficTask[]> {
    const { data, error } = await this.supabase
      .from("traffic_navershopping")
      .select("*")
      .order("id", { ascending: true })
      .limit(limit);

    if (error) {
      console.error("트래픽 조회 오류:", error);
      throw error;
    }

    return data || [];
  }

  /**
   * slot_naver 매칭 (쿠팡 로직 참조)
   * 1순위: slot_id로 직접 찾기
   * 2순위: 복합 조건으로 찾기
   */
  async findSlotNaver(task: NaverTrafficTask): Promise<number | null> {
    // 1순위: slot_id로 직접 찾기
    if (task.slot_id) {
      const { data } = await this.supabase
        .from("slot_naver")
        .select("id")
        .eq("id", task.slot_id)
        .single();

      if (data) return data.id;
    }

    // 2순위: 복합 조건으로 찾기
    const { data } = await this.supabase
      .from("slot_naver")
      .select("id")
      .eq("slot_sequence", task.slot_sequence)
      .eq("keyword", task.keyword)
      .eq("link_url", task.link_url)
      .eq("slot_type", "네이버쇼핑")
      .single();

    return data?.id || null;
  }

  /**
   * slot_naver에서 product_name과 mid 가져오기
   * fullname 검색에 필요한 상품명 조회
   */
  async getSlotProductInfo(
    slotId: number
  ): Promise<{ productName: string | null; mid: string | null }> {
    const { data, error } = await this.supabase
      .from("slot_naver")
      .select("product_name, mid")
      .eq("id", slotId)
      .single();

    if (error || !data) {
      return { productName: null, mid: null };
    }

    return {
      productName: data.product_name || null,
      mid: data.mid || null,
    };
  }

  /**
   * slot_naver에 결과 업데이트 (success_count++ 또는 fail_count++)
   */
  async updateSlotResult(slotId: number, success: boolean): Promise<void> {
    const column = success ? "success_count" : "fail_count";

    // 현재 값 조회
    const { data: current, error: selectError } = await this.supabase
      .from("slot_naver")
      .select(column)
      .eq("id", slotId)
      .single();

    if (selectError) {
      console.error(`slot_naver 조회 오류 (id=${slotId}):`, selectError);
      throw selectError;
    }

    // 값 증가
    const currentValue = (current as any)?.[column] || 0;
    const newValue = currentValue + 1;

    const { error: updateError } = await this.supabase
      .from("slot_naver")
      .update({ [column]: newValue })
      .eq("id", slotId);

    if (updateError) {
      console.error(`slot_naver 업데이트 오류 (id=${slotId}):`, updateError);
      throw updateError;
    }

    console.log(`📊 slot_naver[${slotId}] ${column}: ${currentValue} → ${newValue}`);
  }

  /**
   * 처리 완료 작업 삭제 (쿠팡의 deleteProcessedTraffic 참조)
   * finally 블록에서 항상 호출 - 성공/실패 관계없이
   */
  async deleteProcessedTraffic(trafficId: number): Promise<void> {
    const { error } = await this.supabase
      .from("traffic_navershopping")
      .delete()
      .eq("id", trafficId);

    if (error) {
      console.error(`트래픽 삭제 오류 (id=${trafficId}):`, error);
      throw error;
    }

    console.log(`🗑️ 트래픽 ID ${trafficId} 삭제 완료`);
  }

  /**
   * 연결 테스트
   */
  async testConnection(): Promise<boolean> {
    try {
      const { data, error } = await this.supabase
        .from("traffic_navershopping")
        .select("count")
        .limit(1);

      if (error) {
        console.error("연결 테스트 실패:", error);
        return false;
      }

      console.log("✅ Production Supabase 연결 성공");
      return true;
    } catch (err) {
      console.error("연결 테스트 예외:", err);
      return false;
    }
  }

  /**
   * 대기 중인 작업 수 조회
   */
  async getPendingTaskCount(): Promise<number> {
    const { count, error } = await this.supabase
      .from("traffic_navershopping")
      .select("*", { count: "exact", head: true });

    if (error) {
      console.error("작업 수 조회 오류:", error);
      return 0;
    }

    return count || 0;
  }

  /**
   * 실패 로그 DB 저장 (traffic_failures 테이블)
   */
  async insertFailure(data: {
    task_id?: number;
    slot_id?: number;
    keyword: string;
    target_mid: string;
    fail_reason: string;
    search_url?: string;
    found_mids?: string[];
    found_count?: number;
    engine_version?: string;
    error_message?: string;
  }): Promise<void> {
    const { error } = await this.supabase
      .from("traffic_failures")
      .insert({
        task_id: data.task_id,
        slot_id: data.slot_id,
        keyword: data.keyword,
        target_mid: data.target_mid,
        fail_reason: data.fail_reason,
        search_url: data.search_url,
        found_mids: data.found_mids,
        found_count: data.found_count ?? 0,
        engine_version: data.engine_version,
        error_message: data.error_message,
      });

    if (error) {
      console.error("실패 로그 저장 오류:", error);
      throw error;
    }

    console.log(`📝 실패 로그 저장: ${data.fail_reason} - ${data.keyword}`);
  }

  /**
   * 실패 로그 통계 조회 (fail_reason별)
   */
  async getFailureStats(): Promise<{ fail_reason: string; count: number }[]> {
    const { data, error } = await this.supabase
      .from("traffic_failures")
      .select("fail_reason")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("실패 로그 통계 오류:", error);
      return [];
    }

    // fail_reason별 카운트
    const stats: { [key: string]: number } = {};
    for (const row of data || []) {
      const reason = row.fail_reason;
      stats[reason] = (stats[reason] || 0) + 1;
    }

    return Object.entries(stats).map(([fail_reason, count]) => ({
      fail_reason,
      count,
    }));
  }

  /**
   * 최근 실패 로그 조회
   */
  async getRecentFailures(limit: number = 20): Promise<any[]> {
    const { data, error } = await this.supabase
      .from("traffic_failures")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      console.error("최근 실패 로그 조회 오류:", error);
      return [];
    }

    return data || [];
  }
}
