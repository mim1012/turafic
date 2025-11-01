-- =====================================================
-- 순위 체크 시스템 DB 마이그레이션
-- 생성일: 2025-11-01
-- 목적: 네이버 쇼핑 순위 측정 및 변동 추적
-- =====================================================

-- 1. 순위 체크 기록 테이블
CREATE TABLE IF NOT EXISTS ranking_checks (
    check_id VARCHAR(36) PRIMARY KEY,
    campaign_id VARCHAR(36) NOT NULL,
    product_keyword VARCHAR(100) NOT NULL,
    check_type VARCHAR(20),                  -- 'baseline', 'batch_1', 'batch_2', ... 'batch_9'
    rank_position INTEGER NOT NULL,          -- 측정된 순위 (1~200)
    page_number INTEGER,                     -- 몇 페이지인지 (1페이지 = 1~20위)
    position_in_page INTEGER,                -- 페이지 내 위치 (1~20)
    product_id VARCHAR(50),                  -- 네이버 상품 ID
    product_name VARCHAR(200),               -- 상품명
    product_url TEXT,                        -- 상품 URL
    measured_at TIMESTAMP DEFAULT NOW(),     -- 측정 시각
    measurement_method VARCHAR(20) DEFAULT 'bot',  -- 'api', 'manual', 'bot'
    measured_by VARCHAR(36),                 -- 봇 ID 또는 관리자 ID
    notes TEXT,                              -- 추가 메모
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE
);

CREATE INDEX idx_ranking_checks_campaign ON ranking_checks(campaign_id);
CREATE INDEX idx_ranking_checks_measured_at ON ranking_checks(measured_at);
CREATE INDEX idx_ranking_checks_type ON ranking_checks(check_type);

-- 2. 순위 변동 분석 테이블
CREATE TABLE IF NOT EXISTS ranking_changes (
    change_id VARCHAR(36) PRIMARY KEY,
    campaign_id VARCHAR(36) NOT NULL,
    test_case_id VARCHAR(20),               -- 어느 테스트 케이스 때문인지 (TC#001~243)
    before_check_id VARCHAR(36),            -- 이전 순위 체크 ID
    after_check_id VARCHAR(36),             -- 이후 순위 체크 ID
    before_rank INTEGER NOT NULL,           -- 이전 순위
    after_rank INTEGER NOT NULL,            -- 이후 순위
    rank_change INTEGER,                    -- 순위 변동 (after - before, 음수 = 상승)
    traffic_count INTEGER,                  -- 트래픽 몇 회 후
    time_elapsed_hours INTEGER,             -- 시간 경과 (시간)
    improved BOOLEAN,                       -- 순위 개선 여부 (rank_change < 0)
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
    FOREIGN KEY (before_check_id) REFERENCES ranking_checks(check_id) ON DELETE SET NULL,
    FOREIGN KEY (after_check_id) REFERENCES ranking_checks(check_id) ON DELETE SET NULL
);

CREATE INDEX idx_ranking_changes_campaign ON ranking_changes(campaign_id);
CREATE INDEX idx_ranking_changes_test_case ON ranking_changes(test_case_id);

-- 3. 배치 실행 기록 테이블
CREATE TABLE IF NOT EXISTS batch_executions (
    batch_id VARCHAR(36) PRIMARY KEY,
    campaign_id VARCHAR(36) NOT NULL,
    batch_number INTEGER NOT NULL,          -- 1~9
    test_cases JSONB,                       -- ["TC#001", "TC#002", ..., "TC#027"]
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    traffic_generated INTEGER DEFAULT 0,    -- 총 발생 트래픽 (목표: 2700회)
    baseline_rank INTEGER,                  -- 초기 순위
    final_rank INTEGER,                     -- 배치 완료 후 순위
    rank_change INTEGER,                    -- 순위 변동
    status VARCHAR(20) DEFAULT 'pending',   -- 'pending', 'in_progress', 'completed', 'failed'
    notes TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE
);

CREATE INDEX idx_batch_executions_campaign ON batch_executions(campaign_id);
CREATE INDEX idx_batch_executions_batch_num ON batch_executions(batch_number);
CREATE INDEX idx_batch_executions_status ON batch_executions(status);

-- 4. 통계 뷰 (쿼리 편의성)
CREATE OR REPLACE VIEW ranking_statistics AS
SELECT
    campaign_id,
    COUNT(*) AS total_checks,
    MIN(rank_position) AS best_rank,
    MAX(rank_position) AS worst_rank,
    AVG(rank_position)::NUMERIC(10,2) AS avg_rank,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY rank_position) AS median_rank,
    MAX(measured_at) AS last_checked_at
FROM ranking_checks
GROUP BY campaign_id;

-- 완료 메시지
DO $$
BEGIN
    RAISE NOTICE '순위 체크 시스템 DB 마이그레이션 완료!';
    RAISE NOTICE '생성된 테이블: ranking_checks, ranking_changes, batch_executions';
    RAISE NOTICE '생성된 뷰: ranking_statistics';
END $$;
