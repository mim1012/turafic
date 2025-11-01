-- =====================================================
-- 대장-쫄병 순위 체크 시스템 DB 마이그레이션
-- 생성일: 2025-11-02
-- 목적: 유동적 쫄병 수 관리 (5~7개) + IP 충돌 해결
-- =====================================================

-- 1. Bots 테이블 확장
ALTER TABLE bots ADD COLUMN IF NOT EXISTS bot_type VARCHAR(20) DEFAULT 'traffic';
-- 'traffic': 트래픽 발생 전용
-- 'rank_checker': 순위 체크 전용

ALTER TABLE bots ADD COLUMN IF NOT EXISTS is_leader BOOLEAN DEFAULT FALSE;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS leader_bot_id VARCHAR(36) DEFAULT NULL;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS ranking_group_id VARCHAR(36) DEFAULT NULL;

-- 대장 봇 상태 (대장만 사용)
ALTER TABLE bots ADD COLUMN IF NOT EXISTS max_minion_capacity INTEGER DEFAULT 7;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS current_minion_count INTEGER DEFAULT 0;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS health_score FLOAT DEFAULT 100.0;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS battery_level INTEGER DEFAULT 100;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS memory_available_mb INTEGER DEFAULT 0;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS hotspot_stability_score FLOAT DEFAULT 100.0;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS network_latency_ms INTEGER DEFAULT 0;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS device_temperature FLOAT DEFAULT 25.0;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS last_health_check_at TIMESTAMP DEFAULT NULL;

-- IP 변경 관련
ALTER TABLE bots ADD COLUMN IF NOT EXISTS current_ip VARCHAR(50) DEFAULT NULL;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS last_ip_change_at TIMESTAMP DEFAULT NULL;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS ip_change_count INTEGER DEFAULT 0;

-- 쫄병 봇 상태 (쫄병만 사용)
ALTER TABLE bots ADD COLUMN IF NOT EXISTS connection_status VARCHAR(20) DEFAULT 'disconnected';
-- 'disconnected', 'connecting', 'connected', 'reconnecting'
ALTER TABLE bots ADD COLUMN IF NOT EXISTS last_connected_at TIMESTAMP DEFAULT NULL;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS connection_retry_count INTEGER DEFAULT 0;

-- 작업 완료 상태 (IP 변경 타이밍 조율용)
ALTER TABLE bots ADD COLUMN IF NOT EXISTS task_status VARCHAR(20) DEFAULT 'idle';
-- 'idle', 'working', 'completed'
ALTER TABLE bots ADD COLUMN IF NOT EXISTS task_started_at TIMESTAMP DEFAULT NULL;
ALTER TABLE bots ADD COLUMN IF NOT EXISTS task_completed_at TIMESTAMP DEFAULT NULL;

-- 2. RankingGroups 테이블 생성
CREATE TABLE IF NOT EXISTS ranking_groups (
    group_id VARCHAR(36) PRIMARY KEY,
    group_name VARCHAR(100) NOT NULL,
    group_type VARCHAR(20) NOT NULL,  -- 'traffic' or 'rank_checker'
    leader_bot_id VARCHAR(36) NOT NULL,

    -- 쫄병 수 설정
    min_minions INTEGER DEFAULT 5,
    max_minions INTEGER DEFAULT 7,
    target_minion_count INTEGER DEFAULT 7,  -- 기본값 7개
    current_minion_count INTEGER DEFAULT 0,

    -- IP 변경 전략
    ip_change_strategy VARCHAR(30) DEFAULT 'wait_for_completion',
    -- 'wait_for_completion': 작업 완료 후 IP 변경 (하이브리드)
    -- 'fixed_interval': 고정 주기 (5분)
    -- 'manual': 수동

    ip_change_interval_sec INTEGER DEFAULT 300,  -- 5분 (300초)
    max_wait_time_sec INTEGER DEFAULT 180,  -- 최대 대기 3분

    -- 현재 IP 정보
    current_ip VARCHAR(50) DEFAULT NULL,
    last_ip_change_at TIMESTAMP DEFAULT NULL,

    -- 할당된 작업
    assigned_products TEXT,  -- JSON 배열: ["product_1", "product_2", ...]
    assigned_test_cases TEXT,  -- JSON 배열: ["TC#001", "TC#002", ...]
    total_products INTEGER DEFAULT 0,
    total_test_cases INTEGER DEFAULT 0,

    -- 상태 관리
    status VARCHAR(20) DEFAULT 'active',  -- 'active', 'resizing', 'paused', 'waiting_for_tasks'
    created_at TIMESTAMP DEFAULT NOW(),
    last_resize_at TIMESTAMP DEFAULT NULL,
    resize_reason TEXT,

    -- 통계
    total_rank_checks INTEGER DEFAULT 0,
    total_traffic_tasks INTEGER DEFAULT 0,
    avg_task_duration_sec FLOAT DEFAULT 0.0,
    total_ip_changes INTEGER DEFAULT 0,

    FOREIGN KEY (leader_bot_id) REFERENCES bots(bot_id) ON DELETE CASCADE
);

-- 3. 인덱스 추가
CREATE INDEX IF NOT EXISTS idx_bots_bot_type ON bots(bot_type);
CREATE INDEX IF NOT EXISTS idx_bots_is_leader ON bots(is_leader);
CREATE INDEX IF NOT EXISTS idx_bots_leader_bot_id ON bots(leader_bot_id);
CREATE INDEX IF NOT EXISTS idx_bots_ranking_group_id ON bots(ranking_group_id);
CREATE INDEX IF NOT EXISTS idx_bots_task_status ON bots(task_status);

CREATE INDEX IF NOT EXISTS idx_ranking_groups_leader ON ranking_groups(leader_bot_id);
CREATE INDEX IF NOT EXISTS idx_ranking_groups_status ON ranking_groups(status);
CREATE INDEX IF NOT EXISTS idx_ranking_groups_type ON ranking_groups(group_type);

-- 4. IP 변경 이력 테이블 (선택적)
CREATE TABLE IF NOT EXISTS ip_change_history (
    id SERIAL PRIMARY KEY,
    group_id VARCHAR(36) NOT NULL,
    leader_bot_id VARCHAR(36) NOT NULL,
    old_ip VARCHAR(50),
    new_ip VARCHAR(50),
    change_reason VARCHAR(50),  -- 'scheduled', 'manual', 'emergency'
    minions_completed INTEGER DEFAULT 0,
    minions_total INTEGER DEFAULT 0,
    wait_duration_sec INTEGER DEFAULT 0,
    changed_at TIMESTAMP DEFAULT NOW(),

    FOREIGN KEY (group_id) REFERENCES ranking_groups(group_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ip_change_history_group ON ip_change_history(group_id);
CREATE INDEX IF NOT EXISTS idx_ip_change_history_changed_at ON ip_change_history(changed_at);

-- 5. 작업 완료 신호 테이블 (IP 타이밍 조율용)
CREATE TABLE IF NOT EXISTS task_completion_signals (
    signal_id VARCHAR(36) PRIMARY KEY,
    group_id VARCHAR(36) NOT NULL,
    bot_id VARCHAR(36) NOT NULL,
    task_id VARCHAR(36),
    completed_at TIMESTAMP DEFAULT NOW(),
    reported_at TIMESTAMP DEFAULT NOW(),

    FOREIGN KEY (group_id) REFERENCES ranking_groups(group_id) ON DELETE CASCADE,
    FOREIGN KEY (bot_id) REFERENCES bots(bot_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_task_signals_group ON task_completion_signals(group_id);
CREATE INDEX IF NOT EXISTS idx_task_signals_completed_at ON task_completion_signals(completed_at);

-- 6. 뷰: 그룹 상태 요약
CREATE OR REPLACE VIEW ranking_group_status AS
SELECT
    g.group_id,
    g.group_name,
    g.group_type,
    g.target_minion_count,
    g.current_minion_count,
    g.status,
    g.current_ip,
    g.last_ip_change_at,

    -- 대장 봇 정보
    b.bot_id AS leader_bot_id,
    b.battery_level AS leader_battery,
    b.device_temperature AS leader_temp,
    b.health_score AS leader_health,

    -- 작업 중인 쫄병 수
    (SELECT COUNT(*) FROM bots WHERE ranking_group_id = g.group_id AND task_status = 'working') AS working_minions,

    -- 완료한 쫄병 수
    (SELECT COUNT(*) FROM bots WHERE ranking_group_id = g.group_id AND task_status = 'completed') AS completed_minions,

    -- IP 변경 가능 여부
    CASE
        WHEN (SELECT COUNT(*) FROM bots WHERE ranking_group_id = g.group_id AND task_status = 'working') = 0
        THEN TRUE
        ELSE FALSE
    END AS can_change_ip

FROM ranking_groups g
LEFT JOIN bots b ON g.leader_bot_id = b.bot_id;

-- 완료 메시지
DO $$
BEGIN
    RAISE NOTICE '========================================';
    RAISE NOTICE '대장-쫄병 시스템 DB 마이그레이션 완료!';
    RAISE NOTICE '========================================';
    RAISE NOTICE '생성된 테이블:';
    RAISE NOTICE '  - ranking_groups (그룹 정보)';
    RAISE NOTICE '  - ip_change_history (IP 변경 이력)';
    RAISE NOTICE '  - task_completion_signals (작업 완료 신호)';
    RAISE NOTICE '생성된 뷰:';
    RAISE NOTICE '  - ranking_group_status (그룹 상태 요약)';
    RAISE NOTICE '========================================';
END $$;
