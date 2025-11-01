-- C&C 서버 데이터베이스 스키마

-- 봇 테이블
CREATE TABLE IF NOT EXISTS bots (
    bot_id VARCHAR(36) PRIMARY KEY,
    device_id VARCHAR(64) UNIQUE NOT NULL,
    manufacturer VARCHAR(64),
    model VARCHAR(64),
    android_version VARCHAR(16),
    screen_resolution VARCHAR(16),
    current_ip VARCHAR(45),
    last_ip_change TIMESTAMP,
    status VARCHAR(16) DEFAULT 'offline',
    last_seen TIMESTAMP,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_group VARCHAR(32),
    current_task VARCHAR(64),
    completed_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0,
    avg_task_duration FLOAT DEFAULT 0.0,
    success_rate FLOAT DEFAULT 1.0,
    battery_level INTEGER
);

CREATE INDEX IF NOT EXISTS idx_bots_status ON bots(status);
CREATE INDEX IF NOT EXISTS idx_bots_group ON bots(assigned_group);

-- 캠페인 테이블
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    target_product JSON,
    test_matrix JSON,
    total_iterations INTEGER DEFAULT 100,
    status VARCHAR(16) DEFAULT 'draft',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    assigned_bots INTEGER DEFAULT 0,
    completed_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0
);

-- 작업 테이블
CREATE TABLE IF NOT EXISTS tasks (
    task_id VARCHAR(64) PRIMARY KEY,
    campaign_id VARCHAR(36),
    bot_id VARCHAR(36),
    test_case VARCHAR(32),
    profile VARCHAR(8),
    behavior VARCHAR(32),
    status VARCHAR(16) DEFAULT 'pending',
    assigned_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration FLOAT,
    success BOOLEAN
);

-- 결과 테이블
CREATE TABLE IF NOT EXISTS results (
    result_id SERIAL PRIMARY KEY,
    task_id VARCHAR(64),
    bot_id VARCHAR(36),
    before_rank INTEGER,
    after_rank INTEGER,
    rank_change INTEGER,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
