-- traffic_failures 테이블 생성
-- MID 매칭 실패 및 기타 트래픽 실패 기록용

CREATE TABLE IF NOT EXISTS traffic_failures (
  id SERIAL PRIMARY KEY,
  task_id INT,                    -- traffic_navershopping.id
  slot_id INT,                    -- slot_naver.id
  keyword TEXT NOT NULL,          -- 검색 키워드
  target_mid TEXT NOT NULL,       -- 찾으려던 MID
  fail_reason TEXT NOT NULL,      -- 'MID_NOT_FOUND', 'CAPTCHA', 'BLOCKED', 'TIMEOUT', 'OTHER'
  search_url TEXT,                -- 검색했던 URL
  found_mids TEXT[],              -- 검색 결과에서 발견된 MID 목록 (최대 20개)
  found_count INT DEFAULT 0,      -- 발견된 총 상품 수
  engine_version TEXT,            -- 사용한 엔진 (v7, v8...)
  error_message TEXT,             -- 상세 에러 메시지
  created_at TIMESTAMP DEFAULT NOW()
);

-- 인덱스 생성
CREATE INDEX IF NOT EXISTS idx_traffic_failures_fail_reason ON traffic_failures(fail_reason);
CREATE INDEX IF NOT EXISTS idx_traffic_failures_keyword ON traffic_failures(keyword);
CREATE INDEX IF NOT EXISTS idx_traffic_failures_created_at ON traffic_failures(created_at);
CREATE INDEX IF NOT EXISTS idx_traffic_failures_target_mid ON traffic_failures(target_mid);

-- 코멘트 추가
COMMENT ON TABLE traffic_failures IS 'MID 매칭 실패 및 트래픽 실패 기록';
COMMENT ON COLUMN traffic_failures.fail_reason IS 'MID_NOT_FOUND, CAPTCHA, BLOCKED, TIMEOUT, OTHER';
COMMENT ON COLUMN traffic_failures.found_mids IS '검색 결과에서 발견된 MID 목록 (최대 20개)';
