-- Migration: Add bot-campaign assignment fields
-- Date: 2025-11-01
-- Description: "1봇 = 1캠페인 전담" 모델을 위한 필드 추가

-- Campaign 테이블에 assigned_bot_id 필드 추가
ALTER TABLE campaigns ADD COLUMN assigned_bot_id VARCHAR(36);

-- Bot 테이블에 assigned_campaign_id 필드 추가
ALTER TABLE bots ADD COLUMN assigned_campaign_id VARCHAR(36);

-- 인덱스 추가 (조회 성능 향상)
CREATE INDEX idx_campaigns_assigned_bot ON campaigns(assigned_bot_id);
CREATE INDEX idx_bots_assigned_campaign ON bots(assigned_campaign_id);

-- SQLite용 (개발 환경)
-- SQLite는 ALTER TABLE ADD COLUMN을 지원하므로 위 쿼리 그대로 사용 가능
