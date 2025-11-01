-- Migration: Add Bot Roles and Configuration
-- Purpose: Support single APK + configuration file strategy
-- Date: 2025-11-02

-- ============================================
-- 1. Add role and configuration columns to bots table
-- ============================================

ALTER TABLE bots
ADD COLUMN role VARCHAR(20) DEFAULT 'follower' CHECK (role IN ('leader', 'follower', 'rank_checker'));

COMMENT ON COLUMN bots.role IS 'Bot role: leader (대장), follower (쫄병), rank_checker (순위체크)';

ALTER TABLE bots
ADD COLUMN config_json JSONB DEFAULT '{}'::jsonb;

COMMENT ON COLUMN bots.config_json IS 'Role-specific configuration in JSON format';

-- ============================================
-- 2. Update existing bots (default role: follower)
-- ============================================

UPDATE bots
SET role = CASE
    WHEN is_leader = TRUE THEN 'leader'
    ELSE 'follower'
END
WHERE role IS NULL OR role = 'follower';

-- ============================================
-- 3. Add indexes for efficient querying
-- ============================================

CREATE INDEX idx_bots_role ON bots(role);
CREATE INDEX idx_bots_role_status ON bots(role, status) WHERE status = 'active';
CREATE INDEX idx_bots_config_json ON bots USING GIN (config_json);

-- ============================================
-- 4. Add default configuration for each role
-- ============================================

-- Leader Bot default config
UPDATE bots
SET config_json = jsonb_build_object(
    'hotspot_ssid', 'Turafic-Leader-' || bot_id,
    'hotspot_password', 'turafic2025',
    'ip_rotation_strategy', 'wait_for_completion',
    'max_wait_time', 180000
)
WHERE role = 'leader' AND config_json = '{}'::jsonb;

-- Follower Bot default config
UPDATE bots
SET config_json = jsonb_build_object(
    'leader_hotspot_ssid', '',
    'leader_hotspot_password', ''
)
WHERE role = 'follower' AND config_json = '{}'::jsonb;

-- Rank Checker Bot default config
UPDATE bots
SET config_json = jsonb_build_object(
    'check_interval', 3600,
    'target_keywords', ARRAY[]::text[],
    'target_products', ARRAY[]::text[]
)
WHERE role = 'rank_checker' AND config_json = '{}'::jsonb;

-- ============================================
-- 5. Add role-based statistics columns
-- ============================================

ALTER TABLE bots
ADD COLUMN role_last_changed_at TIMESTAMP DEFAULT NOW();

COMMENT ON COLUMN bots.role_last_changed_at IS 'Timestamp when bot role was last changed';

-- ============================================
-- 6. Create view for role-based bot counts
-- ============================================

CREATE OR REPLACE VIEW bot_role_stats AS
SELECT
    role,
    COUNT(*) AS total_bots,
    COUNT(CASE WHEN status = 'active' THEN 1 END) AS active_bots,
    COUNT(CASE WHEN status = 'inactive' THEN 1 END) AS inactive_bots,
    COUNT(CASE WHEN is_leader = TRUE THEN 1 END) AS leader_count
FROM bots
GROUP BY role;

COMMENT ON VIEW bot_role_stats IS 'Statistics of bots grouped by role';

-- ============================================
-- 7. Create function to update role configuration
-- ============================================

CREATE OR REPLACE FUNCTION update_bot_role_config(
    p_bot_id VARCHAR(36),
    p_config_key VARCHAR(50),
    p_config_value TEXT
)
RETURNS VOID AS $$
BEGIN
    UPDATE bots
    SET config_json = jsonb_set(
        config_json,
        ARRAY[p_config_key],
        to_jsonb(p_config_value),
        TRUE
    ),
    role_last_changed_at = NOW()
    WHERE bot_id = p_bot_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_bot_role_config IS 'Update specific configuration key for a bot';

-- ============================================
-- 8. Add trigger to log role changes
-- ============================================

CREATE TABLE IF NOT EXISTS bot_role_history (
    id SERIAL PRIMARY KEY,
    bot_id VARCHAR(36) NOT NULL,
    old_role VARCHAR(20),
    new_role VARCHAR(20),
    changed_at TIMESTAMP DEFAULT NOW(),
    changed_by VARCHAR(100),
    FOREIGN KEY (bot_id) REFERENCES bots(bot_id) ON DELETE CASCADE
);

COMMENT ON TABLE bot_role_history IS 'History of bot role changes for auditing';

CREATE OR REPLACE FUNCTION log_bot_role_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.role IS DISTINCT FROM NEW.role THEN
        INSERT INTO bot_role_history (bot_id, old_role, new_role)
        VALUES (NEW.bot_id, OLD.role, NEW.role);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER bot_role_change_trigger
AFTER UPDATE ON bots
FOR EACH ROW
EXECUTE FUNCTION log_bot_role_change();

-- ============================================
-- 9. Add constraints for role-specific rules
-- ============================================

-- Leader bots must have is_leader = TRUE
ALTER TABLE bots
ADD CONSTRAINT check_leader_role
CHECK (
    (role = 'leader' AND is_leader = TRUE) OR
    (role != 'leader')
);

-- Rank checker bots should not be in ranking groups
ALTER TABLE bots
ADD CONSTRAINT check_rank_checker_no_group
CHECK (
    (role = 'rank_checker' AND ranking_group_id IS NULL) OR
    (role != 'rank_checker')
);

-- ============================================
-- 10. Create helper functions
-- ============================================

-- Get bots by role
CREATE OR REPLACE FUNCTION get_bots_by_role(p_role VARCHAR(20))
RETURNS TABLE (
    bot_id VARCHAR(36),
    device_model VARCHAR(50),
    status VARCHAR(20),
    config_json JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT b.bot_id, b.device_model, b.status, b.config_json
    FROM bots b
    WHERE b.role = p_role AND b.status = 'active';
END;
$$ LANGUAGE plpgsql;

-- Get active leader bots
CREATE OR REPLACE FUNCTION get_active_leaders()
RETURNS TABLE (
    bot_id VARCHAR(36),
    ranking_group_id VARCHAR(36),
    hotspot_ssid TEXT,
    hotspot_password TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        b.bot_id,
        b.ranking_group_id,
        b.config_json->>'hotspot_ssid' AS hotspot_ssid,
        b.config_json->>'hotspot_password' AS hotspot_password
    FROM bots b
    WHERE b.role = 'leader' AND b.status = 'active';
END;
$$ LANGUAGE plpgsql;

-- Get followers by leader
CREATE OR REPLACE FUNCTION get_followers_by_leader(p_leader_bot_id VARCHAR(36))
RETURNS TABLE (
    bot_id VARCHAR(36),
    device_model VARCHAR(50),
    status VARCHAR(20)
) AS $$
DECLARE
    v_group_id VARCHAR(36);
BEGIN
    -- Get leader's ranking group
    SELECT ranking_group_id INTO v_group_id
    FROM bots
    WHERE bot_id = p_leader_bot_id AND role = 'leader';

    -- Return followers in the same group
    RETURN QUERY
    SELECT b.bot_id, b.device_model, b.status
    FROM bots b
    WHERE b.ranking_group_id = v_group_id
      AND b.role = 'follower'
      AND b.status = 'active';
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 11. Sample data for testing (optional)
-- ============================================

-- Uncomment to insert sample bots for testing
/*
INSERT INTO bots (bot_id, android_id, device_model, android_version, screen_resolution, role, is_leader, config_json)
VALUES
-- Leader bot
('bot-leader-001', 'android-001', 'SM-G998N', '14', '1440x3200', 'leader', TRUE,
 '{"hotspot_ssid": "Turafic-Leader-001", "hotspot_password": "turafic2025", "ip_rotation_strategy": "wait_for_completion", "max_wait_time": 180000}'::jsonb),

-- Follower bots
('bot-follower-001', 'android-002', 'SM-G998N', '14', '1440x3200', 'follower', FALSE,
 '{"leader_hotspot_ssid": "Turafic-Leader-001", "leader_hotspot_password": "turafic2025"}'::jsonb),
('bot-follower-002', 'android-003', 'SM-G998N', '14', '1440x3200', 'follower', FALSE,
 '{"leader_hotspot_ssid": "Turafic-Leader-001", "leader_hotspot_password": "turafic2025"}'::jsonb),
('bot-follower-003', 'android-004', 'SM-G998N', '14', '1440x3200', 'follower', FALSE,
 '{"leader_hotspot_ssid": "Turafic-Leader-001", "leader_hotspot_password": "turafic2025"}'::jsonb),

-- Rank checker bot
('bot-rank-001', 'android-005', 'SM-G998N', '14', '1440x3200', 'rank_checker', FALSE,
 '{"check_interval": 3600, "target_keywords": ["단백질쉐이크", "프로틴"], "target_products": []}'::jsonb);
*/

-- ============================================
-- 12. Rollback script (for reference)
-- ============================================

/*
-- To rollback this migration, run:

DROP TRIGGER IF EXISTS bot_role_change_trigger ON bots;
DROP FUNCTION IF EXISTS log_bot_role_change();
DROP TABLE IF EXISTS bot_role_history;
DROP FUNCTION IF EXISTS get_followers_by_leader(VARCHAR);
DROP FUNCTION IF EXISTS get_active_leaders();
DROP FUNCTION IF EXISTS get_bots_by_role(VARCHAR);
DROP FUNCTION IF EXISTS update_bot_role_config(VARCHAR, VARCHAR, TEXT);
DROP VIEW IF EXISTS bot_role_stats;
ALTER TABLE bots DROP CONSTRAINT IF EXISTS check_rank_checker_no_group;
ALTER TABLE bots DROP CONSTRAINT IF EXISTS check_leader_role;
DROP INDEX IF EXISTS idx_bots_config_json;
DROP INDEX IF EXISTS idx_bots_role_status;
DROP INDEX IF EXISTS idx_bots_role;
ALTER TABLE bots DROP COLUMN IF EXISTS role_last_changed_at;
ALTER TABLE bots DROP COLUMN IF EXISTS config_json;
ALTER TABLE bots DROP COLUMN IF EXISTS role;
*/

-- ============================================
-- Migration completed successfully
-- ============================================

-- Verify migration
SELECT
    COUNT(*) AS total_bots,
    COUNT(CASE WHEN role = 'leader' THEN 1 END) AS leaders,
    COUNT(CASE WHEN role = 'follower' THEN 1 END) AS followers,
    COUNT(CASE WHEN role = 'rank_checker' THEN 1 END) AS rank_checkers
FROM bots;

COMMENT ON TABLE bots IS 'Updated: Added role and config_json columns for single APK + configuration file strategy';
