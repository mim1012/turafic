-- Migration: Make product_id required and add test_case column
-- Purpose: Enforce 1 campaign = 1 product = 1 test case relationship
-- Date: 2025-11-02

-- ============================================
-- 1. Make product_id NOT NULL
-- ============================================

-- First, ensure no NULL values exist (cleanup)
UPDATE campaigns
SET product_id = 'PLACEHOLDER'
WHERE product_id IS NULL;

-- Make product_id required
ALTER TABLE campaigns
ALTER COLUMN product_id SET NOT NULL;

COMMENT ON COLUMN campaigns.product_id IS
'Target product for this campaign (REQUIRED). Each campaign tests one specific product with one test case. Products are single-use for experiment purity.';

-- ============================================
-- 2. Add test_case column
-- ============================================

ALTER TABLE campaigns
ADD COLUMN IF NOT EXISTS test_case VARCHAR(20);

COMMENT ON COLUMN campaigns.test_case IS
'Test case ID (e.g., TC#001, TC#002, ..., TC#243) for A/B testing analysis. Used to identify which variable combination is most effective for ranking improvement.';

-- ============================================
-- 3. Create indexes for performance
-- ============================================

CREATE INDEX IF NOT EXISTS idx_campaigns_test_case ON campaigns(test_case);
CREATE INDEX IF NOT EXISTS idx_campaigns_product_id ON campaigns(product_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status_test_case ON campaigns(status, test_case);

-- ============================================
-- 4. Verify migration
-- ============================================

SELECT
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_name = 'campaigns'
  AND column_name IN ('product_id', 'test_case')
ORDER BY column_name;

-- Expected output:
-- product_id  | character varying | NO  | NULL
-- test_case   | character varying | YES | NULL

-- ============================================
-- 5. Usage notes
-- ============================================

/*
After this migration:

1. All campaigns MUST have a product_id
2. test_case should be set when creating campaigns (e.g., "TC#001")
3. Each test case tests one specific product (one-time use)

Example campaign creation:
INSERT INTO campaigns (campaign_id, name, target_keyword, target_traffic, product_id, test_case, status)
VALUES (
    gen_random_uuid()::text,
    '프로틴 쉐이크 A - TC#001',
    '프로틴 쉐이크',
    100,
    'prod-abc-123',  -- Required!
    'TC#001',        -- Test case identifier
    'active'
);

Performance analysis query:
SELECT
    c.test_case,
    p.product_name,
    p.initial_rank,
    p.current_rank,
    p.rank_improvement
FROM campaigns c
JOIN products p ON c.product_id = p.product_id
WHERE c.status = 'completed'
ORDER BY p.rank_improvement ASC;  -- Best performing test cases first
*/

-- ============================================
-- 6. Rollback (if needed)
-- ============================================

/*
-- To rollback this migration:

ALTER TABLE campaigns
ALTER COLUMN product_id DROP NOT NULL;

ALTER TABLE campaigns
DROP COLUMN IF EXISTS test_case;

DROP INDEX IF EXISTS idx_campaigns_test_case;
DROP INDEX IF EXISTS idx_campaigns_status_test_case;
-- (idx_campaigns_product_id might be needed, keep it)
*/
