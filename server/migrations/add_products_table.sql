-- Migration: Add Products Table and Campaign-Product Integration
-- Purpose: Support arbitrary product registration for bot operations
-- Date: 2025-11-02

-- ============================================
-- 1. Create products table
-- ============================================

CREATE TABLE IF NOT EXISTS products (
    product_id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,

    -- 핵심 5가지 파라미터
    keyword VARCHAR(200) NOT NULL,
    naver_product_id VARCHAR(100) NOT NULL UNIQUE,
    product_name VARCHAR(300) NOT NULL,
    product_url TEXT NOT NULL,

    -- 추가 메타데이터
    category VARCHAR(100),
    brand VARCHAR(100),
    price INTEGER,
    original_price INTEGER,
    discount_rate INTEGER,

    -- 순위 정보
    current_rank INTEGER DEFAULT NULL,
    initial_rank INTEGER DEFAULT NULL,
    best_rank INTEGER DEFAULT NULL,
    worst_rank INTEGER DEFAULT NULL,
    last_rank_check_at TIMESTAMP,

    -- 통계 정보
    total_traffic_count INTEGER DEFAULT 0,
    total_rank_checks INTEGER DEFAULT 0,
    rank_improvement INTEGER DEFAULT 0,  -- 순위 개선 폭 (음수 = 상승)

    -- 상태 관리
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'testing', 'completed')),
    is_target BOOLEAN DEFAULT TRUE,  -- 타겟 상품 여부

    -- 타임스탬프
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(100),

    -- 메모
    notes TEXT
);

COMMENT ON TABLE products IS 'Naver Shopping products for bot traffic generation and rank tracking';

COMMENT ON COLUMN products.keyword IS 'Search keyword users will type';
COMMENT ON COLUMN products.naver_product_id IS 'Naver Shopping unique product ID from URL';
COMMENT ON COLUMN products.product_name IS 'Product display name for UI';
COMMENT ON COLUMN products.product_url IS 'Full Naver Shopping product URL';
COMMENT ON COLUMN products.current_rank IS 'Latest ranking position';
COMMENT ON COLUMN products.initial_rank IS 'Ranking when first registered';
COMMENT ON COLUMN products.rank_improvement IS 'Rank change from initial (negative = improved)';

-- ============================================
-- 2. Create indexes for efficient querying
-- ============================================

CREATE INDEX idx_products_status ON products(status);
CREATE INDEX idx_products_keyword ON products(keyword);
CREATE INDEX idx_products_naver_id ON products(naver_product_id);
CREATE INDEX idx_products_is_target ON products(is_target) WHERE is_target = TRUE;
CREATE INDEX idx_products_created_at ON products(created_at DESC);

-- ============================================
-- 3. Add campaign-product relationship to campaigns table
-- ============================================

ALTER TABLE campaigns
ADD COLUMN product_id VARCHAR(36) REFERENCES products(product_id) ON DELETE SET NULL;

COMMENT ON COLUMN campaigns.product_id IS 'Target product for this campaign';

CREATE INDEX idx_campaigns_product_id ON campaigns(product_id);

-- ============================================
-- 4. Create product rank history table
-- ============================================

CREATE TABLE IF NOT EXISTS product_rank_history (
    id SERIAL PRIMARY KEY,
    product_id VARCHAR(36) NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,

    rank INTEGER NOT NULL,
    page INTEGER NOT NULL,
    position INTEGER NOT NULL,  -- Position within page (1-20)

    keyword VARCHAR(200) NOT NULL,
    checked_by VARCHAR(36),  -- bot_id that checked

    -- Context
    campaign_id VARCHAR(36) REFERENCES campaigns(campaign_id) ON DELETE SET NULL,
    test_case VARCHAR(20),

    checked_at TIMESTAMP DEFAULT NOW(),

    -- Metadata
    total_results INTEGER,  -- Total search results count
    competitor_count INTEGER  -- Number of products above this one
);

COMMENT ON TABLE product_rank_history IS 'Historical ranking data for products';

CREATE INDEX idx_rank_history_product ON product_rank_history(product_id, checked_at DESC);
CREATE INDEX idx_rank_history_campaign ON product_rank_history(campaign_id);
CREATE INDEX idx_rank_history_checked_at ON product_rank_history(checked_at DESC);

-- ============================================
-- 5. Create view for product statistics
-- ============================================

CREATE OR REPLACE VIEW product_stats AS
SELECT
    p.product_id,
    p.product_name,
    p.keyword,
    p.current_rank,
    p.initial_rank,
    p.rank_improvement,
    p.status,

    -- Campaign stats
    COUNT(DISTINCT c.campaign_id) AS total_campaigns,
    COUNT(DISTINCT CASE WHEN c.status = 'active' THEN c.campaign_id END) AS active_campaigns,

    -- Traffic stats
    COALESCE(SUM(c.current_traffic_count), 0) AS total_traffic_generated,
    COALESCE(SUM(c.success_tasks), 0) AS successful_tasks,

    -- Rank check stats
    (SELECT COUNT(*) FROM product_rank_history h WHERE h.product_id = p.product_id) AS total_rank_checks,
    (SELECT MIN(rank) FROM product_rank_history h WHERE h.product_id = p.product_id) AS best_rank_ever,
    (SELECT MAX(rank) FROM product_rank_history h WHERE h.product_id = p.product_id) AS worst_rank_ever,

    -- Last check
    (SELECT checked_at FROM product_rank_history h
     WHERE h.product_id = p.product_id
     ORDER BY checked_at DESC LIMIT 1) AS last_rank_check_at

FROM products p
LEFT JOIN campaigns c ON c.product_id = p.product_id
GROUP BY p.product_id;

COMMENT ON VIEW product_stats IS 'Aggregated statistics for each product';

-- ============================================
-- 6. Create function to update product rank
-- ============================================

CREATE OR REPLACE FUNCTION update_product_rank(
    p_product_id VARCHAR(36),
    p_rank INTEGER,
    p_page INTEGER,
    p_position INTEGER,
    p_checked_by VARCHAR(36) DEFAULT NULL,
    p_campaign_id VARCHAR(36) DEFAULT NULL
)
RETURNS VOID AS $$
DECLARE
    v_initial_rank INTEGER;
BEGIN
    -- Get initial rank if not set
    SELECT initial_rank INTO v_initial_rank
    FROM products
    WHERE product_id = p_product_id;

    -- If this is the first rank check, set initial_rank
    IF v_initial_rank IS NULL THEN
        UPDATE products
        SET initial_rank = p_rank,
            current_rank = p_rank,
            best_rank = p_rank,
            worst_rank = p_rank,
            last_rank_check_at = NOW(),
            updated_at = NOW()
        WHERE product_id = p_product_id;
    ELSE
        -- Update current rank and statistics
        UPDATE products
        SET current_rank = p_rank,
            best_rank = LEAST(COALESCE(best_rank, p_rank), p_rank),
            worst_rank = GREATEST(COALESCE(worst_rank, p_rank), p_rank),
            rank_improvement = p_rank - initial_rank,  -- Negative = improved
            total_rank_checks = total_rank_checks + 1,
            last_rank_check_at = NOW(),
            updated_at = NOW()
        WHERE product_id = p_product_id;
    END IF;

    -- Insert into history
    INSERT INTO product_rank_history (
        product_id, rank, page, position, keyword, checked_by, campaign_id, checked_at
    )
    SELECT
        p_product_id,
        p_rank,
        p_page,
        p_position,
        keyword,
        p_checked_by,
        p_campaign_id,
        NOW()
    FROM products
    WHERE product_id = p_product_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_product_rank IS 'Update product ranking and insert history record';

-- ============================================
-- 7. Create function to get products by status
-- ============================================

CREATE OR REPLACE FUNCTION get_active_products()
RETURNS TABLE (
    product_id VARCHAR(36),
    keyword VARCHAR(200),
    product_name VARCHAR(300),
    naver_product_id VARCHAR(100),
    current_rank INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT p.product_id, p.keyword, p.product_name, p.naver_product_id, p.current_rank
    FROM products p
    WHERE p.status = 'active' AND p.is_target = TRUE
    ORDER BY p.created_at DESC;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 8. Create function to get rank trend
-- ============================================

CREATE OR REPLACE FUNCTION get_rank_trend(
    p_product_id VARCHAR(36),
    p_days INTEGER DEFAULT 7
)
RETURNS TABLE (
    check_date DATE,
    avg_rank NUMERIC,
    min_rank INTEGER,
    max_rank INTEGER,
    check_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        DATE(h.checked_at) AS check_date,
        ROUND(AVG(h.rank), 1) AS avg_rank,
        MIN(h.rank) AS min_rank,
        MAX(h.rank) AS max_rank,
        COUNT(*) AS check_count
    FROM product_rank_history h
    WHERE h.product_id = p_product_id
      AND h.checked_at >= NOW() - (p_days || ' days')::INTERVAL
    GROUP BY DATE(h.checked_at)
    ORDER BY check_date DESC;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 9. Create trigger to update updated_at
-- ============================================

CREATE OR REPLACE FUNCTION update_product_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER product_update_timestamp
BEFORE UPDATE ON products
FOR EACH ROW
EXECUTE FUNCTION update_product_timestamp();

-- ============================================
-- 10. Sample data for testing (optional)
-- ============================================

-- Uncomment to insert sample products
/*
INSERT INTO products (
    keyword,
    naver_product_id,
    product_name,
    product_url,
    category,
    brand,
    status,
    created_by
)
VALUES
-- Sample Product 1
('프로틴 쉐이크 초코',
 '1234567890',
 '머슬밀 단백질 쉐이크 초코맛 20팩',
 'https://smartstore.naver.com/musclemeal/products/1234567890',
 '건강식품',
 '머슬밀',
 'active',
 'admin'),

-- Sample Product 2
('무선 이어폰',
 '9876543210',
 '갤럭시 버즈2 프로 블랙',
 'https://smartstore.naver.com/samsung/products/9876543210',
 '이어폰',
 '삼성',
 'active',
 'admin'),

-- Sample Product 3
('노트북 가방',
 '5555555555',
 '맥북 15인치 파우치 가방',
 'https://smartstore.naver.com/bags/products/5555555555',
 '가방',
 'Generic',
 'testing',
 'admin');
*/

-- ============================================
-- 11. Rollback script (for reference)
-- ============================================

/*
-- To rollback this migration, run:

DROP TRIGGER IF EXISTS product_update_timestamp ON products;
DROP FUNCTION IF EXISTS update_product_timestamp();
DROP FUNCTION IF EXISTS get_rank_trend(VARCHAR, INTEGER);
DROP FUNCTION IF EXISTS get_active_products();
DROP FUNCTION IF EXISTS update_product_rank(VARCHAR, INTEGER, INTEGER, INTEGER, VARCHAR, VARCHAR);
DROP VIEW IF EXISTS product_stats;
DROP INDEX IF EXISTS idx_rank_history_checked_at;
DROP INDEX IF EXISTS idx_rank_history_campaign;
DROP INDEX IF EXISTS idx_rank_history_product;
DROP TABLE IF EXISTS product_rank_history;
ALTER TABLE campaigns DROP COLUMN IF EXISTS product_id;
DROP INDEX IF EXISTS idx_campaigns_product_id;
DROP INDEX IF EXISTS idx_products_created_at;
DROP INDEX IF EXISTS idx_products_is_target;
DROP INDEX IF EXISTS idx_products_naver_id;
DROP INDEX IF EXISTS idx_products_keyword;
DROP INDEX IF EXISTS idx_products_status;
DROP TABLE IF EXISTS products;
*/

-- ============================================
-- Migration completed successfully
-- ============================================

-- Verify migration
SELECT
    tablename,
    schemaname
FROM pg_tables
WHERE tablename IN ('products', 'product_rank_history')
ORDER BY tablename;

COMMENT ON TABLE products IS 'Products table created successfully for bot traffic generation system';
