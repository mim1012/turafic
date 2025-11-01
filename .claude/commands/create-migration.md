# /create-migration

데이터베이스 마이그레이션 스크립트를 생성합니다.

## 사용법
```
/create-migration [migration_name]
```

**파라미터**:
- `migration_name`: 마이그레이션 이름 (예: `add_bot_campaign_assignment`)

## 예시
```
/create-migration add_bot_campaign_assignment
/create-migration add_rank_checker_groups
/create-migration update_bots_table
```

## 마이그레이션 파일 위치
```
server/migrations/
├── 001_init.sql
├── 002_add_bot_campaign_assignment.sql
├── 003_add_rank_checker_groups.sql
└── ...
```

## 마이그레이션 템플릿

### PostgreSQL
```sql
-- Migration: {migration_name}
-- Created: {timestamp}
-- Description: {description}

BEGIN;

-- 테이블 생성
CREATE TABLE IF NOT EXISTS {table_name} (
    id SERIAL PRIMARY KEY,
    -- 필드 정의
    created_at TIMESTAMP DEFAULT NOW()
);

-- 인덱스 추가
CREATE INDEX idx_{table_name}_{field} ON {table_name}({field});

-- 외래 키 추가
ALTER TABLE {table_name}
ADD CONSTRAINT fk_{table_name}_{ref_table}
FOREIGN KEY ({field}) REFERENCES {ref_table}(id);

COMMIT;
```

### SQLite (개발용)
```sql
-- Migration: {migration_name}
-- Created: {timestamp}
-- Description: {description}

-- 테이블 생성
CREATE TABLE IF NOT EXISTS {table_name} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 필드 정의
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스 추가
CREATE INDEX IF NOT EXISTS idx_{table_name}_{field} ON {table_name}({field});
```

## 예시: Bot Campaign Assignment 마이그레이션

### 파일: `server/migrations/002_add_bot_campaign_assignment.sql`

```sql
-- Migration: add_bot_campaign_assignment
-- Created: 2025-11-01
-- Description: Add assigned_bot_id to campaigns and assigned_campaign_id to bots

BEGIN;

-- Campaign 테이블에 assigned_bot_id 추가
ALTER TABLE campaigns
ADD COLUMN assigned_bot_id VARCHAR(36);

-- Bot 테이블에 assigned_campaign_id 추가
ALTER TABLE bots
ADD COLUMN assigned_campaign_id VARCHAR(36);

-- 인덱스 추가 (성능 최적화)
CREATE INDEX idx_campaigns_assigned_bot ON campaigns(assigned_bot_id);
CREATE INDEX idx_bots_assigned_campaign ON bots(assigned_campaign_id);

-- 외래 키 제약 조건 추가
ALTER TABLE campaigns
ADD CONSTRAINT fk_campaigns_bots
FOREIGN KEY (assigned_bot_id) REFERENCES bots(bot_id)
ON DELETE SET NULL;

ALTER TABLE bots
ADD CONSTRAINT fk_bots_campaigns
FOREIGN KEY (assigned_campaign_id) REFERENCES campaigns(campaign_id)
ON DELETE SET NULL;

COMMIT;
```

## 예시: Rank Checker Groups 마이그레이션

### 파일: `server/migrations/003_add_rank_checker_groups.sql`

```sql
-- Migration: add_rank_checker_groups
-- Created: 2025-11-01
-- Description: Add rank_checker_groups table for managing rank checker bot groups

BEGIN;

-- RankCheckerGroups 테이블 생성
CREATE TABLE IF NOT EXISTS rank_checker_groups (
    group_id INTEGER PRIMARY KEY,
    leader_bot_id VARCHAR(36) NOT NULL,
    member_bot_ids TEXT NOT NULL,  -- JSON 배열
    current_ip VARCHAR(45),
    last_ip_change TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW()
);

-- 인덱스 추가
CREATE INDEX idx_rank_checker_groups_leader ON rank_checker_groups(leader_bot_id);
CREATE INDEX idx_rank_checker_groups_status ON rank_checker_groups(status);

-- 외래 키 제약 조건
ALTER TABLE rank_checker_groups
ADD CONSTRAINT fk_rank_checker_groups_leader
FOREIGN KEY (leader_bot_id) REFERENCES bots(bot_id)
ON DELETE CASCADE;

COMMIT;
```

## 마이그레이션 실행

### PostgreSQL (프로덕션)
```bash
# Railway 데이터베이스에 연결
psql $DATABASE_URL < server/migrations/002_add_bot_campaign_assignment.sql
```

### SQLite (개발)
```bash
# 로컬 데이터베이스에 적용
sqlite3 turafic.db < server/migrations/002_add_bot_campaign_assignment.sql
```

### Python 스크립트로 실행
```python
import psycopg2
from config.settings import config

def run_migration(migration_file: str):
    """마이그레이션 실행"""
    conn = psycopg2.connect(config.DATABASE_URL)
    cursor = conn.cursor()
    
    try:
        with open(migration_file, 'r') as f:
            sql = f.read()
        
        cursor.execute(sql)
        conn.commit()
        print(f"Migration {migration_file} applied successfully")
    
    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        raise
    
    finally:
        cursor.close()
        conn.close()

# 실행
run_migration("server/migrations/002_add_bot_campaign_assignment.sql")
```

## 롤백 스크립트

마이그레이션마다 롤백 스크립트도 함께 작성하세요.

### 파일: `server/migrations/002_add_bot_campaign_assignment_rollback.sql`

```sql
-- Rollback: add_bot_campaign_assignment
-- Created: 2025-11-01

BEGIN;

-- 외래 키 제약 조건 제거
ALTER TABLE campaigns DROP CONSTRAINT IF EXISTS fk_campaigns_bots;
ALTER TABLE bots DROP CONSTRAINT IF EXISTS fk_bots_campaigns;

-- 인덱스 제거
DROP INDEX IF EXISTS idx_campaigns_assigned_bot;
DROP INDEX IF EXISTS idx_bots_assigned_campaign;

-- 컬럼 제거
ALTER TABLE campaigns DROP COLUMN IF EXISTS assigned_bot_id;
ALTER TABLE bots DROP COLUMN IF EXISTS assigned_campaign_id;

COMMIT;
```

## 마이그레이션 관리

### 마이그레이션 이력 테이블

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    id SERIAL PRIMARY KEY,
    migration_name VARCHAR(255) NOT NULL UNIQUE,
    applied_at TIMESTAMP DEFAULT NOW()
);
```

### 마이그레이션 적용 여부 확인

```python
def is_migration_applied(migration_name: str) -> bool:
    """마이그레이션 적용 여부 확인"""
    cursor.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE migration_name = %s",
        (migration_name,)
    )
    return cursor.fetchone()[0] > 0

def record_migration(migration_name: str):
    """마이그레이션 이력 기록"""
    cursor.execute(
        "INSERT INTO schema_migrations (migration_name) VALUES (%s)",
        (migration_name,)
    )
```

## 베스트 프랙티스

1. **순차적 번호 사용**: `001_`, `002_`, `003_` 등
2. **명확한 이름**: `add_bot_campaign_assignment`, `update_bots_table`
3. **트랜잭션 사용**: `BEGIN;` ... `COMMIT;`
4. **롤백 스크립트 작성**: 항상 롤백 가능하도록
5. **테스트**: 개발 환경에서 먼저 테스트
6. **백업**: 프로덕션 적용 전 데이터베이스 백업

## 관련 문서
- server/core/database.py: 데이터베이스 모델
- ARCHITECTURE.md: 데이터베이스 스키마
- server/migrations/: 마이그레이션 스크립트
