-- Production DB Schema
-- 테이블: workerNodes, distributedTasks
-- distributedExperiments는 Production에서는 불필요

-- 1. Enum 타입 생성
DO $$ BEGIN
  CREATE TYPE worker_node_type AS ENUM ('experiment', 'worker');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE worker_node_status AS ENUM ('online', 'offline', 'busy');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE distributed_task_type AS ENUM ('experiment', 'production');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE distributed_task_status AS ENUM ('pending', 'assigned', 'running', 'completed', 'failed');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

-- 2. workerNodes 테이블
CREATE TABLE IF NOT EXISTS "workerNodes" (
  id SERIAL PRIMARY KEY,
  "nodeId" VARCHAR(50) NOT NULL UNIQUE,
  "nodeType" worker_node_type NOT NULL,
  status worker_node_status DEFAULT 'offline' NOT NULL,
  "lastHeartbeat" TIMESTAMP,
  "currentTaskId" INTEGER,
  hostname VARCHAR(100),
  "ipAddress" VARCHAR(50),
  "createdAt" TIMESTAMP DEFAULT NOW() NOT NULL,
  "updatedAt" TIMESTAMP DEFAULT NOW() NOT NULL
);

-- workerNodes 인덱스
CREATE INDEX IF NOT EXISTS idx_worker_nodes_status ON "workerNodes" (status);
CREATE INDEX IF NOT EXISTS idx_worker_nodes_type ON "workerNodes" ("nodeType");

-- 3. distributedTasks 테이블
CREATE TABLE IF NOT EXISTS "distributedTasks" (
  id SERIAL PRIMARY KEY,
  "experimentId" INTEGER,
  "taskType" distributed_task_type NOT NULL,
  "targetNodeType" worker_node_type,
  "assignedNodeId" VARCHAR(50),
  "productId" INTEGER,
  keyword VARCHAR(255) NOT NULL,
  "nvMid" VARCHAR(100) NOT NULL,
  "productName" TEXT NOT NULL,
  "productUrl" TEXT,
  variables TEXT NOT NULL,
  status distributed_task_status DEFAULT 'pending' NOT NULL,
  priority INTEGER DEFAULT 0 NOT NULL,
  result TEXT,
  "beforeRank" INTEGER,
  "afterRank" INTEGER,
  "createdAt" TIMESTAMP DEFAULT NOW() NOT NULL,
  "assignedAt" TIMESTAMP,
  "startedAt" TIMESTAMP,
  "completedAt" TIMESTAMP
);

-- distributedTasks 인덱스
CREATE INDEX IF NOT EXISTS idx_distributed_tasks_polling
  ON "distributedTasks" (status, priority DESC, "createdAt" ASC)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_distributed_tasks_experiment
  ON "distributedTasks" ("experimentId")
  WHERE "experimentId" IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_distributed_tasks_node
  ON "distributedTasks" ("assignedNodeId")
  WHERE "assignedNodeId" IS NOT NULL;

-- 완료 메시지
SELECT 'Production DB Schema Created Successfully!' as message;
