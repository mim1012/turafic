#!/usr/bin/env npx tsx
/**
 * Supabase REST API를 통한 스키마 적용
 *
 * 사용법:
 *   npx tsx scripts/sql/apply-schema-rest.ts production
 *   npx tsx scripts/sql/apply-schema-rest.ts experiment
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// DB 설정
const DB_CONFIGS = {
  production: {
    url: "https://cwsdvgkjptuvbdtxcejt.supabase.co",
    serviceKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN3c2R2Z2tqcHR1dmJkdHhjZWp0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NjM5NDQzOSwiZXhwIjoyMDcxOTcwNDM5fQ.KOOooT-vz-JW2rcdwJdQdirePPIERmYWR4Vqy2v_2NY",
    sqlFile: "create-production-schema.sql",
    name: "Production DB (adpang-production)"
  },
  experiment: {
    url: "https://hdtjkaieulphqwmcjhcx.supabase.co",
    serviceKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhkdGprYWlldWxwaHF3bWNqaGN4Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2Mzg3OTMzNSwiZXhwIjoyMDc5NDU1MzM1fQ.Jn6RiB8H-_pEZ9BW9x9Mqt4fW-XTj0M3gEAShWDjOtE",
    sqlFile: "create-experiment-schema.sql",
    name: "Experiment DB"
  }
};

// SQL 문장 분리 (DO 블록, CREATE TABLE 등을 올바르게 분리)
function splitSqlStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = "";
  let inDoBlock = false;
  let dollarQuoteDepth = 0;

  const lines = sql.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    // 주석만 있는 줄 무시
    if (trimmed.startsWith("--") && !current.trim()) {
      continue;
    }

    current += line + "\n";

    // DO $$ ... END $$; 블록 감지
    if (trimmed.includes("DO $$")) {
      inDoBlock = true;
      dollarQuoteDepth++;
    }
    if (inDoBlock && trimmed.includes("END $$;")) {
      dollarQuoteDepth--;
      if (dollarQuoteDepth === 0) {
        inDoBlock = false;
        statements.push(current.trim());
        current = "";
        continue;
      }
    }

    // DO 블록 밖에서 세미콜론으로 끝나면 문장 완료
    if (!inDoBlock && trimmed.endsWith(";") && current.trim()) {
      statements.push(current.trim());
      current = "";
    }
  }

  // 남은 내용이 있으면 추가
  if (current.trim()) {
    statements.push(current.trim());
  }

  return statements.filter(s => {
    const cleaned = s.replace(/--.*$/gm, "").trim();
    return cleaned.length > 0;
  });
}

async function executeRpc(url: string, serviceKey: string, sql: string): Promise<any> {
  const response = await fetch(`${url}/rest/v1/rpc/exec_sql`, {
    method: "POST",
    headers: {
      "apikey": serviceKey,
      "Authorization": `Bearer ${serviceKey}`,
      "Content-Type": "application/json",
      "Prefer": "return=minimal"
    },
    body: JSON.stringify({ sql_query: sql })
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`RPC 실패 (${response.status}): ${text}`);
  }

  return response.json().catch(() => ({}));
}

async function checkRpcAvailable(url: string, serviceKey: string): Promise<boolean> {
  try {
    const response = await fetch(`${url}/rest/v1/rpc/exec_sql`, {
      method: "POST",
      headers: {
        "apikey": serviceKey,
        "Authorization": `Bearer ${serviceKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ sql_query: "SELECT 1" })
    });
    return response.ok || response.status === 404; // 404면 RPC 함수가 없는 것
  } catch {
    return false;
  }
}

async function applySchema(target: "production" | "experiment") {
  const config = DB_CONFIGS[target];

  console.log(`\n🔧 ${config.name} 스키마 적용 시작...\n`);

  // SQL 파일 읽기
  const sqlPath = path.join(__dirname, config.sqlFile);
  console.log(`📄 SQL 파일: ${sqlPath}`);

  if (!fs.existsSync(sqlPath)) {
    console.error(`❌ SQL 파일을 찾을 수 없습니다: ${sqlPath}`);
    process.exit(1);
  }

  const sql = fs.readFileSync(sqlPath, "utf-8");
  console.log(`📄 SQL 파일 로드 완료 (${sql.length} bytes)\n`);

  // RPC 사용 가능 여부 확인
  console.log(`🔍 Supabase 연결 확인 중...`);
  const isRpcAvailable = await checkRpcAvailable(config.url, config.serviceKey);

  if (!isRpcAvailable) {
    console.log(`\n⚠️  REST API RPC를 사용할 수 없습니다.`);
    console.log(`\n📋 Supabase SQL Editor에서 직접 실행해주세요:`);
    console.log(`\n   1. ${config.url} 에 접속`);
    console.log(`   2. SQL Editor로 이동`);
    console.log(`   3. 아래 SQL 파일 내용을 복사하여 실행:`);
    console.log(`      ${sqlPath}\n`);

    console.log(`\n${"=".repeat(60)}`);
    console.log(`SQL 내용:\n`);
    console.log(sql);
    console.log(`${"=".repeat(60)}\n`);

    return;
  }

  // SQL 실행
  const statements = splitSqlStatements(sql);
  console.log(`📝 ${statements.length}개 SQL 문장 실행 중...\n`);

  for (let i = 0; i < statements.length; i++) {
    const stmt = statements[i];
    const preview = stmt.split("\n")[0].substring(0, 50);

    try {
      await executeRpc(config.url, config.serviceKey, stmt);
      console.log(`✅ [${i + 1}/${statements.length}] ${preview}...`);
    } catch (err: any) {
      if (err.message.includes("already exists") || err.message.includes("duplicate")) {
        console.log(`⏭️  [${i + 1}/${statements.length}] (이미 존재) ${preview}...`);
      } else {
        console.error(`❌ [${i + 1}/${statements.length}] 오류: ${err.message}`);
      }
    }
  }

  console.log(`\n🎉 ${config.name} 스키마 적용 시도 완료!`);
}

// 글로벌 에러 핸들러
process.on('unhandledRejection', (reason) => {
  console.error('\n❌ Unhandled Rejection:', reason);
  process.exit(1);
});

// 메인 실행
const target = process.argv[2] as "production" | "experiment";

if (!target || !["production", "experiment"].includes(target)) {
  console.log(`
사용법: npx tsx scripts/sql/apply-schema-rest.ts <target>

target:
  production  - Production DB에 스키마 적용
  experiment  - Experiment DB에 스키마 적용
`);
  process.exit(1);
}

applySchema(target).catch((err) => {
  console.error('\n❌ 에러 발생:', err.message);
  process.exit(1);
});
