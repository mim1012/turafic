#!/usr/bin/env npx tsx
/**
 * Supabase DB에 스키마 적용 스크립트
 *
 * 사용법:
 *   npx tsx scripts/sql/apply-schema.ts production
 *   npx tsx scripts/sql/apply-schema.ts experiment
 */

import postgres from "postgres";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// DB 설정
// Supabase Session mode pooler (5432) - DDL 지원
const DB_CONFIGS = {
  production: {
    url: "postgresql://postgres.cwsdvgkjptuvbdtxcejt:EGxhoDsQvygcwY5c@aws-0-ap-northeast-2.pooler.supabase.com:5432/postgres",
    sqlFile: "create-production-schema.sql",
    name: "Production DB (adpang-production)"
  },
  experiment: {
    url: "postgresql://postgres.hdtjkaieulphqwmcjhcx:rlawlgns2233%40@aws-0-ap-northeast-2.pooler.supabase.com:5432/postgres",
    sqlFile: "create-experiment-schema.sql",
    name: "Experiment DB"
  }
};

async function applySchema(target: "production" | "experiment") {
  const config = DB_CONFIGS[target];

  console.log(`\n🔧 ${config.name} 스키마 적용 시작...\n`);
  console.log(`📡 연결 중: ${config.url.replace(/:[^:@]+@/, ':****@')}\n`);

  // SQL 파일 읽기
  const sqlPath = path.join(__dirname, config.sqlFile);
  console.log(`📄 SQL 파일: ${sqlPath}`);

  if (!fs.existsSync(sqlPath)) {
    console.error(`❌ SQL 파일을 찾을 수 없습니다: ${sqlPath}`);
    process.exit(1);
  }

  const sql = fs.readFileSync(sqlPath, "utf-8");
  console.log(`📄 SQL 파일 로드 완료 (${sql.length} bytes)\n`);

  // DB 연결
  console.log(`🔌 DB 연결 시도 중...`);
  const client = postgres(config.url, {
    max: 1,
    idle_timeout: 20,
    connect_timeout: 30,
    ssl: 'require',
    debug: (connection, query, params) => {
      // 디버그 로그 비활성화
    },
    onnotice: () => {},
  });

  try {
    // 연결 테스트
    console.log(`🔍 연결 테스트 중...`);
    const testResult = await client`SELECT 1 as test`;
    console.log(`✅ DB 연결 성공!\n`);

    // SQL 실행 (각 문장 분리 실행)
    const statements = sql
      .split(/;(?=\s*(?:--|DO|CREATE|ALTER|SELECT))/g)
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith("--"));

    for (const statement of statements) {
      if (statement.trim()) {
        try {
          await client.unsafe(statement);
          // 성공한 문장의 첫 줄만 출력
          const firstLine = statement.split("\n")[0].substring(0, 60);
          console.log(`✅ ${firstLine}...`);
        } catch (err: any) {
          // 이미 존재하는 경우 무시
          if (err.message.includes("already exists") || err.message.includes("duplicate")) {
            console.log(`⏭️  (이미 존재) ${statement.split("\n")[0].substring(0, 50)}...`);
          } else {
            console.error(`❌ 오류: ${err.message}`);
            console.error(`   문장: ${statement.substring(0, 100)}...`);
          }
        }
      }
    }

    // 테이블 확인
    console.log(`\n📋 테이블 확인 중...`);
    const tables = await client`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
      AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `;

    console.log(`\n✅ ${config.name} 테이블 목록:`);
    tables.forEach((t: any) => {
      console.log(`   - ${t.table_name}`);
    });

    // Enum 타입 확인
    const enums = await client`
      SELECT t.typname as enum_name,
             array_agg(e.enumlabel ORDER BY e.enumsortorder) as values
      FROM pg_type t
      JOIN pg_enum e ON t.oid = e.enumtypid
      WHERE t.typtype = 'e'
      GROUP BY t.typname
      ORDER BY t.typname
    `;

    console.log(`\n✅ Enum 타입 목록:`);
    enums.forEach((e: any) => {
      console.log(`   - ${e.enum_name}: [${e.values.join(", ")}]`);
    });

    console.log(`\n🎉 ${config.name} 스키마 적용 완료!\n`);

  } catch (error: any) {
    console.error(`\n❌ 스키마 적용 실패: ${error.message}`);
    throw error;
  } finally {
    await client.end();
  }
}

// 글로벌 에러 핸들러
process.on('unhandledRejection', (reason, promise) => {
  console.error('\n❌ Unhandled Rejection:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error('\n❌ Uncaught Exception:', error);
  process.exit(1);
});

// 메인 실행
const target = process.argv[2] as "production" | "experiment";

if (!target || !["production", "experiment"].includes(target)) {
  console.log(`
사용법: npx tsx scripts/sql/apply-schema.ts <target>

target:
  production  - Production DB에 스키마 적용
  experiment  - Experiment DB에 스키마 적용

예시:
  npx tsx scripts/sql/apply-schema.ts production
  npx tsx scripts/sql/apply-schema.ts experiment
`);
  process.exit(1);
}

applySchema(target).catch((err) => {
  console.error('\n❌ 에러 발생:', err.message);
  console.error(err.stack);
  process.exit(1);
});
