"""
Server Configuration Settings
서버 설정 (환경 변수 기반)
"""

import os
from pathlib import Path

# 프로젝트 루트 디렉토리
BASE_DIR = Path(__file__).parent.parent.parent

# 데이터베이스 설정
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./turafic.db"  # 개발용 SQLite
    # 실제 배포 시: "postgresql+asyncpg://user:password@localhost/turafic"
)

# Redis 설정
USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# 서버 설정
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
DEBUG_MODE = os.getenv("DEBUG_MODE", "true").lower() == "true"

# 보안 설정
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")  # 실제 배포 시 변경 필수
API_KEY = os.getenv("API_KEY", None)  # 봇 인증용 API 키 (선택 사항)

# 파일 업로드 설정
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/tmp/turafic_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# AI 비전 설정 (자가 치유 시스템용)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", None)
USE_AI_VISION = OPENAI_API_KEY is not None

# 로깅 설정
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "turafic_server.log")

# 테스트 매트릭스 파일 경로
TEST_MATRIX_PATH = BASE_DIR / "config" / "test_matrix.json"

print(f"✅ Server configuration loaded:")
print(f"  - Database: {DATABASE_URL}")
print(f"  - Redis: {'Enabled' if USE_REDIS else 'Disabled (in-memory cache)'}")
print(f"  - Debug Mode: {DEBUG_MODE}")
print(f"  - AI Vision: {'Enabled' if USE_AI_VISION else 'Disabled'}")
