"""
Turafic C&C Server - Run Script
서버 실행 스크립트
"""

import uvicorn
from server.config.server_settings import SERVER_HOST, SERVER_PORT, DEBUG_MODE

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Starting Turafic C&C Server")
    print("=" * 60)
    print(f"Host: {SERVER_HOST}")
    print(f"Port: {SERVER_PORT}")
    print(f"Debug Mode: {DEBUG_MODE}")
    print(f"API Docs: http://{SERVER_HOST}:{SERVER_PORT}/docs")
    print("=" * 60)
    
    uvicorn.run(
        "server.main:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=DEBUG_MODE,  # 개발 모드에서만 자동 재시작
        log_level="info"
    )
