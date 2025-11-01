"""
Turafic C&C Server - Main Entry Point
FastAPI 기반 봇 네트워크 중앙 제어 서버
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
import asyncio

from server.api import bot_management, task_assignment, admin, campaign_management, ranking_group_api, product_management, analytics
from server.core.database import init_db, close_db
from server.core.cache import init_cache, close_cache
from server.core.rank_check_scheduler import rank_check_scheduler_loop

@asynccontextmanager
async def lifespan(app: FastAPI):
    """서버 시작/종료 시 실행되는 라이프사이클 이벤트"""
    # 시작 시
    print("🚀 Turafic C&C Server Starting...")
    await init_db()
    await init_cache()
    print("✅ Database and Cache initialized")

    # Rank Check Scheduler 시작
    scheduler_task = asyncio.create_task(rank_check_scheduler_loop())
    print("✅ Rank Check Scheduler started (6-hour interval)")

    yield

    # 종료 시
    print("🛑 Turafic C&C Server Shutting down...")
    scheduler_task.cancel()  # 스케줄러 태스크 취소
    try:
        await scheduler_task
    except asyncio.CancelledError:
        print("✅ Rank Check Scheduler stopped")
    await close_db()
    await close_cache()
    print("✅ Cleanup completed")

# FastAPI 앱 초기화
app = FastAPI(
    title="Turafic C&C Server",
    description="봇 네트워크 중앙 제어 서버 - 작업 할당, 모니터링, 관리",
    version="1.0.0",
    lifespan=lifespan
)

# CORS 설정 (관리자 대시보드 웹 UI 접근 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 실제 배포 시 특정 도메인으로 제한
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API 라우터 등록
app.include_router(bot_management.router, prefix="/api/v1/bots", tags=["Bot Management"])
app.include_router(task_assignment.router, prefix="/api/v1/tasks", tags=["Task Assignment"])
app.include_router(campaign_management.router, prefix="/api/v1/campaigns", tags=["Campaign Management"])
app.include_router(ranking_group_api.router, prefix="/api/v1/ranking-groups", tags=["Ranking Groups"])
app.include_router(product_management.router, prefix="/api/v1", tags=["Product Management"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["Admin Dashboard"])
app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["Analytics"])

@app.get("/")
async def root():
    """서버 상태 확인"""
    return {
        "service": "Turafic C&C Server",
        "status": "running",
        "version": "1.0.0",
        "endpoints": {
            "bot_registration": "/api/v1/bots/register",
            "task_request": "/api/v1/tasks/get_task",
            "task_report": "/api/v1/tasks/report_result",
            "admin_dashboard": "/api/v1/admin/dashboard",
            "api_docs": "/docs"
        }
    }

@app.get("/health")
async def health_check():
    """헬스 체크 엔드포인트"""
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(
        "server.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # 개발 모드에서만 사용
        log_level="info"
    )
