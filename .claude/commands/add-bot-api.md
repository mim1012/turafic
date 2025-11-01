# /add-bot-api

봇 등록 API 엔드포인트를 추가합니다.

## 사용법
```
/add-bot-api [bot_type]
```

**파라미터**:
- `bot_type`: `traffic` 또는 `rank_checker` (선택, 기본값: `traffic`)

## 예시
```
/add-bot-api traffic
/add-bot-api rank_checker
```

## 생성되는 파일
- `server/api/traffic_bot.py` 또는 `server/api/rank_checker.py`

## API 엔드포인트

### POST /api/v1/bots
봇 등록

**Request Body**:
```json
{
    "bot_id": "bot-t1",
    "bot_type": "traffic",
    "android_id": "abc123def456",
    "device_model": "SM-G998N",
    "is_leader": true,
    "leader_bot_id": null,
    "group_id": 1
}
```

**Response**:
```json
{
    "bot_id": "bot-t1",
    "status": "active",
    "message": "Bot registered successfully"
}
```

### GET /api/v1/bots/{bot_id}
봇 정보 조회

**Response**:
```json
{
    "bot_id": "bot-t1",
    "bot_type": "traffic",
    "is_leader": true,
    "group_id": 1,
    "assigned_campaign_id": "campaign-1",
    "status": "active",
    "last_heartbeat": "2025-11-01T12:00:00"
}
```

### PUT /api/v1/bots/{bot_id}/heartbeat
봇 하트비트 업데이트

**Response**:
```json
{
    "message": "Heartbeat updated",
    "last_heartbeat": "2025-11-01T12:00:00"
}
```

### DELETE /api/v1/bots/{bot_id}
봇 삭제

**Response**:
```json
{
    "message": "Bot deleted"
}
```

## 구현 예시

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from server.core.database import get_db, Bot
from src.utils.logger import log

router = APIRouter()

class BotRegister(BaseModel):
    bot_id: str
    bot_type: str  # 'traffic' or 'rank_checker'
    android_id: str
    device_model: str
    is_leader: bool = False
    leader_bot_id: Optional[str] = None
    group_id: Optional[int] = None

@router.post("/api/v1/bots")
async def register_bot(
    bot: BotRegister,
    db: Session = Depends(get_db)
):
    """
    봇 등록
    
    Args:
        bot: 봇 정보
        db: 데이터베이스 세션
    
    Returns:
        등록된 봇 정보
    
    Raises:
        HTTPException: 봇 ID 또는 Android ID 중복 시
    """
    try:
        # 중복 확인
        existing_bot = db.query(Bot).filter(
            (Bot.bot_id == bot.bot_id) | (Bot.android_id == bot.android_id)
        ).first()
        
        if existing_bot:
            raise HTTPException(
                status_code=400,
                detail="Bot ID or Android ID already exists"
            )
        
        # 봇 생성
        new_bot = Bot(
            bot_id=bot.bot_id,
            bot_type=bot.bot_type,
            android_id=bot.android_id,
            device_model=bot.device_model,
            is_leader=bot.is_leader,
            leader_bot_id=bot.leader_bot_id,
            group_id=bot.group_id,
            status='active',
            registered_at=datetime.now()
        )
        
        db.add(new_bot)
        db.commit()
        db.refresh(new_bot)
        
        log.info(f"Bot {bot.bot_id} registered successfully")
        
        return {
            "bot_id": new_bot.bot_id,
            "status": new_bot.status,
            "message": "Bot registered successfully"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Failed to register bot {bot.bot_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/v1/bots/{bot_id}")
async def get_bot(
    bot_id: str,
    db: Session = Depends(get_db)
):
    """봇 정보 조회"""
    bot = db.query(Bot).filter(Bot.bot_id == bot_id).first()
    
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    return bot.to_dict()

@router.put("/api/v1/bots/{bot_id}/heartbeat")
async def update_heartbeat(
    bot_id: str,
    db: Session = Depends(get_db)
):
    """봇 하트비트 업데이트"""
    bot = db.query(Bot).filter(Bot.bot_id == bot_id).first()
    
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    bot.last_heartbeat = datetime.now()
    db.commit()
    
    return {
        "message": "Heartbeat updated",
        "last_heartbeat": bot.last_heartbeat
    }

@router.delete("/api/v1/bots/{bot_id}")
async def delete_bot(
    bot_id: str,
    db: Session = Depends(get_db)
):
    """봇 삭제"""
    bot = db.query(Bot).filter(Bot.bot_id == bot_id).first()
    
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    db.delete(bot)
    db.commit()
    
    log.info(f"Bot {bot_id} deleted")
    
    return {"message": "Bot deleted"}
```

## 테스트

```python
import pytest
from fastapi.testclient import TestClient

def test_봇_등록_성공(client: TestClient):
    """봇 등록이 성공하는 경우"""
    response = client.post("/api/v1/bots", json={
        "bot_id": "test-bot-1",
        "bot_type": "traffic",
        "android_id": "test-android-1",
        "device_model": "SM-G998N",
        "is_leader": True,
        "group_id": 1
    })
    
    assert response.status_code == 200
    assert response.json()["bot_id"] == "test-bot-1"
    assert response.json()["status"] == "active"

def test_봇_등록_중복(client: TestClient):
    """봇 ID 중복 시 실패"""
    # 첫 번째 등록
    client.post("/api/v1/bots", json={
        "bot_id": "test-bot-1",
        "bot_type": "traffic",
        "android_id": "test-android-1",
        "device_model": "SM-G998N"
    })
    
    # 두 번째 등록 (중복)
    response = client.post("/api/v1/bots", json={
        "bot_id": "test-bot-1",
        "bot_type": "traffic",
        "android_id": "test-android-2",
        "device_model": "SM-G998N"
    })
    
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]
```

## 관련 문서
- CLAUDE.md: 봇 아키텍처 설명
- ARCHITECTURE.md: 시스템 아키텍처
- server/core/database.py: Bot 모델 정의
