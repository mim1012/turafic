# Turafic C&C Server 설치 및 실행 가이드

## 개요

Turafic C&C (Command & Control) 서버는 봇 네트워크를 중앙에서 제어하는 FastAPI 기반 REST API 서버입니다.

## 시스템 요구사항

- Python 3.10 이상
- PostgreSQL 13 이상 (또는 SQLite 개발용)
- Redis 6 이상 (선택 사항)
- 최소 2GB RAM
- 최소 10GB 디스크 공간

## 설치 단계

### 1. 의존성 설치

```bash
# 서버 의존성 설치
pip install -r requirements_server.txt
```

### 2. 환경 변수 설정

`.env` 파일 생성:

```bash
# 데이터베이스 설정
DATABASE_URL=postgresql+asyncpg://user:password@localhost/turafic
# 또는 개발용 SQLite
# DATABASE_URL=sqlite+aiosqlite:///./turafic.db

# Redis 설정 (선택 사항)
USE_REDIS=true
REDIS_URL=redis://localhost:6379

# 서버 설정
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
DEBUG_MODE=true

# 보안 설정
SECRET_KEY=your-secret-key-here-change-this-in-production

# AI 비전 (자가 치유 시스템용, 선택 사항)
OPENAI_API_KEY=sk-...
```

### 3. 데이터베이스 준비

#### PostgreSQL 사용 시:

```bash
# PostgreSQL 데이터베이스 생성
createdb turafic

# 또는 psql에서
psql -U postgres
CREATE DATABASE turafic;
\q
```

#### SQLite 사용 시:

자동으로 `turafic.db` 파일이 생성됩니다.

### 4. 서버 실행

```bash
# 서버 실행
python run_server.py
```

서버가 정상적으로 시작되면:

```
🚀 Starting Turafic C&C Server
============================================================
Host: 0.0.0.0
Port: 8000
Debug Mode: True
API Docs: http://0.0.0.0:8000/docs
============================================================
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### 5. API 문서 확인

브라우저에서 다음 URL 접속:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## API 엔드포인트

### 봇 관리 (`/api/v1/bots`)

| 메서드 | 엔드포인트 | 설명 |
|---|---|---|
| POST | `/api/v1/bots/register` | 신규 봇 등록 |
| GET | `/api/v1/bots/{bot_id}` | 봇 정보 조회 |
| PATCH | `/api/v1/bots/{bot_id}/status` | 봇 상태 업데이트 |
| GET | `/api/v1/bots/` | 봇 목록 조회 |

### 작업 할당 (`/api/v1/tasks`)

| 메서드 | 엔드포인트 | 설명 |
|---|---|---|
| GET | `/api/v1/tasks/get_task?bot_id=xxx` | 작업 요청 |
| POST | `/api/v1/tasks/report_result` | 작업 결과 보고 |
| POST | `/api/v1/tasks/feedback/error` | 오류 피드백 (스크린샷 포함) |
| GET | `/api/v1/tasks/tasks/{task_id}` | 작업 정보 조회 |

### 관리자 대시보드 (`/api/v1/admin`)

| 메서드 | 엔드포인트 | 설명 |
|---|---|---|
| GET | `/api/v1/admin/dashboard` | 메인 대시보드 통계 |
| GET | `/api/v1/admin/bots/statistics` | 봇 통계 (그룹별, 상태별) |
| GET | `/api/v1/admin/tasks/statistics` | 작업 통계 (그룹별 성공률) |
| GET | `/api/v1/admin/top_performers` | 상위 성과 봇 목록 |
| GET | `/api/v1/admin/recent_activity` | 최근 활동 로그 |

## 사용 예시

### 1. 봇 등록

```bash
curl -X POST "http://localhost:8000/api/v1/bots/register" \
  -H "Content-Type: application/json" \
  -d '{
    "device_model": "SM-G996N",
    "android_version": "12",
    "screen_resolution": "1080x2340",
    "android_id": "abc123def456"
  }'
```

응답:

```json
{
  "bot_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "group": 5,
  "message": "Registration successful"
}
```

### 2. 작업 요청

```bash
curl -X GET "http://localhost:8000/api/v1/tasks/get_task?bot_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

응답:

```json
{
  "task_id": "task-uuid-here",
  "pattern": [
    {
      "action": "kill",
      "target": "com.sec.android.app.sbrowser",
      "description": "삼성 브라우저 강제 종료"
    },
    {
      "action": "wait",
      "duration": 2000
    },
    {
      "action": "tap",
      "x": 540,
      "y": 150,
      "description": "검색창 터치"
    }
  ]
}
```

### 3. 작업 결과 보고

```bash
curl -X POST "http://localhost:8000/api/v1/tasks/report_result" \
  -H "Content-Type: application/json" \
  -d '{
    "bot_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "task_id": "task-uuid-here",
    "status": "success",
    "log": "Task completed successfully"
  }'
```

### 4. 대시보드 통계 조회

```bash
curl -X GET "http://localhost:8000/api/v1/admin/dashboard"
```

응답:

```json
{
  "bots": {
    "total": 27,
    "active": 25,
    "inactive": 2
  },
  "tasks": {
    "total": 1350,
    "success": 1280,
    "failed": 70,
    "success_rate": 94.81
  },
  "performance": {
    "tasks_last_hour": 45,
    "tasks_per_minute": 0.75
  }
}
```

## 프로덕션 배포

### 1. Gunicorn + Nginx 사용

```bash
# Gunicorn 설치
pip install gunicorn

# Gunicorn으로 서버 실행
gunicorn server.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

### 2. Systemd 서비스 등록

`/etc/systemd/system/turafic-server.service`:

```ini
[Unit]
Description=Turafic C&C Server
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/turafic
ExecStart=/usr/bin/python3 run_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# 서비스 활성화 및 시작
sudo systemctl enable turafic-server
sudo systemctl start turafic-server
sudo systemctl status turafic-server
```

### 3. Nginx 리버스 프록시 설정

`/etc/nginx/sites-available/turafic`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
# Nginx 설정 활성화
sudo ln -s /etc/nginx/sites-available/turafic /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## 문제 해결

### 데이터베이스 연결 오류

```
sqlalchemy.exc.OperationalError: could not connect to server
```

**해결책**: PostgreSQL 서버가 실행 중인지 확인하고, `DATABASE_URL` 설정을 확인하세요.

### Redis 연결 오류

```
redis.exceptions.ConnectionError: Error connecting to Redis
```

**해결책**: Redis 서버가 실행 중인지 확인하거나, `.env`에서 `USE_REDIS=false`로 설정하여 인메모리 캐시를 사용하세요.

### 포트 이미 사용 중

```
OSError: [Errno 98] Address already in use
```

**해결책**: 다른 포트를 사용하거나, 기존 프로세스를 종료하세요.

```bash
# 포트 8000을 사용하는 프로세스 찾기
lsof -i :8000

# 프로세스 종료
kill -9 <PID>
```

## 로그 확인

```bash
# 서버 로그 확인
tail -f turafic_server.log

# Systemd 서비스 로그 확인
sudo journalctl -u turafic-server -f
```

## 보안 권장사항

1. **SECRET_KEY 변경**: 프로덕션 환경에서는 반드시 강력한 SECRET_KEY 사용
2. **HTTPS 사용**: Nginx에서 SSL/TLS 인증서 설정
3. **방화벽 설정**: 필요한 포트만 개방
4. **API 인증**: API 키 또는 JWT 토큰 기반 인증 추가 (향후 구현)

## 다음 단계

- Android 에이전트 APK 빌드 및 배포
- 테스트 매트릭스 설정 (`config/test_matrix.json`)
- 관리자 대시보드 웹 UI 개발 (선택 사항)
