# Turafic Project - Claude Skills

이 디렉토리는 Claude AI가 Turafic 프로젝트를 효율적으로 지원하기 위한 스킬 문서를 포함합니다.

## 📋 프로젝트 컨텍스트

### 프로젝트 개요
C&C 서버 기반 분산 봇 네트워크를 통해 네이버 쇼핑 상품의 트래픽 생성 및 순위 변동을 자동화하고, L18 직교배열을 통해 어떤 사용자 행동 패턴이 상품 순위에 영향을 미치는지 분석하는 시스템입니다.

### 핵심 아키텍처
- **서버**: FastAPI (Python 3.10+) on Railway
- **데이터베이스**: PostgreSQL
- **Android 봇**: Java/Kotlin, Android 7.0+, Root 필수
- **총 봇 수**: 22개 (트래픽 18개 + 순위 체크 4개)

### 주요 개념
- **대장-쫄병 구조**: 대장 봇(핫스팟 제공) + 쫄병 봇(핫스팟 연결)
- **1봇 = 1캠페인 전담**: 각 트래픽 봇은 1개 테스트 케이스를 100회 반복
- **L18 직교배열**: 7차원 변수를 18개 테스트 케이스로 압축

## 🎯 슬래시 커맨드

Claude와 대화 시 다음 슬래시 커맨드를 사용할 수 있습니다:

### 개발 관련
- `/add-bot-api` - 봇 등록 API 엔드포인트 추가
- `/add-campaign-api` - 캠페인 관리 API 엔드포인트 추가
- `/add-rank-api` - 순위 체크 API 엔드포인트 추가
- `/create-migration` - 데이터베이스 마이그레이션 스크립트 생성

### 테스트 관련
- `/test-rank-checker` - 순위 체크 로직 테스트
- `/test-bot-registration` - 봇 등록 API 테스트
- `/test-task-assignment` - 작업 할당 로직 테스트

### 문서 관련
- `/update-architecture` - ARCHITECTURE.md 업데이트
- `/update-api-docs` - API 문서 업데이트
- `/create-deployment-guide` - 배포 가이드 작성

### 분석 관련
- `/analyze-l18` - L18 테스트 매트릭스 분석
- `/analyze-rank-data` - 순위 데이터 분석
- `/generate-report` - 테스트 결과 리포트 생성

## 📚 주요 문서

### 필수 문서
1. **CLAUDE.md**: 전체 시스템 가이드
2. **ARCHITECTURE.md**: 시스템 아키텍처 상세 설명
3. **TASK_ALLOCATION_MODEL.md**: 작업 할당 모델 설명

### 개발 문서
1. **development_roadmap.md**: 개발 로드맵
2. **rank_accuracy_testing_guide.md**: 순위 체크 정확도 검증 가이드
3. **bot_separation_strategy.md**: 트래픽 봇 vs 순위 체크 봇 분리 전략

## 🔧 개발 워크플로우

### 1. 서버 개발
```bash
# 1. 가상 환경 활성화
cd server
python -m venv venv
source venv/bin/activate

# 2. 의존성 설치
pip install -r requirements.txt

# 3. 환경 변수 설정
cp .env.example .env
# .env 파일 편집

# 4. 데이터베이스 마이그레이션
psql $DATABASE_URL < migrations/init.sql

# 5. 서버 실행
python main.py
```

### 2. Android 개발
```bash
# 1. Android Studio 열기
# 2. android_agent 프로젝트 열기
# 3. Gradle 동기화
# 4. APK 빌드
./gradlew assembleDebug

# 5. APK 설치
adb install app/build/outputs/apk/debug/app-debug.apk
```

### 3. 테스트
```bash
# 단위 테스트
pytest tests/test_rank_checker_unit.py -v

# 순위 체크 정확도 테스트
python test_rank_accuracy.py

# API 테스트
pytest tests/test_api.py -v
```

## 🎓 Claude에게 요청할 수 있는 작업

### 코드 작성
- "트래픽 봇 등록 API 엔드포인트를 작성해줘"
- "순위 체크 결과를 DB에 저장하는 함수를 만들어줘"
- "Android 봇 서비스 클래스를 작성해줘"

### 코드 리뷰
- "이 API 엔드포인트의 보안 문제를 점검해줘"
- "이 데이터베이스 쿼리를 최적화해줘"
- "이 코드의 에러 핸들링을 개선해줘"

### 디버깅
- "봇 등록 시 500 에러가 발생하는데 원인을 찾아줘"
- "순위 체크가 실패하는 이유를 분석해줘"
- "작업 할당이 제대로 안 되는 문제를 해결해줘"

### 문서 작성
- "순위 체크 API 문서를 작성해줘"
- "배포 가이드를 업데이트해줘"
- "README.md에 설치 방법을 추가해줘"

### 데이터 분석
- "L18 테스트 결과를 ANOVA로 분석해줘"
- "순위 변동 데이터를 시각화해줘"
- "최적의 테스트 케이스 조합을 찾아줘"

## 📖 프로젝트별 가이드라인

### API 개발
1. FastAPI 라우터 사용
2. 타입 힌팅 필수
3. Docstring 작성 (Google 스타일)
4. 에러 핸들링 (HTTPException)
5. 로깅 (`src/utils/logger.py`)

### 데이터베이스
1. SQLAlchemy ORM 사용
2. 마이그레이션 스크립트 작성
3. 인덱스 추가 (성능 최적화)
4. 외래 키 제약 조건 설정

### Android 개발
1. Root 권한 확인
2. 백그라운드 서비스 (ForegroundService)
3. HTTP API 클라이언트 (Retrofit)
4. 에러 핸들링 (try-catch)
5. 로깅 (Log.d/e)

### 테스트
1. pytest 사용
2. Mock 데이터 활용
3. 통합 테스트는 `@pytest.mark.integration` 마커
4. 커버리지 80% 이상 목표

## 🚀 배포

### Railway 배포
1. GitHub 연동
2. 환경 변수 설정
3. 자동 배포 활성화
4. HTTPS 도메인 확인

### Android APK 배포
1. Release 빌드
2. 서명 (keystore)
3. APK 배포 (GitHub Releases)

## 🔍 트러블슈팅

### 서버 문제
- **500 에러**: 로그 확인 (`logs/app.log`)
- **DB 연결 실패**: `DATABASE_URL` 확인
- **봇 등록 실패**: `android_id` 중복 확인

### Android 문제
- **Root 권한 없음**: `su` 명령어 확인
- **핫스팟 연결 실패**: WiFi 설정 확인
- **API 요청 실패**: 서버 URL 확인

### 순위 체크 문제
- **상품을 찾을 수 없음**: 키워드, 상품 ID 확인
- **광고 필터링 오류**: HTML 선택자 업데이트
- **순위 오차 큼**: 광고 감지 패턴 추가

## 📞 도움말

### 문서
- **CLAUDE.md**: 전체 가이드
- **ARCHITECTURE.md**: 아키텍처
- **development_roadmap.md**: 개발 로드맵

### 테스트
- **test_rank_accuracy.py**: 순위 체크 정확도 검증
- **test_rank_checker.py**: 순위 체크 기본 테스트

### 슬래시 커맨드
- `/help` - 도움말 표시
- `/docs` - 문서 목록 표시
- `/status` - 프로젝트 상태 확인

---

**Claude와 함께 Turafic 프로젝트를 성공적으로 완성하세요!**
