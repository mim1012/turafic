# Phase 1 Full Factorial 구현 가이드

## 남은 파일 구현 현황

### 1. server/core/http_pattern_generator.py ✅ 준비 완료

아래 코드를 `server/core/http_pattern_generator.py` 파일에 복사하세요:

파일 경로: `D:/Project/Navertrafic/server/core/http_pattern_generator.py`

코드: `D:/Project/Navertrafic/docs/http_pattern_generator_phase1.py` 참조

### 2. server/core/task_engine.py ⏳ 수정 필요

수정 내용:
- TEST_MATRIX_PATH 변경: `test_matrix.json` → `test_matrix_phase1.json`
- `load_test_matrix()` 함수 수정
- `generate_task_pattern()` 함수에 Phase 1 변수 전달

### 3. server/core/ranking_scheduler.py ⏳ 신규 생성

12시간 주기 순위 체크 스케줄러 구현 필요

### 4. CLAUDE.md ⏳ 순위 측정 프로토콜 문서화

12시간 롤링 윈도우 방식 문서화 필요

## 구현 우선순위

1. http_pattern_generator.py (현재 작업 중)
2. task_engine.py
3. ranking_scheduler.py
4. CLAUDE.md 업데이트

## 예상 완료 시간

- http_pattern_generator.py: 완료
- task_engine.py: 30분
- ranking_scheduler.py: 1시간
- CLAUDE.md: 30분

총: 2시간
