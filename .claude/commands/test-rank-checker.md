# /test-rank-checker

순위 체크 로직을 테스트합니다.

## 사용법
```
/test-rank-checker [keyword] [product_id]
```

**파라미터**:
- `keyword`: 검색 키워드 (선택)
- `product_id`: 상품 ID (선택)

## 예시
```
/test-rank-checker
/test-rank-checker "삼성 갤럭시 S24"
/test-rank-checker "삼성 갤럭시 S24" "12345678"
```

## 테스트 시나리오

### 1. 기본 순위 체크 테스트
```bash
python test_rank_checker.py
# 선택: 1. 기본 순위 체크 테스트
```

**입력**:
- 검색 키워드: "삼성 갤럭시 S24"
- 상품 ID: "12345678"

**출력**:
```
✅ 상품을 찾았습니다!

【순위 정보】
  페이지:     2페이지
  위치:       8번째
  절대 순위:  28위
  상품명:     삼성 갤럭시 S24 울트라 256GB
  확인 시각:  2025-11-01 12:00:00

【추적 통계】
  총 기록 수: 1개
  평균 순위: 28.0
```

### 2. HTML 파싱 테스트
```bash
python test_rank_checker.py
# 선택: 2. HTML 파싱 테스트
```

**목적**: 네이버 쇼핑 HTML 선택자 검증

**출력**:
```
✅ 파싱 완료: 20개 상품 발견

【상위 5개 상품】
1. 1위 - 삼성 갤럭시 S24 울트라 256GB...
   ID: 12345678
2. 2위 - 삼성 갤럭시 S24 플러스 128GB...
   ID: 87654321
...
```

### 3. 정확도 검증 테스트
```bash
python test_rank_accuracy.py
# 선택: 1. 수동 확인 vs 자동 체크 비교
```

**절차**:
1. 네이버 쇼핑에서 수동으로 순위 확인
2. 상품 ID 입력
3. 자동 체크 실행
4. 오차 확인

**출력**:
```
수동 확인 순위: 15위
자동 체크 순위: 15위
오차: 0위

✅ 완벽하게 일치합니다!
```

## 단위 테스트 (pytest)

```bash
pytest tests/test_rank_checker_unit.py -v
```

**테스트 항목**:
- ✅ 검색 URL 생성
- ✅ 상품 ID 추출
- ✅ 광고 필터링 (8가지 패턴)
- ✅ 순위 계산
- ✅ 광고 제외 순위 계산

**출력**:
```
tests/test_rank_checker_unit.py::test_검색_URL_생성 PASSED
tests/test_rank_checker_unit.py::test_상품_ID_추출 PASSED
tests/test_rank_checker_unit.py::test_광고_필터링_텍스트 PASSED
tests/test_rank_checker_unit.py::test_광고_필터링_클래스 PASSED
tests/test_rank_checker_unit.py::test_광고_필터링_data_속성 PASSED
tests/test_rank_checker_unit.py::test_일반_상품_감지 PASSED
tests/test_rank_checker_unit.py::test_순위_계산 PASSED
tests/test_rank_checker_unit.py::test_상품_찾기_성공 PASSED
tests/test_rank_checker_unit.py::test_상품_찾기_실패 PASSED
tests/test_rank_checker_unit.py::test_광고_제외_순위_계산 PASSED

========== 10 passed in 2.5s ==========
```

## 통합 테스트

```bash
pytest tests/test_rank_checker_unit.py::test_실제_순위_체크 -v -m integration
```

**주의**: 실제 네이버 쇼핑에 요청을 보냅니다.

## 트러블슈팅

### 문제: 상품을 찾을 수 없음
**원인**:
- 키워드가 정확하지 않음
- 상품 ID가 올바르지 않음
- 상품이 검색 결과에 없음

**해결**:
1. 네이버 쇼핑에서 키워드 검색
2. 상품 URL 확인
3. 상품 ID 재확인

### 문제: 순위 오차가 큼
**원인**:
- 광고 필터링 오류
- HTML 선택자 변경
- 네이버 쇼핑 구조 변경

**해결**:
1. HTML 파싱 테스트 실행
2. 광고 감지 패턴 확인
3. 선택자 업데이트

### 문제: 403 또는 429 에러
**원인**:
- 과도한 요청
- IP 차단

**해결**:
1. 요청 간 대기 시간 증가
2. User-Agent 변경
3. IP 변경 (VPN)

## 코드 예시

### RankChecker 사용
```python
from src.ranking.checker import RankChecker

checker = RankChecker()

# 순위 체크
result = checker.check_product_rank(
    keyword="삼성 갤럭시 S24",
    product_id="12345678",
    max_page=5
)

if result:
    print(f"순위: {result['absolute_rank']}위")
    print(f"페이지: {result['page']}페이지")
    print(f"위치: {result['position']}번째")
else:
    print("상품을 찾을 수 없습니다.")
```

### RankTracker 사용
```python
from src.ranking.tracker import RankTracker

tracker = RankTracker(product_id="12345678")

# 순위 기록 추가
tracker.add_record(
    rank_info=result,
    iteration=1,
    test_case_id=1,
    notes="테스트 실행"
)

# 통계 조회
stats = tracker.get_statistics()
print(f"평균 순위: {stats['average_rank']}")
print(f"최고 순위: {stats['best_rank']}")
print(f"최저 순위: {stats['worst_rank']}")
```

## 관련 문서
- rank_accuracy_testing_guide.md: 정확도 검증 가이드
- src/ranking/checker.py: RankChecker 클래스
- src/ranking/tracker.py: RankTracker 클래스
- test_rank_accuracy.py: 정확도 검증 스크립트
