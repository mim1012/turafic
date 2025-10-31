# 테스트 케이스 정의서

## 목적
각 테스트 케이스별로 트래픽 패턴을 다르게 생성하여, **어떤 사용자 행동이 네이버 쇼핑 순위 상승에 가장 효과적인지** 실험적으로 검증합니다.

---

## 테스트 변수

### 1. 진입 경로 (Entry Path)
- **A**: 네이버 통합검색 → 쇼핑탭 클릭 → 상품 선택
- **B**: 네이버쇼핑 직접 접속 → 검색 → 상품 선택

### 2. 스크롤 깊이 (Scroll Depth)
- **Light**: 상품 이미지 + 가격만 확인 (최소 스크롤)
- **Medium**: 상품 상세정보까지 스크롤
- **Deep**: 리뷰 + Q&A까지 스크롤

### 3. 액션 타입 (Action Type)
- **Cart**: 장바구니 담기 클릭
- **Review**: 리뷰 영역 클릭 (특정 리뷰 읽기)
- **QnA**: 1:1 문의 클릭
- **Options**: 옵션 선택 (색상, 사이즈 등)
- **Browse**: 액션 없이 둘러보기만

### 4. 체류 시간 (Dwell Time)
- **Short**: 30-40초
- **Medium**: 40-50초
- **Long**: 50-60초

---

## 테스트 케이스 정의 (5개 케이스)

각 케이스당 2개 상품 할당 → 총 10개 상품

### 케이스 1: 적극적 구매 의사 (High Intent)
```yaml
ID: CASE_1
진입경로: A (네이버 검색 → 쇼핑탭)
스크롤: Deep (리뷰까지)
액션: Cart (장바구니 담기)
체류시간: Long (50-60초)
가설: 구매 의사가 강한 사용자 패턴 → 순위 상승 효과 높음
```

### 케이스 2: 정보 탐색형 (Research)
```yaml
ID: CASE_2
진입경로: A (네이버 검색 → 쇼핑탭)
스크롤: Deep (리뷰 + Q&A까지)
액션: Review (리뷰 클릭 읽기)
체류시간: Long (50-60초)
가설: 꼼꼼히 비교하는 사용자 → 관심도 높음 신호
```

### 케이스 3: 쇼핑몰 직접 방문 (Direct)
```yaml
ID: CASE_3
진입경로: B (네이버쇼핑 직접 검색)
스크롤: Medium (상세정보까지)
액션: Options (옵션 선택)
체류시간: Medium (40-50초)
가설: 쇼핑몰 직접 방문 트래픽의 가치 검증
```

### 케이스 4: 빠른 비교 (Quick Compare)
```yaml
ID: CASE_4
진입경로: B (네이버쇼핑 직접 검색)
스크롤: Light (상품 기본정보만)
액션: Browse (액션 없음)
체류시간: Short (30-40초)
가설: 짧은 체류도 효과가 있는지 확인
```

### 케이스 5: 문의형 (Inquiry)
```yaml
ID: CASE_5
진입경로: A (네이버 검색 → 쇼핑탭)
스크롤: Medium (상세정보까지)
액션: QnA (1:1 문의 클릭)
체류시간: Medium (40-50초)
가설: 문의 행동의 효과 검증
```

---

## 상품 할당 전략

### 원칙
1. **동일 카테고리 회피**: 같은 케이스에 유사 카테고리 상품 배치 금지
2. **초기 순위 유사**: 각 케이스별 상품들의 초기 순위 범위 비슷하게 (공정한 비교)
3. **키워드 경쟁도 분산**: 고경쟁/저경쟁 키워드 골고루 배치

### 할당 예시 (실제 상품 선정 후 조정)
```
케이스 1 (적극적 구매):
  - 상품 1: [카테고리A] [키워드X] 초기순위 ~50위
  - 상품 2: [카테고리B] [키워드Y] 초기순위 ~50위

케이스 2 (정보 탐색):
  - 상품 3: [카테고리C] [키워드Z] 초기순위 ~60위
  - 상품 4: [카테고리D] [키워드W] 초기순위 ~60위

케이스 3 (쇼핑몰 직접):
  - 상품 5: [카테고리E] [키워드V] 초기순위 ~70위
  - 상품 6: [카테고리F] [키워드U] 초기순위 ~70위

케이스 4 (빠른 비교):
  - 상품 7: [카테고리G] [키워드T] 초기순위 ~80위
  - 상품 8: [카테고리H] [키워드S] 초기순위 ~80위

케이스 5 (문의형):
  - 상품 9: [카테고리I] [키워드R] 초기순위 ~90위
  - 상품 10: [카테고리J] [키워드Q] 초기순위 ~90위
```

---

## 실험 프로세스

### 1단계: 초기 순위 측정 (Day 0)
```python
for product in all_products:
    initial_rank = check_product_rank(product.keyword, product.id)
    save_initial_rank(product, initial_rank)
```

### 2단계: 테스트 실행 (Day 1-N)
```python
for product in all_products:
    test_case = get_test_case(product.case_id)

    for iteration in range(1, 101):  # 100회 반복
        # Before 순위
        rank_before = check_product_rank(product.keyword, product.id)

        # 트래픽 생성 (케이스별 시나리오)
        execute_test_case(product, test_case)

        # IP 변경
        toggle_airplane_mode()
        wait_for_network()

        # After 순위 (30분 후)
        time.sleep(1800)
        rank_after = check_product_rank(product.keyword, product.id)

        # 결과 저장
        save_result(product, iteration, rank_before, rank_after)
```

### 3단계: 케이스별 비교 분석
```python
for case_id in [1, 2, 3, 4, 5]:
    case_products = get_products_by_case(case_id)

    # 케이스별 통계
    avg_rank_change = calculate_avg_rank_change(case_products)
    improvement_rate = calculate_improvement_rate(case_products)

    print(f"케이스 {case_id}: 평균 {avg_rank_change}위 변동")
    print(f"  개선율: {improvement_rate}%")
```

---

## 평가 지표

### 1차 지표 (Primary Metrics)
- **평균 순위 변동**: 각 케이스별 평균 몇 위 상승/하락
- **순위 개선율**: 100회 중 순위가 상승한 비율 (%)
- **최대 순위 상승폭**: 가장 많이 상승한 경우

### 2차 지표 (Secondary Metrics)
- **순위 안정성**: 표준편차 (순위 변동의 일관성)
- **페이지 이동률**: 다음 페이지로 넘어간 비율
- **순위권 진입률**: 초기에 순위권 밖이었다가 들어온 비율

### 통계적 유의성 검증
```python
# t-test로 케이스 간 차이 검증
from scipy import stats

case1_changes = get_rank_changes(case_id=1)
case2_changes = get_rank_changes(case_id=2)

t_stat, p_value = stats.ttest_ind(case1_changes, case2_changes)

if p_value < 0.05:
    print("케이스 1과 2는 통계적으로 유의한 차이가 있음")
```

---

## 결과 리포트 형식

### 케이스별 요약표
```
┌─────────┬──────────────┬────────────┬──────────┬────────────┐
│ 케이스  │ 평균순위변동 │ 개선율(%)  │ 최대상승 │ 표준편차   │
├─────────┼──────────────┼────────────┼──────────┼────────────┤
│ CASE_1  │   -12.5      │    68%     │   -35    │    8.2     │
│ CASE_2  │   -8.3       │    54%     │   -28    │    10.5    │
│ CASE_3  │   -5.1       │    47%     │   -22    │    12.1    │
│ CASE_4  │   -2.8       │    35%     │   -15    │    15.3    │
│ CASE_5  │   -6.7       │    51%     │   -25    │    9.8     │
└─────────┴──────────────┴────────────┴──────────┴────────────┘

결론: 케이스 1 (적극적 구매 패턴)이 가장 효과적
```

### 권장사항
분석 결과를 바탕으로:
1. 가장 효과적인 케이스 2-3개 선정
2. 해당 케이스 비율 증가
3. 효과 낮은 케이스 제거 또는 변형

---

## 주의사항

### 통제 변수
다음 변수들은 모든 케이스에서 동일하게 유지:
- 테스트 시간대 (동일 시간대 분산)
- 기기 종류 (동일 Android 기기)
- 네트워크 환경 (동일 통신사)
- 반복 횟수 (각 상품 100회)

### 외부 요인 고려
- 네이버 알고리즘 변경
- 계절성/이벤트 (특정 날짜 영향)
- 경쟁사 활동
- 상품 가격/재고 변동

---

## 체크리스트

테스트 시작 전 확인:
- [ ] 10개 상품 선정 완료
- [ ] 각 상품의 초기 순위 측정 완료
- [ ] 상품을 5개 케이스에 2개씩 할당 완료
- [ ] test_products.json 파일 작성 완료
- [ ] 모든 케이스의 시나리오 구현 완료
- [ ] ADB 연결 및 비행기모드 테스트 완료
- [ ] 데이터 저장 구조 확인 완료

---

**작성일**: 2025-11-01
**최종 업데이트**: 테스트 케이스 정의 완료
