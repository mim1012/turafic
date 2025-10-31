# 테스트 전략 재설계

## 문제점: 단일 패턴 반복의 위험성

### ❌ 잘못된 접근
```
상품 1 → CASE_1만 100회 반복
상품 2 → CASE_1만 100회 반복
상품 3 → CASE_2만 100회 반복
...
```

**문제:**
1. 봇 탐지 리스크 높음 (동일 패턴 반복)
2. 네이버 알고리즘이 "비정상 트래픽"으로 판단 가능
3. 순위 반영 안 될 가능성 높음

---

## ✅ 개선된 접근: 혼합 시나리오 전략

### 전략 A: 케이스 비중 차별화
**각 상품마다 주 케이스 + 부 케이스 혼합**

```yaml
상품 1:
  주 케이스: CASE_1 (60%)  # 적극적 구매
  부 케이스:
    - CASE_2 (20%)  # 정보 탐색
    - CASE_4 (10%)  # 빠른 비교
    - CASE_5 (10%)  # 문의형
  → 100회 중 CASE_1이 60회, 나머지 섞임

상품 2:
  주 케이스: CASE_1 (60%)
  부 케이스: 동일

상품 3:
  주 케이스: CASE_2 (60%)  # 정보 탐색
  부 케이스:
    - CASE_1 (20%)
    - CASE_4 (10%)
    - CASE_5 (10%)

...
```

**비교 방법:**
- 상품 1,2의 주 케이스가 CASE_1 (60%)
- 상품 3,4의 주 케이스가 CASE_2 (60%)
- → 평균 순위 변동을 비교하여 어떤 주 케이스가 효과적인지 판단

**장점:**
- 자연스러운 트래픽 패턴
- 순위 반영 가능성 높음
- 주 케이스의 효과성 여전히 측정 가능

---

### 전략 B: 시간대별 케이스 변경
**시간/날짜별로 케이스 로테이션**

```yaml
Day 1 (Iteration 1-20):
  상품 1,2 → CASE_1 (100%)
  상품 3,4 → CASE_2 (100%)
  ...

Day 2 (Iteration 21-40):
  상품 1,2 → CASE_2 (50%) + CASE_1 (50%)
  상품 3,4 → CASE_1 (50%) + CASE_2 (50%)

Day 3 (Iteration 41-60):
  모든 상품 → 랜덤 케이스

Day 4 (Iteration 61-80):
  상품 1,2 → CASE_1 (70%) + 기타 (30%)
  상품 3,4 → CASE_2 (70%) + 기타 (30%)

Day 5 (Iteration 81-100):
  효과 좋은 케이스 위주로 집중
```

**장점:**
- 시간에 따른 순위 변화 추적 가능
- 다양성 확보
- 중간에 전략 조정 가능

---

### 전략 C: 확률 기반 랜덤 시나리오 (권장)
**각 iteration마다 확률적으로 케이스 선택**

```python
# 상품 1,2의 케이스 확률 분포
case_probabilities = {
    "CASE_1": 0.50,  # 적극적 구매 (주력)
    "CASE_2": 0.20,  # 정보 탐색
    "CASE_3": 0.15,  # 쇼핑몰 직접
    "CASE_4": 0.10,  # 빠른 비교
    "CASE_5": 0.05,  # 문의형
}

# 매 iteration마다 확률에 따라 선택
for i in range(100):
    selected_case = random.choices(
        list(case_probabilities.keys()),
        weights=list(case_probabilities.values())
    )[0]
    execute_scenario(product, selected_case)
```

**상품별 확률 분포 설계:**

```
그룹 A (상품 1,2): CASE_1 주력 그룹
  CASE_1: 50%, CASE_2: 20%, CASE_3: 15%, CASE_4: 10%, CASE_5: 5%

그룹 B (상품 3,4): CASE_2 주력 그룹
  CASE_2: 50%, CASE_1: 20%, CASE_3: 15%, CASE_4: 10%, CASE_5: 5%

그룹 C (상품 5,6): CASE_3 주력 그룹
  CASE_3: 50%, CASE_1: 20%, CASE_2: 15%, CASE_4: 10%, CASE_5: 5%

그룹 D (상품 7,8): CASE_4 주력 그룹
  CASE_4: 50%, CASE_1: 15%, CASE_2: 15%, CASE_3: 15%, CASE_5: 5%

그룹 E (상품 9,10): CASE_5 주력 그룹
  CASE_5: 50%, CASE_1: 20%, CASE_2: 15%, CASE_3: 10%, CASE_4: 5%
```

**비교 방법:**
```python
# 그룹 A의 평균 순위 변동 (CASE_1 주력)
group_a_avg = (상품1_평균 + 상품2_평균) / 2

# 그룹 B의 평균 순위 변동 (CASE_2 주력)
group_b_avg = (상품3_평균 + 상품4_평균) / 2

# 비교
if group_a_avg < group_b_avg:
    print("CASE_1 (적극적 구매)가 더 효과적")
```

**장점:**
- 자연스러운 트래픽 패턴
- 봇 탐지 회피
- 주력 케이스 효과 측정 가능
- 실제 사용자 행동과 유사

---

## 케이스 내 Variation (추가 다양성)

### 동일 케이스 내에서도 변형 적용

```python
# CASE_1 (장바구니 담기) 실행 시에도 매번 다르게
class Case1Executor:
    def execute(self):
        # 1. 스크롤 패턴 다양화
        scroll_count = random.randint(3, 6)  # 3~6회 스크롤
        scroll_speed = random.uniform(200, 400)  # 스크롤 속도 다양화

        # 2. 클릭 위치 다양화
        cart_button_x = base_x + random.randint(-10, 10)
        cart_button_y = base_y + random.randint(-10, 10)

        # 3. 체류 시간 정규분포
        dwell_time = int(np.random.normal(55, 5))  # 평균 55초, 표준편차 5초

        # 4. 중간 액션 확률적 추가
        if random.random() < 0.3:  # 30% 확률로
            click_product_image()  # 이미지 확대 보기

        if random.random() < 0.4:  # 40% 확률로
            scroll_to_reviews()  # 리뷰 영역까지 스크롤

        # 5. 타이핑 속도 다양화
        if need_search:
            type_with_random_speed(keyword)
```

**Variation 요소:**
1. **스크롤**: 횟수, 속도, 위치
2. **클릭**: 좌표 미세 조정 (±10px)
3. **체류 시간**: 정규분포 (평균 ± 10초)
4. **중간 액션**: 확률적으로 추가 액션 삽입
5. **타이핑**: 속도, 오타 → 수정

---

## 추천 구현: 전략 C (확률 기반)

### test_products.json 구조 업데이트

```json
{
  "product_groups": [
    {
      "group_id": "GROUP_A",
      "primary_case": "CASE_1",
      "description": "적극적 구매 의사 주력 그룹",
      "case_distribution": {
        "CASE_1": 0.50,
        "CASE_2": 0.20,
        "CASE_3": 0.15,
        "CASE_4": 0.10,
        "CASE_5": 0.05
      },
      "products": [
        {"id": 1, "product_name": "...", ...},
        {"id": 2, "product_name": "...", ...}
      ]
    },
    {
      "group_id": "GROUP_B",
      "primary_case": "CASE_2",
      "description": "정보 탐색형 주력 그룹",
      "case_distribution": {
        "CASE_2": 0.50,
        "CASE_1": 0.20,
        "CASE_3": 0.15,
        "CASE_4": 0.10,
        "CASE_5": 0.05
      },
      "products": [
        {"id": 3, "product_name": "...", ...},
        {"id": 4, "product_name": "...", ...}
      ]
    }
    // ... GROUP_C, D, E
  ]
}
```

### 실행 로직

```python
def run_test_iteration(product, iteration):
    """단일 iteration 실행"""

    # 1. 그룹 정보 로드
    group = get_product_group(product)
    case_distribution = group['case_distribution']

    # 2. 확률 기반 케이스 선택
    selected_case = random.choices(
        list(case_distribution.keys()),
        weights=list(case_distribution.values())
    )[0]

    log.info(f"Iteration {iteration}: {selected_case} 선택 (확률: {case_distribution[selected_case]*100}%)")

    # 3. Before 순위 체크
    rank_before = check_rank(product)

    # 4. 시나리오 실행 (케이스별 + Variation)
    execute_scenario_with_variation(product, selected_case)

    # 5. IP 변경
    toggle_airplane_mode()
    wait_for_network()

    # 6. After 순위 체크 (30분 후)
    time.sleep(1800)
    rank_after = check_rank(product)

    # 7. 결과 저장 (어떤 케이스를 실행했는지도 기록)
    tracker.add_record(
        rank_after,
        iteration=iteration,
        executed_case=selected_case,  # 실행한 케이스 기록
        notes=f"{selected_case} 실행"
    )


def analyze_group_effectiveness():
    """그룹별 효과성 분석"""

    for group in product_groups:
        primary_case = group['primary_case']
        products = group['products']

        # 각 상품의 평균 순위 변동 계산
        avg_changes = []
        for product in products:
            tracker = RankTracker(product['product_id'])
            stats = tracker.get_statistics()
            avg_changes.append(stats['avg_rank_change'])

        group_avg = statistics.mean(avg_changes)

        print(f"그룹 {group['group_id']} (주력: {primary_case})")
        print(f"  평균 순위 변동: {group_avg:.1f}")

        # 주력 케이스 실행 시에만 필터링한 통계도 계산
        primary_case_only_stats = get_stats_for_case(products, primary_case)
        print(f"  {primary_case}만 실행 시: {primary_case_only_stats['avg_change']:.1f}")
```

---

## 데이터 구조: 케이스 실행 기록

### rank_history 저장 형식 업데이트

```json
{
  "product_id": "12345678",
  "history": [
    {
      "iteration": 1,
      "executed_case": "CASE_1",  // 실행한 케이스 기록
      "rank_info": { ... },
      "rank_change": -5,
      "timestamp": "..."
    },
    {
      "iteration": 2,
      "executed_case": "CASE_2",  // 이번엔 CASE_2 실행
      "rank_info": { ... },
      "rank_change": -3,
      "timestamp": "..."
    }
  ]
}
```

### 케이스별 필터링 분석

```python
# 특정 케이스만 실행한 경우의 순위 변동 분석
def analyze_case_specific_impact(product_id, case_id):
    """특정 케이스 실행 시에만 효과 분석"""

    history = load_rank_history(product_id)

    # CASE_1만 실행한 iteration 필터링
    case_1_changes = [
        record['rank_change']
        for record in history
        if record.get('executed_case') == case_id
        and record.get('rank_change') is not None
    ]

    if case_1_changes:
        return {
            'avg_change': statistics.mean(case_1_changes),
            'improvement_rate': sum(1 for c in case_1_changes if c < 0) / len(case_1_changes),
            'count': len(case_1_changes)
        }

    return None
```

---

## 요약: 권장 전략

### ✅ 최종 추천 구조

```
5개 그룹 (각 그룹 2개 상품)

그룹 A (상품 1,2): CASE_1 주력 50% + 나머지 섞음
그룹 B (상품 3,4): CASE_2 주력 50% + 나머지 섞음
그룹 C (상품 5,6): CASE_3 주력 50% + 나머지 섞음
그룹 D (상품 7,8): CASE_4 주력 50% + 나머지 섞음
그룹 E (상품 9,10): CASE_5 주력 50% + 나머지 섞음

각 상품 100회 실행 시:
  - 주력 케이스: 약 50회
  - 부수 케이스: 약 50회 (다양하게 섞임)
  - 매 iteration마다 확률적으로 선택
  - 동일 케이스 내에서도 Variation 적용
```

### 장점
1. ✅ 봇 탐지 회피 (다양한 패턴)
2. ✅ 순위 반영 가능성 높음 (자연스러운 트래픽)
3. ✅ 케이스 효과성 측정 가능 (주력 케이스 비교)
4. ✅ 실제 사용자 행동과 유사

### 비교 분석
```python
# 그룹별 평균 순위 변동 비교
group_a_avg = -8.5  # CASE_1 주력
group_b_avg = -5.2  # CASE_2 주력
group_c_avg = -3.1  # CASE_3 주력
...

결론: CASE_1 (적극적 구매)이 가장 효과적
```

---

**작성일**: 2025-11-01
**상태**: 전략 재설계 완료
