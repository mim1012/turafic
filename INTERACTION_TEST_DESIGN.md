# 상호작용 효과 측정 실험 설계

**목적**: 브라우저 지문 × 사용자 행동 패턴 × 카테고리의 상호작용 효과 측정

---

## 📊 실험 설계 개요

### 고정 변수
- **총 트래픽량**: 100회 (고정)
- **측정 지표**: 순위 변화 (Before - After)

### 독립 변수 (3개)
1. **브라우저 지문** (3 수준)
   - Profile A: Canvas/WebGL/해상도 조합 1
   - Profile B: Canvas/WebGL/해상도 조합 2
   - Profile C: Canvas/WebGL/해상도 조합 3

2. **사용자 행동 패턴** (4 수준)
   - 빠른 이탈 (30초)
   - 일반 둘러보기 (90초)
   - 심층 탐색 (180초)
   - 비교 쇼핑 (150초 + 다중 탭)

3. **카테고리** (4 수준)
   - 전자기기
   - 패션의류
   - 식품
   - 뷰티

### 종속 변수
- **순위 변화량** (Rank Change)
- **순위 개선률** (Improvement Rate)
- **봇 탐지 회피율** (Detection Avoidance Rate)

---

## 🧪 실험 설계 유형

### Option 1: 완전 요인 설계 (Full Factorial Design)
```
총 테스트 케이스 = 3 (지문) × 4 (행동) × 4 (카테고리) = 48개
각 케이스당 트래픽 = 100회
총 소요 트래픽 = 4,800회
```

**장점**: 모든 상호작용 효과 측정 가능
**단점**: 시간/리소스 과다 (약 200시간)

---

### Option 2: 부분 요인 설계 (Fractional Factorial Design) ⭐ **권장**
```
총 테스트 케이스 = 12개 (1/4 설계)
각 케이스당 트래픽 = 100회
총 소요 트래픽 = 1,200회
```

**장점**:
- 주 효과 + 2차 상호작용 측정 가능
- 시간/리소스 절감 (약 50시간)
- 통계적 검정력 유지

**선택된 조합** (Latin Square + Orthogonal Array):

| TC | 브라우저 지문 | 행동 패턴 | 카테고리 | 반복 |
|----|------------|----------|---------|------|
| **IT-001** | Profile A | 빠른 이탈 | 전자기기 | 100회 |
| **IT-002** | Profile A | 일반 둘러보기 | 패션의류 | 100회 |
| **IT-003** | Profile A | 심층 탐색 | 식품 | 100회 |
| **IT-004** | Profile A | 비교 쇼핑 | 뷰티 | 100회 |
| **IT-005** | Profile B | 빠른 이탈 | 패션의류 | 100회 |
| **IT-006** | Profile B | 일반 둘러보기 | 전자기기 | 100회 |
| **IT-007** | Profile B | 심층 탐색 | 뷰티 | 100회 |
| **IT-008** | Profile B | 비교 쇼핑 | 식품 | 100회 |
| **IT-009** | Profile C | 빠른 이탈 | 식품 | 100회 |
| **IT-010** | Profile C | 일반 둘러보기 | 뷰티 | 100회 |
| **IT-011** | Profile C | 심층 탐색 | 전자기기 | 100회 |
| **IT-012** | Profile C | 비교 쇼핑 | 패션의류 | 100회 |

---

### Option 3: 응답 표면 설계 (Response Surface Design)
```
총 테스트 케이스 = 20개 (중심점 포함)
각 케이스당 트래픽 = 100회
총 소요 트래픽 = 2,000회
```

**용도**: 최적 조합 탐색 (2단계 실험)

---

## 📐 브라우저 지문 프로필 정의

### Profile A: "일반 사용자"
```python
{
    "canvas_fingerprint": "hash_12345abc",
    "webgl_vendor": "Intel Inc.",
    "webgl_renderer": "Intel Iris OpenGL Engine",
    "screen_resolution": "1920x1080",
    "color_depth": 24,
    "timezone": "Asia/Seoul",
    "platform": "Win32",
    "hardware_concurrency": 8,
    "device_memory": 8,
    "languages": ["ko-KR", "ko", "en-US"],
    "plugins": [
        "Chrome PDF Plugin",
        "Chrome PDF Viewer",
        "Native Client"
    ]
}
```

### Profile B: "고사양 사용자"
```python
{
    "canvas_fingerprint": "hash_67890def",
    "webgl_vendor": "NVIDIA Corporation",
    "webgl_renderer": "NVIDIA GeForce RTX 3080",
    "screen_resolution": "2560x1440",
    "color_depth": 32,
    "timezone": "Asia/Seoul",
    "platform": "Win32",
    "hardware_concurrency": 16,
    "device_memory": 32,
    "languages": ["ko-KR", "en-US"],
    "plugins": [
        "Chrome PDF Plugin",
        "Chrome PDF Viewer",
        "Native Client"
    ]
}
```

### Profile C: "모바일 사용자"
```python
{
    "canvas_fingerprint": "hash_mobile456",
    "webgl_vendor": "ARM",
    "webgl_renderer": "Mali-G78",
    "screen_resolution": "1080x2400",
    "color_depth": 24,
    "timezone": "Asia/Seoul",
    "platform": "Linux aarch64",
    "hardware_concurrency": 8,
    "device_memory": 8,
    "languages": ["ko-KR", "ko"],
    "plugins": []  # 모바일은 플러그인 없음
}
```

---

## 📊 통계 분석 방법

### 1. 주 효과 분석 (Main Effects)

**분산분석 (ANOVA)**:
```python
# 각 변수의 독립적 효과
- H0: 브라우저 지문에 따른 순위 변화 차이 없음
- H0: 행동 패턴에 따른 순위 변화 차이 없음
- H0: 카테고리에 따른 순위 변화 차이 없음

# F-통계량 계산
F = MS_between / MS_within

# 유의수준: α = 0.05
```

### 2. 상호작용 효과 분석 (Interaction Effects)

**2-way ANOVA**:
```python
# 2차 상호작용
- 지문 × 행동: F_{지문×행동}
- 지문 × 카테고리: F_{지문×카테고리}
- 행동 × 카테고리: F_{행동×카테고리}

# 효과 크기 (η²)
η² = SS_effect / SS_total

# 해석:
- η² < 0.01: 작은 효과
- 0.01 ≤ η² < 0.06: 중간 효과
- η² ≥ 0.06: 큰 효과
```

### 3. 교호작용 플롯 (Interaction Plot)

```python
import matplotlib.pyplot as plt
import seaborn as sns

# Profile A vs B vs C (행동 패턴별)
for behavior in ['빠른이탈', '일반', '심층', '비교쇼핑']:
    profile_a = results[(profile == 'A') & (behavior == behavior)]
    profile_b = results[(profile == 'B') & (behavior == behavior)]
    profile_c = results[(profile == 'C') & (behavior == behavior)]

    plt.plot(['A', 'B', 'C'], [profile_a, profile_b, profile_c],
             label=behavior, marker='o')

plt.xlabel('브라우저 지문 프로필')
plt.ylabel('평균 순위 변화')
plt.legend()
plt.title('지문 × 행동 패턴 상호작용')

# 교차선 → 상호작용 有
# 평행선 → 상호작용 無
```

---

## 🎯 상호작용 효과 측정 가능성

### ✅ 측정 가능한 상호작용

#### 1. 지문 × 행동 패턴
**가설**: 고사양 지문(Profile B)은 심층 탐색에서 더 효과적

```
예상 결과:
- Profile A + 빠른이탈: -2위
- Profile B + 빠른이탈: -2.5위
- Profile A + 심층탐색: -4위
- Profile B + 심층탐색: -6위 ← 상승효과!
```

#### 2. 지문 × 카테고리
**가설**: 전자기기는 고사양 지문에 민감

```
예상 결과:
- Profile A + 전자기기: -3위
- Profile B + 전자기기: -5위 ← 효과 2배
- Profile A + 식품: -2위
- Profile B + 식품: -2.5위 ← 효과 소폭
```

#### 3. 행동 × 카테고리
**가설**: 전자기기는 비교 쇼핑 패턴에 효과적

```
예상 결과:
- 일반 + 전자기기: -3위
- 비교쇼핑 + 전자기기: -5위 ← 효과 증가
- 일반 + 식품: -2위
- 비교쇼핑 + 식품: -2.5위 ← 효과 미미
```

---

## 📈 검정력 분석 (Power Analysis)

### 필요 표본 크기 계산

```python
from statsmodels.stats.power import FTestAnovaPower

# 설정
effect_size = 0.25  # 중간 효과 크기
alpha = 0.05        # 유의수준
power = 0.80        # 검정력 80%
k_groups = 12       # 그룹 수

# 계산
power_analysis = FTestAnovaPower()
required_n = power_analysis.solve_power(
    effect_size=effect_size,
    alpha=alpha,
    power=power,
    k_groups=k_groups
)

print(f"그룹당 필요 표본: {required_n:.0f}회")
# 예상: 약 15-20회/그룹

# 현재 설정 (100회/그룹) → 검정력 99%+
```

### 결론
✅ **100회/케이스는 충분**
- 검정력 > 99%
- 매우 작은 효과도 탐지 가능
- 상호작용 효과 측정 가능

---

## 🔬 실험 실행 계획

### Phase 1: 파일럿 테스트 (1주)
```bash
# 4개 케이스만 실행 (각 코너)
IT-001, IT-006, IT-010, IT-012
총 400회 (4 × 100)

목적:
- 설계 검증
- 효과 크기 추정
- 실행 시간 측정
```

### Phase 2: 본 실험 (3주)
```bash
# 전체 12개 케이스
IT-001 ~ IT-012
총 1,200회 (12 × 100)

목적:
- 주 효과 측정
- 상호작용 효과 측정
- 최적 조합 도출
```

### Phase 3: 검증 실험 (1주)
```bash
# 최적 조합으로 재검증
총 200회 (2 × 100)

목적:
- 재현성 확인
- 효과 크기 확정
```

---

## 📊 예상 결과 시각화

### 1. 주 효과 플롯
```python
# 브라우저 지문 효과
Profile A: -2.5위 (±0.5)
Profile B: -4.0위 (±0.8) ← 최고 효과
Profile C: -3.0위 (±0.6)

# 행동 패턴 효과
빠른이탈: -1.5위
일반: -2.5위
심층: -4.5위 ← 최고 효과
비교쇼핑: -3.5위

# 카테고리 효과
전자기기: -4.0위 ← 최고 효과
패션: -3.0위
식품: -2.0위
뷰티: -2.5위
```

### 2. 상호작용 히트맵
```
           빠른이탈  일반  심층  비교쇼핑
Profile A    -2    -2.5  -4    -3
Profile B    -2.5  -3.5  -6    -5  ← 심층 탐색에서 최대
Profile C    -2    -3    -4.5  -3.5
```

---

## 🎯 최종 권장 조합 도출

### 분석 방법
```python
# 1. 회귀 분석으로 최적 조합 예측
from sklearn.ensemble import RandomForestRegressor

model = RandomForestRegressor()
model.fit(X_train, y_train)

# 변수 중요도
feature_importance = model.feature_importances_

# 2. 최적 조합 탐색
best_combination = maximize(rank_change,
                           subject_to=[profile, behavior, category])
```

### 예상 최적 조합
```
Profile B (고사양)
+ 심층 탐색 (180초)
+ 전자기기 카테고리
= 예상 효과: -7위 (±1.5)
```

---

## 📅 실행 타임라인

| 주차 | 작업 | TC | 트래픽 | 소요 시간 |
|-----|------|----|----|---------|
| **Week 1** | 파일럿 | 4개 | 400회 | 16시간 |
| **Week 2-4** | 본 실험 | 12개 | 1,200회 | 48시간 |
| **Week 5** | 검증 | 2개 | 200회 | 8시간 |
| **Week 6** | 분석 | - | - | 40시간 |

**총 소요**: 6주, 1,800회, 112시간

---

## 🔍 예상 인사이트

### 1. 브라우저 지문 효과
```
발견 예상:
- 고사양 지문이 전자기기에서 2배 효과
- 모바일 지문은 패션/뷰티에서 효과적
- 일반 지문은 범용성 높음
```

### 2. 행동 × 카테고리 시너지
```
발견 예상:
- 전자기기 + 비교쇼핑: 상승효과 50%
- 식품 + 빠른이탈: 오히려 효과적 (충동구매)
- 패션 + 심층탐색: 큰 효과
```

### 3. 최적 전략 도출
```
카테고리별 맞춤 전략:
- 전자기기: Profile B + 비교쇼핑
- 패션의류: Profile C + 심층탐색
- 식품: Profile A + 빠른이탈
- 뷰티: Profile C + 일반
```

---

## ✅ 결론

### 상호작용 효과 측정 가능 여부
✅ **가능합니다!**

**이유**:
1. **충분한 표본 크기**: 100회/케이스 → 검정력 99%+
2. **균형 설계**: 부분 요인 설계로 주 효과 + 2차 상호작용 측정
3. **통계 기법**: ANOVA + 교호작용 플롯 + 회귀 분석

**권장 접근**:
- Option 2 (부분 요인 설계, 12개 케이스)
- 1,200회 총 트래픽
- 6주 완료

**다음 단계**:
1. 브라우저 지문 프로필 구현 (`browser_fingerprint.py`)
2. 상호작용 테스트 실행 스크립트 (`run_interaction_test.py`)
3. 상호작용 분석 스크립트 (`analyze_interaction.py`)

---

**작성일**: 2025-11-01
**난이도**: ⭐⭐⭐⭐ 고급
**소요 시간**: 6주 (파일럿 1주 + 본실험 3주 + 검증 1주 + 분석 1주)
