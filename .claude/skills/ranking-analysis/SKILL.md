---
name: ranking-analysis
description: 네이버 쇼핑 상품 순위 분석 및 추적 전문 스킬. 순위 데이터 수집, 통계 분석, 트렌드 파악, A/B 테스트 비교가 필요할 때 사용. 키워드: 순위, 랭킹, 통계, 분석, 트렌드, A/B 테스트, 순위 추적
allowed-tools: Read, Write, Bash(python:*), Grep, Glob
---

# Ranking Analysis Specialist

네이버 쇼핑 상품 순위 분석 및 추적 전문가입니다. 통계적 방법론을 활용하여 순위 변동을 분석하고 인사이트를 제공합니다.

## 전문 분야

### 1. 순위 데이터 수집 및 관리
- 네이버 쇼핑 순위 크롤링
- 순위 데이터 정규화 및 검증
- 시계열 데이터 관리
- 데이터 무결성 확인

### 2. 통계 분석
- 순위 변동 통계 (평균, 중앙값, 표준편차)
- A/B 테스트 비교 (t-test, 카이제곱 검정)
- 이상치 탐지 및 제거
- 신뢰구간 계산

### 3. 트렌드 분석
- 시간대별 순위 변동 패턴
- 요일별/시간대별 효과성 분석
- 계절성 및 주기성 탐지
- 추세선 및 예측 모델

### 4. 시각화 및 보고
- 대시보드 생성
- 그래프 및 차트 제작
- 인사이트 추출 및 요약
- 보고서 자동 생성

## 순위 데이터 구조

### 기본 데이터 포맷

```python
{
    "product_id": "12345678",
    "test_case_id": 1,
    "iteration": 1,
    "timestamp": "2025-01-01 12:00:00",
    "keyword": "무선 이어폰",
    "rank": {
        "page": 3,          # 페이지 번호 (1부터 시작)
        "position": 12,     # 페이지 내 위치 (1~40)
        "absolute_rank": 92 # 절대 순위: (page-1)*40 + position
    },
    "metadata": {
        "price": 49900,
        "review_count": 1234,
        "rating": 4.5,
        "delivery": "무료배송",
        "brand": "브랜드명"
    },
    "test_info": {
        "test_type": "A",  # A: 네이버 검색, B: 쇼핑 직접
        "ip_address": "123.456.789.0",
        "user_agent": "Mozilla/5.0...",
        "device_id": "RF8M12345XY"
    }
}
```

### 순위 변동 데이터 포맷

```python
{
    "product_id": "12345678",
    "test_case_id": 1,
    "iteration": 1,
    "before_rank": {
        "timestamp": "2025-01-01 12:00:00",
        "absolute_rank": 92,
        "page": 3,
        "position": 12
    },
    "after_rank": {
        "timestamp": "2025-01-01 12:30:00",
        "absolute_rank": 68,
        "page": 2,
        "position": 28
    },
    "rank_change": +24,  # 양수: 상승, 음수: 하락
    "page_moved": True,  # 페이지 이동 발생 여부
    "success": True,     # 순위 상승 성공 여부
    "test_duration": 1800  # 테스트 소요 시간 (초)
}
```

## 분석 메트릭

### 1. 기본 통계

```python
import numpy as np
import pandas as pd

def calculate_basic_stats(rank_changes):
    """
    순위 변동 기본 통계를 계산합니다.
    """
    stats = {
        # 중심 경향성
        'mean': np.mean(rank_changes),
        'median': np.median(rank_changes),
        'mode': pd.Series(rank_changes).mode()[0],

        # 산포도
        'std': np.std(rank_changes),
        'variance': np.var(rank_changes),
        'range': np.max(rank_changes) - np.min(rank_changes),
        'iqr': np.percentile(rank_changes, 75) - np.percentile(rank_changes, 25),

        # 분포 특성
        'min': np.min(rank_changes),
        'max': np.max(rank_changes),
        'q1': np.percentile(rank_changes, 25),
        'q3': np.percentile(rank_changes, 75),

        # 성공률
        'success_rate': sum(1 for x in rank_changes if x > 0) / len(rank_changes),
        'total_count': len(rank_changes)
    }

    return stats

# 사용 예시
rank_changes = [+12, -3, +18, +5, +8, +22, -1, +15, +9, +11]
stats = calculate_basic_stats(rank_changes)

print(f"평균 순위 변동: {stats['mean']:.2f}위")
print(f"중앙값: {stats['median']:.2f}위")
print(f"표준편차: {stats['std']:.2f}")
print(f"성공률: {stats['success_rate']*100:.1f}%")
```

### 2. 안정성 지수

순위 변동의 일관성을 측정합니다. 안정성이 높을수록 예측 가능한 효과를 의미합니다.

```python
def calculate_stability_index(rank_changes):
    """
    안정성 지수 = 평균 / 표준편차
    높을수록 안정적 (낮은 변동성으로 일관된 효과)
    """
    mean = np.mean(rank_changes)
    std = np.std(rank_changes)

    if std == 0:
        return float('inf')  # 완벽한 안정성

    stability = mean / std
    return stability

# 예시
case_a_changes = [+15, +16, +14, +17, +15]  # 안정적
case_b_changes = [+25, -5, +10, +30, -10]   # 불안정

print(f"케이스 A 안정성: {calculate_stability_index(case_a_changes):.2f}")
print(f"케이스 B 안정성: {calculate_stability_index(case_b_changes):.2f}")
```

### 3. 효과 크기 (Effect Size)

```python
def calculate_cohen_d(group1, group2):
    """
    Cohen's d: 두 그룹 간 효과 크기 측정
    0.2 = 작음, 0.5 = 중간, 0.8 = 큼
    """
    mean1, mean2 = np.mean(group1), np.mean(group2)
    std1, std2 = np.std(group1), np.std(group2)
    n1, n2 = len(group1), len(group2)

    # Pooled standard deviation
    pooled_std = np.sqrt(((n1-1)*std1**2 + (n2-1)*std2**2) / (n1+n2-2))

    cohen_d = (mean1 - mean2) / pooled_std
    return cohen_d

# 예시: 케이스 A vs B
case_a = [+15, +12, +18, +14, +16]
case_b = [+8, +6, +10, +7, +9]

effect_size = calculate_cohen_d(case_a, case_b)
print(f"Effect Size (Cohen's d): {effect_size:.2f}")

if abs(effect_size) < 0.2:
    print("효과 크기: 작음")
elif abs(effect_size) < 0.5:
    print("효과 크기: 중간")
else:
    print("효과 크기: 큼")
```

## 통계적 유의성 검증

### 1. t-test (두 그룹 비교)

```python
from scipy import stats

def compare_two_cases(case_a, case_b, alpha=0.05):
    """
    두 케이스의 순위 변동을 비교하여 통계적 유의성을 검증합니다.
    """
    # 독립표본 t-검정
    t_stat, p_value = stats.ttest_ind(case_a, case_b)

    result = {
        't_statistic': t_stat,
        'p_value': p_value,
        'is_significant': p_value < alpha,
        'mean_a': np.mean(case_a),
        'mean_b': np.mean(case_b),
        'mean_difference': np.mean(case_a) - np.mean(case_b)
    }

    # 해석
    if result['is_significant']:
        if result['mean_difference'] > 0:
            result['interpretation'] = f"케이스 A가 케이스 B보다 평균 {result['mean_difference']:.2f}위 더 효과적 (p < {alpha})"
        else:
            result['interpretation'] = f"케이스 B가 케이스 A보다 평균 {abs(result['mean_difference']):.2f}위 더 효과적 (p < {alpha})"
    else:
        result['interpretation'] = f"두 케이스 간 통계적으로 유의한 차이 없음 (p = {p_value:.3f})"

    return result

# 사용 예시
case_a_data = [+15, +12, +18, +14, +16, +13, +17, +15, +14, +16]
case_b_data = [+8, +6, +10, +7, +9, +8, +10, +7, +8, +9]

result = compare_two_cases(case_a_data, case_b_data)
print(result['interpretation'])
```

### 2. 쌍체 t-test (Before/After 비교)

```python
def compare_before_after(before_ranks, after_ranks, alpha=0.05):
    """
    동일 상품의 테스트 전후 순위를 비교합니다.
    """
    # 순위 변동 계산 (Before - After, 음수면 순위 상승)
    rank_changes = np.array(before_ranks) - np.array(after_ranks)

    # 단일표본 t-검정 (귀무가설: 평균 변동 = 0)
    t_stat, p_value = stats.ttest_1samp(rank_changes, 0)

    result = {
        't_statistic': t_stat,
        'p_value': p_value,
        'is_significant': p_value < alpha,
        'mean_change': np.mean(rank_changes),
        'median_change': np.median(rank_changes)
    }

    # 해석
    if result['is_significant']:
        if result['mean_change'] > 0:
            result['interpretation'] = f"테스트로 인해 평균 {result['mean_change']:.2f}위 상승 (통계적으로 유의, p < {alpha})"
        else:
            result['interpretation'] = f"테스트로 인해 평균 {abs(result['mean_change']):.2f}위 하락 (통계적으로 유의, p < {alpha})"
    else:
        result['interpretation'] = f"테스트 전후 유의한 순위 변동 없음 (p = {p_value:.3f})"

    return result
```

### 3. 카이제곱 검정 (범주형 데이터)

```python
def compare_success_rates(case_a_success, case_a_total, case_b_success, case_b_total):
    """
    두 케이스의 성공률을 비교합니다.
    """
    # 분할표 생성
    observed = [
        [case_a_success, case_a_total - case_a_success],  # 케이스 A: 성공, 실패
        [case_b_success, case_b_total - case_b_success]   # 케이스 B: 성공, 실패
    ]

    chi2, p_value, dof, expected = stats.chi2_contingency(observed)

    case_a_rate = case_a_success / case_a_total
    case_b_rate = case_b_success / case_b_total

    result = {
        'chi2': chi2,
        'p_value': p_value,
        'case_a_success_rate': case_a_rate,
        'case_b_success_rate': case_b_rate,
        'rate_difference': case_a_rate - case_b_rate
    }

    # 해석
    if p_value < 0.05:
        result['interpretation'] = f"두 케이스의 성공률이 통계적으로 유의하게 다름 (p < 0.05)"
    else:
        result['interpretation'] = f"두 케이스의 성공률이 통계적으로 유의한 차이 없음 (p = {p_value:.3f})"

    return result

# 예시
# 케이스 A: 100회 중 89회 성공
# 케이스 B: 100회 중 76회 성공
result = compare_success_rates(89, 100, 76, 100)
print(f"케이스 A 성공률: {result['case_a_success_rate']*100:.1f}%")
print(f"케이스 B 성공률: {result['case_b_success_rate']*100:.1f}%")
print(result['interpretation'])
```

## 시간대별 패턴 분석

### 1. 시간대별 평균 순위 변동

```python
import pandas as pd

def analyze_by_time_of_day(data):
    """
    시간대별 순위 변동 패턴을 분석합니다.
    data: [{'timestamp': '2025-01-01 14:30:00', 'rank_change': +12}, ...]
    """
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour

    # 시간대 분류
    def classify_time(hour):
        if 6 <= hour < 12:
            return '오전'
        elif 12 <= hour < 18:
            return '오후'
        elif 18 <= hour < 24:
            return '저녁'
        else:
            return '심야'

    df['time_period'] = df['hour'].apply(classify_time)

    # 시간대별 통계
    time_stats = df.groupby('time_period')['rank_change'].agg([
        ('평균', 'mean'),
        ('중앙값', 'median'),
        ('표준편차', 'std'),
        ('테스트 횟수', 'count'),
        ('성공률', lambda x: sum(x > 0) / len(x))
    ]).round(2)

    return time_stats

# 사용 예시
data = [
    {'timestamp': '2025-01-01 08:00:00', 'rank_change': +14},
    {'timestamp': '2025-01-01 14:00:00', 'rank_change': +11},
    {'timestamp': '2025-01-01 20:00:00', 'rank_change': +9},
    # ... 더 많은 데이터
]

time_stats = analyze_by_time_of_day(data)
print(time_stats)
```

### 2. 요일별 패턴 분석

```python
def analyze_by_day_of_week(data):
    """
    요일별 순위 변동 패턴을 분석합니다.
    """
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['day_of_week'] = df['timestamp'].dt.day_name()

    # 요일별 통계
    day_stats = df.groupby('day_of_week')['rank_change'].agg([
        ('평균', 'mean'),
        ('중앙값', 'median'),
        ('표준편차', 'std'),
        ('테스트 횟수', 'count'),
        ('성공률', lambda x: sum(x > 0) / len(x))
    ]).round(2)

    # 주중 vs 주말 비교
    weekday_mask = df['timestamp'].dt.dayofweek < 5  # 월~금
    weekday_mean = df[weekday_mask]['rank_change'].mean()
    weekend_mean = df[~weekday_mask]['rank_change'].mean()

    print(f"주중 평균: {weekday_mean:.2f}위")
    print(f"주말 평균: {weekend_mean:.2f}위")
    print(f"주중-주말 차이: {weekday_mean - weekend_mean:.2f}위")

    return day_stats
```

### 3. 히트맵 데이터 생성

```python
def create_heatmap_data(data):
    """
    요일 × 시간대 히트맵 데이터를 생성합니다.
    """
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['day_of_week'] = df['timestamp'].dt.day_name()
    df['hour'] = df['timestamp'].dt.hour

    # 피벗 테이블 생성
    heatmap = df.pivot_table(
        values='rank_change',
        index='day_of_week',
        columns='hour',
        aggfunc='mean'
    ).round(2)

    return heatmap
```

## 이상치 탐지

### 1. IQR 방법

```python
def detect_outliers_iqr(rank_changes):
    """
    IQR(Interquartile Range) 방법으로 이상치를 탐지합니다.
    """
    q1 = np.percentile(rank_changes, 25)
    q3 = np.percentile(rank_changes, 75)
    iqr = q3 - q1

    # 이상치 경계
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    outliers = [x for x in rank_changes if x < lower_bound or x > upper_bound]
    normal = [x for x in rank_changes if lower_bound <= x <= upper_bound]

    result = {
        'outliers': outliers,
        'normal': normal,
        'outlier_count': len(outliers),
        'outlier_rate': len(outliers) / len(rank_changes),
        'bounds': (lower_bound, upper_bound)
    }

    return result

# 사용 예시
rank_changes = [+12, +15, +8, +68, +14, -25, +11, +13, +10, +16]
outliers = detect_outliers_iqr(rank_changes)

print(f"이상치: {outliers['outliers']}")
print(f"이상치 비율: {outliers['outlier_rate']*100:.1f}%")
```

### 2. Z-score 방법

```python
def detect_outliers_zscore(rank_changes, threshold=3):
    """
    Z-score 방법으로 이상치를 탐지합니다.
    threshold: 일반적으로 3 (표준편차 3배)
    """
    mean = np.mean(rank_changes)
    std = np.std(rank_changes)

    z_scores = [(x - mean) / std for x in rank_changes]
    outliers = [x for x, z in zip(rank_changes, z_scores) if abs(z) > threshold]

    return outliers
```

## 시각화

### 1. 순위 변동 추이 그래프

```python
import matplotlib.pyplot as plt

def plot_rank_trend(data):
    """
    시간에 따른 순위 변동 추이를 그래프로 표시합니다.
    """
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['absolute_rank'], marker='o', linewidth=2)
    plt.xlabel('시간')
    plt.ylabel('절대 순위')
    plt.title('상품 순위 변동 추이')
    plt.gca().invert_yaxis()  # 순위는 낮을수록 좋음
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig('rank_trend.png', dpi=300)
    plt.close()
```

### 2. 박스플롯 (케이스 비교)

```python
def plot_boxplot_comparison(case_a, case_b):
    """
    두 케이스의 순위 변동을 박스플롯으로 비교합니다.
    """
    data = [case_a, case_b]
    labels = ['케이스 A\n(네이버 검색)', '케이스 B\n(쇼핑 직접)']

    plt.figure(figsize=(8, 6))
    plt.boxplot(data, labels=labels)
    plt.ylabel('순위 변동 (위)')
    plt.title('케이스별 순위 변동 분포 비교')
    plt.grid(True, alpha=0.3, axis='y')
    plt.axhline(y=0, color='r', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig('boxplot_comparison.png', dpi=300)
    plt.close()
```

### 3. 히트맵 (시간대별 효과)

```python
import seaborn as sns

def plot_heatmap(heatmap_data):
    """
    요일 × 시간대 히트맵을 생성합니다.
    """
    plt.figure(figsize=(14, 6))
    sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='RdYlGn', center=0)
    plt.xlabel('시간 (Hour)')
    plt.ylabel('요일')
    plt.title('요일 × 시간대별 평균 순위 변동')
    plt.tight_layout()
    plt.savefig('heatmap.png', dpi=300)
    plt.close()
```

## 인사이트 추출

### 자동 인사이트 생성

```python
def generate_insights(stats, case_a, case_b, time_stats):
    """
    분석 결과를 바탕으로 주요 인사이트를 추출합니다.
    """
    insights = []

    # 1. 평균 순위 변동
    if stats['mean'] > 10:
        insights.append(f"✅ 평균 {stats['mean']:.1f}위 상승으로 목표(+10위) 달성")
    else:
        insights.append(f"⚠️  평균 {stats['mean']:.1f}위 상승으로 목표(+10위) 미달성")

    # 2. 성공률
    if stats['success_rate'] > 0.85:
        insights.append(f"✅ 높은 성공률({stats['success_rate']*100:.1f}%) 유지")
    else:
        insights.append(f"⚠️  성공률({stats['success_rate']*100:.1f}%) 개선 필요")

    # 3. 케이스 비교
    case_a_mean = np.mean(case_a)
    case_b_mean = np.mean(case_b)
    if case_a_mean > case_b_mean:
        insights.append(f"📊 케이스 A가 케이스 B보다 평균 {case_a_mean - case_b_mean:.1f}위 더 효과적")
    else:
        insights.append(f"📊 케이스 B가 케이스 A보다 평균 {case_b_mean - case_a_mean:.1f}위 더 효과적")

    # 4. 최적 시간대
    best_time = time_stats['평균'].idxmax()
    best_avg = time_stats['평균'].max()
    insights.append(f"⏰ {best_time} 시간대가 가장 효과적 (평균 +{best_avg:.1f}위)")

    # 5. 안정성
    stability = calculate_stability_index(case_a + case_b)
    if stability > 1.0:
        insights.append(f"✅ 높은 안정성 지수({stability:.2f})로 예측 가능한 효과")
    else:
        insights.append(f"⚠️  낮은 안정성 지수({stability:.2f})로 변동폭 큼")

    return insights
```

## 사용 가이드

### 언제 이 Skill이 발동되는가?

사용자가 다음과 같은 요청을 하면 이 Skill이 자동으로 발동됩니다:
- "순위 변동 분석해줘"
- "케이스 A랑 B 중 어떤 게 더 효과적이야?"
- "최근 1주일 순위 추이를 보여줘"
- "통계적으로 유의한 차이가 있어?"
- "어떤 시간대에 테스트하는 게 좋아?"

### 참조 문서

상세한 메트릭 가이드는 @metrics-guide.md 를 참고하세요.

## 권장 분석 프로세스

1. **데이터 수집 및 정제**: 이상치 제거, 결측치 처리
2. **기본 통계 계산**: 평균, 중앙값, 표준편차
3. **통계적 검증**: t-test, 카이제곱 검정
4. **패턴 분석**: 시간대별, 요일별 분석
5. **시각화**: 그래프, 차트 생성
6. **인사이트 추출**: 주요 발견사항 요약
7. **권장 사항 제시**: 다음 액션 가이드
