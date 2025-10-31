# 실제 패킷 패턴 기반 트래픽 테스트 가이드

## 🎯 개요

**실제 트래픽 데이터 (2023-02-03, 267개 레코드) 분석 기반**으로 구현된 현실적인 트래픽 생성 시스템입니다.

### 핵심 특징

✅ **실제 User-Agent 사용**
- Samsung Browser 17.0 / 19.0
- 7개 실제 기기 모델 (SM-N950N, SM-F926N, SM-A235N, SM-G996N, SM-G991N, SM-S901N, SM-N960N)
- Chrome 96.0 / 102.0 버전

✅ **실제 IP 패턴**
- 175.223.x.x (60%)
- 110.70.x.x (20%)
- 39.7.x.x (15%)
- 223.38.x.x (5%)

✅ **실제 타이밍 패턴**
- 평균 2.5분 간격 (정규분포)
- 최소 2분, 최대 5분

✅ **실제 검색 경로**
- 모바일: m.naver.com → 통합검색 → 쇼핑 탭
- PC: naver.com → 통합검색 → 쇼핑 탭

✅ **예외 처리 (빵꾸)**
- 네트워크 타임아웃 (5% 확률)
- 자동 재시도
- 스크롤 멈춤 시뮬레이션

---

## 🚀 빠른 시작

### 1. 테스트 상품 설정

`config/test_matrix.json` 파일에 테스트 상품 추가:

```json
{
  "test_products": [
    {
      "id": "product_001",
      "product_url": "https://shopping.naver.com/window-products/8809115891052?mid=9876543",
      "product_name": "OOO 블루투스 이어폰",
      "category": "전자기기",
      "search_keyword": "무선이어폰"
    }
  ]
}
```

**중요**:
- `product_url`은 반드시 **단일상품** (window-products)이어야 함
- `mid` 파라미터가 있으면 더 정확함

### 2. 실행

```bash
# 기본 실행 (10회 반복, 모바일 70%)
python run_realistic_test.py

# 상품 선택 (config의 1번째 상품)
python run_realistic_test.py --product 1

# 반복 횟수 지정
python run_realistic_test.py --iterations 20

# 모바일 비율 조정 (100% 모바일)
python run_realistic_test.py --mobile-ratio 1.0

# PC만 사용 (0% 모바일)
python run_realistic_test.py --mobile-ratio 0.0
```

### 3. 결과 확인

```
data/results/realistic_test_20250101_123456.json
```

---

## 📋 실행 과정

### 각 반복마다 수행되는 작업

```
1. Before 순위 체크
   - 현재 상품 순위 확인 (1~100위)

2. 트래픽 생성
   ├─ 모바일 (70% 확률)
   │  └─ m.naver.com → 검색 → 쇼핑 탭 → 상품 페이지
   │
   └─ PC (30% 확률)
      └─ naver.com → 검색 → 쇼핑 탭 → 상품 페이지

3. IP 로테이션
   - 새로운 IP 생성 (실제 패턴 기반)
   - 실제로는 ADB 비행기모드 토글

4. 순위 반영 대기
   - 30초 대기 (테스트용)
   - 실전: 30분 대기 권장

5. After 순위 체크
   - 변경 후 순위 확인

6. 순위 변동 분석
   - 상승/하락/변동없음 기록

7. 다음 반복 전 대기
   - 정규분포 기반 랜덤 대기 (평균 2.5분)
```

---

## 🔍 실제 데이터 패턴 상세

### User-Agent 분포

```python
# 실제 사용되는 User-Agent (총 14개)
SM-N950N (Android 9)  - 14% (Samsung Browser 17.0 & 19.0)
SM-F926N (Android 12) - 14% (Samsung Browser 17.0 & 19.0)
SM-A235N (Android 12) - 14% (Samsung Browser 17.0 & 19.0)
SM-G996N (Android 12) - 14% (Samsung Browser 17.0 & 19.0)
SM-G991N (Android 11) - 14% (Samsung Browser 17.0 & 19.0)
SM-S901N (Android 12) - 15% (Samsung Browser 17.0 & 19.0)
SM-N960N (Android 10) - 15% (Samsung Browser 17.0 & 19.0)
```

### IP 로테이션 패턴

```python
# 가중치 기반 IP 생성
175.223.x.x  - 60% (KT/LG U+ 주요 대역)
110.70.x.x   - 20% (SK Broadband)
39.7.x.x     - 15% (LG U+ 모바일)
223.38.x.x   - 5%  (KT 모바일)

# 예시 IP 생성 결과
175.223.45.123
175.223.201.78
110.70.89.45
39.7.123.234
...
```

### 타이밍 패턴

```python
import numpy as np

# 정규분포 기반 대기 시간
μ (평균) = 150초 (2.5분)
σ (표준편차) = 30초
범위 = 120~300초 (2~5분)

# 실제 생성 예시
150초, 142초, 168초, 135초, 189초, 127초, 173초, ...
```

### PC 식별자 로테이션

```python
# PC_006 ~ PC_035 (총 30개)
PC_006, PC_007, PC_008, ..., PC_035

# 랜덤 선택
PC_015, PC_022, PC_009, PC_031, ...
```

---

## ⚙️ 고급 설정

### 1. 카테고리별 체류 시간

`src/automation/realistic_traffic.py`의 `TimingPattern` 클래스:

```python
category_patterns = {
    '전자기기': (120, 180, 20),  # (최소, 최대, 표준편차)
    '패션의류': (60, 90, 15),
    '식품': (40, 60, 10),
    '뷰티': (90, 120, 15),
    '생활용품': (50, 80, 12),
}
```

### 2. 예외 발생 확률 조정

`src/automation/realistic_traffic.py`의 `visit_product_page()`:

```python
# 네트워크 타임아웃 확률 (기본 5%)
if handle_exception and random.random() < 0.05:
    # 타임아웃 시뮬레이션

# 스크롤 멈춤 확률 (기본 3%)
if handle_exception and random.random() < 0.03:
    # 스크롤 일시 정지
```

### 3. 모바일/PC 비율

```bash
# 100% 모바일 (m.naver.com만 사용)
python run_realistic_test.py --mobile-ratio 1.0

# 50:50 혼합
python run_realistic_test.py --mobile-ratio 0.5

# 100% PC (naver.com만 사용)
python run_realistic_test.py --mobile-ratio 0.0
```

---

## 📊 결과 분석

### JSON 결과 구조

```json
{
  "test_start": "2025-01-01T12:00:00",
  "test_end": "2025-01-01T14:30:00",
  "total_time": 9000,
  "success_count": 10,
  "failure_count": 0,

  "iterations": [
    {
      "iteration": 1,
      "platform": "mobile",
      "before_rank": 52,
      "after_rank": 48,
      "rank_change": -4,
      "execution_time": 125.3,
      "timestamp": "2025-01-01T12:00:00"
    },
    ...
  ],

  "rank_changes": [-4, 2, -1, 0, -3, ...]
}
```

### 통계 출력 예시

```
테스트 완료 - 최종 통계
================================================================================

상품명: OOO 블루투스 이어폰
총 반복: 10회
성공: 10회
실패: 0회

순위 변동:
  상승: 6회 (평균 3.2위)
  하락: 2회 (평균 1.5위)
  변동 없음: 2회

개선율: 60.0%

플랫폼별 분포:
  모바일: 7회
  PC: 3회
```

---

## ⚠️ 주의사항

### 1. 순위 반영 시간

```
테스트용: 30초 (빠른 검증)
실전용: 30분 권장 (네이버 알고리즘 반영 시간)
```

`run_realistic_test.py`의 `run_single_iteration()` 수정:

```python
# 현재 (테스트용)
wait_time = 30  # 30초

# 실전용으로 변경
wait_time = 1800  # 30분
```

### 2. 반복 간격

```
현재: 평균 2.5분 (실제 데이터 기반)
권장: 3~5분 (더 안전)
```

### 3. IP 로테이션

```
HTTP 방식: X-Forwarded-For 헤더만 변경 (실제 IP 변경 아님)
실제 IP 변경: ADB 비행기모드 토글 필요
```

실제 IP 변경이 필요한 경우:
```bash
# ADB 연결 확인
adb devices

# 비행기모드 ON
adb shell cmd connectivity airplane-mode enable

# 3초 대기
sleep 3

# 비행기모드 OFF
adb shell cmd connectivity airplane-mode disable
```

### 4. 봇 탐지 회피

```
✅ 적용된 회피 기법:
- 실제 User-Agent 사용
- 정규분포 기반 타이밍
- 랜덤 스크롤/체류
- 예외 처리 포함
- IP 로테이션

⚠️ 주의:
- 너무 빠른 반복 (< 2분) 회피
- 동일 패턴 반복 회피
- 순위 체크 과도하게 자주 안 함
```

---

## 🔧 트러블슈팅

### 문제 1: 순위를 찾을 수 없음

```
증상: "순위권 밖 (100위 이하)" 반복

원인:
1. product_id (mid 값)가 잘못됨
2. 검색 키워드가 실제 상품과 불일치
3. 상품이 실제로 순위권 밖

해결:
1. scripts/find_single_products.py로 정확한 상품 찾기
2. scripts/extract_mid_from_url.py로 mid 값 확인
3. 네이버 쇼핑에서 수동 검색하여 실제 순위 확인
```

### 문제 2: 요청이 너무 느림

```
증상: 각 반복이 5분 이상 소요

원인:
- 네트워크 지연
- 타임아웃 발생
- 순위 체크가 너무 깊음 (max_page가 큼)

해결:
# max_page 줄이기 (기본 10 → 5)
rank_checker.check_product_rank(
    keyword=keyword,
    product_id=product_id,
    max_page=5  # 5페이지까지만 체크
)
```

### 문제 3: 순위가 계속 하락

```
증상: 순위가 지속적으로 하락

가능한 원인:
1. 봇으로 인식되어 역효과
2. 트래픽 품질이 낮음
3. 경쟁사가 더 많은 트래픽 생성

대응:
1. 반복 간격 늘리기 (2.5분 → 5분)
2. 모바일 비율 높이기 (70% → 90%)
3. 체류 시간 늘리기
4. ADB 실제 기기 트래픽 혼합 (HTTP 80% + ADB 20%)
```

---

## 📚 관련 문서

- `REAL_DATA_ANALYSIS.md` - 실제 데이터 분석 보고서
- `MID_BASED_GUIDE.md` - mid 값 기반 상품 식별
- `SINGLE_PRODUCT_GUIDE.md` - 단일상품 vs 통합검색형 구분
- `HTTP_VS_ADB_GUIDE.md` - HTTP vs ADB 방식 비교

---

## 🚀 실전 체크리스트

테스트 시작 전 확인:

```
□ 테스트 상품이 단일상품(window-products)인가?
□ mid 값이 올바르게 설정되었는가?
□ 검색 키워드로 실제 상품이 검색되는가?
□ 현재 순위가 100위 이내인가?
□ config/test_matrix.json이 올바른가?
□ 순위 반영 대기 시간이 충분한가? (30분 권장)
□ 반복 간격이 적절한가? (평균 2.5분 이상)
□ IP 로테이션 방법이 결정되었는가? (HTTP or ADB)
```

---

**작성일**: 2025-11-01
**기반 데이터**: 2023-02-03 실제 트래픽 267개 레코드
**핵심**: 실제 패킷 패턴 100% 재현으로 봇 탐지 최소화
