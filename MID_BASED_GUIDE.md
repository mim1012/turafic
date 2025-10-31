# mid 값 기반 상품 식별 가이드

## 🎯 핵심 개념

**mid = 상품 코드 (상품을 고유하게 식별하는 값)**

```
단일상품 URL 예시:
https://smartstore.naver.com/mystore/products/8809115891052?mid=9876543
                                                              ^^^^^^^^^
                                                              이게 실제 상품 코드!

URL 경로의 숫자 (8809115891052):
- 공개용 ID (여러 판매자가 같은 번호 사용 가능)

mid 파라미터 (9876543):
- 실제 상품 코드 (고유값, 단일 상품 식별)
```

---

## 📋 mid 추출 우선순위

### 1순위: mid 파라미터 (가장 정확) ⭐⭐⭐

```python
URL: https://smartstore.naver.com/abc/products/8809115891052?mid=9876543

import re
from urllib.parse import urlparse, parse_qs

parsed = urlparse(url)
query_params = parse_qs(parsed.query)

if 'mid' in query_params:
    mid = query_params['mid'][0]  # '9876543'
    # ✅ 이게 실제 상품 코드!
```

### 2순위: URL 경로 숫자 (폴백)

```python
URL: https://shopping.naver.com/window-products/8809115891052

# mid 파라미터 없으면 경로에서 추출
pattern = r"/(?:window-)?products/(\d+)"
match = re.search(pattern, url)

if match:
    product_id = match.group(1)  # '8809115891052'
    # ⚠️ mid 파라미터 있으면 그걸 우선 사용
```

---

## 🔍 실전 예시

### 예시 1: 스마트스토어 상품

```
URL:
https://smartstore.naver.com/mystore/products/8809115891052?mid=88091158

분석:
- 경로 ID: 8809115891052
- mid: 88091158  ← 실제 상품 코드

사용:
product_id = '88091158'  # mid 값 사용
```

### 예시 2: window-products (mid 없음)

```
URL:
https://shopping.naver.com/window-products/7708226780941

분석:
- mid 파라미터 없음
- 경로 ID: 7708226780941

사용:
product_id = '7708226780941'  # 경로 ID 사용
```

### 예시 3: mid 파라미터 우선

```
URL:
https://smartstore.naver.com/store/products/123456?mid=789012

mid 파라미터 있음: 789012 ✅
경로 ID: 123456 ❌ (무시)

사용:
product_id = '789012'  # mid 우선
```

---

## 🛠️ 사용 방법

### 자동 추출 스크립트

```bash
# mid 추출 테스트
python scripts/extract_mid_from_url.py

# 출력:
# URL: https://smartstore.naver.com/abc/products/123...
#   mid: 9876543
#   단일상품: True
#   타입: smartstore
#   판매자: abc
#   유효성: ✅
```

### Python 코드에서 사용

```python
from scripts.extract_mid_from_url import extract_mid_from_url

url = "https://smartstore.naver.com/mystore/products/8809115891052?mid=9876543"

mid = extract_mid_from_url(url)
print(mid)  # '9876543'
```

### ranking checker는 자동으로 mid 추출

```python
from src.ranking.checker import check_rank

# URL을 넣으면 자동으로 mid 추출하여 순위 체크
rank = check_rank(
    keyword="무선이어폰",
    product_id="9876543",  # mid 값
    max_page=5
)

if rank:
    print(f"순위: {rank['absolute_rank']}위")
```

---

## 📊 단일상품 찾기 (mid 포함)

### 스크립트로 단일상품 검색

```bash
# 단일상품 검색 (자동으로 mid 추출)
python scripts/find_single_products.py "무선이어폰" --pages 3 --save
```

### JSON 결과

```json
{
  "total_count": 85,
  "products": [
    {
      "page": 2,
      "position": 1,
      "absolute_rank": 41,
      "product_id": "9876543",  ← mid 값 (자동 추출)
      "product_name": "OOO 블루투스 이어폰",
      "product_url": "https://smartstore.naver.com/abc/products/...?mid=9876543",
      "is_single": true,
      "url_type": "smartstore"
    }
  ]
}
```

---

## ✅ 테스트 설정 시 주의사항

### config/test_matrix.json 작성

```json
{
  "test_products": [
    {
      "id": "9876543",  ← mid 값 사용!
      "product_url": "https://smartstore.naver.com/abc/products/...?mid=9876543",
      "product_name": "OOO 블루투스 이어폰",
      "category": "전자기기",
      "search_keyword": "무선이어폰"
    }
  ]
}
```

**중요:**
- `"id"` 필드에는 **mid 값** 입력
- URL 경로의 숫자가 아님!
- mid 파라미터 있으면 그 값 사용

### 검증 방법

```python
# URL에서 자동 추출한 mid가 맞는지 확인
from scripts.extract_mid_from_url import extract_mid_from_url

url = "https://smartstore.naver.com/abc/products/8809115891052?mid=9876543"
mid = extract_mid_from_url(url)

print(f"추출된 mid: {mid}")  # '9876543'
print(f"config의 id와 일치: {mid == '9876543'}")  # True
```

---

## 🔄 mid vs URL 경로 ID 비교

| 항목 | mid 파라미터 | URL 경로 ID |
|------|-------------|------------|
| **정확성** | ⭐⭐⭐ 가장 정확 | ⭐⭐ 대부분 정확 |
| **고유성** | ✅ 완전 고유 | ⚠️ 중복 가능 |
| **존재** | ⚠️ 없을 수 있음 | ✅ 항상 있음 |
| **사용** | 있으면 우선 사용 | 폴백으로 사용 |

### 추출 로직 (구현됨)

```python
def _extract_product_id(url: str) -> Optional[str]:
    """mid 우선, 없으면 경로 ID 사용"""

    # 1. mid 파라미터 확인 (우선)
    query_params = parse_qs(urlparse(url).query)
    if 'mid' in query_params:
        return query_params['mid'][0]  # ✅ mid 있으면 반환

    # 2. URL 경로에서 추출 (폴백)
    pattern = r"/(?:window-)?products/(\d+)"
    match = re.search(pattern, url)
    if match:
        return match.group(1)  # ⚠️ mid 없을 때만 사용

    return None
```

---

## 📝 실전 체크리스트

### 테스트 전 확인

```
□ 상품 URL에 'window-products' 또는 'smartstore' 포함 (단일상품)
□ URL에서 mid 파라미터 확인
□ mid 있으면 그 값을 product_id로 사용
□ mid 없으면 URL 경로의 숫자 사용
□ config/test_matrix.json의 "id" 필드에 올바른 값 입력
□ find_single_products.py로 자동 추출한 값 사용 권장
```

### 순위 체크 시

```python
# 방법 1: mid 값으로 체크 (권장)
rank = check_rank("무선이어폰", "9876543")

# 방법 2: URL로 체크 (자동 추출)
# checker 내부에서 자동으로 mid 추출
```

---

## 🚀 빠른 시작 가이드

### Step 1: 단일상품 검색

```bash
# 키워드로 단일상품 검색 (자동 mid 추출)
python scripts/find_single_products.py "무선이어폰" --save
```

### Step 2: JSON 결과 확인

```bash
cat data/product_search/무선이어폰_products.json

# product_id 필드 확인 → 이게 mid 값
```

### Step 3: test_matrix.json 업데이트

```json
{
  "id": "JSON에서_확인한_product_id",  ← 여기에 복사
  "product_url": "JSON에서_확인한_product_url"
}
```

### Step 4: 테스트 실행

```bash
python run_comprehensive_test.py --product 0 --iterations 10
```

---

## ⚠️ 주의사항

### 1. mid 파라미터 있는 상품 우선

```
스마트스토어 상품:
https://smartstore.naver.com/abc/products/123?mid=456

사용할 ID: 456 (mid)
사용 안 할 ID: 123 (경로)
```

### 2. window-products는 경로 ID 사용

```
일반 윈도우 상품:
https://shopping.naver.com/window-products/789012

사용할 ID: 789012 (경로)
mid 파라미터 없음
```

### 3. 자동 추출 권장

```bash
# 수동으로 mid 확인하지 말고
# 스크립트로 자동 추출 권장

python scripts/find_single_products.py "키워드" --save
→ JSON 결과의 product_id 사용
```

---

## 🔧 트러블슈팅

### 문제: 순위 체크가 안 됨

```
증상:
check_rank() 실행 시 None 반환

원인:
- product_id가 mid가 아닌 경로 ID일 가능성

해결:
1. URL에서 mid 파라미터 확인
2. scripts/extract_mid_from_url.py로 정확한 값 추출
3. config 업데이트
```

### 문제: mid 값이 다름

```
증상:
URL 경로: 8809115891052
mid 파라미터: 9876543
어느 것을 사용?

해결:
✅ mid 파라미터 (9876543) 사용
❌ 경로 ID 무시
```

---

**작성일**: 2025-11-01
**핵심**: mid 파라미터 = 실제 상품 코드 (우선 사용)
**폴백**: URL 경로 ID (mid 없을 때만)
