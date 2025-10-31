# 단일상품 vs 통합검색형 구분 가이드

## 🎯 핵심 요약

**반드시 "단일상품"으로 테스트해야 합니다!**

```
✅ 단일상품 (OK)
https://shopping.naver.com/window-products/12345678
→ 특정 스마트스토어의 개별 상품
→ 트래픽이 정확히 해당 상품으로 집중

❌ 통합검색형 (NG)
https://search.shopping.naver.com/catalog/12345678
→ 여러 판매처가 같은 상품 판매
→ 트래픽 효과 분산됨
```

---

## 📋 두 타입 비교

### 단일상품 (스마트스토어 상품) ✅

#### 특징
```
- URL: window-products 포함
- 판매자: 단일 스토어
- 구매: 바로 구매 가능
- 순위: 명확한 위치
- 트래픽: 100% 해당 상품으로 집중
```

#### 예시
```
키워드 "무선이어폰" 검색 시:

상품명: OOO 블루투스 이어폰 TWS
판매자: ABC스마트스토어
가격: 29,900원
URL: https://shopping.naver.com/window-products/8809115891052
```

#### 페이지 구조
```
┌─────────────────────────────┐
│ 상품명                       │
│ [상품 이미지]               │
│                             │
│ 가격: 29,900원              │
│ 판매자: ABC스마트스토어      │  ← 단일 판매자
│                             │
│ [장바구니] [바로구매]       │  ← 바로 구매 가능
│                             │
│ 상품 상세정보               │
│ 리뷰                        │
│ Q&A                         │
└─────────────────────────────┘
```

---

### 통합검색형 (카탈로그) ❌

#### 특징
```
- URL: catalog 포함
- 판매자: 여러 쇼핑몰
- 구매: 판매처 선택 후 구매
- 순위: 카탈로그 순위 (의미 없음)
- 트래픽: 효과 분산됨
```

#### 예시
```
키워드 "삼성 갤럭시 버즈" 검색 시:

상품명: 삼성전자 갤럭시 버즈2 SM-R177
판매처: 123개 >                    ← 여러 판매처
최저가: 89,000원
URL: https://search.shopping.naver.com/catalog/33558076619
```

#### 페이지 구조
```
┌─────────────────────────────┐
│ 상품명                       │
│ [상품 이미지]               │
│                             │
│ 최저가: 89,000원            │
│ 판매처: 123개 >             │  ← 여러 판매처
│                             │
│ [판매처 목록]               │  ← 클릭 후 선택
│ ├ A쇼핑몰: 89,000원        │
│ ├ B스토어: 90,500원        │
│ ├ C마켓:  91,200원         │
│ └ ...                       │
│                             │
│ 상품 정보                   │
│ 통합 리뷰                   │
└─────────────────────────────┘
```

**문제점:**
- 트래픽을 A쇼핑몰로 보내도 B스토어도 혜택
- 순위는 "카탈로그" 기준 (개별 판매자 의미 없음)
- 구매까지 클릭 2번 필요 (전환율 낮음)

---

## 🔍 단일상품 찾는 방법

### 방법 1: 자동 검색 스크립트 사용 (권장)

```bash
# 스크립트 실행
python scripts/find_single_products.py "무선이어폰" --pages 3 --save

# 출력:
# 페이지 1 검색 중...
#   총 상품: 40개
#   단일상품: 32개
# 페이지 2 검색 중...
#   총 상품: 40개
#   단일상품: 28개
# 페이지 3 검색 중...
#   총 상품: 40개
#   단일상품: 25개
#
# 총 85개 단일상품 발견
#
# 단일상품 목록 (스마트스토어 상품)
# =====================================
#
# 1. [21위] OOO 블루투스 이어폰
#    ID: 8809115891052
#    가격: 29,900원
#    판매자: ABC스마트스토어
#    URL: https://shopping.naver.com/window-products/8809115891052
#
# 2. [24위] XXX 무선 이어폰
#    ID: 7708226780941
#    ...
#
# ✅ 저장 완료: data/product_search/무선이어폰_products.json
```

#### 옵션 설명

```bash
# 기본 사용
python scripts/find_single_products.py "검색키워드"

# 페이지 수 지정 (기본: 3)
python scripts/find_single_products.py "무선이어폰" --pages 5

# 순위 범위 지정 (2-5페이지만)
python scripts/find_single_products.py "무선이어폰" --min-rank 21 --max-rank 100

# JSON 파일로 저장
python scripts/find_single_products.py "무선이어폰" --save
```

### 방법 2: 수동 확인

```
1. 네이버 쇼핑에서 키워드 검색
   https://shopping.naver.com

2. 검색 결과에서 상품 클릭

3. URL 확인
   window-products → ✅ 단일상품
   catalog → ❌ 통합검색형

4. 페이지 내용 확인
   "판매자: ABC스토어" → ✅ 단일
   "판매처 123개 >" → ❌ 통합
```

### 방법 3: Python 코드로 확인

```python
def is_single_product(url: str) -> bool:
    """단일상품 여부 확인"""
    if 'window-products' in url:
        return True  # ✅ 단일상품
    elif 'catalog' in url:
        return False  # ❌ 통합검색형
    else:
        return None  # 알 수 없음

# 사용 예시
url1 = "https://shopping.naver.com/window-products/12345678"
url2 = "https://search.shopping.naver.com/catalog/12345678"

print(is_single_product(url1))  # True
print(is_single_product(url2))  # False
```

---

## 📊 테스트 상품 선정 기준

### ✅ 좋은 테스트 상품

```
1. 단일상품 (window-products) ✅
2. 현재 순위: 2-5페이지 (21-100위)
3. 가격: 2-10만원 (클릭 가능성 높은 가격대)
4. 리뷰: 10개 이상 (신뢰도)
5. 판매자: 활성 스토어 (배송 빠름)
```

### ❌ 피해야 할 상품

```
1. 통합검색형 (catalog) ❌
2. 순위 너무 높음 (1페이지) → 경쟁 심함
3. 순위 너무 낮음 (10페이지 이후) → 효과 미미
4. 가격 너무 비쌈 (50만원+) → 클릭 낮음
5. 리뷰 없음 → 신뢰도 낮음
```

### 예시: 좋은 테스트 케이스

```json
{
  "id": "product_001",
  "product_url": "https://shopping.naver.com/window-products/8809115891052",
  "product_name": "OOO 블루투스 이어폰 TWS",
  "category": "전자기기",
  "search_keyword": "무선이어폰",
  "initial_rank": 42,
  "price": 29900,
  "review_count": 127,
  "seller": "ABC스마트스토어",
  "url_type": "window-products"  ← 확인 필수!
}
```

---

## 🚀 실전 워크플로우

### Step 1: 단일상품 검색

```bash
# 원하는 카테고리 키워드로 검색
python scripts/find_single_products.py "무선이어폰" --pages 3 --save
python scripts/find_single_products.py "겨울패딩" --pages 3 --save
python scripts/find_single_products.py "건강식품" --pages 3 --save
```

### Step 2: JSON 결과 확인

```bash
# 저장된 파일 확인
cat data/product_search/무선이어폰_products.json
```

```json
{
  "total_count": 85,
  "products": [
    {
      "page": 2,
      "position": 1,
      "absolute_rank": 41,
      "product_id": "8809115891052",
      "product_name": "OOO 블루투스 이어폰",
      "product_url": "https://shopping.naver.com/window-products/8809115891052",
      "price": "29,900원",
      "seller": "ABC스마트스토어",
      "is_single": true,
      "url_type": "window-products"
    },
    ...
  ]
}
```

### Step 3: 테스트 상품 선정

```
JSON 결과에서 2-10개 상품 선택:
- 순위가 적절한가? (21-100위)
- 가격이 적절한가? (클릭 가능성)
- 판매자가 활성 스토어인가?
```

### Step 4: test_matrix.json 업데이트

```json
{
  "test_products": [
    {
      "id": "8809115891052",
      "product_url": "https://shopping.naver.com/window-products/8809115891052",
      "product_name": "OOO 블루투스 이어폰",
      "category": "전자기기",
      "search_keyword": "무선이어폰",
      "competitor_urls": [
        "https://shopping.naver.com/window-products/7708226780941",
        "https://shopping.naver.com/window-products/6607337669830"
      ]
    }
  ]
}
```

**주의:** `competitor_urls`도 반드시 `window-products` 단일상품이어야 함!

### Step 5: 테스트 실행

```bash
# HTTP 방식으로 빠른 검증
python run_comprehensive_test.py --product 0 --iterations 10
```

---

## ⚠️ 주의사항

### 1. 통합검색형으로 테스트하면?

```
문제:
- 순위 측정 불가 (카탈로그 순위는 의미 없음)
- 트래픽 효과 분산 (여러 판매처로 분산)
- 순위 변동 측정 어려움

결과:
❌ 트래픽 100회 생성해도 순위 변화 없음
❌ 시간과 리소스 낭비
```

### 2. URL 확인 필수

```python
# 테스트 전 반드시 확인
def validate_product_url(url: str):
    if 'window-products' not in url:
        raise ValueError(f"❌ 단일상품이 아닙니다: {url}")
    print(f"✅ 단일상품 확인: {url}")

# 모든 상품 URL 검증
for product in test_products:
    validate_product_url(product['product_url'])

    # 경쟁사 URL도 검증
    for comp_url in product.get('competitor_urls', []):
        validate_product_url(comp_url)
```

### 3. 스마트스토어 권장

```
단일상품 중에서도:

✅ 스마트스토어 (권장)
- 네이버 플랫폼 내 상품
- 순위 알고리즘에 민감
- 트래픽 효과 높음

⚠️ 외부몰 (비권장)
- 11번가, G마켓 등 외부몰 링크
- 순위 알고리즘 다름
- 효과 예측 어려움
```

확인 방법:
```
URL에 shopping.naver.com 포함 → ✅ 스마트스토어
URL에 외부 도메인 → ⚠️ 외부몰
```

---

## 📝 체크리스트

테스트 시작 전 반드시 확인:

```
□ 모든 상품 URL에 'window-products' 포함
□ 모든 경쟁사 URL도 'window-products' 포함
□ 'catalog' URL 없음
□ 상품 페이지에 "판매처 NN개" 버튼 없음
□ 상품 페이지에 단일 판매자만 표시
□ 바로 장바구니/구매 버튼 있음
□ 현재 순위 확인 (2-5페이지 권장)
```

---

## 🔧 트러블슈팅

### 문제: 단일상품을 찾을 수 없음

```
증상:
python scripts/find_single_products.py "키워드"
→ "단일상품을 찾을 수 없습니다."

원인:
1. 해당 키워드로 스마트스토어 상품이 실제로 없음
2. HTML 선택자 변경 (네이버 구조 업데이트)

해결:
1. 다른 키워드 시도
2. 네이버 쇼핑에서 수동으로 확인
3. scripts/find_single_products.py의 선택자 업데이트
```

### 문제: 순위 체크 시 상품이 안 나옴

```
증상:
check_rank() 실행 시 None 반환

원인:
- 통합검색형 상품일 가능성
- 검색 키워드와 실제 상품 불일치

해결:
1. URL에 window-products 있는지 확인
2. 네이버 쇼핑에서 수동 검색하여 실제 순위 확인
3. 검색 키워드 조정
```

---

## 📚 참고 자료

### 네이버 쇼핑 상품 타입 URL 패턴

```
1. 단일상품 (스마트스토어)
   https://shopping.naver.com/window-products/[PRODUCT_ID]

2. 통합검색형 (카탈로그)
   https://search.shopping.naver.com/catalog/[CATALOG_ID]

3. 브랜드 스토어
   https://brand.naver.com/[BRAND]/products/[PRODUCT_ID]

4. 외부몰 링크
   https://search.shopping.naver.com/gate.nhn?id=[ID]
   → 11번가, G마켓 등으로 리다이렉트
```

### 권장 상품 타입

```
1순위: window-products (스마트스토어)  ⭐⭐⭐
2순위: brand.naver.com (브랜드 스토어) ⭐⭐
3순위: 외부몰 링크                    ⭐
금지:   catalog (통합검색형)           ❌
```

---

**작성일**: 2025-11-01
**버전**: v1.0
**중요도**: ⚠️ 필수 확인 사항

**반드시 단일상품으로 테스트하세요!**
