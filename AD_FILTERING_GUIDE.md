# 광고 필터링 가이드

## 🎯 핵심 개념

네이버 쇼핑 검색 결과에는 **광고 상품**과 **일반 상품**이 섞여 있습니다.

순위 카운팅 시 **광고 상품은 제외**하고, **일반 상품만** 카운팅해야 정확한 순위를 측정할 수 있습니다.

---

## 📊 검색 결과 구조

### 예시: "무선이어폰" 검색 결과 (1페이지)

```
┌─────────────────────────────────────┐
│ [광고] A사 블루투스 이어폰          │ ← 광고 (카운팅 제외)
├─────────────────────────────────────┤
│ [광고] B사 무선 이어폰              │ ← 광고 (카운팅 제외)
├─────────────────────────────────────┤
│ C사 TWS 이어폰                      │ ← 1위 (일반 상품)
├─────────────────────────────────────┤
│ D사 블루투스 이어폰                 │ ← 2위 (일반 상품)
├─────────────────────────────────────┤
│ [광고] E사 무선 이어폰              │ ← 광고 (카운팅 제외)
├─────────────────────────────────────┤
│ F사 노이즈캔슬링 이어폰             │ ← 3위 (일반 상품)
├─────────────────────────────────────┤
│ G사 게이밍 이어폰                   │ ← 4위 (일반 상품)
└─────────────────────────────────────┘
```

**총 7개 아이템 중:**
- 광고: 3개 (A사, B사, E사) → 순위 카운팅 제외
- 일반 상품: 4개 (C사, D사, F사, G사) → 1위, 2위, 3위, 4위

---

## 🔍 광고 탐지 방법

### 1. "광고" 텍스트 확인 (가장 확실)

```html
<!-- 패턴 1: 광고 뱃지 -->
<span class="ad_badge">광고</span>

<!-- 패턴 2: AD 표시 -->
<span class="ad">AD</span>

<!-- 패턴 3: 클래스명에 ad 포함 -->
<div class="basicList_ad__LEz5E">
  <span>광고</span>
</div>
```

### 1-2. 파워링크 배지 확인 ⭐ (중요)

```html
<!-- 패턴 1: 파워링크 SVG 배지 -->
<svg xmlns="http://www.w3.org/2000/svg" width="39" height="16"
     fill="none" viewBox="0 0 39 16"
     class="A4ub2IBr hHtxeo9d">
  <rect width="38" height="15" x="0.5" y="0.5" stroke="currentColor" rx="7.5"></rect>
  <path fill="currentColor" d="..."></path>
  <!-- 파워링크 아이콘 내용 -->
</svg>

<!-- 패턴 2: 파워링크 클래스 -->
<span class="powerlink_badge">파워링크</span>
<div class="power_link">...</div>

<!-- 패턴 3: SVG viewBox 체크 -->
<!-- viewBox="0 0 39 16" 은 파워링크 고유값 -->
```

**파워링크 탐지 방법:**
- SVG 클래스 확인: `A4ub2IBr`, `hHtxeo9d`
- SVG viewBox 확인: `0 0 39 16`
- 클래스명에 `powerlink`, `power_link` 포함
- URL에 `nv_ad=`, `powerlink` 파라미터 포함

### 2. data-ad 속성 체크

```html
<!-- 패턴 4: data-ad 속성 -->
<div class="product_item" data-ad="true">
  ...
</div>

<!-- 패턴 5: data-is-ad 속성 -->
<div class="basicList_item__0T9JD" data-is-ad="true">
  ...
</div>
```

### 3. URL 패턴 확인

```html
<!-- 패턴 6: URL에 /ad/ 포함 -->
<a href="https://shopping.naver.com/ad/12345678">

<!-- 패턴 7: 광고 파라미터 포함 -->
<a href="https://shopping.naver.com/products/12345?adcr=xxx">
<a href="https://shopping.naver.com/products/12345?ad_id=xxx">
```

### 4. 클래스명 패턴

```html
<!-- 패턴 8: advertisement 클래스 -->
<div class="advertisement">...</div>

<!-- 패턴 9: sponsored 클래스 -->
<div class="sponsored">...</div>
```

### 5. 부모 요소 확인

```html
<!-- 패턴 10: 광고 영역 안에 위치 -->
<div data-ad-area="top">
  <div class="product_item">...</div>  ← 광고
</div>
```

---

## 💻 구현 코드

### Python (BeautifulSoup)

```python
def _is_advertisement(self, element) -> bool:
    """
    광고 상품 여부 확인 (파워링크 포함)

    Args:
        element: BeautifulSoup 요소

    Returns:
        True if 광고/파워링크, False if 일반 상품
    """
    # 1. "광고" 텍스트 포함 여부
    ad_text_elements = element.select(
        "span.ad_badge, span.ad, div.ad_badge, "
        "span[class*='ad'], div[class*='ad'], "
        "span.basicList_ad__LEz5E, div.product_ad"
    )

    for ad_elem in ad_text_elements:
        text = ad_elem.get_text(strip=True)
        if "광고" in text or "AD" in text.upper():
            return True

    # 2. 파워링크 배지 체크 (SVG 아이콘) ⭐
    powerlink_elements = element.select(
        "svg[class*='power'], "
        "span[class*='power'], "
        "div[class*='power'], "
        "svg.A4ub2IBr, "  # 파워링크 SVG 클래스
        "svg.hHtxeo9d"    # 파워링크 SVG 클래스
    )

    if powerlink_elements:
        return True

    # SVG viewBox 체크 (파워링크 고유값)
    svg_elements = element.select("svg")
    for svg_elem in svg_elements:
        viewbox = svg_elem.get("viewBox", "")
        if viewbox == "0 0 39 16":  # 파워링크 SVG 크기
            return True

        # SVG 텍스트 확인
        svg_text = svg_elem.get_text(strip=True)
        if "파워링크" in svg_text or "POWER" in svg_text.upper():
            return True

    # 3. data-ad 속성 체크
    if element.get('data-ad') == 'true' or element.get('data-is-ad') == 'true':
        return True

    # 4. data-nv-ad 속성 체크 (네이버 광고 마크)
    if element.get('data-nv-ad'):
        return True

    # 5. 클래스명에 'powerlink', 'power_link' 포함
    class_names = ' '.join(element.get('class', []))
    if 'powerlink' in class_names.lower() or 'power_link' in class_names.lower():
        return True

    # 6. 클래스명에 'ad' 포함
    if 'advertisement' in class_names.lower() or 'sponsored' in class_names.lower():
        return True

    # 7. URL에 '/ad/' 또는 파워링크 파라미터 포함 체크
    link_element = element.select_one("a")
    if link_element:
        href = link_element.get("href", "")
        if '/ad/' in href or 'adcr=' in href or 'ad_id=' in href:
            return True
        # 파워링크 URL 패턴
        if 'nv_ad=' in href or 'powerlink' in href.lower():
            return True

    # 8. 부모 요소가 광고 영역인지 체크
    parent = element.parent
    if parent and parent.get('data-ad-area'):
        return True

    return False
```

---

## 📋 순위 카운팅 로직

### Before (잘못된 방법) ❌

```python
# 광고 포함 카운팅 (잘못됨)
for idx, element in enumerate(product_elements, start=1):
    product_id = extract_product_id(element)
    absolute_rank = (page - 1) * 20 + idx  # ❌ 광고도 카운팅

    products.append({
        'product_id': product_id,
        'absolute_rank': absolute_rank  # 잘못된 순위
    })
```

**문제점:**
```
페이지 1:
  [광고] 상품A → 1위 (❌ 잘못됨)
  [광고] 상품B → 2위 (❌ 잘못됨)
  상품C     → 3위 (❌ 잘못됨, 실제로는 1위)
  상품D     → 4위 (❌ 잘못됨, 실제로는 2위)
```

### After (올바른 방법) ✅

```python
# 광고 제외 카운팅 (올바름)
organic_position = 0  # 광고 제외한 실제 순위

for idx, element in enumerate(product_elements, start=1):
    # 광고 체크
    is_ad = _is_advertisement(element)

    if is_ad:
        log.debug(f"광고 상품 (순위 카운팅 제외)")
        continue  # ✅ 광고는 건너뛰기

    # 광고가 아닌 경우에만 카운팅
    organic_position += 1  # ✅ 일반 상품만 카운팅

    product_id = extract_product_id(element)
    absolute_rank = (page - 1) * 20 + organic_position  # ✅ 정확한 순위

    products.append({
        'product_id': product_id,
        'absolute_rank': absolute_rank  # ✅ 광고 제외한 정확한 순위
    })
```

**결과:**
```
페이지 1:
  [광고] 상품A → 카운팅 제외 ✅
  [광고] 상품B → 카운팅 제외 ✅
  상품C     → 1위 ✅ (organic_position = 1)
  상품D     → 2위 ✅ (organic_position = 2)
```

---

## 🧪 테스트 방법

### 1. 수동 테스트

```python
# 순위 체크 테스트
from src.ranking.checker import RankChecker

checker = RankChecker()

# 실제 검색 실행
result = checker.check_product_rank(
    keyword="무선이어폰",
    product_id="8809115891052",
    max_page=3
)

if result:
    print(f"순위: {result['absolute_rank']}위")
    print(f"페이지: {result['page']}")
    print(f"위치: {result['position']} (광고 제외)")
```

### 2. 로그 확인

```
실행 시 다음과 같은 로그 출력:

[DEBUG] [페이지 1] 위치 1: 광고 상품 (순위 카운팅 제외)
[DEBUG] [페이지 1] 위치 2: 광고 상품 (순위 카운팅 제외)
[DEBUG] 상품 파싱: 8809115891052 - C사 TWS 이어폰 (순위: 1위, 광고 제외)
[DEBUG] 상품 파싱: 7708226780941 - D사 블루투스 이어폰 (순위: 2위, 광고 제외)
[DEBUG] [페이지 1] 위치 5: 광고 상품 (순위 카운팅 제외)
[DEBUG] 상품 파싱: 6607337669830 - F사 노이즈캔슬링 이어폰 (순위: 3위, 광고 제외)
```

### 3. 네이버 쇼핑에서 수동 확인

```
1. 네이버 쇼핑에서 키워드 검색
2. "광고" 표시 있는 상품 확인
3. 광고 제외하고 순위 카운팅
4. 프로그램 결과와 비교
```

---

## ⚠️ 주의사항

### 1. HTML 구조 변경

네이버는 주기적으로 HTML 구조를 변경합니다.

**대응 방법:**
```python
# 여러 선택자 패턴 시도
ad_text_elements = element.select(
    "span.ad_badge, "          # 패턴 1
    "span.ad, "                # 패턴 2
    "div.ad_badge, "           # 패턴 3
    "span[class*='ad'], "      # 패턴 4 (넓은 범위)
    "div[class*='ad'], "       # 패턴 5 (넓은 범위)
    "span.basicList_ad__LEz5E" # 패턴 6 (최신 클래스명)
)
```

### 2. False Positive (오탐)

클래스명에 'ad'가 포함된 일반 단어도 있습니다.

**예시:**
- `badminton` (배드민턴) - 'ad' 포함
- `headphone` (헤드폰) - 'ad' 포함
- `thread` (실) - 'ad' 포함

**해결:**
```python
# 정확한 패턴만 사용
if 'advertisement' in class_names.lower():  # ✅ 정확
    return True

# 아래는 사용 안 함 (오탐 가능성)
# if 'ad' in class_names.lower():  # ❌ 너무 넓음
```

### 3. False Negative (미탐)

새로운 광고 패턴이 추가될 수 있습니다.

**대응:**
```python
# 정기적으로 실제 HTML 확인
# 새로운 광고 패턴 발견 시 코드 업데이트
```

---

## 📊 통계 예시

### 광고 비율 분석

```
검색어: "무선이어폰"
페이지 1 분석:
  - 전체 아이템: 23개
  - 광고: 5개 (22%)
  - 일반 상품: 18개 (78%)

페이지 2 분석:
  - 전체 아이템: 21개
  - 광고: 3개 (14%)
  - 일반 상품: 18개 (86%)

평균 광고 비율: 약 18%
```

### 순위 계산 예시

```
페이지 1:
  광고 5개, 일반 상품 18개
  → 1위~18위

페이지 2:
  광고 3개, 일반 상품 18개
  → 19위~36위 (18 + 18)

페이지 3:
  광고 2개, 일반 상품 19개
  → 37위~55위 (36 + 19)
```

---

## 🔧 트러블슈팅

### 문제 1: 광고가 필터링되지 않음

```
증상: 광고 상품이 순위에 포함됨

원인:
- 새로운 광고 HTML 패턴
- 선택자가 맞지 않음

해결:
1. 브라우저에서 해당 페이지 HTML 확인
2. 광고 상품의 HTML 구조 분석
3. _is_advertisement() 함수에 새 패턴 추가
```

### 문제 2: 일반 상품이 광고로 오탐됨

```
증상: 일반 상품이 광고로 분류되어 제외됨

원인:
- 클래스명에 'ad' 포함 (예: 'headphone')
- 너무 넓은 범위의 선택자

해결:
1. 정확한 패턴만 사용
2. 'advertisement', 'sponsored' 등 명확한 키워드만
3. 로그 확인하여 오탐 패턴 찾기
```

### 문제 3: 순위가 실제와 다름

```
증상: 프로그램 순위와 실제 순위가 다름

원인:
- 광고 필터링 누락
- 페이지별 상품 수 다름

해결:
1. 네이버 쇼핑에서 수동 확인
2. 광고 개수 카운팅
3. 로그로 광고 필터링 확인
```

---

## 📚 관련 문서

- `src/ranking/checker.py` - 순위 체크 구현
- `REAL_DATA_ANALYSIS.md` - 실제 트래픽 데이터 분석
- `MID_BASED_GUIDE.md` - mid 값 기반 상품 식별

---

**작성일**: 2025-11-01
**핵심**: 광고 제외하고 일반 상품만 카운팅해야 정확한 순위 측정
**구현**: `_is_advertisement()` 함수로 5가지 패턴 체크
