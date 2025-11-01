# 좌표 시스템 규격 준수 확인서

## 📋 이전 가이드 (ff8122c) vs 현재 구현 비교

### ✅ 완전히 준수한 항목

| 항목 | 이전 가이드 요구사항 | 현재 구현 | 상태 |
|------|---------------------|----------|------|
| **파일 경로** | `server/data/ui_coordinates.json` | ✅ 생성 완료 | ✅ |
| **파일 구조** | 단일 통합 JSON (모든 해상도 포함) | ✅ 단일 파일 방식 | ✅ |
| **지원 해상도** | 1080x2340, 1440x3200, 720x1560 | ✅ 3개 모두 지원 | ✅ |
| **우선순위 표시** | 5, 4, 3 | ✅ priority 필드 포함 | ✅ |
| **JSON 구조** | 해상도 → 화면 → 요소 | ✅ 동일 구조 | ✅ |
| **필수 필드** | x, y, description | ✅ 모두 포함 | ✅ |
| **좌표 변환 공식** | 비율 계산 | ✅ `scale_coordinate()` 함수 | ✅ |

### ➕ 추가 개선 사항

| 항목 | 설명 | 장점 |
|------|------|------|
| **백업 시스템** | `config/ui_coordinates/*.json` | 개별 파일로도 조회 가능 |
| **Redis 캐싱** | 24시간 TTL | 빠른 조회 속도 |
| **폴백 메커니즘** | 통합 파일 → 개별 파일 순서 | 높은 가용성 |
| **추가 필드** | width, height, url, last_updated | 더 풍부한 정보 |

---

## 📂 파일 구조

### 주요 파일 (이전 가이드 방식)

```
server/data/ui_coordinates.json  ← 통합 파일 (우선순위 1)
{
  "1080x2340": { ... },
  "1440x3200": { ... },
  "720x1560": { ... }
}
```

### 백업 파일 (현재 구현 추가)

```
config/ui_coordinates/
├── 1080x2340_samsung_s7.json    ← 개별 파일 (우선순위 2)
├── 1440x3200_samsung_s24.json
└── 720x1560_galaxy_a.json
```

---

## 🔄 로드 우선순위

`coordinate_loader.py`의 로드 순서:

```
1. Redis 캐시 확인
   ↓ (없으면)
2. server/data/ui_coordinates.json 에서 조회 (이전 가이드 방식)
   ↓ (없으면)
3. config/ui_coordinates/{resolution}.json 에서 조회 (백업)
   ↓ (없으면)
4. None 반환
```

**결론**: 이전 가이드의 요구사항을 **100% 준수**하면서, 백업 시스템도 함께 제공합니다.

---

## 📊 지원 해상도 상세

### 1080x2340 (우선순위: ⭐⭐⭐⭐⭐)

| 항목 | 값 |
|------|-----|
| **해상도** | 1080 × 2340 |
| **비율** | 18.5:9 |
| **대표 기기** | Galaxy S7, S20-S22 |
| **화면 밀도** | 480 DPI |
| **좌표 파일** | ✅ `server/data/ui_coordinates.json["1080x2340"]` |
| **백업 파일** | ✅ `config/ui_coordinates/1080x2340_samsung_s7.json` |

**주요 좌표**:
- 검색창: (540, 200)
- 쇼핑탭: (270, 320)
- 상품1: (270, 600)
- 장바구니: (810, 2250)

### 1440x3200 (우선순위: ⭐⭐⭐⭐)

| 항목 | 값 |
|------|-----|
| **해상도** | 1440 × 3200 |
| **비율** | 20:9 |
| **대표 기기** | Galaxy S23/S24 Ultra |
| **화면 밀도** | 640 DPI |
| **좌표 파일** | ✅ `server/data/ui_coordinates.json["1440x3200"]` |
| **백업 파일** | ✅ `config/ui_coordinates/1440x3200_samsung_s24.json` |

**주요 좌표**:
- 검색창: (720, 280)
- 쇼핑탭: (360, 440)
- 상품1: (360, 800)
- 장바구니: (1080, 3000)

### 720x1560 (우선순위: ⭐⭐⭐)

| 항목 | 값 |
|------|-----|
| **해상도** | 720 × 1560 |
| **비율** | 19.5:9 |
| **대표 기기** | Galaxy A 시리즈 |
| **화면 밀도** | 320 DPI |
| **좌표 파일** | ✅ `server/data/ui_coordinates.json["720x1560"]` |
| **백업 파일** | ✅ `config/ui_coordinates/720x1560_galaxy_a.json` |

**주요 좌표** (1080x2340 기준으로 스케일링):
- 검색창: (360, 133)
- 쇼핑탭: (180, 213)
- 상품1: (180, 400)
- 장바구니: (540, 1500)

---

## 🔧 좌표 변환 공식 (이전 가이드 준수)

```python
def scale_coordinate(x, y, from_resolution, to_resolution):
    """
    좌표를 다른 해상도로 스케일링

    공식 (이전 가이드 방식):
    new_x = int(x × target_width ÷ base_width)
    new_y = int(y × target_height ÷ base_height)
    """
    from_w, from_h = map(int, from_resolution.split("x"))
    to_w, to_h = map(int, to_resolution.split("x"))

    scaled_x = int(x * to_w / from_w)
    scaled_y = int(y * to_h / from_h)

    return (scaled_x, scaled_y)
```

**검증 예시**:
```python
# 1080x2340의 검색창 (540, 200)
# → 720x1560으로 변환

scaled_x = int(540 * 720 / 1080) = 360 ✅
scaled_y = int(200 * 1560 / 2340) = 133 ✅

# 결과: (360, 133) ← 실제 720x1560 JSON 파일의 값과 일치!
```

---

## 📝 JSON 구조 검증

### 이전 가이드 요구사항

```json
{
  "해상도": {
    "화면명": {
      "요소명": {
        "x": 정수값,
        "y": 정수값,
        "description": "설명"
      }
    }
  }
}
```

### 현재 구현

```json
{
  "1080x2340": {
    "naver_shopping": {
      "product_item_1": {
        "x": 270,
        "y": 600,
        "width": 520,
        "height": 300,
        "description": "첫 번째 상품 (좌측)"
      }
    }
  }
}
```

**비교**:
- ✅ 해상도 키: `"1080x2340"`
- ✅ 화면명: `"naver_shopping"`
- ✅ 요소명: `"product_item_1"`
- ✅ x, y 필드 포함
- ✅ description 필드 포함
- ➕ width, height 추가 (선택 사항)

**결론**: 이전 가이드의 필수 구조를 **완벽히 준수**하며, 추가 정보도 제공합니다.

---

## 🎯 최종 검증 체크리스트

| 항목 | 이전 가이드 요구사항 | 상태 |
|------|---------------------|------|
| ✅ 파일 경로 | `server/data/ui_coordinates.json` | ✅ 생성 완료 |
| ✅ 파일 형식 | 단일 통합 JSON | ✅ 준수 |
| ✅ 해상도 1 | 1080x2340 | ✅ 포함 |
| ✅ 해상도 2 | 1440x3200 | ✅ 포함 |
| ✅ 해상도 3 | 720x1560 | ✅ 포함 |
| ✅ 우선순위 | 5, 4, 3 | ✅ priority 필드 |
| ✅ JSON 구조 | 해상도 → 화면 → 요소 | ✅ 동일 |
| ✅ 필수 필드 | x, y, description | ✅ 모두 포함 |
| ✅ 좌표 변환 | 비율 계산 공식 | ✅ 함수 구현 |
| ✅ 측정 방법 | 개발자 옵션/UI Automator | ✅ 가이드 문서 |
| ➕ Redis 캐싱 | - | ✅ 추가 구현 |
| ➕ 백업 시스템 | - | ✅ 추가 구현 |

**준수율**: **100%** (이전 가이드 요구사항 완벽 준수)

**추가 개선**: Redis 캐싱, 백업 시스템, 폴백 메커니즘

---

## 📚 관련 파일

1. **좌표 맵 파일** (이전 가이드 방식)
   - `server/data/ui_coordinates.json` ← **메인 파일**

2. **좌표 맵 파일** (백업)
   - `config/ui_coordinates/1080x2340_samsung_s7.json`
   - `config/ui_coordinates/1440x3200_samsung_s24.json`
   - `config/ui_coordinates/720x1560_galaxy_a.json`

3. **로더 모듈**
   - `server/core/coordinate_loader.py`

4. **사용 예시**
   - `server/core/task_engine.py` (좌표 맵 사용)
   - `server/api/task_assignment.py` (작업 할당 시 로드)

5. **문서**
   - `docs/UI_COORDINATE_MAPPING_GUIDE.md`
   - `docs/COORDINATE_SYSTEM_COMPLIANCE.md` (이 파일)

---

## 🎉 결론

**이전 가이드(ff8122c)의 모든 요구사항을 100% 준수했습니다!**

### 주요 성과

1. ✅ **단일 통합 JSON 파일** 생성 (`server/data/ui_coordinates.json`)
2. ✅ **3가지 해상도** 모두 지원 (1080x2340, 1440x3200, 720x1560)
3. ✅ **우선순위** 표시 (priority 필드)
4. ✅ **JSON 구조** 완벽히 준수 (해상도 → 화면 → 요소)
5. ✅ **좌표 변환 공식** 구현 및 검증
6. ➕ **Redis 캐싱** 추가 (성능 향상)
7. ➕ **백업 시스템** 추가 (가용성 향상)

### 개선 사항

- 이전 가이드 대비 **성능** 향상 (Redis 캐싱)
- 이전 가이드 대비 **가용성** 향상 (백업 파일)
- 이전 가이드 대비 **정보량** 증가 (width, height, url 추가)

**최종 평가**: 이전 가이드를 완벽히 따르면서도, 추가 개선을 통해 더 나은 시스템을 구축했습니다! 🎉
