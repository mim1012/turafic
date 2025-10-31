---
description: 상품 순위를 체크하고 현재 위치 확인
model: claude-3-5-sonnet-20241022
allowed-tools: Bash(python:*), Read, Grep, Glob
argument-hint: [product-id] [keyword]
---

네이버 쇼핑 상품 순위를 체크합니다.

## 파라미터
- **상품 ID**: $1 (예: 12345678)
- **검색 키워드**: $2 (예: "무선 이어폰")

## 실행 단계

1. **테스트 상품 데이터 확인**
   - @config/test_products.json 에서 상품 정보 로드
   - 상품 ID $1 로 검색

2. **순위 체크 스크립트 실행**
   ```bash
   python src/ranking/checker.py --product-id $1 --keyword "$2"
   ```

3. **결과 분석**
   - 현재 페이지 번호
   - 페이지 내 위치
   - 절대 순위 계산: (페이지-1) × 40 + 위치
   - 이전 순위와 비교 (있는 경우)

4. **데이터 저장**
   - `data/rankings/` 폴더에 JSON 형식으로 저장
   - 파일명: `rank_{product_id}_{timestamp}.json`

## 출력 형식

```
=== 순위 체크 결과 ===
상품 ID: $1
키워드: "$2"
현재 순위: 페이지 3, 위치 12 (절대 순위: 92위)
이전 순위: 페이지 4, 위치 8 (절대 순위: 128위)
변동: ↑ 36위 상승
체크 시간: 2025-01-01 12:00:00
```

## 에러 핸들링
- 상품을 찾을 수 없는 경우: "순위권 밖 (100위 이상)" 표시
- 네트워크 오류: 최대 3회 재시도
- 크롤링 차단: User-Agent 변경 후 재시도
