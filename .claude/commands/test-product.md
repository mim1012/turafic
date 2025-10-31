---
description: 특정 상품에 대한 트래픽 테스트 실행
model: claude-3-5-sonnet-20241022
allowed-tools: Bash(python:*), Bash(adb:*), Read, Write, Grep
argument-hint: [product-id] [iterations] [test-type]
---

네이버 쇼핑 상품에 대한 자동화된 트래픽 테스트를 실행합니다.

## 파라미터
- **상품 ID**: $1 (필수)
- **반복 횟수**: $2 (기본값: 10, 최대: 100)
- **테스트 타입**: $3 (A: 네이버 검색, B: 쇼핑 직접, 기본값: A)

## 사전 확인

1. **ADB 연결 확인**
   ```bash
   adb devices
   ```

2. **테스트 상품 정보 로드**
   - @config/test_products.json 에서 상품 $1 검색
   - 키워드, 카테고리, 초기 순위 확인

3. **Appium Server 상태 확인** (자동화 모드가 appium인 경우)
   ```bash
   curl -s http://localhost:4723/status
   ```

## 테스트 실행

```bash
python src/automation/main.py \
  --product-id $1 \
  --iterations $2 \
  --test-type $3 \
  --log-level INFO
```

## 실행 프로세스

각 반복마다:
1. 순위 체크 (Before)
2. 트래픽 생성 작업 수행
   - 케이스 A: 네이버 메인 → 검색 → 쇼핑탭 → 상품
   - 케이스 B: 네이버쇼핑 → 검색 → 상품
3. 사용자 행동 시뮬레이션
   - 자연스러운 스크롤
   - 랜덤 액션 (장바구니/리뷰/문의)
   - 체류 시간 (정규분포 기반)
4. IP 변경 (10회마다 비행기모드 토글)
5. 순위 체크 (After, 30분 후)
6. 결과 저장
7. 다음 반복 전 랜덤 대기 (3~5분)

## 실시간 모니터링

테스트 진행 중 다음 정보를 실시간으로 출력:
```
=== 테스트 진행 상황 ===
상품 ID: $1
진행률: 5/10 (50%)
성공: 4회
실패: 1회 (재시도 완료)
평균 순위 변동: +8위
예상 완료 시간: 2025-01-01 16:30
```

## 에러 핸들링

- **ADB 연결 끊김**: 자동 재연결 (최대 3회)
- **네트워크 타임아웃**: 비행기모드 재토글
- **순위 체크 실패**: 재시도 (최대 5회)
- **크리티컬 에러**: 테스트 일시 중단 후 알림

## 결과 저장

- **로그 파일**: `logs/test_{product_id}_{timestamp}.log`
- **결과 데이터**: `data/results/test_{product_id}_{timestamp}.json`
- **통계 요약**: `data/results/summary_{product_id}_{timestamp}.txt`
