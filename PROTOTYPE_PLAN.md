# 프로토타입 구현 계획

## 목표
**1개 상품, 1개 케이스, 10회 반복 → 순위 변동 검증**

---

## Phase 1: 프로토타입 (1-2일)

### 구현 범위 (최소)
```
✅ 필수 기능만:
  - 상품 URL 직접 열기 (검색 건너뛰기)
  - 스크롤 다운 3-5회
  - 장바구니 버튼 탭
  - 30-60초 체류
  - IP 변경 (비행기모드)

❌ 제외:
  - 검색 자동화 (나중에)
  - 5개 케이스 (1개만)
  - 복잡한 액션 (나중에)
  - 에러 핸들링 (최소만)
```

### 파일 구조
```
Navertrafic/
├── prototype/
│   ├── prototype_browser.py      # Pure ADB 간단 제어
│   ├── prototype_main.py          # 10회 반복 실행
│   ├── prototype_config.json      # 1개 상품 + 좌표
│   └── README.md                  # 실행 방법
```

---

## Step 1: 좌표 찾기 (수동 작업)

### 필요한 좌표
1. **장바구니 버튼** 위치
2. **스크롤 영역** 시작/끝점
3. **뒤로가기 버튼** (필요 시)

### 좌표 찾는 방법

#### 방법 1: ADB Shell (빠름)
```bash
# 화면 해상도 확인
adb shell wm size

# 화면 터치 시 좌표 확인 (개발자 옵션 - 포인터 위치 ON)
# 또는 직접 추정:
# 1080x2400 화면 기준:
#   - 화면 중앙: (540, 1200)
#   - 장바구니 버튼: 보통 하단 (540, 2100)
#   - 스크롤: 중앙에서 위아래 (540, 1600) → (540, 800)
```

#### 방법 2: Appium Inspector (정확)
```bash
# Appium Inspector 실행
# 요소 선택하면 좌표 표시됨
```

### prototype_config.json 예시
```json
{
  "test_product": {
    "id": 1,
    "product_name": "테스트 상품 1",
    "product_url": "https://shopping.naver.com/window-products/12345678",
    "search_keyword": "무선 이어폰",
    "category": "전자기기"
  },
  "screen": {
    "width": 1080,
    "height": 2400
  },
  "coordinates": {
    "cart_button": {
      "x": 540,
      "y": 2100,
      "description": "장바구니 담기 버튼"
    },
    "scroll_start": {
      "x": 540,
      "y": 1600,
      "description": "스크롤 시작점"
    },
    "scroll_end": {
      "x": 540,
      "y": 800,
      "description": "스크롤 끝점"
    }
  },
  "timing": {
    "scroll_duration": 300,
    "wait_after_scroll": 1.0,
    "dwell_time_min": 30,
    "dwell_time_max": 60
  }
}
```

---

## Step 2: prototype_browser.py 구현

### 기능
```python
class PrototypeBrowser:
    """프로토타입용 간단한 브라우저 제어"""

    def __init__(self, controller, config):
        self.controller = controller  # ADBController
        self.config = config

    def open_product_direct(self, product_url):
        """상품 URL 직접 열기"""
        self.controller.open_url(product_url)
        time.sleep(3)  # 페이지 로드 대기

    def scroll_product_page(self, count=3):
        """상품 페이지 스크롤"""
        coords = self.config['coordinates']

        for i in range(count):
            self.controller.swipe(
                coords['scroll_start']['x'],
                coords['scroll_start']['y'],
                coords['scroll_end']['x'],
                coords['scroll_end']['y'],
                duration=self.config['timing']['scroll_duration']
            )
            time.sleep(self.config['timing']['wait_after_scroll'])

    def click_cart_button(self):
        """장바구니 버튼 클릭"""
        coords = self.config['coordinates']['cart_button']
        self.controller.tap(coords['x'], coords['y'])
        time.sleep(1)

    def wait_dwell_time(self):
        """체류 시간 대기"""
        timing = self.config['timing']
        dwell = random.randint(timing['dwell_time_min'], timing['dwell_time_max'])
        log.info(f"체류 중: {dwell}초")
        time.sleep(dwell)

    def execute_simple_scenario(self, product_url):
        """간단한 시나리오 실행"""
        log.info("=== 프로토타입 시나리오 시작 ===")

        # 1. 상품 페이지 열기
        log.info("1. 상품 페이지 열기")
        self.open_product_direct(product_url)

        # 2. 스크롤
        scroll_count = random.randint(3, 5)
        log.info(f"2. 스크롤 {scroll_count}회")
        self.scroll_product_page(scroll_count)

        # 3. 장바구니 클릭
        log.info("3. 장바구니 버튼 클릭")
        self.click_cart_button()

        # 4. 체류
        log.info("4. 체류 시간 대기")
        self.wait_dwell_time()

        # 5. 뒤로가기
        log.info("5. 뒤로가기")
        self.controller.press_back()
        time.sleep(1)

        log.success("=== 시나리오 완료 ===")
```

---

## Step 3: prototype_main.py 구현

### 기능
```python
def run_prototype_test():
    """프로토타입 테스트 실행"""

    # 1. 설정 로드
    with open('prototype/prototype_config.json') as f:
        config = json.load(f)

    product = config['test_product']

    # 2. 초기화
    controller = ADBController()
    browser = PrototypeBrowser(controller, config)
    tracker = RankTracker(product['id'])

    log.info("=== 프로토타입 테스트 시작 ===")
    log.info(f"상품: {product['product_name']}")
    log.info(f"반복 횟수: 10회")

    # 3. 10회 반복
    for iteration in range(1, 11):
        log.info(f"\n{'='*60}")
        log.info(f"Iteration {iteration}/10")
        log.info(f"{'='*60}\n")

        try:
            # Before 순위 체크
            log.info("Before 순위 체크 중...")
            rank_before = check_rank(
                product['search_keyword'],
                str(product['id']),
                max_page=5
            )

            if rank_before:
                log.info(f"현재 순위: {rank_before['absolute_rank']}위")
            else:
                log.warning("순위권 밖 (5페이지 이내 없음)")

            # 트래픽 생성
            log.info("\n트래픽 생성 시작...")
            browser.execute_simple_scenario(product['product_url'])

            # IP 변경
            log.info("\nIP 변경 중...")
            ip_before = controller.get_ip_address()
            controller.toggle_airplane_mode(duration=3)
            controller.wait_for_network(timeout=30)
            ip_after = controller.get_ip_address()

            if ip_before != ip_after:
                log.success(f"IP 변경 완료: {ip_before} → {ip_after}")
            else:
                log.warning("IP 변경 안됨 (동일 네트워크)")

            # After 순위 체크 (30분 후)
            log.info("\n30분 대기 후 순위 재체크...")
            log.info("(프로토타입: 5분만 대기)")
            time.sleep(300)  # 5분만 대기 (프로토타입)

            rank_after = check_rank(
                product['search_keyword'],
                str(product['id']),
                max_page=5
            )

            if rank_after:
                log.info(f"After 순위: {rank_after['absolute_rank']}위")
            else:
                log.warning("순위권 밖")

            # 결과 저장
            tracker.add_record(
                rank_after,
                iteration=iteration,
                test_case_id=1,
                notes=f"프로토타입 테스트 - Iteration {iteration}"
            )

            # 순위 변동 계산
            if rank_before and rank_after:
                change = rank_after['absolute_rank'] - rank_before['absolute_rank']
                if change < 0:
                    log.success(f"✅ 순위 상승: {abs(change)}위 ↑")
                elif change > 0:
                    log.warning(f"⬇️ 순위 하락: {change}위 ↓")
                else:
                    log.info("➡️ 순위 유지")

        except Exception as e:
            log.error(f"Iteration {iteration} 실패: {e}")
            continue

    # 4. 최종 통계
    log.info("\n" + "="*60)
    log.info("프로토타입 테스트 완료!")
    log.info("="*60)

    stats = tracker.get_statistics()
    log.info(f"\n총 기록: {stats.get('total_records', 0)}회")
    log.info(f"평균 순위 변동: {stats.get('average_change', 0):.1f}위")
    log.info(f"최고 순위: {stats.get('best_rank', 0)}위")
    log.info(f"최저 순위: {stats.get('worst_rank', 0)}위")

    # CSV 내보내기
    csv_path = tracker.export_to_csv()
    log.success(f"\n결과 저장: {csv_path}")


if __name__ == "__main__":
    try:
        run_prototype_test()
    except KeyboardInterrupt:
        log.warning("\n사용자에 의해 중단됨")
    except Exception as e:
        log.error(f"프로토타입 실행 실패: {e}")
        raise
```

---

## Phase 2: 검증 (1일)

### 체크리스트
- [ ] 10회 반복 실행 완료
- [ ] 에러 없이 안정적으로 동작
- [ ] 순위 데이터 정상 수집
- [ ] **순위가 실제로 변동하는가?** ⭐

### 검증 기준
```
✅ 성공:
  - 10회 중 5회 이상 순위 상승
  - 평균 2-3위 이상 상승
  - 큰 에러 없이 안정 동작

⚠️ 재검토 필요:
  - 순위 변동 없음 또는 미미함
  - 에러 빈번 발생
  → 전략 수정 필요 (체류시간, 액션 변경 등)

❌ 실패:
  - 순위 하락
  - 네이버 차단 (IP 밴)
  → 근본적 재설계 필요
```

---

## Phase 3: 확장 (1-2주)

### 검증 성공 시 확장 계획

#### 1단계: 케이스 추가
```
CASE_1 (프로토타입) → 검증 완료
→ CASE_2 추가 (리뷰 클릭)
→ CASE_3 추가 (옵션 선택)
→ CASE_4, 5 추가
```

#### 2단계: 상품 확장
```
1개 상품 → 3개 상품
3개 상품 → 10개 상품
```

#### 3단계: 반복 횟수 증가
```
10회 → 30회 → 100회
```

#### 4단계: 자동화 개선
```
Pure ADB → Appium (더 안정적)
좌표 기반 → 요소 인식
```

#### 5단계: 확률 기반 시나리오
```
단일 케이스 → 확률 분포 케이스
그룹 기반 분석 추가
```

---

## 실행 방법

### 1. 준비 작업
```bash
# 1. 테스트 상품 선정
# - 네이버 쇼핑에서 상품 하나 선택
# - 상품 ID 확인 (URL의 숫자)
# - 검색 키워드 확인

# 2. 좌표 확인
# - 개발자 옵션 - 포인터 위치 ON
# - 장바구니 버튼 위치 확인
# - prototype_config.json 수정

# 3. 초기 순위 체크
python -c "
from src.ranking.checker import check_rank
rank = check_rank('검색키워드', '상품ID')
print(f'초기 순위: {rank}')
"
```

### 2. 프로토타입 실행
```bash
# 가상환경 활성화
venv\Scripts\activate

# ADB 연결 확인
adb devices

# 실행
python prototype/prototype_main.py
```

### 3. 결과 확인
```bash
# 순위 히스토리 확인
cat data/rankings/rank_history_1.json

# CSV 확인
open data/results/rank_history_1.csv
```

---

## 예상 소요 시간

```
Day 1:
  - prototype_browser.py 작성 (2시간)
  - prototype_main.py 작성 (2시간)
  - 좌표 확인 및 테스트 (2시간)

Day 2:
  - 10회 반복 실행 (5시간 - 대기시간 포함)
  - 결과 분석 (1시간)
  - 검증 및 개선 (2시간)

총: 2일
```

---

## 주의사항

1. **좌표 정확성**
   - 화면 해상도 다르면 좌표 다름
   - 여러 번 테스트하여 정확한 좌표 확인

2. **네이버 차단 리스크**
   - 10회 정도는 안전
   - IP 변경 확실히 할 것
   - 에러 발생 시 즉시 중단

3. **배터리/발열**
   - 기기 충전 상태 유지
   - 과열 시 휴식

4. **순위 체크 간격**
   - 프로토타입: 5분 대기
   - 본 테스트: 30분 대기 (더 정확)

---

**다음 작업**: prototype_browser.py 구현 시작
