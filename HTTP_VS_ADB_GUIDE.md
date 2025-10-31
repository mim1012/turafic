# HTTP vs ADB 트래픽 생성 방식 비교 가이드

## 📊 두 방식 비교 요약

| 항목 | HTTP 요청 조작 | ADB 실제 기기 제어 |
|------|---------------|-------------------|
| **속도** | ⚡ 매우 빠름 (5-10초/회) | 🐌 느림 (3-4분/회) |
| **확장성** | 🚀 매우 높음 (동시 100개+) | 📱 낮음 (기기당 1개) |
| **탐지 위험** | ⚠️ 높음 (봇 탐지 가능) | ✅ 낮음 (실제 사용자) |
| **구현 난이도** | 💻 중간 (HTTP 지식 필요) | 🔧 쉬움 (좌표만 설정) |
| **비용** | 💰 저렴 (PC만 필요) | 💰💰 높음 (기기 필요) |
| **안정성** | ⚡ 높음 (네트워크만 OK) | 🔋 중간 (발열, 배터리) |
| **권장 용도** | 대량 테스트, 빠른 검증 | 소량 고품질 트래픽 |

---

## 🔥 HTTP 요청 방식 (권장 - 빠른 대량 테스트)

### 작동 원리

```
Python Script
    ↓
requests 라이브러리
    ↓
HTTP 요청 (GET/POST)
    ↓
네이버 쇼핑 서버
```

실제 브라우저 없이 HTTP 요청만으로 트래픽 생성

### 핵심 조작 요소

#### 1. User-Agent 로테이션

```python
# 10개 이상의 실제 기기 User-Agent 사용
user_agents = [
    "Mozilla/5.0 (Linux; Android 13; SM-S911B) ...",  # Samsung Galaxy S23
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4) ...",    # iPhone 14
    # ... 더 많은 다양한 기기
]

# 매 요청마다 랜덤 선택
session.headers['User-Agent'] = random.choice(user_agents)
```

**왜 중요한가?**
- 네이버는 User-Agent로 기기 종류 파악
- 동일 User-Agent 반복 = 봇 의심
- 다양한 기기에서 접속하는 것처럼 보여야 함

#### 2. 쿠키 조작

```python
# 신규 방문자 쿠키
cookies = {
    'page_uid': '1709123456_789012',  # 페이지 고유 ID
    'nx_ssl': 'v2',                    # SSL 버전
    '_naver_usersession_': 'abc123...',# 세션 토큰
}

# 로그인 상태 시뮬레이션
cookies.update({
    'NID_AUT': 'def456...',  # 자동 로그인 토큰
    'NID_SES': 'ghi789...',  # 세션 쿠키
})

# 관심 카테고리 기록
cookies['user_interests'] = 'E001,F001'  # 전자기기, 패션
```

**왜 조작하는가?**
- 쿠키는 사용자의 "과거 행동" 기록
- 로그인 상태 vs 비로그인 = 신뢰도 차이
- 관심 카테고리 = 자연스러운 유입 증명

#### 3. Referer 조작 (유입 경로)

```python
# 네이버 검색에서 유입
headers['Referer'] = 'https://search.naver.com/search.naver?query=무선이어폰'

# 블로그 리뷰에서 유입
headers['Referer'] = 'https://blog.naver.com/abc123/456789'

# 가격비교 사이트에서 유입
headers['Referer'] = 'https://www.danawa.com'
```

**왜 중요한가?**
- Referer = "어디서 왔는지" 알려주는 헤더
- 네이버는 유입 경로별로 가중치 다르게 부여
- 블로그/카페 유입 = 오가닉 트래픽 = 높은 가치

#### 4. 패킷 헤더 커스터마이징

```python
headers = {
    'Accept': 'text/html,application/xhtml+xml,...',
    'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',                          # Do Not Track
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
}
```

**실제 브라우저와 동일한 헤더 = 탐지 회피**

### 장점

1. **속도**: 5-10초/회 (ADB 대비 20배 빠름)
2. **확장성**: PC 1대로 동시 100개 세션 가능
3. **비용**: 별도 기기 불필요
4. **자동화**: 완전 자동, 사람 개입 불필요

### 단점 및 리스크

1. **봇 탐지 위험**
   - 네이버의 봇 탐지 시스템 (Akamai, Cloudflare 등)
   - JavaScript 챌린지 (CAPTCHA 등)
   - IP 밴 가능성

2. **JavaScript 실행 불가**
   - 페이지 로드 후 AJAX 요청 시뮬레이션 어려움
   - 동적 컨텐츠 처리 복잡

3. **세션 관리 복잡**
   - 쿠키 유효 기간 관리
   - 세션 타임아웃 처리

### 봇 탐지 회피 전략

```python
# 1. 요청 간격 랜덤화
time.sleep(random.uniform(2.0, 5.0))

# 2. User-Agent 로테이션 (매 요청)
session.headers['User-Agent'] = UserAgentPool.get_random()

# 3. 세션 분리 (IP 변경 시뮬레이션)
session_id = hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()

# 4. 정규분포 기반 체류 시간
dwell = int(random.gauss(mean=60, std=10))

# 5. 실제 사용자처럼 스크롤 시뮬레이션
# (추가 이미지 요청 등)
```

### 사용 시나리오

- ✅ 100회+ 대량 테스트
- ✅ 다양한 유입 경로 빠른 검증
- ✅ A/B 테스트 (어떤 패턴이 효과적?)
- ✅ 프로토타입 빠른 검증

---

## 📱 ADB 실제 기기 제어 방식 (고품질 트래픽)

### 작동 원리

```
Python Script
    ↓
ADB 명령어
    ↓
Android 기기
    ↓
실제 Chrome 브라우저
    ↓
네이버 쇼핑 서버
```

실제 스마트폰으로 사람처럼 행동

### 장점

1. **100% 실제 사용자 행동**
   - JavaScript 자동 실행
   - 모든 쿠키/세션 자동 처리
   - 봇 탐지 거의 불가능

2. **안정성**
   - 네이버 UI 변경에도 유연
   - IP 밴 위험 거의 없음

3. **고품질 트래픽**
   - 순위 반영 확률 높음
   - 신뢰도 높은 시그널

### 단점

1. **느린 속도**: 3-4분/회
2. **기기 필요**: 기기당 1개 세션
3. **발열/배터리**: 장시간 실행 시 문제
4. **좌표 의존**: 화면 해상도별 조정 필요

### 사용 시나리오

- ✅ 최종 검증 (10-20회 고품질 트래픽)
- ✅ HTTP 방식 차단 시 대체
- ✅ 중요 상품의 확실한 순위 상승

---

## 🎯 추천 전략: 혼합 사용

### Phase 1: HTTP로 빠른 검증 (1-2일)

```bash
# HTTP 방식으로 100회 테스트
python run_comprehensive_test.py --iterations 100
```

**목표:**
- 어떤 시나리오가 효과적인지 파악
- 카테고리별 최적 패턴 발견
- 빠른 A/B 테스트

**예상 결과:**
```
시나리오별 효과:
1. 블로그 리뷰 유입: 개선율 75%, 평균 3.2위 상승 ⭐
2. 가격비교 사이트: 개선율 68%, 평균 2.8위 상승
3. 네이버 검색: 개선율 55%, 평균 1.5위 상승
4. 카테고리 탐색: 개선율 45%, 평균 0.8위 상승
```

### Phase 2: ADB로 확실한 순위 상승 (3-5일)

```bash
# 효과 좋았던 시나리오만 ADB로 실행
# 예: 블로그 리뷰 유입 패턴을 ADB로 재현
cd prototype
python prototype_main.py  # CASE_S3 (비교쇼핑)
```

**목표:**
- HTTP에서 검증된 효과적 패턴을 고품질로 재실행
- 확실한 순위 상승 달성

### Phase 3: 혼합 실행 (지속적)

```
HTTP (80%) : 다양한 유입 경로, 빠른 대량 트래픽
    +
ADB (20%)  : 고품질 핵심 트래픽
```

**이유:**
- HTTP로 "베이스" 트래픽 생성
- ADB로 "확실한" 시그널 추가
- 네이버 입장: 다양한 기기에서 자연스러운 유입

---

## 🛠️ 실행 방법

### HTTP 방식 실행

#### 1. 단독 테스트 (빠른 확인)

```bash
# 1회만 실행하여 동작 확인
python src/automation/http_traffic.py

# 출력:
# [INFO] 페이지 방문: https://shopping.naver.com/...
# [INFO] 응답: 200, 크기: 245678 bytes
# [INFO] 스크롤 시뮬레이션: 추가 리소스 로드
# ✅ 상품 페이지 시뮬레이션 완료
```

#### 2. 고급 시나리오 테스트

```bash
# 카테고리별, 유입경로별 다양한 시나리오
python src/automation/advanced_scenarios.py

# 3가지 테스트 케이스 자동 실행:
# - 네이버 검색 유입
# - 블로그 리뷰 유입
# - 가격비교 사이트 유입
```

#### 3. 종합 테스트 (전체 자동화)

```bash
# config/test_matrix.json 설정 후 실행
python run_comprehensive_test.py

# 옵션:
# --product 0        # 첫 번째 상품만 테스트
# --iterations 50    # 50회만 실행
```

### ADB 방식 실행

```bash
# 1. ADB 연결 확인
adb devices

# 2. 프로토타입 설정
# prototype/prototype_config.json 수정 (상품 URL, 좌표)

# 3. 단독 테스트
cd prototype
python prototype_browser.py

# 4. 전체 실행 (10회)
python prototype_main.py
```

---

## 📋 설정 파일 가이드

### `config/test_matrix.json`

모든 테스트 시나리오, 카테고리 패턴, 유입 경로 정의

#### 중요 섹션:

**1. 테스트 상품 정의**

```json
"test_products": [
  {
    "id": "product_001",
    "product_url": "https://shopping.naver.com/window-products/실제ID",
    "category": "전자기기",
    "search_keyword": "무선이어폰"
  }
]
```

**2. 시나리오 가중치**

```json
"test_scenarios": {
  "SCENARIO_1": {
    "name": "네이버 검색",
    "weight": 0.3  // 30% 확률로 선택
  },
  "SCENARIO_3": {
    "name": "블로그 리뷰 유입",
    "weight": 0.15  // 15% 확률
  }
}
```

**3. 카테고리별 패턴**

```json
"category_patterns": {
  "전자기기": {
    "dwell_time_range": [120, 180],  // 긴 체류
    "scroll_depth_range": [5, 8],     // 깊은 스크롤
    "review_probability": 0.7         // 리뷰 확인 70%
  }
}
```

---

## 📊 결과 분석

### 실행 중 로그

```
[INFO] === 카테고리별 시나리오 실행 ===
[INFO] 카테고리: 전자기기
[INFO] 유입 경로: blog
[INFO] ✅ 쿠키 설정 완료: 8개
[INFO] 📍 유입 경로: https://blog.naver.com...
[INFO] 🔍 경쟁사 비교 진행
[INFO] 🎯 타겟 상품 접근
[INFO] 📜 스크롤: 6회
[INFO] ⏱️ 체류: 145초
[INFO] ⭐ 리뷰 영역 확인
[INFO] ✅ 카테고리 시나리오 완료
```

### 최종 통계

```
=== 시나리오별 효과 ===

1. 블로그 리뷰 유입
   실행: 15회
   개선율: 73.3%
   평균 상승: 3.2위

2. 가격비교 사이트 유입
   실행: 10회
   개선율: 70.0%
   평균 상승: 2.8위

3. 네이버 검색 → 쇼핑탭
   실행: 30회
   개선율: 56.7%
   평균 상승: 1.5위

📊 상세 결과 저장: data/results/comprehensive_test_results.json
```

### JSON 결과 파일

```json
{
  "products": {
    "product_001": {
      "iterations": [
        {
          "iteration": 1,
          "scenario": "SCENARIO_3",
          "scenario_name": "블로그 리뷰 유입",
          "method": "http",
          "rank_before": 52,
          "rank_after": 48,
          "rank_change": -4
        }
      ]
    }
  },
  "scenarios": {
    "SCENARIO_3": {
      "total": 15,
      "success": 15,
      "rank_improvements": 11,
      "total_change": -35
    }
  }
}
```

---

## ⚠️ 주의사항

### HTTP 방식 사용 시

1. **IP 밴 대비**
   - 프록시 사용 권장 (선택적)
   - 요청 간격 충분히 두기 (2-5초)
   - 하루 100회 이상 시 분산 실행

2. **세션 관리**
   - 세션 파일 주기적 삭제 (용량 관리)
   - 오래된 쿠키 자동 정리

3. **에러 핸들링**
   - HTTP 429 (Too Many Requests) 대비
   - CAPTCHA 출현 시 일시 중단

### ADB 방식 사용 시

1. **기기 관리**
   - 발열 모니터링 (과열 시 휴식)
   - 배터리 충전 상태 유지
   - 화면 켜짐 유지 설정

2. **좌표 정확도**
   - 기기별로 좌표 재확인
   - 화면 회전 OFF
   - 글꼴 크기 표준

---

## 🚀 최종 권장 사항

### 초보자

```
1. HTTP 방식부터 시작 (빠른 학습)
2. test_matrix.json 설정 (1개 상품만)
3. 10회 실행 후 결과 확인
4. 효과 있으면 횟수 증가
```

### 중급자

```
1. HTTP 방식으로 100회 실행
2. 시나리오별 효과 분석
3. 최고 효과 시나리오를 ADB로 재현
4. HTTP:ADB = 80:20 혼합
```

### 고급자

```
1. 프록시 로테이션 추가
2. 여러 기기 병렬 실행 (ADB)
3. 시간대별 트래픽 분산
4. 네이버 정책 변경 모니터링
```

---

## 📞 문제 해결

### HTTP 방식이 차단될 때

```
증상: HTTP 403, 429 에러 또는 CAPTCHA

해결:
1. 프록시 사용
2. User-Agent 더 다양화
3. 요청 간격 증가 (5-10초)
4. ADB 방식으로 전환
```

### ADB 방식이 느릴 때

```
해결:
1. 체류 시간 단축 (120초 → 90초)
2. 스크롤 횟수 감소
3. HTTP 방식 병행
4. 여러 기기 동시 사용
```

---

**작성일**: 2025-11-01
**버전**: v1.0
**업데이트**: HTTP 방식 + 카테고리별 패턴 + 종합 테스트 프레임워크
