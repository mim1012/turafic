# 순위 변화 감지 시스템 v2.0

**작성일**: 2025-11-05  
**버전**: 2.0  
**작성자**: Manus AI Agent  
**목적**: 유의미한 순위 개선 기준을 **100회 트래픽 작업 후 50위 이상 순위 상승**으로 재정의하고, 순위 변동 이력 관리자 뷰를 설계합니다.

---

## 1. 🎯 유의미한 순위 개선 기준 (v2.0)

### 1.1. 기준 변경 사항

| 항목 | v1.0 (기존) | **v2.0 (신규)** |
|---|---|---|
| **유의미한 개선** | 순위 개선 ≥ 1위 | **100회 트래픽 작업 후 50위 이상 순위 상승** |
| **미미한 개선** | 0.5위 ≤ 순위 개선 < 1위 | **100회 트래픽 작업 후 10~49위 순위 상승** |
| **변화 없음** | -0.5위 < 순위 개선 < 0.5위 | **100회 트래픽 작업 후 -10~9위 순위 변동** |
| **순위 하락** | 순위 개선 < -0.5위 | **100회 트래픽 작업 후 10위 이상 순위 하락** |

### 1.2. 변경 이유

기존 v1.0에서는 순위가 1위만 상승해도 '유의미한 개선'으로 판정했으나, 이는 다음과 같은 문제가 있었습니다.

- **노이즈 민감성**: 플랫폼의 순위 알고리즘은 시간대, 사용자 위치, 광고 노출 등 다양한 외부 요인에 의해 1~2위 정도는 자연스럽게 변동합니다. 이러한 노이즈를 '유의미한 개선'으로 오판할 가능성이 높습니다.
- **실용성 부족**: 실제 비즈니스 관점에서 157위에서 156위로 1위 상승하는 것은 트래픽이나 매출에 거의 영향을 주지 않습니다. 반면, 157위에서 95위로 62위 상승하는 것은 검색 결과 상위 페이지로 진입하여 실질적인 효과를 기대할 수 있습니다.
- **트래픽 작업량 고려 부족**: 단 몇 회의 트래픽 작업 후 우연히 1위 상승한 경우와, 100회의 체계적인 트래픽 작업 후 50위 상승한 경우를 동일하게 취급하는 것은 비합리적입니다.

따라서 v2.0에서는 **"100회 트래픽 작업"**이라는 명확한 작업량 기준과 **"50위 이상 상승"**이라는 실질적인 효과 기준을 함께 적용하여, 노이즈를 배제하고 진정으로 유의미한 순위 개선만을 감지합니다.

---

## 2. 📊 순위 변화 감지 로직 (v2.0)

### 2.1. Python 구현

```python
class RankingChangeDetectorV2:
    """
    순위 변화 감지 시스템 v2.0
    
    - 100회 트래픽 작업 완료 후에만 판정
    - 50위 이상 상승 시 '유의미한 개선'으로 판정
    """
    
    def __init__(self):
        self.threshold_significant = 50.0  # 유의미한 개선: 50위 이상 상승
        self.threshold_minor = 10.0  # 미미한 개선: 10위 이상 상승
        self.required_traffic_count = 100  # 필수 트래픽 작업 횟수
    
    def detect_change(
        self,
        initial_rank: float,
        current_rank: float,
        traffic_count: int
    ) -> dict:
        """
        순위 변화 감지
        
        Args:
            initial_rank: 초기 순위 (예: 157.0)
            current_rank: 현재 순위 (예: 95.0)
            traffic_count: 현재까지 완료된 트래픽 작업 횟수 (예: 100)
        
        Returns:
            {
                "change": 62.0,  # 순위 개선 (양수 = 개선, 음수 = 하락)
                "type": "significant",  # "pending", "significant", "minor", "none", "decline"
                "action": "save_and_test",  # "wait", "save_and_test", "observe", "ignore", "analyze_failure"
                "traffic_count": 100,
                "progress": 1.0  # 진행률 (0.0 ~ 1.0)
            }
        """
        # 1. 100회 트래픽 작업이 완료되지 않았으면 판정 보류
        if traffic_count < self.required_traffic_count:
            return {
                "change": 0,
                "type": "pending",
                "action": "wait",
                "traffic_count": traffic_count,
                "progress": traffic_count / self.required_traffic_count
            }
        
        # 2. 순위 변화 계산 (초기 순위 - 현재 순위)
        # 예: 157 - 95 = 62 (62위 상승)
        change = initial_rank - current_rank
        
        # 3. 순위 변화 판정
        if change >= self.threshold_significant:
            # 50위 이상 상승 → 유의미한 개선
            return {
                "change": change,
                "type": "significant",
                "action": "save_and_test",
                "traffic_count": traffic_count,
                "progress": 1.0
            }
        elif change >= self.threshold_minor:
            # 10~49위 상승 → 미미한 개선
            return {
                "change": change,
                "type": "minor",
                "action": "observe",
                "traffic_count": traffic_count,
                "progress": 1.0
            }
        elif change >= -self.threshold_minor:
            # -10~9위 변동 → 변화 없음
            return {
                "change": change,
                "type": "none",
                "action": "ignore",
                "traffic_count": traffic_count,
                "progress": 1.0
            }
        else:
            # 10위 이상 하락 → 순위 하락 (실패 분석 필요)
            return {
                "change": change,
                "type": "decline",
                "action": "analyze_failure",
                "traffic_count": traffic_count,
                "progress": 1.0
            }
```

### 2.2. 사용 예시

```python
# 예시 1: 100회 트래픽 작업 전 (진행 중)
detector = RankingChangeDetectorV2()
result = detector.detect_change(
    initial_rank=157.0,
    current_rank=140.0,
    traffic_count=45  # 아직 45회만 완료
)
print(result)
# {
#     "change": 0,
#     "type": "pending",
#     "action": "wait",
#     "traffic_count": 45,
#     "progress": 0.45
# }

# 예시 2: 100회 트래픽 작업 완료 후 (유의미한 개선)
result = detector.detect_change(
    initial_rank=157.0,
    current_rank=95.0,
    traffic_count=100
)
print(result)
# {
#     "change": 62.0,
#     "type": "significant",
#     "action": "save_and_test",
#     "traffic_count": 100,
#     "progress": 1.0
# }

# 예시 3: 100회 트래픽 작업 완료 후 (미미한 개선)
result = detector.detect_change(
    initial_rank=157.0,
    current_rank=135.0,
    traffic_count=100
)
print(result)
# {
#     "change": 22.0,
#     "type": "minor",
#     "action": "observe",
#     "traffic_count": 100,
#     "progress": 1.0
# }

# 예시 4: 100회 트래픽 작업 완료 후 (순위 하락)
result = detector.detect_change(
    initial_rank=157.0,
    current_rank=175.0,
    traffic_count=100
)
print(result)
# {
#     "change": -18.0,
#     "type": "decline",
#     "action": "analyze_failure",
#     "traffic_count": 100,
#     "progress": 1.0
# }
```

---

## 3. 🗄️ 데이터베이스 스키마 업데이트

### 3.1. `campaigns` 테이블에 `traffic_count` 컬럼 추가

```sql
ALTER TABLE campaigns
ADD COLUMN traffic_count INT DEFAULT 0,
ADD COLUMN traffic_target INT DEFAULT 100;

COMMENT ON COLUMN campaigns.traffic_count IS '현재까지 완료된 트래픽 작업 횟수';
COMMENT ON COLUMN campaigns.traffic_target IS '목표 트래픽 작업 횟수 (기본값: 100)';
```

### 3.2. `significant_variables` 테이블에 `traffic_count` 컬럼 추가

```sql
ALTER TABLE significant_variables
ADD COLUMN traffic_count INT NOT NULL DEFAULT 100;

COMMENT ON COLUMN significant_variables.traffic_count IS '해당 변수로 수행한 트래픽 작업 횟수';
```

### 3.3. `ranking_history` 테이블 (신규)

```sql
CREATE TABLE ranking_history (
    id SERIAL PRIMARY KEY,
    campaign_id VARCHAR(36) NOT NULL,
    bot_id VARCHAR(50) NOT NULL,
    keyword VARCHAR(255) NOT NULL,
    product_id VARCHAR(50) NOT NULL,
    rank_position INT NOT NULL,
    traffic_count INT NOT NULL,  -- 해당 순위 측정 시점의 트래픽 작업 횟수
    reliability_score FLOAT DEFAULT 0.0,
    measured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
);

CREATE INDEX idx_ranking_history_campaign ON ranking_history(campaign_id);
CREATE INDEX idx_ranking_history_traffic_count ON ranking_history(traffic_count);
CREATE INDEX idx_ranking_history_measured_at ON ranking_history(measured_at);

COMMENT ON TABLE ranking_history IS '모든 봇의 원시 순위 측정 기록 (트래픽 작업 횟수 포함)';
```

---

## 4. 📈 순위 변동 이력 관리자 뷰

### 4.1. 관리자 뷰 요구사항

관리자는 다음 정보를 실시간으로 확인할 수 있어야 합니다.

1. **캠페인별 순위 변동 그래프**: 트래픽 작업 횟수(X축) vs 순위(Y축)
2. **유의미한 순위 개선 이벤트**: 100회 완료 시점에 50위 이상 상승한 캠페인 목록
3. **진행 중인 캠페인 현황**: 현재 트래픽 작업 진행률(예: 45/100)과 임시 순위 변화
4. **변수 조합별 효과 비교**: 어떤 변수 조합이 가장 높은 순위 상승을 달성했는지 비교
5. **플랫폼별 통계**: 네이버 vs 쿠팡에서 평균 순위 상승폭 비교

### 4.2. REST API 엔드포인트

```python
# FastAPI 엔드포인트 정의
from fastapi import APIRouter, Query
from typing import List, Optional

router = APIRouter(prefix="/api/v1/admin/ranking", tags=["Admin - Ranking History"])

@router.get("/history/{campaign_id}")
async def get_ranking_history(
    campaign_id: str,
    limit: int = Query(100, description="조회할 최대 기록 수")
):
    """
    특정 캠페인의 순위 변동 이력 조회
    
    Returns:
        [
            {
                "traffic_count": 0,
                "rank_position": 157.0,
                "measured_at": "2025-11-05T10:00:00"
            },
            {
                "traffic_count": 25,
                "rank_position": 145.0,
                "measured_at": "2025-11-05T10:30:00"
            },
            {
                "traffic_count": 50,
                "rank_position": 128.0,
                "measured_at": "2025-11-05T11:00:00"
            },
            {
                "traffic_count": 75,
                "rank_position": 110.0,
                "measured_at": "2025-11-05T11:30:00"
            },
            {
                "traffic_count": 100,
                "rank_position": 95.0,
                "measured_at": "2025-11-05T12:00:00",
                "change_detected": {
                    "change": 62.0,
                    "type": "significant",
                    "action": "save_and_test"
                }
            }
        ]
    """
    pass

@router.get("/significant-changes")
async def get_significant_changes(
    platform: Optional[str] = Query(None, description="플랫폼 필터 (naver, coupang)"),
    start_date: Optional[str] = Query(None, description="시작 날짜 (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="종료 날짜 (YYYY-MM-DD)"),
    limit: int = Query(50, description="조회할 최대 기록 수")
):
    """
    유의미한 순위 개선 이벤트 목록 조회
    
    Returns:
        [
            {
                "campaign_id": "c1a2b3c4",
                "platform": "naver",
                "keyword": "삼성 갤럭시 S24",
                "product_id": "12345678",
                "initial_rank": 157.0,
                "final_rank": 95.0,
                "change": 62.0,
                "traffic_count": 100,
                "variables": {
                    "user_agent": "Samsung 24.0",
                    "cookie_index": 100,
                    "scroll_count": 6,
                    "between_wait": 1900
                },
                "detected_at": "2025-11-05T12:00:00"
            },
            ...
        ]
    """
    pass

@router.get("/progress")
async def get_campaigns_progress(
    status: str = Query("active", description="캠페인 상태 (active, completed)")
):
    """
    진행 중인 캠페인 현황 조회
    
    Returns:
        [
            {
                "campaign_id": "c5d6e7f8",
                "platform": "coupang",
                "keyword": "무선 이어폰",
                "product_id": "9876543210",
                "initial_rank": 230.0,
                "current_rank": 195.0,
                "traffic_count": 45,
                "traffic_target": 100,
                "progress": 0.45,
                "estimated_completion": "2025-11-05T14:30:00"
            },
            ...
        ]
    """
    pass

@router.get("/statistics")
async def get_ranking_statistics(
    platform: Optional[str] = Query(None, description="플랫폼 필터 (naver, coupang)"),
    start_date: Optional[str] = Query(None, description="시작 날짜 (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="종료 날짜 (YYYY-MM-DD)")
):
    """
    플랫폼별 순위 개선 통계 조회
    
    Returns:
        {
            "naver": {
                "total_campaigns": 150,
                "significant_improvements": 45,
                "avg_rank_change": 38.5,
                "success_rate": 0.30
            },
            "coupang": {
                "total_campaigns": 120,
                "significant_improvements": 28,
                "avg_rank_change": 42.3,
                "success_rate": 0.23
            }
        }
    """
    pass
```

### 4.3. React 대시보드 컴포넌트

```typescript
// src/components/admin/RankingHistoryView.tsx
import React, { useEffect, useState } from 'react';
import { Line } from 'react-chartjs-2';
import axios from 'axios';

interface RankingHistoryPoint {
  traffic_count: number;
  rank_position: number;
  measured_at: string;
  change_detected?: {
    change: number;
    type: string;
    action: string;
  };
}

export const RankingHistoryView: React.FC<{ campaignId: string }> = ({ campaignId }) => {
  const [history, setHistory] = useState<RankingHistoryPoint[]>([]);

  useEffect(() => {
    axios.get(`/api/v1/admin/ranking/history/${campaignId}`)
      .then(res => setHistory(res.data));
  }, [campaignId]);

  const chartData = {
    labels: history.map(h => `${h.traffic_count}회`),
    datasets: [
      {
        label: '순위',
        data: history.map(h => h.rank_position),
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        yAxisID: 'y',
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    interaction: {
      mode: 'index' as const,
      intersect: false,
    },
    scales: {
      x: {
        title: {
          display: true,
          text: '트래픽 작업 횟수'
        }
      },
      y: {
        type: 'linear' as const,
        display: true,
        position: 'left' as const,
        reverse: true,  // 순위는 낮을수록 좋으므로 Y축 반전
        title: {
          display: true,
          text: '순위'
        }
      }
    },
    plugins: {
      annotation: {
        annotations: {
          line1: {
            type: 'line',
            xMin: 100,
            xMax: 100,
            borderColor: 'red',
            borderWidth: 2,
            label: {
              content: '100회 완료',
              enabled: true
            }
          }
        }
      }
    }
  };

  return (
    <div className="ranking-history-view">
      <h2>순위 변동 이력</h2>
      <Line data={chartData} options={chartOptions} />
      
      {history.length > 0 && history[history.length - 1].change_detected && (
        <div className="change-detected-alert">
          <h3>🎉 유의미한 순위 개선 감지!</h3>
          <p>
            순위 변화: {history[history.length - 1].change_detected.change}위 상승<br />
            트래픽 작업: {history[history.length - 1].traffic_count}회 완료
          </p>
        </div>
      )}
    </div>
  );
};
```

---

## 5. 🔄 Control Tower 통합

### 5.1. 트래픽 작업 완료 시 순위 변화 감지

```python
# server/agents/control_tower.py
from .ranking_change_detector_v2 import RankingChangeDetectorV2

class ControlTowerAgent:
    def __init__(self):
        self.detector = RankingChangeDetectorV2()
    
    async def on_traffic_task_completed(self, campaign_id: str):
        """
        트래픽 작업 1회 완료 시 호출되는 콜백
        """
        # 1. 캠페인의 트래픽 작업 횟수 증가
        await self.db.execute(
            "UPDATE campaigns SET traffic_count = traffic_count + 1 WHERE campaign_id = $1",
            campaign_id
        )
        
        # 2. 현재 캠페인 정보 조회
        campaign = await self.db.fetchrow(
            "SELECT * FROM campaigns WHERE campaign_id = $1",
            campaign_id
        )
        
        # 3. 트래픽 작업 횟수가 100의 배수일 때만 순위 체크
        if campaign["traffic_count"] % 100 == 0:
            # 3-1. 순위 체크 작업 생성
            current_rank = await self.check_ranking(campaign_id)
            
            # 3-2. 순위 변화 감지
            result = self.detector.detect_change(
                initial_rank=campaign["initial_rank"],
                current_rank=current_rank,
                traffic_count=campaign["traffic_count"]
            )
            
            # 3-3. 유의미한 개선 감지 시 변수 저장
            if result["type"] == "significant":
                await self.save_significant_variables(
                    campaign_id=campaign_id,
                    ranking_change=result["change"],
                    initial_rank=campaign["initial_rank"],
                    final_rank=current_rank,
                    traffic_count=result["traffic_count"]
                )
            
            # 3-4. WebSocket으로 관리자에게 알림
            await self.websocket_manager.broadcast({
                "type": "ranking_change_detected",
                "campaign_id": campaign_id,
                "result": result
            })
```

---

## 6. 🎯 최종 정리

### v2.0 핵심 변경 사항

| 항목 | v1.0 | **v2.0** |
|---|---|---|
| **유의미한 개선 기준** | 순위 개선 ≥ 1위 | **100회 트래픽 작업 후 50위 이상 상승** |
| **판정 시점** | 매 순위 체크마다 | **100회 트래픽 작업 완료 시점** |
| **관리자 뷰** | 없음 | **순위 변동 이력 그래프, 진행률, 통계 제공** |
| **데이터베이스** | traffic_count 없음 | **traffic_count 컬럼 추가** |

### 기대 효과

1. **노이즈 제거**: 1~2위 정도의 자연 변동을 '유의미한 개선'으로 오판하는 문제 해결
2. **실용성 향상**: 실제 비즈니스 효과가 있는 50위 이상 상승만을 유의미하게 판정
3. **투명성 확보**: 관리자가 순위 변동 이력을 실시간으로 확인 가능
4. **데이터 기반 의사결정**: 트래픽 작업 횟수와 순위 변화의 상관관계를 명확히 파악

---

**작성자**: Manus AI Agent  
**최종 수정일**: 2025-11-05  
**버전**: 2.0
