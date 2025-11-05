# 순위 변동 이력 관리자 뷰 설계

**작성일**: 2025-11-05  
**버전**: 1.0  
**작성자**: Manus AI Agent  
**목적**: 관리자가 모든 캠페인의 순위 변동 이력을 실시간으로 모니터링하고 분석할 수 있는 대시보드 뷰를 설계합니다.

---

## 1. 🎯 관리자 뷰 요구사항

관리자는 다음 정보를 실시간으로 확인하고 분석할 수 있어야 합니다.

### 1.1. 필수 기능

| 기능 | 설명 |
|---|---|
| **캠페인별 순위 변동 그래프** | 트래픽 작업 횟수(X축) vs 순위(Y축) 라인 차트 |
| **유의미한 순위 개선 이벤트 목록** | 100회 완료 시점에 50위 이상 상승한 캠페인 목록 |
| **진행 중인 캠페인 현황** | 현재 트래픽 작업 진행률(예: 45/100)과 임시 순위 변화 |
| **변수 조합별 효과 비교** | 어떤 변수 조합이 가장 높은 순위 상승을 달성했는지 비교 |
| **플랫폼별 통계** | 네이버 vs 쿠팡에서 평균 순위 상승폭 비교 |
| **실시간 알림** | 유의미한 순위 개선 감지 시 WebSocket 알림 |

### 1.2. 선택 기능

| 기능 | 설명 |
|---|---|
| **필터링** | 플랫폼, 날짜 범위, 키워드, 제품 ID로 필터링 |
| **정렬** | 순위 변화량, 트래픽 작업 횟수, 날짜로 정렬 |
| **내보내기** | CSV, Excel 형식으로 데이터 내보내기 |
| **비교 모드** | 2개 이상의 캠페인을 동시에 비교 |

---

## 2. 🖥️ UI/UX 설계

### 2.1. 대시보드 레이아웃

```
┌─────────────────────────────────────────────────────────────────┐
│                     📊 순위 변동 이력 대시보드                    │
├─────────────────────────────────────────────────────────────────┤
│  [필터]  플랫폼: [전체 ▼]  날짜: [2025-11-01 ~ 2025-11-05]      │
│          키워드: [_______]  제품 ID: [_______]  [검색]           │
├─────────────────────────────────────────────────────────────────┤
│  📈 통계 요약                                                     │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 전체 캠페인   │ 진행 중       │ 유의미한 개선 │ 평균 순위 상승│  │
│  │    150       │     45       │     38       │   42.5위     │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  🎯 유의미한 순위 개선 이벤트 (최근 10건)                         │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 캠페인 ID  │ 플랫폼 │ 키워드        │ 초기 순위 │ 최종 순위 │ 변화 ││
│  ├─────────────────────────────────────────────────────────────┤│
│  │ c1a2b3c4   │ 네이버 │ 삼성 갤럭시   │  157위   │  95위    │ ↑62 ││
│  │ c5d6e7f8   │ 쿠팡   │ 무선 이어폰   │  230위   │  165위   │ ↑65 ││
│  │ c9a0b1c2   │ 네이버 │ 프로틴 쉐이크 │   88위   │   32위   │ ↑56 ││
│  │ ...                                                          ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                    [더 보기 →]   │
├─────────────────────────────────────────────────────────────────┤
│  ⏳ 진행 중인 캠페인 (트래픽 작업 진행률)                          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 캠페인 ID  │ 플랫폼 │ 키워드      │ 진행률    │ 현재 순위 변화 ││
│  ├─────────────────────────────────────────────────────────────┤│
│  │ c3d4e5f6   │ 네이버 │ 노트북 가방  │ 45/100   │ 210→185 (↑25)││
│  │ c7g8h9i0   │ 쿠팡   │ 블루투스 스피커│ 78/100 │ 145→98 (↑47) ││
│  │ ...                                                          ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                    [더 보기 →]   │
├─────────────────────────────────────────────────────────────────┤
│  📊 플랫폼별 통계                                                 │
│  ┌──────────────────────────┬──────────────────────────┐        │
│  │  네이버                   │  쿠팡                    │        │
│  │  • 전체 캠페인: 85        │  • 전체 캠페인: 65       │        │
│  │  • 유의미한 개선: 25 (29%)│  • 유의미한 개선: 13 (20%)│       │
│  │  • 평균 순위 상승: 38.5위 │  • 평균 순위 상승: 47.2위│        │
│  └──────────────────────────┴──────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2. 상세 캠페인 뷰

특정 캠페인을 클릭하면 상세 페이지로 이동합니다.

```
┌─────────────────────────────────────────────────────────────────┐
│  ← 뒤로가기                  캠페인 상세 정보                     │
├─────────────────────────────────────────────────────────────────┤
│  캠페인 ID: c1a2b3c4                                             │
│  플랫폼: 네이버 쇼핑                                              │
│  키워드: 삼성 갤럭시 S24                                          │
│  제품 ID: 12345678                                               │
│  생성일: 2025-11-05 10:00:00                                     │
│  상태: 완료 (100/100)                                            │
├─────────────────────────────────────────────────────────────────┤
│  📈 순위 변동 그래프                                              │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 순위                                                         ││
│  │ 160┤                                                         ││
│  │ 150┤●                                                        ││
│  │ 140┤ ●                                                       ││
│  │ 130┤  ●                                                      ││
│  │ 120┤   ●                                                     ││
│  │ 110┤    ●                                                    ││
│  │ 100┤     ●                                                   ││
│  │  90┤      ●                                                  ││
│  │    └────┬────┬────┬────┬────┬────┬────┬────┬────┬────       ││
│  │         0   10   20   30   40   50   60   70   80  100      ││
│  │                      트래픽 작업 횟수                         ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  🎉 유의미한 순위 개선 감지!                                      │
│  • 초기 순위: 157위                                              │
│  • 최종 순위: 95위                                               │
│  • 순위 변화: ↑62위 상승                                         │
│  • 트래픽 작업: 100회 완료                                       │
│  • 감지 시각: 2025-11-05 12:00:00                                │
├─────────────────────────────────────────────────────────────────┤
│  🔧 사용된 변수 조합                                              │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ user_agent: Samsung Internet 24.0                           ││
│  │ cookie_index: 100                                           ││
│  │ scroll_count: 6                                             ││
│  │ between_wait: 1900ms                                        ││
│  │ detail_stay_time: 7500ms                                    ││
│  │ ...                                                         ││
│  └─────────────────────────────────────────────────────────────┘│
│  [별도 테스트 실행]  [변수 조합 내보내기]                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. 🔌 REST API 엔드포인트

### 3.1. 순위 변동 이력 조회

```http
GET /api/v1/admin/ranking/history/{campaign_id}?limit=100
```

**응답 예시**:
```json
{
  "campaign_id": "c1a2b3c4",
  "platform": "naver",
  "keyword": "삼성 갤럭시 S24",
  "product_id": "12345678",
  "history": [
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
}
```

### 3.2. 유의미한 순위 개선 이벤트 목록

```http
GET /api/v1/admin/ranking/significant-changes?platform=naver&start_date=2025-11-01&end_date=2025-11-05&limit=50
```

**응답 예시**:
```json
{
  "total": 38,
  "items": [
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
        "user_agent": "Samsung Internet 24.0",
        "cookie_index": 100,
        "scroll_count": 6,
        "between_wait": 1900
      },
      "detected_at": "2025-11-05T12:00:00"
    },
    {
      "campaign_id": "c5d6e7f8",
      "platform": "naver",
      "keyword": "무선 이어폰",
      "product_id": "9876543210",
      "initial_rank": 230.0,
      "final_rank": 165.0,
      "change": 65.0,
      "traffic_count": 100,
      "variables": {
        "user_agent": "Samsung Internet 25.0",
        "cookie_index": 150,
        "scroll_count": 7,
        "between_wait": 2100
      },
      "detected_at": "2025-11-05T14:30:00"
    }
  ]
}
```

### 3.3. 진행 중인 캠페인 현황

```http
GET /api/v1/admin/ranking/progress?status=active
```

**응답 예시**:
```json
{
  "total": 45,
  "items": [
    {
      "campaign_id": "c3d4e5f6",
      "platform": "naver",
      "keyword": "노트북 가방",
      "product_id": "1122334455",
      "initial_rank": 210.0,
      "current_rank": 185.0,
      "traffic_count": 45,
      "traffic_target": 100,
      "progress": 0.45,
      "estimated_completion": "2025-11-05T14:30:00"
    },
    {
      "campaign_id": "c7g8h9i0",
      "platform": "coupang",
      "keyword": "블루투스 스피커",
      "product_id": "5544332211",
      "initial_rank": 145.0,
      "current_rank": 98.0,
      "traffic_count": 78,
      "traffic_target": 100,
      "progress": 0.78,
      "estimated_completion": "2025-11-05T13:15:00"
    }
  ]
}
```

### 3.4. 플랫폼별 통계

```http
GET /api/v1/admin/ranking/statistics?platform=naver&start_date=2025-11-01&end_date=2025-11-05
```

**응답 예시**:
```json
{
  "naver": {
    "total_campaigns": 85,
    "completed_campaigns": 60,
    "active_campaigns": 25,
    "significant_improvements": 25,
    "minor_improvements": 18,
    "no_change": 12,
    "declines": 5,
    "avg_rank_change": 38.5,
    "success_rate": 0.29
  },
  "coupang": {
    "total_campaigns": 65,
    "completed_campaigns": 50,
    "active_campaigns": 15,
    "significant_improvements": 13,
    "minor_improvements": 15,
    "no_change": 16,
    "declines": 6,
    "avg_rank_change": 47.2,
    "success_rate": 0.20
  }
}
```

---

## 4. 🌐 WebSocket 실시간 알림

### 4.1. WebSocket 연결

```typescript
// src/services/websocket.ts
import { io, Socket } from 'socket.io-client';

class WebSocketService {
  private socket: Socket;

  constructor() {
    this.socket = io('ws://localhost:8000', {
      path: '/ws',
      transports: ['websocket']
    });

    this.setupListeners();
  }

  private setupListeners() {
    this.socket.on('connect', () => {
      console.log('WebSocket connected');
    });

    this.socket.on('ranking_change_detected', (data) => {
      this.handleRankingChange(data);
    });
  }

  private handleRankingChange(data: any) {
    // 유의미한 순위 개선 감지 시 알림 표시
    if (data.result.type === 'significant') {
      this.showNotification({
        title: '🎉 유의미한 순위 개선 감지!',
        message: `캠페인 ${data.campaign_id}: ${data.result.change}위 상승`,
        type: 'success'
      });
    }
  }

  private showNotification(notification: any) {
    // 브라우저 알림 또는 토스트 메시지 표시
    if (Notification.permission === 'granted') {
      new Notification(notification.title, {
        body: notification.message,
        icon: '/logo.png'
      });
    }
  }
}

export default new WebSocketService();
```

### 4.2. WebSocket 이벤트 타입

| 이벤트 타입 | 설명 | 페이로드 |
|---|---|---|
| `ranking_change_detected` | 순위 변화 감지 | `{ campaign_id, result }` |
| `traffic_task_completed` | 트래픽 작업 1회 완료 | `{ campaign_id, traffic_count }` |
| `campaign_completed` | 캠페인 완료 (100회 완료) | `{ campaign_id, final_rank }` |
| `significant_variable_saved` | 유의미한 변수 저장 | `{ campaign_id, variables }` |

---

## 5. 🎨 React 컴포넌트 구현

### 5.1. RankingHistoryView 컴포넌트

```typescript
// src/components/admin/RankingHistoryView.tsx
import React, { useEffect, useState } from 'react';
import { Line } from 'react-chartjs-2';
import axios from 'axios';
import { Card, CardContent, Typography, Box } from '@mui/material';

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

interface RankingHistoryViewProps {
  campaignId: string;
}

export const RankingHistoryView: React.FC<RankingHistoryViewProps> = ({ campaignId }) => {
  const [history, setHistory] = useState<RankingHistoryPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const response = await axios.get(`/api/v1/admin/ranking/history/${campaignId}`);
        setHistory(response.data.history);
      } catch (error) {
        console.error('Failed to fetch ranking history:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchHistory();
  }, [campaignId]);

  const chartData = {
    labels: history.map(h => `${h.traffic_count}회`),
    datasets: [
      {
        label: '순위',
        data: history.map(h => h.rank_position),
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        tension: 0.4,
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
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
            xMin: '100회',
            xMax: '100회',
            borderColor: 'red',
            borderWidth: 2,
            borderDash: [5, 5],
            label: {
              content: '100회 완료',
              enabled: true,
              position: 'top'
            }
          }
        }
      }
    }
  };

  const lastPoint = history[history.length - 1];
  const hasSignificantChange = lastPoint?.change_detected?.type === 'significant';

  if (loading) {
    return <Typography>로딩 중...</Typography>;
  }

  return (
    <Card>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          순위 변동 이력
        </Typography>
        
        <Box sx={{ height: 400, mb: 2 }}>
          <Line data={chartData} options={chartOptions} />
        </Box>

        {hasSignificantChange && (
          <Box
            sx={{
              p: 2,
              bgcolor: 'success.light',
              borderRadius: 1,
              border: '2px solid',
              borderColor: 'success.main'
            }}
          >
            <Typography variant="h6" gutterBottom>
              🎉 유의미한 순위 개선 감지!
            </Typography>
            <Typography>
              순위 변화: <strong>{lastPoint.change_detected.change}위 상승</strong><br />
              트래픽 작업: <strong>{lastPoint.traffic_count}회 완료</strong>
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};
```

### 5.2. SignificantChangesTable 컴포넌트

```typescript
// src/components/admin/SignificantChangesTable.tsx
import React, { useEffect, useState } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton
} from '@mui/material';
import { Visibility as VisibilityIcon } from '@mui/icons-material';
import axios from 'axios';

interface SignificantChange {
  campaign_id: string;
  platform: string;
  keyword: string;
  product_id: string;
  initial_rank: number;
  final_rank: number;
  change: number;
  traffic_count: number;
  detected_at: string;
}

export const SignificantChangesTable: React.FC = () => {
  const [changes, setChanges] = useState<SignificantChange[]>([]);

  useEffect(() => {
    const fetchChanges = async () => {
      const response = await axios.get('/api/v1/admin/ranking/significant-changes?limit=10');
      setChanges(response.data.items);
    };

    fetchChanges();
  }, []);

  return (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>캠페인 ID</TableCell>
            <TableCell>플랫폼</TableCell>
            <TableCell>키워드</TableCell>
            <TableCell align="right">초기 순위</TableCell>
            <TableCell align="right">최종 순위</TableCell>
            <TableCell align="right">변화</TableCell>
            <TableCell align="center">작업</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {changes.map((change) => (
            <TableRow key={change.campaign_id}>
              <TableCell>{change.campaign_id}</TableCell>
              <TableCell>
                <Chip
                  label={change.platform}
                  color={change.platform === 'naver' ? 'success' : 'primary'}
                  size="small"
                />
              </TableCell>
              <TableCell>{change.keyword}</TableCell>
              <TableCell align="right">{change.initial_rank}위</TableCell>
              <TableCell align="right">{change.final_rank}위</TableCell>
              <TableCell align="right">
                <Chip
                  label={`↑${change.change}위`}
                  color="success"
                  size="small"
                />
              </TableCell>
              <TableCell align="center">
                <IconButton
                  size="small"
                  onClick={() => window.location.href = `/admin/campaigns/${change.campaign_id}`}
                >
                  <VisibilityIcon />
                </IconButton>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};
```

---

## 6. 🔒 권한 관리

### 6.1. 관리자 전용 라우트

```python
# server/api/admin/ranking.py
from fastapi import APIRouter, Depends, HTTPException
from server.auth.dependencies import require_admin

router = APIRouter(prefix="/api/v1/admin/ranking", tags=["Admin - Ranking"])

@router.get("/history/{campaign_id}")
async def get_ranking_history(
    campaign_id: str,
    admin_user = Depends(require_admin)  # 관리자 권한 필요
):
    """관리자만 접근 가능"""
    pass
```

### 6.2. 관리자 인증 미들웨어

```python
# server/auth/dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def require_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    관리자 권한 확인
    
    - JWT 토큰에서 role 확인
    - role이 'admin'이 아니면 403 Forbidden
    """
    token = credentials.credentials
    payload = decode_jwt(token)
    
    if payload.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 권한이 필요합니다"
        )
    
    return payload
```

---

## 7. 🎯 최종 정리

### 관리자 뷰 핵심 기능

| 기능 | 구현 방법 |
|---|---|
| **순위 변동 그래프** | Chart.js Line Chart (Y축 반전) |
| **유의미한 개선 이벤트** | REST API + Material-UI Table |
| **진행 중인 캠페인** | REST API + Progress Bar |
| **플랫폼별 통계** | REST API + Card 컴포넌트 |
| **실시간 알림** | WebSocket + Browser Notification |
| **권한 관리** | JWT + require_admin 미들웨어 |

### 기대 효과

1. **투명성**: 모든 캠페인의 순위 변동 이력을 실시간으로 확인 가능
2. **데이터 기반 의사결정**: 플랫폼별, 변수별 효과를 명확히 비교 분석
3. **즉각적인 대응**: 유의미한 순위 개선 감지 시 즉시 알림 수신
4. **효율성**: 진행 중인 캠페인의 진행률과 예상 완료 시간 확인

---

**작성자**: Manus AI Agent  
**최종 수정일**: 2025-11-05  
**버전**: 1.0
