import { useEffect } from 'react';
import { websocketService } from '../services/websocket';
import { useBotStore } from '../stores/botStore';
import { useCampaignStore } from '../stores/campaignStore';
import { useDashboardStore } from '../stores/dashboardStore';
import {
  WebSocketMessage,
  BotStatusUpdateData,
  CampaignProgressUpdateData,
  RankCheckResultData,
  LogMessageData,
  ErrorNotificationData,
  AnalysisCompleteData,
} from '../types';

export const useWebSocket = () => {
  const { updateBot } = useBotStore();
  const { updateCampaign } = useCampaignStore();
  const { addRanking, addLog } = useDashboardStore();

  useEffect(() => {
    // WebSocket 연결
    websocketService.connect();

    // 메시지 핸들러 등록
    const unsubscribe = websocketService.onMessage((message: WebSocketMessage) => {
      switch (message.type) {
        case 'bot_status_update': {
          const data = message.data as BotStatusUpdateData;
          updateBot(data.bot_id, {
            status: data.status,
            assigned_campaign_id: data.assigned_campaign_id,
            progress: data.progress,
          });
          break;
        }

        case 'campaign_progress_update': {
          const data = message.data as CampaignProgressUpdateData;
          updateCampaign(data.campaign_id, {
            rank_improvement: data.rank_improvement,
          });
          break;
        }

        case 'rank_check_result': {
          const data = message.data as RankCheckResultData;
          addRanking({
            ranking_id: Date.now(),
            product_id: data.product_id,
            keyword: data.keyword,
            rank: data.rank,
            page: Math.floor((data.rank - 1) / 40) + 1,
            position: ((data.rank - 1) % 40) + 1,
            checked_at: message.timestamp,
          });
          
          // 로그에도 추가
          addLog({
            level: 'SUCCESS',
            agent: 'Monitoring',
            message: `순위 체크 완료: ${data.keyword} - ${data.rank}위${
              data.improvement ? ` (${data.improvement > 0 ? '↑' : '↓'}${Math.abs(data.improvement)}위)` : ''
            }`,
          });
          break;
        }

        case 'log_message': {
          const data = message.data as LogMessageData;
          addLog(data);
          break;
        }

        case 'error_notification': {
          const data = message.data as ErrorNotificationData;
          addLog({
            level: 'ERROR',
            agent: data.bot_id,
            message: `[${data.error_type}] ${data.message}`,
          });
          break;
        }

        case 'analysis_complete': {
          const data = message.data as AnalysisCompleteData;
          addLog({
            level: 'SUCCESS',
            agent: 'Analytics',
            message: `분석 완료: ${data.campaign_id}`,
          });
          break;
        }

        default:
          console.warn('[WebSocket] 알 수 없는 메시지 타입:', message.type);
      }
    });

    // 컴포넌트 언마운트 시 정리
    return () => {
      unsubscribe();
      websocketService.disconnect();
    };
  }, [updateBot, updateCampaign, addRanking, addLog]);

  return {
    isConnected: websocketService.isConnected(),
    send: websocketService.send.bind(websocketService),
  };
};
