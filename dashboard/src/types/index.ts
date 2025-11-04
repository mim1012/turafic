// Bot 관련 타입
export interface Bot {
  bot_id: string;
  role: 'leader' | 'follower' | 'rank_checker';
  group_id: string;
  status: 'online' | 'offline' | 'working';
  assigned_campaign_id?: string;
  progress?: number;
  last_seen: string;
  created_at: string;
}

// Campaign 관련 타입
export interface Campaign {
  campaign_id: string;
  product_id: string;
  naver_product_id: string;
  keyword: string;
  test_case_id: string;
  variables: CampaignVariables;
  pattern: any;
  traffic_count: number;
  assigned_bot_id?: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  before_rank?: number;
  after_rank?: number;
  rank_improvement?: number;
  created_at: string;
  completed_at?: string;
}

export interface CampaignVariables {
  Platform: 'PC' | 'Mobile';
  Engagement: 'High' | 'Medium' | 'Low';
  'User-Agent': 'Samsung' | 'LG' | 'Generic';
  'HTTP Headers': 'minimal' | 'standard' | 'full';
  'Page Loading': 'domcontentloaded' | 'networkidle' | 'load';
  'Mouse Movement': 'linear' | 'bezier' | 'human';
  'IP Strategy': 'Per Traffic' | 'Per Session';
}

// Ranking 관련 타입
export interface Ranking {
  ranking_id: number;
  product_id: string;
  keyword: string;
  rank: number;
  page: number;
  position: number;
  campaign_id?: string;
  checked_at: string;
}

// WebSocket 메시지 타입
export type WebSocketMessageType =
  | 'bot_status_update'
  | 'campaign_progress_update'
  | 'rank_check_result'
  | 'log_message'
  | 'error_notification'
  | 'analysis_complete';

export interface WebSocketMessage<T = any> {
  type: WebSocketMessageType;
  timestamp: string;
  data: T;
}

export interface BotStatusUpdateData {
  bot_id: string;
  status: 'online' | 'offline' | 'working';
  assigned_campaign_id?: string;
  progress?: number;
}

export interface CampaignProgressUpdateData {
  campaign_id: string;
  test_case_id: string;
  progress: number;
  rank_improvement?: number;
}

export interface RankCheckResultData {
  product_id: string;
  keyword: string;
  rank: number;
  previous_rank?: number;
  improvement?: number;
}

export interface LogMessageData {
  level: 'INFO' | 'SUCCESS' | 'WARNING' | 'ERROR';
  agent: string;
  message: string;
}

export interface ErrorNotificationData {
  bot_id: string;
  error_type: string;
  message: string;
  severity: 'info' | 'warning' | 'error';
}

export interface AnalysisCompleteData {
  campaign_id: string;
  report_url: string;
  optimal_combination: Partial<CampaignVariables>;
}

// Dashboard 통계 타입
export interface DashboardStats {
  totalCampaigns: number;
  runningCampaigns: number;
  completedCampaigns: number;
  failedCampaigns: number;
  totalBots: number;
  onlineBots: number;
  workingBots: number;
  offlineBots: number;
}

// ANOVA 분석 결과 타입
export interface ANOVAResult {
  variable: string;
  f_value: number;
  p_value: number;
  impact: 'high' | 'medium' | 'low' | 'none';
}

// 리포트 타입
export interface AnalyticsReport {
  campaign_id: string;
  product_id: string;
  keyword: string;
  start_time: string;
  end_time: string;
  before_rank: number;
  after_rank: number;
  rank_improvement: number;
  improvement_percentage: number;
  anova_results: ANOVAResult[];
  optimal_combination: CampaignVariables;
  predicted_rank: number;
  recommendations: string[];
}
