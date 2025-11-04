import axios from 'axios';
import { Bot, Campaign, Ranking, AnalyticsReport, DashboardStats } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// 에러 핸들링
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('[API Error]', error);
    return Promise.reject(error);
  }
);

// Bot API
export const botAPI = {
  getAll: async (): Promise<Bot[]> => {
    const response = await apiClient.get('/bots');
    return response.data;
  },
  
  getById: async (botId: string): Promise<Bot> => {
    const response = await apiClient.get(`/bots/${botId}`);
    return response.data;
  },
  
  register: async (bot: Partial<Bot>): Promise<Bot> => {
    const response = await apiClient.post('/bots/register', bot);
    return response.data;
  },
};

// Campaign API
export const campaignAPI = {
  getAll: async (): Promise<Campaign[]> => {
    const response = await apiClient.get('/campaigns');
    return response.data;
  },
  
  getById: async (campaignId: string): Promise<Campaign> => {
    const response = await apiClient.get(`/campaigns/${campaignId}`);
    return response.data;
  },
  
  create: async (campaign: Partial<Campaign>): Promise<Campaign> => {
    const response = await apiClient.post('/campaigns/create', campaign);
    return response.data;
  },
};

// Ranking API
export const rankingAPI = {
  check: async (productId: string, keyword: string): Promise<Ranking> => {
    const response = await apiClient.get('/rank/check', {
      params: { product_id: productId, keyword },
    });
    return response.data;
  },
  
  getHistory: async (productId: string): Promise<Ranking[]> => {
    const response = await apiClient.get(`/rank/history/${productId}`);
    return response.data;
  },
};

// Analytics API
export const analyticsAPI = {
  getReport: async (campaignId: string): Promise<AnalyticsReport> => {
    const response = await apiClient.get(`/analytics/report/${campaignId}`);
    return response.data;
  },
  
  analyzeCampaign: async (campaignId: string): Promise<AnalyticsReport> => {
    const response = await apiClient.post('/analytics/analyze_campaign', {
      campaign_id: campaignId,
    });
    return response.data;
  },
};

// Dashboard API
export const dashboardAPI = {
  getStats: async (): Promise<DashboardStats> => {
    const response = await apiClient.get('/dashboard/stats');
    return response.data;
  },
};

export default apiClient;
