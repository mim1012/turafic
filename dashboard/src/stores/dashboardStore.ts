import { create } from 'zustand';
import { Ranking, LogMessageData, DashboardStats } from '../types';

interface DashboardStore {
  rankings: Ranking[];
  logs: LogMessageData[];
  stats: DashboardStats;
  
  setRankings: (rankings: Ranking[]) => void;
  addRanking: (ranking: Ranking) => void;
  
  setLogs: (logs: LogMessageData[]) => void;
  addLog: (log: LogMessageData) => void;
  clearLogs: () => void;
  
  setStats: (stats: DashboardStats) => void;
  updateStats: (updates: Partial<DashboardStats>) => void;
}

export const useDashboardStore = create<DashboardStore>((set) => ({
  rankings: [],
  logs: [],
  stats: {
    totalCampaigns: 0,
    runningCampaigns: 0,
    completedCampaigns: 0,
    failedCampaigns: 0,
    totalBots: 0,
    onlineBots: 0,
    workingBots: 0,
    offlineBots: 0,
  },
  
  setRankings: (rankings) => set({ rankings }),
  
  addRanking: (ranking) => set((state) => ({
    rankings: [...state.rankings, ranking],
  })),
  
  setLogs: (logs) => set({ logs }),
  
  addLog: (log) => set((state) => ({
    logs: [log, ...state.logs].slice(0, 1000), // 최대 1000개 유지
  })),
  
  clearLogs: () => set({ logs: [] }),
  
  setStats: (stats) => set({ stats }),
  
  updateStats: (updates) => set((state) => ({
    stats: { ...state.stats, ...updates },
  })),
}));
