import { create } from 'zustand';
import { Bot } from '../types';

interface BotStore {
  bots: Bot[];
  setBots: (bots: Bot[]) => void;
  updateBot: (botId: string, updates: Partial<Bot>) => void;
  addBot: (bot: Bot) => void;
  removeBot: (botId: string) => void;
  getBotsByGroup: (groupId: string) => Bot[];
  getBotsByStatus: (status: Bot['status']) => Bot[];
  getOnlineBots: () => Bot[];
  getWorkingBots: () => Bot[];
  getOfflineBots: () => Bot[];
}

export const useBotStore = create<BotStore>((set, get) => ({
  bots: [],
  
  setBots: (bots) => set({ bots }),
  
  updateBot: (botId, updates) => set((state) => ({
    bots: state.bots.map((bot) =>
      bot.bot_id === botId ? { ...bot, ...updates } : bot
    ),
  })),
  
  addBot: (bot) => set((state) => ({
    bots: [...state.bots, bot],
  })),
  
  removeBot: (botId) => set((state) => ({
    bots: state.bots.filter((bot) => bot.bot_id !== botId),
  })),
  
  getBotsByGroup: (groupId) => {
    return get().bots.filter((bot) => bot.group_id === groupId);
  },
  
  getBotsByStatus: (status) => {
    return get().bots.filter((bot) => bot.status === status);
  },
  
  getOnlineBots: () => {
    return get().bots.filter((bot) => bot.status === 'online' || bot.status === 'working');
  },
  
  getWorkingBots: () => {
    return get().bots.filter((bot) => bot.status === 'working');
  },
  
  getOfflineBots: () => {
    return get().bots.filter((bot) => bot.status === 'offline');
  },
}));
