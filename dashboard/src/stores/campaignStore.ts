import { create } from 'zustand';
import { Campaign } from '../types';

interface CampaignStore {
  campaigns: Campaign[];
  setCampaigns: (campaigns: Campaign[]) => void;
  updateCampaign: (campaignId: string, updates: Partial<Campaign>) => void;
  addCampaign: (campaign: Campaign) => void;
  removeCampaign: (campaignId: string) => void;
  getCampaignsByStatus: (status: Campaign['status']) => Campaign[];
  getRunningCampaigns: () => Campaign[];
  getCompletedCampaigns: () => Campaign[];
  getFailedCampaigns: () => Campaign[];
}

export const useCampaignStore = create<CampaignStore>((set, get) => ({
  campaigns: [],
  
  setCampaigns: (campaigns) => set({ campaigns }),
  
  updateCampaign: (campaignId, updates) => set((state) => ({
    campaigns: state.campaigns.map((campaign) =>
      campaign.campaign_id === campaignId ? { ...campaign, ...updates } : campaign
    ),
  })),
  
  addCampaign: (campaign) => set((state) => ({
    campaigns: [...state.campaigns, campaign],
  })),
  
  removeCampaign: (campaignId) => set((state) => ({
    campaigns: state.campaigns.filter((campaign) => campaign.campaign_id !== campaignId),
  })),
  
  getCampaignsByStatus: (status) => {
    return get().campaigns.filter((campaign) => campaign.status === status);
  },
  
  getRunningCampaigns: () => {
    return get().campaigns.filter((campaign) => campaign.status === 'running');
  },
  
  getCompletedCampaigns: () => {
    return get().campaigns.filter((campaign) => campaign.status === 'completed');
  },
  
  getFailedCampaigns: () => {
    return get().campaigns.filter((campaign) => campaign.status === 'failed');
  },
}));
