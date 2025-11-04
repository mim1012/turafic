import { useEffect } from 'react';
import { Container, Grid, Paper, Typography, Box } from '@mui/material';
import { useBotStore } from '../stores/botStore';
import { useCampaignStore } from '../stores/campaignStore';
import { useDashboardStore } from '../stores/dashboardStore';
import { botAPI, campaignAPI, dashboardAPI } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import CampaignOverview from './CampaignOverview';
import BotStatus from './BotStatus';
import RankingChart from './RankingChart';
import EventLog from './EventLog';

const MainDashboard = () => {
  const { setBots } = useBotStore();
  const { setCampaigns } = useCampaignStore();
  const { setStats } = useDashboardStore();
  const { isConnected } = useWebSocket();

  // 초기 데이터 로드
  useEffect(() => {
    const loadInitialData = async () => {
      try {
        // 봇 목록 로드
        const bots = await botAPI.getAll();
        setBots(bots);

        // 캠페인 목록 로드
        const campaigns = await campaignAPI.getAll();
        setCampaigns(campaigns);

        // 통계 로드
        const stats = await dashboardAPI.getStats();
        setStats(stats);
      } catch (error) {
        console.error('[MainDashboard] 초기 데이터 로드 실패:', error);
      }
    };

    loadInitialData();
  }, [setBots, setCampaigns, setStats]);

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" component="h1">
          🚀 Turafic 실시간 모니터링
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box
            sx={{
              width: 12,
              height: 12,
              borderRadius: '50%',
              bgcolor: isConnected ? 'success.main' : 'error.main',
            }}
          />
          <Typography variant="body2" color="text.secondary">
            {isConnected ? '연결됨' : '연결 끊김'}
          </Typography>
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* 캠페인 개요 */}
        <Grid item xs={12}>
          <CampaignOverview />
        </Grid>

        {/* 봇 상태 */}
        <Grid item xs={12}>
          <BotStatus />
        </Grid>

        {/* 순위 변동 차트 */}
        <Grid item xs={12} md={8}>
          <RankingChart />
        </Grid>

        {/* 최근 이벤트 로그 */}
        <Grid item xs={12} md={4}>
          <EventLog />
        </Grid>
      </Grid>
    </Container>
  );
};

export default MainDashboard;
