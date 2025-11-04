import { Paper, Grid, Box, Typography } from '@mui/material';
import {
  Campaign as CampaignIcon,
  PlayArrow,
  CheckCircle,
  Error,
} from '@mui/icons-material';
import { useCampaignStore } from '../stores/campaignStore';

const StatCard = ({
  title,
  value,
  icon,
  color,
}: {
  title: string;
  value: number;
  icon: React.ReactNode;
  color: string;
}) => (
  <Paper sx={{ p: 2 }}>
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
      <Box
        sx={{
          width: 48,
          height: 48,
          borderRadius: 2,
          bgcolor: `${color}.light`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: `${color}.main`,
        }}
      >
        {icon}
      </Box>
      <Box>
        <Typography variant="body2" color="text.secondary">
          {title}
        </Typography>
        <Typography variant="h4">{value}</Typography>
      </Box>
    </Box>
  </Paper>
);

const CampaignOverview = () => {
  const { campaigns } = useCampaignStore();

  const totalCampaigns = campaigns.length;
  const runningCampaigns = campaigns.filter((c) => c.status === 'running').length;
  const completedCampaigns = campaigns.filter((c) => c.status === 'completed').length;
  const failedCampaigns = campaigns.filter((c) => c.status === 'failed').length;

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 2 }}>
        📊 캠페인 개요
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="총 캠페인"
            value={totalCampaigns}
            icon={<CampaignIcon />}
            color="primary"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="진행 중"
            value={runningCampaigns}
            icon={<PlayArrow />}
            color="info"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="완료"
            value={completedCampaigns}
            icon={<CheckCircle />}
            color="success"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="실패"
            value={failedCampaigns}
            icon={<Error />}
            color="error"
          />
        </Grid>
      </Grid>
    </Box>
  );
};

export default CampaignOverview;
