import { Paper, Grid, Box, Typography, LinearProgress, Chip } from '@mui/material';
import {
  SmartToy,
  Cloud,
  CloudOff,
  Work,
} from '@mui/icons-material';
import { useBotStore } from '../stores/botStore';

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

const BotRow = ({ bot }: { bot: any }) => {
  const statusColor =
    bot.status === 'online' || bot.status === 'working' ? 'success' : 'error';
  const statusText =
    bot.status === 'online' ? '온라인' : bot.status === 'working' ? '작업 중' : '오프라인';

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 2,
        p: 1.5,
        borderBottom: '1px solid',
        borderColor: 'divider',
        '&:last-child': { borderBottom: 'none' },
      }}
    >
      <Box sx={{ minWidth: 100 }}>
        <Typography variant="body2" fontWeight="bold">
          {bot.bot_id}
        </Typography>
      </Box>
      <Box sx={{ minWidth: 80 }}>
        <Chip
          label={bot.role === 'leader' ? '🎖️ 대장' : '🪖 쫄병'}
          size="small"
          variant="outlined"
        />
      </Box>
      <Box sx={{ minWidth: 100 }}>
        <Chip label={statusText} color={statusColor} size="small" />
      </Box>
      <Box sx={{ minWidth: 100 }}>
        <Typography variant="body2" color="text.secondary">
          {bot.assigned_campaign_id || '-'}
        </Typography>
      </Box>
      <Box sx={{ flex: 1, minWidth: 200 }}>
        {bot.progress !== undefined ? (
          <Box>
            <LinearProgress
              variant="determinate"
              value={bot.progress}
              sx={{ height: 8, borderRadius: 1 }}
            />
            <Typography variant="caption" color="text.secondary">
              {bot.progress}%
            </Typography>
          </Box>
        ) : (
          <Typography variant="body2" color="text.secondary">
            -
          </Typography>
        )}
      </Box>
    </Box>
  );
};

const BotStatus = () => {
  const { bots } = useBotStore();

  const totalBots = bots.length;
  const onlineBots = bots.filter((b) => b.status === 'online' || b.status === 'working').length;
  const workingBots = bots.filter((b) => b.status === 'working').length;
  const offlineBots = bots.filter((b) => b.status === 'offline').length;

  // 그룹별로 봇 분류
  const groupedBots: { [key: string]: any[] } = {};
  bots.forEach((bot) => {
    if (!groupedBots[bot.group_id]) {
      groupedBots[bot.group_id] = [];
    }
    groupedBots[bot.group_id].push(bot);
  });

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 2 }}>
        🤖 봇 상태
      </Typography>
      
      {/* 통계 카드 */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="총 봇"
            value={totalBots}
            icon={<SmartToy />}
            color="primary"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="온라인"
            value={onlineBots}
            icon={<Cloud />}
            color="success"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="작업 중"
            value={workingBots}
            icon={<Work />}
            color="info"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="오프라인"
            value={offlineBots}
            icon={<CloudOff />}
            color="error"
          />
        </Grid>
      </Grid>

      {/* 그룹별 봇 목록 */}
      {Object.entries(groupedBots).map(([groupId, groupBots]) => (
        <Paper key={groupId} sx={{ mb: 2 }}>
          <Box sx={{ p: 2, bgcolor: 'grey.100' }}>
            <Typography variant="subtitle1" fontWeight="bold">
              {groupId === 'RC' ? '순위 체크 그룹' : `트래픽 작업 그룹 ${groupId}`}
            </Typography>
          </Box>
          <Box>
            {groupBots.map((bot) => (
              <BotRow key={bot.bot_id} bot={bot} />
            ))}
          </Box>
        </Paper>
      ))}
    </Box>
  );
};

export default BotStatus;
