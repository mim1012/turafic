import { Paper, Box, Typography, Chip } from '@mui/material';
import { useDashboardStore } from '../stores/dashboardStore';

const EventLog = () => {
  const { logs } = useDashboardStore();

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'SUCCESS':
        return 'success';
      case 'ERROR':
        return 'error';
      case 'WARNING':
        return 'warning';
      default:
        return 'info';
    }
  };

  return (
    <Paper sx={{ p: 3, height: 400 }}>
      <Typography variant="h6" sx={{ mb: 2 }}>
        📜 최근 이벤트
      </Typography>
      
      <Box
        sx={{
          height: 320,
          overflowY: 'auto',
          '&::-webkit-scrollbar': {
            width: '8px',
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: 'rgba(0,0,0,0.2)',
            borderRadius: '4px',
          },
        }}
      >
        {logs.length > 0 ? (
          logs.slice(0, 50).map((log, index) => (
            <Box
              key={index}
              sx={{
                mb: 1.5,
                pb: 1.5,
                borderBottom: '1px solid',
                borderColor: 'divider',
                '&:last-child': { borderBottom: 'none' },
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <Chip
                  label={log.level}
                  color={getLevelColor(log.level) as any}
                  size="small"
                  sx={{ minWidth: 80 }}
                />
                <Typography variant="caption" color="text.secondary">
                  [{log.agent}]
                </Typography>
              </Box>
              <Typography variant="body2">{log.message}</Typography>
            </Box>
          ))
        ) : (
          <Box
            sx={{
              height: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Typography color="text.secondary">이벤트가 없습니다.</Typography>
          </Box>
        )}
      </Box>
    </Paper>
  );
};

export default EventLog;
