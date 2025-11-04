import { Paper, Box, Typography } from '@mui/material';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { useDashboardStore } from '../stores/dashboardStore';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

const RankingChart = () => {
  const { rankings } = useDashboardStore();

  // 최근 10개 순위 데이터
  const recentRankings = rankings.slice(-10);

  const chartData = {
    labels: recentRankings.map((r) => {
      const date = new Date(r.checked_at);
      return `${date.getHours()}:${date.getMinutes().toString().padStart(2, '0')}`;
    }),
    datasets: [
      {
        label: '순위',
        data: recentRankings.map((r) => r.rank),
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        tension: 0.4,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
      title: {
        display: false,
      },
    },
    scales: {
      y: {
        reverse: true, // 순위는 낮을수록 좋으므로 반전
        beginAtZero: false,
      },
    },
  };

  const currentRank = recentRankings[recentRankings.length - 1]?.rank;
  const beforeRank = recentRankings[0]?.rank;
  const improvement = beforeRank && currentRank ? beforeRank - currentRank : 0;

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" sx={{ mb: 2 }}>
        📈 순위 변동 (실시간)
      </Typography>
      
      {recentRankings.length > 0 ? (
        <>
          <Box sx={{ mb: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Before: {beforeRank}위 → 현재: {currentRank}위{' '}
              {improvement !== 0 && (
                <Typography
                  component="span"
                  color={improvement > 0 ? 'success.main' : 'error.main'}
                  fontWeight="bold"
                >
                  ({improvement > 0 ? '↑' : '↓'}
                  {Math.abs(improvement)}위)
                </Typography>
              )}
            </Typography>
          </Box>
          
          <Box sx={{ height: 300 }}>
            <Line data={chartData} options={options} />
          </Box>
        </>
      ) : (
        <Box sx={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Typography color="text.secondary">순위 데이터가 없습니다.</Typography>
        </Box>
      )}
    </Paper>
  );
};

export default RankingChart;
