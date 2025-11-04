import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import MainDashboard from './components/MainDashboard';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <MainDashboard />
    </ThemeProvider>
  );
}

export default App;
