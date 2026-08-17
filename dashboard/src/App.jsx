import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppProvider } from './lib/AppContext';
import ProtectedRoute from './components/ProtectedRoute';
import Layout from './components/Layout';
import Login from './pages/Login';
import DashboardHome from './pages/DashboardHome';
import Events from './pages/Events';
import Projects from './pages/Projects';
import Team from './pages/Team';
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <AppProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<DashboardHome />} />
            <Route path="events" element={<Events />} />
            <Route path="projects" element={<Projects />} />
            <Route path="team" element={<Team />} />
            <Route path="settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<Login />} />
        </Routes>
      </AppProvider>
    </BrowserRouter>
  );
}
