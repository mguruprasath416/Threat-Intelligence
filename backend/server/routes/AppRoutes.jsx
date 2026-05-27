// ============================================================
// routes/AppRoutes.jsx — PROTECTED ROUTING
// ============================================================
// ProtectedRoute: if NOT logged in → redirect to /login
// PublicRoute:    if ALREADY logged in → redirect to /dashboard
// This ensures:
//   - Unauthenticated users CANNOT access any page except /login
//   - Logged-in users cannot go back to /login page
// ============================================================

import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth }     from '../hooks/useAuth';
import MainLayout      from '../layouts/MainLayout';
import Loader          from '../components/Loader/Loader';

import Login      from '../pages/Login';
import Dashboard  from '../pages/Dashboard';
import IOCSearch  from '../pages/IOCSearch';
import IOCDetails from '../pages/IOCDetails';
import ThreatFeed from '../pages/ThreatFeed';
import Reports    from '../pages/Reports';
import NotFound   from '../pages/NotFound';

// ── Loading Screen ─────────────────────────────────────────
const LoadingScreen = () => (
  <div style={{
    display:         'flex',
    alignItems:      'center',
    justifyContent:  'center',
    height:          '100vh',
    background:      'var(--bg-void)',
    flexDirection:   'column',
    gap:             '16px',
  }}>
    <Loader message="VERIFYING SESSION..." />
  </div>
);

// ── Protected Route ────────────────────────────────────────
// Only lets user IN if they are authenticated
// If not logged in → sends to /login
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  // Still checking localStorage / verifying token
  if (isLoading) return <LoadingScreen />;

  // Not logged in → force to login page
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
};

// ── Public Route ───────────────────────────────────────────
// Only lets user see login page if NOT authenticated
// If already logged in → sends to /dashboard
const PublicRoute = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <LoadingScreen />;

  // Already logged in → skip login, go to dashboard
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

// ── App Routes ─────────────────────────────────────────────
const AppRoutes = () => (
  <Routes>

    {/* ── Public: Login only ── */}
    {/* If logged in, this redirects to /dashboard automatically */}
    <Route
      path="/login"
      element={
        <PublicRoute>
          <Login />
        </PublicRoute>
      }
    />

    {/* ── Root: always redirect to dashboard ── */}
    {/* ProtectedRoute inside handles redirect to /login if not auth */}
    <Route
      path="/"
      element={
        <ProtectedRoute>
          <Navigate to="/dashboard" replace />
        </ProtectedRoute>
      }
    />

    {/* ── Protected: all app pages inside MainLayout ── */}
    {/* If not logged in, ALL these redirect to /login */}
    <Route
      element={
        <ProtectedRoute>
          <MainLayout />
        </ProtectedRoute>
      }
    >
      <Route path="/dashboard"   element={<Dashboard />} />
      <Route path="/search"      element={<IOCSearch />} />
      <Route path="/ioc/:id"     element={<IOCDetails />} />
      <Route path="/threat-feed" element={<ThreatFeed />} />
      <Route path="/reports"     element={<Reports />} />
    </Route>

    {/* ── 404 ── */}
    <Route path="*" element={<NotFound />} />

  </Routes>
);

export default AppRoutes;