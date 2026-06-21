// ============================================================
// routes/AppRoutes.jsx — CENTRALIZED ROUTE DEFINITIONS
// ============================================================
// Defines all routes using React Router v6.
//
// Route structure:
//   /login             → Login page (public)
//   /                  → Redirect to /dashboard
//   /dashboard         → Dashboard (protected)
//   /search            → IOC Search (protected)
//   /ioc/:id           → IOC Details (protected)
//   /threat-feed       → Live Feed (protected)
//   /reports           → Reports (protected)
//   *                  → 404 Not Found
//
// ProtectedRoute:
//   Checks isAuthenticated from AuthContext.
//   If not logged in → redirect to /login.
//   Shows loading spinner while checking stored token.
// ============================================================

import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth }     from '../hooks/useAuth';
import MainLayout      from '../layouts/MainLayout';
import Loader          from '../components/Loader/Loader';

// Pages
import Login          from '../pages/Login';
import Dashboard      from '../pages/Dashboard';
import IOCSearch      from '../pages/IOCSearch';
import IOCDetails     from '../pages/IOCDetails';
import ThreatFeed     from '../pages/ThreatFeed';
import Reports        from '../pages/Reports';
import ThreatActorPage from '../pages/ThreatActorPage';
import RelationshipGraph from '../pages/RelationshipGraph';
import HuntQueryBuilder from '../pages/HuntQueryBuilder';
import NotFound       from '../pages/NotFound';

// ── Protected Route Wrapper ────────────────────────────────
// Renders children only if authenticated, else redirects to /login
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  // Still checking localStorage/verifying token
  if (isLoading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center',
                    justifyContent: 'center', height: '100vh',
                    background: 'var(--bg-void)' }}>
        <Loader message="VERIFYING SESSION..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
};

const AppRoutes = () => (
  <Routes>
    {/* ── Public Routes ── */}
    <Route path="/login" element={<Login />} />

    {/* ── Root redirect ── */}
    <Route path="/" element={<Navigate to="/dashboard" replace />} />

    {/* ── Protected Routes (all inside MainLayout shell) ── */}
    <Route
      element={
        <ProtectedRoute>
          <MainLayout />
        </ProtectedRoute>
      }
    >
      <Route path="/dashboard"        element={<Dashboard />} />
      <Route path="/search"           element={<IOCSearch />} />
      <Route path="/ioc/:id"          element={<IOCDetails />} />
      <Route path="/graph"            element={<RelationshipGraph />} />
      <Route path="/graph/:id"        element={<RelationshipGraph />} />
      <Route path="/hunt"             element={<HuntQueryBuilder />} />
      <Route path="/threat-feed"      element={<ThreatFeed />} />
      <Route path="/reports"          element={<Reports />} />
      <Route path="/threat-actors"    element={<ThreatActorPage />} />
      <Route path="/threat-actors/:id" element={<ThreatActorPage />} />
    </Route>

    {/* ── 404 ── */}
    <Route path="*" element={<NotFound />} />
  </Routes>
);

export default AppRoutes;
