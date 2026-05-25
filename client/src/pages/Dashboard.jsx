// ============================================================
// pages/Dashboard.jsx — MAIN DASHBOARD PAGE
// ============================================================
// The home screen of the application. Shows:
//   - Four KPI stat cards (Total / Critical / High / Medium IOCs)
//   - Severity donut chart
//   - IOC type distribution pie
//   - 30-day trend line
//   - Top countries bar chart
//   - Recent IOCs mini-table
//
// All data comes from GET /api/ioc/stats (one aggregated call).
// Refreshes every 60 seconds automatically.
// ============================================================

import { useEffect, useRef } from 'react';
import { useNavigate }       from 'react-router-dom';
import { useIOC }            from '../hooks/useIOC';
import {
  SeverityDonut, IOCTypePie, TrendLineChart, CountryBarChart
} from '../components/Charts/Charts';
import Loader from '../components/Loader/Loader';
import './Dashboard.css';

// ── Stat Card ─────────────────────────────────────────────
const StatCard = ({ label, value, color, icon, sub }) => (
  <div className="stat-card" style={{ '--accent': color }}>
    <div className="stat-card-top">
      <div className="stat-icon">{icon}</div>
      <div className="stat-value" style={{ color }}>{value ?? '—'}</div>
    </div>
    <div className="stat-label">{label}</div>
    {sub && <div className="stat-sub">{sub}</div>}
  </div>
);

// ── Chart Panel ────────────────────────────────────────────
const ChartPanel = ({ title, children }) => (
  <div className="chart-panel card">
    <div className="chart-panel-title">{title}</div>
    {children}
  </div>
);

const Dashboard = () => {
  const navigate         = useNavigate();
  const { stats, fetchStats, isFetching } = useIOC();
  const refreshTimer     = useRef(null);

  // Fetch on mount + refresh every 60 seconds
  useEffect(() => {
    fetchStats();
    refreshTimer.current = setInterval(fetchStats, 60_000);
    return () => clearInterval(refreshTimer.current);
  }, [fetchStats]);

  if (!stats && isFetching) {
    return (
      <div className="page-center">
        <Loader message="LOADING THREAT INTELLIGENCE..." />
      </div>
    );
  }

  // ── Derived values ─────────────────────────────────────
  const totalIOCs    = stats?.totalIOCs || 0;
  const criticalCount = stats?.severityDistribution?.find(s => s._id === 'Critical')?.count || 0;
  const highCount     = stats?.severityDistribution?.find(s => s._id === 'High')?.count     || 0;
  const mediumCount   = stats?.severityDistribution?.find(s => s._id === 'Medium')?.count   || 0;

  return (
    <div className="dashboard-page animate-in">

      {/* ── Page Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">THREAT DASHBOARD</h1>
          <p className="page-subtitle">Real-time threat intelligence overview</p>
        </div>
        <div className="header-actions">
          <button className="btn" onClick={fetchStats}>↻ REFRESH</button>
          <button className="btn btn-primary" onClick={() => navigate('/search')}>
            + ANALYZE IOC
          </button>
        </div>
      </div>

      {/* ── KPI Cards ── */}
      <div className="grid-4 kpi-grid">
        <StatCard
          label="TOTAL IOCs"
          value={totalIOCs.toLocaleString()}
          color="var(--cyan)"
          icon="⬡"
          sub="all active indicators"
        />
        <StatCard
          label="CRITICAL"
          value={criticalCount}
          color="var(--red)"
          icon="▲"
          sub="immediate action required"
        />
        <StatCard
          label="HIGH"
          value={highCount}
          color="var(--orange)"
          icon="▲"
          sub="high-priority threats"
        />
        <StatCard
          label="MEDIUM"
          value={mediumCount}
          color="var(--yellow)"
          icon="◆"
          sub="monitor and investigate"
        />
      </div>

      {/* ── Charts Row 1 ── */}
      <div className="charts-row-2">
        <ChartPanel title="SEVERITY DISTRIBUTION">
          <SeverityDonut data={stats?.severityDistribution} />
        </ChartPanel>
        <ChartPanel title="IOC TYPE BREAKDOWN">
          <IOCTypePie data={stats?.typeDistribution} />
        </ChartPanel>
      </div>

      {/* ── Charts Row 2 ── */}
      <div className="charts-row-2">
        <ChartPanel title="IOC TREND — LAST 30 DAYS">
          <TrendLineChart data={stats?.dailyTrend} />
        </ChartPanel>
        <ChartPanel title="TOP THREAT COUNTRIES">
          <CountryBarChart data={stats?.topCountries} />
        </ChartPanel>
      </div>

      {/* ── Top Tags ── */}
      {stats?.topTags?.length > 0 && (
        <div className="card">
          <div className="chart-panel-title">TOP THREAT TAGS</div>
          <div className="tags-cloud">
            {stats.topTags.map((t, i) => (
              <span
                key={t._id}
                className="cloud-tag"
                style={{ fontSize: `${Math.max(11, 18 - i)}px` }}
              >
                {t._id}
                <sup className="tag-count">{t.count}</sup>
              </span>
            ))}
          </div>
        </div>
      )}

    </div>
  );
};

export default Dashboard;
