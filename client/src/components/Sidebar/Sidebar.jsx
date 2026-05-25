// ============================================================
// components/Sidebar/Sidebar.jsx — LEFT NAVIGATION SIDEBAR
// ============================================================
// Vertical navigation panel showing all app pages.
// Highlights the currently active route.
// Shows live IOC count badges on nav items.
//
// Navigation items:
//   Dashboard    → /dashboard    (overview + charts)
//   IOC Search   → /search       (search/enrich IOCs)
//   Threat Feed  → /threat-feed  (live feed of threats)
//   Reports      → /reports      (analyst reports)
// ============================================================

import { NavLink, useLocation } from 'react-router-dom';
import { useIOC } from '../../hooks/useIOC';
import './Sidebar.css';

const NAV_ITEMS = [
  {
    path:  '/dashboard',
    label: 'DASHBOARD',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <rect x="1" y="1" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.2"/>
        <rect x="9" y="1" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.2"/>
        <rect x="1" y="9" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.2"/>
        <rect x="9" y="9" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.2"/>
      </svg>
    ),
  },
  {
    path:  '/search',
    label: 'IOC SEARCH',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="6.5" cy="6.5" r="4.5" stroke="currentColor" strokeWidth="1.2"/>
        <line x1="10.5" y1="10.5" x2="15" y2="15" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    path:  '/threat-feed',
    label: 'THREAT FEED',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <path d="M8 1 L8 5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
        <path d="M8 11 L8 15" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
        <path d="M3 3 L5.5 5.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
        <path d="M10.5 10.5 L13 13" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
        <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.2"/>
        <circle cx="8" cy="8" r="1" fill="currentColor"/>
      </svg>
    ),
    badge: 'LIVE',
  },
  {
    path:  '/reports',
    label: 'REPORTS',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <rect x="2" y="1" width="12" height="14" rx="1.5" stroke="currentColor" strokeWidth="1.2"/>
        <line x1="5" y1="5" x2="11" y2="5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
        <line x1="5" y1="8" x2="11" y2="8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
        <line x1="5" y1="11" x2="8"  y2="11" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
      </svg>
    ),
  },
];

const Sidebar = () => {
  const location = useLocation();
  const { stats } = useIOC();

  return (
    <aside className="sidebar">
      {/* ── Top Decorative Line ── */}
      <div className="sidebar-top-accent" />

      {/* ── Navigation ── */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">NAVIGATION</div>
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `sidebar-nav-item ${isActive ? 'active' : ''}`
            }
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
            {item.badge && (
              <span className="nav-live-badge">{item.badge}</span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* ── Stats Summary ── */}
      {stats && (
        <div className="sidebar-stats">
          <div className="nav-section-label">CURRENT STATS</div>
          <div className="stat-row">
            <span className="stat-label">Total IOCs</span>
            <span className="stat-value">{stats.totalIOCs?.toLocaleString() || 0}</span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Critical</span>
            <span className="stat-value critical">
              {stats.severityDistribution?.find(s => s._id === 'Critical')?.count || 0}
            </span>
          </div>
          <div className="stat-row">
            <span className="stat-label">High</span>
            <span className="stat-value high">
              {stats.severityDistribution?.find(s => s._id === 'High')?.count || 0}
            </span>
          </div>
        </div>
      )}

      {/* ── Bottom: System Info ── */}
      <div className="sidebar-footer">
        <div className="footer-line">
          <span className="status-dot online" />
          <span>SYSTEM ONLINE</span>
        </div>
        <div className="footer-version">v1.0.0 — IOC SENTINEL</div>
      </div>
    </aside>
  );
};

export default Sidebar;
