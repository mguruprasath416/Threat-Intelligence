// ============================================================
// components/Sidebar/Sidebar.jsx — WITH MOBILE SUPPORT
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
        <rect x="1" y="1" width="6" height="6" rx="1"
          stroke="currentColor" strokeWidth="1.2"/>
        <rect x="9" y="1" width="6" height="6" rx="1"
          stroke="currentColor" strokeWidth="1.2"/>
        <rect x="1" y="9" width="6" height="6" rx="1"
          stroke="currentColor" strokeWidth="1.2"/>
        <rect x="9" y="9" width="6" height="6" rx="1"
          stroke="currentColor" strokeWidth="1.2"/>
      </svg>
    ),
  },
  {
    path:  '/search',
    label: 'IOC SEARCH',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="6.5" cy="6.5" r="4.5"
          stroke="currentColor" strokeWidth="1.2"/>
        <line x1="10.5" y1="10.5" x2="15" y2="15"
          stroke="currentColor" strokeWidth="1.5"
          strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    path:  '/graph',
    label: 'RELATIONSHIP GRAPH',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="4" cy="4" r="2"
          stroke="currentColor" strokeWidth="1.2"/>
        <circle cx="12" cy="4" r="2"
          stroke="currentColor" strokeWidth="1.2"/>
        <circle cx="8" cy="12" r="2"
          stroke="currentColor" strokeWidth="1.2"/>
        <line x1="6" y1="4" x2="10" y2="4"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
        <line x1="5" y1="5.5" x2="7" y2="10.5"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
        <line x1="11" y1="5.5" x2="9" y2="10.5"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    path:  '/hunt',
    label: 'HUNT BUILDER',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="8" r="5"
          stroke="currentColor" strokeWidth="1.2"/>
        <circle cx="8" cy="8" r="2" fill="currentColor"/>
        <line x1="8" y1="1" x2="8" y2="3"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
        <line x1="8" y1="13" x2="8" y2="15"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
        <line x1="1" y1="8" x2="3" y2="8"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
        <line x1="13" y1="8" x2="15" y2="8"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    path:  '/threat-feed',
    label: 'THREAT FEED',
    badge: 'LIVE',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="8" r="3"
          stroke="currentColor" strokeWidth="1.2"/>
        <circle cx="8" cy="8" r="1" fill="currentColor"/>
        <path d="M8 1 L8 5" stroke="currentColor"
          strokeWidth="1.2" strokeLinecap="round"/>
        <path d="M8 11 L8 15" stroke="currentColor"
          strokeWidth="1.2" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    path:  '/threat-actors',
    label: 'THREAT ACTORS',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="5" r="3"
          stroke="currentColor" strokeWidth="1.2"/>
        <path d="M2 14c0-3.3 2.7-6 6-6s6 2.7 6 6"
          stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
        <circle cx="13" cy="4" r="1.5" fill="currentColor" opacity="0.7"/>
        <path d="M13 6v2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    path:  '/reports',
    label: 'REPORTS',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <rect x="2" y="1" width="12" height="14" rx="1.5"
          stroke="currentColor" strokeWidth="1.2"/>
        <line x1="5" y1="5" x2="11" y2="5"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
        <line x1="5" y1="8" x2="11" y2="8"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
        <line x1="5" y1="11" x2="8" y2="11"
          stroke="currentColor" strokeWidth="1.2"
          strokeLinecap="round"/>
      </svg>
    ),
  },
];

const Sidebar = ({ isOpen, onClose }) => {
  const { stats } = useIOC();

  return (
    <aside className={`sidebar ${isOpen ? 'open' : ''}`}>

      {/* Close button — mobile only */}
      <button
        className="sidebar-close-btn"
        onClick={onClose}
        aria-label="Close menu"
      >
        ✕
      </button>

      <div className="sidebar-top-accent" />

      {/* Navigation */}
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

      {/* Stats */}
      {stats && (
        <div className="sidebar-stats">
          <div className="nav-section-label">CURRENT STATS</div>
          <div className="stat-row">
            <span className="stat-label">Total IOCs</span>
            <span className="stat-value">
              {stats.totalIOCs?.toLocaleString() || 0}
            </span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Critical</span>
            <span className="stat-value critical">
              {stats.severityDistribution?.find(
                s => s._id === 'Critical'
              )?.count || 0}
            </span>
          </div>
          <div className="stat-row">
            <span className="stat-label">High</span>
            <span className="stat-value high">
              {stats.severityDistribution?.find(
                s => s._id === 'High'
              )?.count || 0}
            </span>
          </div>
        </div>
      )}

      {/* Footer */}
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