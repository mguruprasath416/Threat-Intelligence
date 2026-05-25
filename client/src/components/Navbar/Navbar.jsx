// ============================================================
// components/Navbar/Navbar.jsx — TOP NAVIGATION BAR
// ============================================================
// Fixed top bar showing:
//   - Logo / system name with blinking cursor
//   - Live clock (updates every second)
//   - System status indicators
//   - User info + logout button
//
// Stays on screen at all times — content scrolls beneath it.
// ============================================================

import { useState, useEffect } from 'react';
import { useAuth } from '../../hooks/useAuth';
import './Navbar.css';

const Navbar = () => {
  const { user, logout } = useAuth();
  const [time, setTime] = useState(new Date());
  const [showUserMenu, setShowUserMenu] = useState(false);

  // Live clock — updates every second
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (date) =>
    date.toUTCString().slice(17, 25); // HH:MM:SS

  const formatDate = (date) =>
    date.toISOString().slice(0, 10); // YYYY-MM-DD

  return (
    <nav className="navbar">
      {/* ── Left: Logo ── */}
      <div className="navbar-brand">
        <div className="brand-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
            <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" stroke="#00d4ff" strokeWidth="1.5" fill="none"/>
            <polygon points="12,6 18,9.5 18,14.5 12,18 6,14.5 6,9.5" stroke="#00d4ff" strokeWidth="1" fill="rgba(0,212,255,0.1)"/>
            <circle cx="12" cy="12" r="2" fill="#00d4ff"/>
          </svg>
        </div>
        <div className="brand-text">
          <span className="brand-name">IOC SENTINEL</span>
          <span className="brand-sub">Threat Intelligence Platform</span>
        </div>
      </div>

      {/* ── Center: Status Indicators ── */}
      <div className="navbar-status">
        <div className="status-item">
          <span className="status-dot online"></span>
          <span className="status-label">FEEDS ACTIVE</span>
        </div>
        <div className="status-divider">|</div>
        <div className="status-item">
          <span className="status-dot online"></span>
          <span className="status-label">APIs CONNECTED</span>
        </div>
        <div className="status-divider">|</div>
        <div className="status-item">
          <span className="status-label threat-level">THREAT LEVEL:</span>
          <span className="threat-value high">HIGH</span>
        </div>
      </div>

      {/* ── Right: Clock + User ── */}
      <div className="navbar-right">
        <div className="navbar-clock">
          <div className="clock-time">{formatTime(time)} UTC</div>
          <div className="clock-date">{formatDate(time)}</div>
        </div>

        <div className="navbar-user" onClick={() => setShowUserMenu(p => !p)}>
          <div className="user-avatar">
            {user?.username?.[0]?.toUpperCase() || 'A'}
          </div>
          <div className="user-info">
            <span className="user-name">{user?.username || 'Analyst'}</span>
            <span className="user-role">{user?.role?.toUpperCase() || 'ANALYST'}</span>
          </div>
          <span className="chevron">▾</span>

          {showUserMenu && (
            <div className="user-menu">
              <div className="user-menu-header">
                <span>{user?.email}</span>
              </div>
              <button className="user-menu-item" onClick={logout}>
                ⏻ LOGOUT
              </button>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
