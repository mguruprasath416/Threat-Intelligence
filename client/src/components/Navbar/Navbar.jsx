// ============================================================
// components/Navbar/Navbar.jsx — WITH MOBILE HAMBURGER MENU
// ============================================================

import { useState, useEffect } from 'react';
import { useAuth } from '../../hooks/useAuth';
import NotificationBell from './NotificationBell';
import './Navbar.css';

const Navbar = ({ onMenuToggle, sidebarOpen }) => {
  const { user, logout } = useAuth();
  const [time, setTime] = useState(new Date());
  const [showUserMenu, setShowUserMenu] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (date) => date.toUTCString().slice(17, 25);
  const formatDate = (date) => date.toISOString().slice(0, 10);

  return (
    <nav className="navbar">

      {/* ── Left: Hamburger + Logo ── */}
      <div className="navbar-left">
        {/* Hamburger button — only visible on mobile */}
        <button
          className="hamburger-btn"
          onClick={onMenuToggle}
          aria-label="Toggle menu"
          style={{ display: 'none' }} // shown via CSS media query
        >
          {sidebarOpen ? '✕' : '☰'}
        </button>

        <div className="navbar-brand">
          <div className="brand-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <polygon points="12,2 22,8 22,16 12,22 2,16 2,8"
                stroke="#00d4ff" strokeWidth="1.5" fill="none"/>
              <polygon points="12,6 18,9.5 18,14.5 12,18 6,14.5 6,9.5"
                stroke="#00d4ff" strokeWidth="1"
                fill="rgba(0,212,255,0.1)"/>
              <circle cx="12" cy="12" r="2" fill="#00d4ff"/>
            </svg>
          </div>
          <div className="brand-text">
            <span className="brand-name">IOC SENTINEL</span>
            <span className="brand-sub">Threat Intelligence Platform</span>
          </div>
        </div>
      </div>

      {/* ── Center: Status ── */}
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

        {/* ── Real-time Alerting Notification Bell ── */}
        <NotificationBell />

        <div className="navbar-user"
          onClick={() => setShowUserMenu(p => !p)}>
          <div className="user-avatar">
            {user?.username?.[0]?.toUpperCase() || 'A'}
          </div>
          <div className="user-info">
            <span className="user-name">{user?.username || 'Analyst'}</span>
            <span className="user-role">
              {user?.role?.toUpperCase() || 'ANALYST'}
            </span>
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