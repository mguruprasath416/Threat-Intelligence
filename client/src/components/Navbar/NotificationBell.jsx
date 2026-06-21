// ============================================================
// components/Navbar/NotificationBell.jsx — LIVE ALERTS BELL
// ============================================================

import { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from '../../hooks/useAuth';
import api from '../../api/axios';
import WatchlistModal from './WatchlistModal';
import './NotificationBell.css';

const NotificationBell = () => {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isOpen, setIsOpen] = useState(false);
  const [watchlistOpen, setWatchlistOpen] = useState(false);
  const dropdownRef = useRef(null);

  // Derive Socket.io host from Axios API base URL (e.g. http://localhost:5000/api -> http://localhost:5000)
  const apiBaseURL = api.defaults.baseURL || 'http://localhost:5000/api';
  const socketHost = apiBaseURL.replace('/api', '');

  // Load existing alerts
  const fetchAlerts = async () => {
    try {
      const response = await api.get('/alerts');
      if (response.data) {
        setAlerts(response.data.alerts || []);
        setUnreadCount(response.data.unreadCount || 0);
      }
    } catch (err) {
      console.error('Error fetching alerts:', err);
    }
  };

  useEffect(() => {
    if (!user) return;

    fetchAlerts();

    // Setup Socket.io connection
    const socket = io(socketHost, {
      transports: ['websocket', 'polling']
    });

    socket.on('connect', () => {
      console.log('📡 Connected to live alerts websocket');
      // Authenticate socket to join room
      socket.emit('authenticate', user.id || user._id);
    });

    // Listen for new matched watchlist alerts
    socket.on('new-alert', (alert) => {
      console.log('🔔 Live alert received:', alert);
      setAlerts(prev => [alert, ...prev]);
      setUnreadCount(prev => prev + 1);

      // Play subtle warning sound
      try {
        const audio = new Audio('https://assets.mixkit.co/active_storage/sfx/2869/2869-600.wav');
        audio.volume = 0.2;
        audio.play();
      } catch (e) {
        // ignore audio errors (e.g. browser autoplay block)
      }
    });

    // Close dropdown on click outside
    const handleOutsideClick = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);

    return () => {
      socket.disconnect();
      document.removeEventListener('mousedown', handleOutsideClick);
    };
  }, [user, socketHost]);

  const toggleDropdown = () => {
    setIsOpen(!isOpen);
  };

  const handleMarkAsRead = async (alertId) => {
    try {
      await api.patch(`/alerts/${alertId}/read`);
      setAlerts(prev =>
        prev.map(a => (a._id === alertId ? { ...a, read: true } : a))
      );
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (err) {
      console.error('Error marking alert as read:', err);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await api.post('/alerts/read-all');
      setAlerts(prev => prev.map(a => ({ ...a, read: true })));
      setUnreadCount(0);
    } catch (err) {
      console.error('Error marking all read:', err);
    }
  };

  const handleDeleteAlert = async (e, alertId) => {
    e.stopPropagation(); // Avoid triggering click to read
    try {
      await api.delete(`/alerts/${alertId}`);
      const deletedAlert = alerts.find(a => a._id === alertId);
      setAlerts(prev => prev.filter(a => a._id !== alertId));
      if (deletedAlert && !deletedAlert.read) {
        setUnreadCount(prev => Math.max(0, prev - 1));
      }
    } catch (err) {
      console.error('Error deleting alert:', err);
    }
  };

  const formatTimeAgo = (dateStr) => {
    const elapsed = Date.now() - new Date(dateStr).getTime();
    const seconds = Math.floor(elapsed / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (seconds < 60) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return new Date(dateStr).toLocaleDateString();
  };

  return (
    <div className="bell-container" ref={dropdownRef}>
      {/* ── Bell Trigger Button ── */}
      <button
        id="nav-alert-bell"
        className={`bell-button ${unreadCount > 0 ? 'pulse' : ''}`}
        onClick={toggleDropdown}
        title="Security Alerts"
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
        {unreadCount > 0 && (
          <span className="bell-badge">{unreadCount > 99 ? '99+' : unreadCount}</span>
        )}
      </button>

      {/* ── Dropdown Box ── */}
      {isOpen && (
        <div className="bell-dropdown animate-dropdown">
          <div className="bell-dropdown-header">
            <span>ALERTS FEED ({unreadCount} UNREAD)</span>
            {unreadCount > 0 && (
              <button onClick={handleMarkAllRead} className="btn-text">
                MARK ALL READ
              </button>
            )}
          </div>

          <div className="bell-dropdown-body">
            {alerts.length === 0 ? (
              <div className="bell-empty-state">
                <span className="bell-empty-icon">🛡️</span>
                <p>System secure. No new watchlist matches.</p>
              </div>
            ) : (
              alerts.map((alert) => (
                <div
                  key={alert._id}
                  className={`alert-item ${!alert.read ? 'unread' : ''}`}
                  onClick={() => !alert.read && handleMarkAsRead(alert._id)}
                >
                  <div className="alert-item-top">
                    <span className={`alert-severity ${alert.severity?.toLowerCase()}`}>
                      ● {alert.severity?.toUpperCase()}
                    </span>
                    <span className="alert-time">{formatTimeAgo(alert.createdAt)}</span>
                    <button
                      className="btn-delete-alert"
                      onClick={(e) => handleDeleteAlert(e, alert._id)}
                      title="Dismiss alert"
                    >
                      ✕
                    </button>
                  </div>
                  <div className="alert-item-indicator">{alert.iocIndicator}</div>
                  <div className="alert-item-meta">
                    Matched: <span className="alert-pattern">{alert.matchedPattern}</span>
                    <span className="alert-type">{alert.iocType?.toUpperCase()}</span>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="bell-dropdown-footer">
            <button
              onClick={() => {
                setWatchlistOpen(true);
                setIsOpen(false);
              }}
              className="btn-watchlist-settings"
            >
              🛠️ WATCHLIST CONFIG
            </button>
          </div>
        </div>
      )}

      {/* ── Watchlist Modal Configuration ── */}
      <WatchlistModal
        isOpen={watchlistOpen}
        onClose={() => setWatchlistOpen(false)}
      />
    </div>
  );
};

export default NotificationBell;
