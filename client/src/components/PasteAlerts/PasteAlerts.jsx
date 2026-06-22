// ============================================================
// components/PasteAlerts/PasteAlerts.jsx — PASTE ALERTS COMPONENT
// ============================================================
// Real-time feed of paste hits from dark web monitoring
// Shows IOC matches, credential dumps, and watchlist hits
// ============================================================

import { useState, useEffect } from 'react';
import axios from '../../api/axios';
import Loader from '../Loader/Loader';
import './PasteAlerts.css';

const PasteAlerts = () => {
  const [pastes, setPastes] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [watchlist, setWatchlist] = useState([]);
  const [newPattern, setNewPattern] = useState('');
  const [patternType, setPatternType] = useState('keyword');
  const [socket, setSocket] = useState(null);

  // Fetch recent pastes on mount
  useEffect(() => {
    const fetchPastes = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get('/paste/recent', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setPastes(response.data.data || []);
        setLoading(false);
      } catch (err) {
        console.error('Failed to fetch pastes:', err);
        setLoading(false);
      }
    };

    const fetchStats = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get('/paste/stats', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setStats(response.data.data);
      } catch (err) {
        console.error('Failed to fetch stats:', err);
      }
    };

    const fetchWatchlist = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get('/paste/watchlist', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setWatchlist(response.data.data || []);
      } catch (err) {
        console.error('Failed to fetch watchlist:', err);
      }
    };

    fetchPastes();
    fetchStats();
    fetchWatchlist();
  }, []);

  // Socket.io connection for real-time alerts
  useEffect(() => {
    const socketUrl = import.meta.env.VITE_API_URL?.replace('/api', '') || 'http://localhost:5000';
    const newSocket = new WebSocket(`${socketUrl.replace('http', 'ws')}`);
    
    newSocket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'paste-alert') {
        setPastes(prev => [data.payload, ...prev].slice(0, 50));
      }
    };

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, []);

  // Add watchlist pattern
  const handleAddPattern = async (e) => {
    e.preventDefault();
    if (!newPattern.trim()) return;

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('/paste/watchlist', {
        pattern: newPattern.trim(),
        patternType,
        description: ''
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setWatchlist(prev => [response.data.data, ...prev]);
      setNewPattern('');
    } catch (err) {
      console.error('Failed to add pattern:', err);
      alert('Failed to add pattern');
    }
  };

  // Delete watchlist pattern
  const handleDeletePattern = async (id) => {
    try {
      const token = localStorage.getItem('token');
      await axios.delete(`/paste/watchlist/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setWatchlist(prev => prev.filter(p => p._id !== id));
    } catch (err) {
      console.error('Failed to delete pattern:', err);
      alert('Failed to delete pattern');
    }
  };

  // Get severity badge class
  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'severity-critical';
      case 'high':
        return 'severity-high';
      case 'medium':
        return 'severity-medium';
      case 'low':
        return 'severity-low';
      default:
        return 'severity-medium';
    }
  };

  // Format date
  const formatDate = (date) => {
    return new Date(date).toLocaleString();
  };

  if (loading) {
    return (
      <div className="paste-alerts-container">
        <div className="page-header">
          <h1 className="page-title">PASTE ALERTS</h1>
          <p className="page-subtitle">Real-time dark web monitoring</p>
        </div>
        <Loader message="Loading paste alerts..." />
      </div>
    );
  }

  return (
    <div className="paste-alerts-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">PASTE ALERTS</h1>
          <p className="page-subtitle">Real-time dark web monitoring</p>
        </div>
        {stats && (
          <div className="stats-summary">
            <div className="stat-item">
              <span className="stat-value">{stats.total}</span>
              <span className="stat-label">Last 7 Days</span>
            </div>
          </div>
        )}
      </div>

      {/* Paste Hits Table */}
      <div className="paste-table-container">
        <h2 className="section-title">Recent Paste Hits</h2>
        <div className="paste-table-wrapper">
          <table className="paste-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Paste Title</th>
                <th>Match Type</th>
                <th>Matched Value</th>
                <th>Severity</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pastes.length === 0 ? (
                <tr>
                  <td colSpan="6" className="empty-state">
                    No paste hits found
                  </td>
                </tr>
              ) : (
                pastes.map((paste) => (
                  <tr key={paste._id}>
                    <td className="time-cell">{formatDate(paste.dateFound)}</td>
                    <td className="title-cell">{paste.pasteTitle}</td>
                    <td className="type-cell">{paste.matchType}</td>
                    <td className="value-cell">{paste.matchedValue}</td>
                    <td className="severity-cell">
                      <span className={`severity-badge ${getSeverityClass(paste.severity)}`}>
                        {paste.severity}
                      </span>
                    </td>
                    <td className="actions-cell">
                      <a
                        href={paste.pasteUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="btn btn-secondary btn-sm"
                      >
                        View Paste
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Watchlist Manager */}
      <div className="watchlist-container">
        <h2 className="section-title">Watchlist Patterns</h2>
        
        {/* Add Pattern Form */}
        <form className="add-pattern-form" onSubmit={handleAddPattern}>
          <div className="form-row">
            <input
              type="text"
              className="form-input"
              placeholder="Enter keyword or regex pattern..."
              value={newPattern}
              onChange={(e) => setNewPattern(e.target.value)}
            />
            <select
              className="form-select"
              value={patternType}
              onChange={(e) => setPatternType(e.target.value)}
            >
              <option value="keyword">Keyword</option>
              <option value="regex">Regex</option>
            </select>
            <button type="submit" className="btn btn-primary">
              Add Pattern
            </button>
          </div>
        </form>

        {/* Watchlist Patterns List */}
        <div className="watchlist-list">
          {watchlist.length === 0 ? (
            <div className="empty-state">
              <p>No watchlist patterns added yet</p>
            </div>
          ) : (
            watchlist.map((pattern) => (
              <div key={pattern._id} className="watchlist-item">
                <div className="pattern-info">
                  <span className="pattern-value">{pattern.pattern}</span>
                  <span className="pattern-type">{pattern.patternType}</span>
                  <span className="pattern-hits">{pattern.hitCount} hits</span>
                </div>
                <button
                  className="btn btn-secondary btn-sm delete-btn"
                  onClick={() => handleDeletePattern(pattern._id)}
                >
                  Delete
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default PasteAlerts;
