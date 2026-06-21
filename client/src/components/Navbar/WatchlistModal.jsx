// ============================================================
// components/Navbar/WatchlistModal.jsx — WATCHLIST CONFIG MODAL
// ============================================================

import { useState, useEffect } from 'react';
import api from '../../api/axios';
import './WatchlistModal.css';

const WatchlistModal = ({ isOpen, onClose }) => {
  const [patterns, setPatterns] = useState([]);
  const [newPattern, setNewPattern] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchWatchlist();
    }
  }, [isOpen]);

  const fetchWatchlist = async () => {
    setLoading(true);
    setError('');
    setSuccess(false);
    try {
      const response = await api.get('/watchlist');
      if (response.data && response.data.patterns) {
        setPatterns(response.data.patterns);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to fetch watchlist patterns.');
    } finally {
      setLoading(false);
    }
  };

  const handleAddPattern = (e) => {
    e.preventDefault();
    const val = newPattern.trim();
    if (!val) return;
    if (patterns.includes(val)) {
      setError('Pattern already exists.');
      return;
    }
    setPatterns([...patterns, val]);
    setNewPattern('');
    setError('');
  };

  const handleRemovePattern = (indexToRemove) => {
    setPatterns(patterns.filter((_, idx) => idx !== indexToRemove));
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSuccess(false);
    try {
      const response = await api.post('/watchlist', { patterns });
      if (response.data && response.data.success) {
        setSuccess(true);
        setTimeout(() => {
          setSuccess(false);
        }, 3000);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save watchlist.');
    } finally {
      setSaving(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="watchlist-modal-backdrop" onClick={onClose}>
      <div className="watchlist-modal-content" onClick={e => e.stopPropagation()}>
        <div className="watchlist-modal-header">
          <h3>🛡️ Watchlist Settings</h3>
          <button className="watchlist-close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="watchlist-modal-body">
          <p className="watchlist-desc">
            Define threat keywords, specific domain strings, or IP address chunks.
            When newly fetched indicators match any entry, you will receive real-time notifications and email updates.
          </p>

          <form onSubmit={handleAddPattern} className="watchlist-add-form">
            <input
              type="text"
              placeholder="e.g. ransomware, evil.com, 192.168.1"
              value={newPattern}
              onChange={e => setNewPattern(e.target.value)}
              className="watchlist-input"
              disabled={loading || saving}
            />
            <button type="submit" className="btn btn-add" disabled={loading || saving}>
              + ADD
            </button>
          </form>

          {error && <div className="watchlist-error-box">{error}</div>}
          {success && <div className="watchlist-success-box">✓ Watchlist saved successfully!</div>}

          {loading ? (
            <div className="watchlist-loading">Loading configuration…</div>
          ) : (
            <div className="watchlist-list-container">
              <h4>Active Triggers ({patterns.length})</h4>
              {patterns.length === 0 ? (
                <div className="watchlist-empty-state">No active watchlist patterns. Add keywords above.</div>
              ) : (
                <ul className="watchlist-items-list">
                  {patterns.map((pat, idx) => (
                    <li key={idx} className="watchlist-item">
                      <span className="watchlist-item-text">{pat}</span>
                      <button
                        type="button"
                        onClick={() => handleRemovePattern(idx)}
                        className="btn-remove-pattern"
                        title="Remove pattern"
                      >
                        ✕
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        <div className="watchlist-modal-footer">
          <button className="btn btn-secondary" onClick={onClose} disabled={saving}>
            CANCEL
          </button>
          <button className="btn btn-primary" onClick={handleSave} disabled={saving || loading}>
            {saving ? 'SAVING…' : 'SAVE CHANGES'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default WatchlistModal;
