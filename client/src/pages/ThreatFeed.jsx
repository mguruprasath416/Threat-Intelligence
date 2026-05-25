// ============================================================
// pages/ThreatFeed.jsx — LIVE THREAT FEED PAGE
// ============================================================
// Displays the latest IOCs pulled from automated feeds
// (primarily OpenPhish + scheduled enrichment jobs).
// Auto-refreshes every 30 seconds to show new threats.
//
// Features:
//   - Live feed ticker at top
//   - Filterable IOC table (feed source)
//   - Stats: new in last hour, new today
//   - Click IOC → goes to details page
// ============================================================

import { useEffect, useState, useRef } from 'react';
import { useIOC }       from '../hooks/useIOC';
import ThreatTable      from '../components/ThreatTable/ThreatTable';
import Loader           from '../components/Loader/Loader';
import './ThreatFeed.css';

// Marquee ticker showing recent critical/high IOCs
const ThreatTicker = ({ iocs }) => {
  const criticals = iocs.filter(i => i.severity === 'Critical' || i.severity === 'High').slice(0, 15);
  if (!criticals.length) return null;

  return (
    <div className="threat-ticker">
      <div className="ticker-label">⚡ LIVE THREATS</div>
      <div className="ticker-track">
        <div className="ticker-content">
          {[...criticals, ...criticals].map((ioc, i) => (
            <span key={i} className="ticker-item">
              <span
                className="ticker-severity"
                style={{ color: ioc.severity === 'Critical' ? 'var(--red)' : 'var(--orange)' }}
              >
                [{ioc.severity}]
              </span>
              {' '}
              <span className="ticker-indicator">{ioc.indicator}</span>
              <span className="ticker-sep">◆</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};

const ThreatFeed = () => {
  const { iocs, pagination, isFetching, fetchIOCs } = useIOC();

  const [filters, setFilters] = useState({
    source: 'openphish', page: 1,
    sortBy: 'createdAt', sortOrder: 'desc',
    isActive: true,
  });

  const [secondsAgo, setSecondsAgo] = useState(0);
  const refreshTimer = useRef(null);
  const clockTimer   = useRef(null);

  // Auto-refresh every 30 seconds
  const doRefresh = () => {
    fetchIOCs(filters);
    setSecondsAgo(0);
  };

  useEffect(() => {
    doRefresh();
    refreshTimer.current = setInterval(doRefresh, 30_000);
    clockTimer.current   = setInterval(() => setSecondsAgo(s => s + 1), 1000);
    return () => {
      clearInterval(refreshTimer.current);
      clearInterval(clockTimer.current);
    };
  }, [filters.page, filters.source]);

  // Stats from current IOC list
  const now           = Date.now();
  const newLastHour   = iocs.filter(i => now - new Date(i.createdAt) < 3_600_000).length;
  const newToday      = iocs.filter(i => now - new Date(i.createdAt) < 86_400_000).length;

  return (
    <div className="feed-page animate-in">

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            LIVE THREAT FEED
            <span className="live-dot" />
          </h1>
          <p className="page-subtitle">
            Auto-refreshes every 30s — last updated {secondsAgo}s ago
          </p>
        </div>
        <div className="header-actions">
          <select
            className="filter-select"
            value={filters.source}
            onChange={e => setFilters(f => ({ ...f, source: e.target.value, page: 1 }))}
          >
            <option value="">ALL SOURCES</option>
            <option value="openphish">OpenPhish</option>
            <option value="manual">Manual</option>
            <option value="api_enrichment">API Enrichment</option>
          </select>
          <button className="btn btn-primary" onClick={doRefresh}>
            ↻ REFRESH NOW
          </button>
        </div>
      </div>

      {/* ── Live Ticker ── */}
      <ThreatTicker iocs={iocs} />

      {/* ── Feed Stats Row ── */}
      <div className="feed-stats">
        <div className="feed-stat-card">
          <div className="feed-stat-value cyan">{pagination?.total || 0}</div>
          <div className="feed-stat-label">TOTAL ACTIVE</div>
        </div>
        <div className="feed-stat-card">
          <div className="feed-stat-value red">{newLastHour}</div>
          <div className="feed-stat-label">NEW (1H)</div>
        </div>
        <div className="feed-stat-card">
          <div className="feed-stat-value orange">{newToday}</div>
          <div className="feed-stat-label">NEW (24H)</div>
        </div>
        <div className="feed-stat-card">
          <div className="feed-stat-value green">{30 - secondsAgo}s</div>
          <div className="feed-stat-label">NEXT REFRESH</div>
        </div>
      </div>

      {/* ── Live Feed Table ── */}
      <div className="card table-section">
        <div className="table-header">
          <span className="chart-panel-title" style={{ margin: 0 }}>
            ACTIVE THREAT INDICATORS
          </span>
          {isFetching && (
            <span className="fetching-label">⟳ SYNCING...</span>
          )}
        </div>

        {isFetching && !iocs.length ? (
          <Loader message="FETCHING THREAT FEED..." />
        ) : (
          <ThreatTable
            iocs={iocs}
            pagination={pagination}
            onPageChange={(p) => setFilters(f => ({ ...f, page: p }))}
          />
        )}
      </div>

    </div>
  );
};

export default ThreatFeed;
