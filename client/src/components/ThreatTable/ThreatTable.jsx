// ============================================================
// components/ThreatTable/ThreatTable.jsx — IOC DATA TABLE
// ============================================================
// Paginated, sortable table for displaying lists of IOCs.
// Features:
//   - Severity color coding per row
//   - IOC type icons
//   - Threat score bar
//   - Click row → navigate to IOC details
//   - Flag false positive button
//   - Delete button (admin only)
//   - Pagination controls
// ============================================================

import { useNavigate } from 'react-router-dom';
import { useAuth }     from '../../hooks/useAuth';
import { useIOC }      from '../../hooks/useIOC';
import {
  getSeverityClass, getTypeColor, getSeverityColor,
} from '../../utils/formatDate';
import { timeAgo } from '../../utils/formatDate';
import './ThreatTable.css';

const ScoreBar = ({ score }) => {
  const color = score >= 76 ? 'var(--red)'
              : score >= 51 ? 'var(--orange)'
              : score >= 26 ? 'var(--yellow)'
              : 'var(--green)';
  return (
    <div className="score-bar-wrapper">
      <div
        className="score-bar-fill"
        style={{ width: `${score}%`, background: color }}
      />
      <span className="score-bar-label">{score}</span>
    </div>
  );
};

const TypeIcon = ({ type }) => {
  const icons = {
    ip:     '◈',
    domain: '◉',
    url:    '◎',
    hash:   '◆',
    email:  '◇',
  };
  return (
    <span
      className="type-icon"
      style={{ color: getTypeColor(type) }}
      title={type}
    >
      {icons[type] || '○'}
    </span>
  );
};

const ThreatTable = ({ iocs, pagination, onPageChange, onSort, sortBy, sortOrder }) => {
  const navigate  = useNavigate();
  const { isAdmin } = useAuth();
  const { flagFP, deleteIOC } = useIOC();

  const handleDelete = async (e, iocId) => {
    e.stopPropagation(); // Prevent row click
    if (window.confirm('Archive this IOC?')) {
      await deleteIOC(iocId);
    }
  };

  const handleFlag = async (e, iocId) => {
    e.stopPropagation();
    await flagFP(iocId);
  };

  const handleSort = (field) => {
    if (onSort) onSort(field);
  };

  const SortIcon = ({ field }) => {
    if (sortBy !== field) return <span className="sort-icon neutral">↕</span>;
    return <span className="sort-icon active">{sortOrder === 'desc' ? '↓' : '↑'}</span>;
  };

  if (!iocs || iocs.length === 0) {
    return (
      <div className="table-empty">
        <div className="empty-icon">⬡</div>
        <div className="empty-title">NO IOCs FOUND</div>
        <div className="empty-sub">Search or import indicators to begin analysis</div>
      </div>
    );
  }

  return (
    <div className="threat-table-wrapper">
      <table className="data-table threat-table">
        <thead>
          <tr>
            <th className="col-type">TYPE</th>
            <th className="col-indicator sortable" onClick={() => handleSort('indicator')}>
              INDICATOR <SortIcon field="indicator" />
            </th>
            <th className="col-severity sortable" onClick={() => handleSort('severity')}>
              SEVERITY <SortIcon field="severity" />
            </th>
            <th className="col-score sortable" onClick={() => handleSort('threatScore')}>
              SCORE <SortIcon field="threatScore" />
            </th>
            <th className="col-source">SOURCE</th>
            <th className="col-seen sortable"  onClick={() => handleSort('createdAt')}>
              FIRST SEEN <SortIcon field="createdAt" />
            </th>
            <th className="col-actions">ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc) => (
            <tr
              key={ioc._id}
              className={`table-row ${ioc.isFP ? 'is-fp' : ''} ${ioc.severity?.toLowerCase()}`}
              onClick={() => navigate(`/ioc/${ioc._id}`)}
              title="Click to view details"
            >
              {/* Type */}
              <td className="col-type">
                <TypeIcon type={ioc.iocType} />
                <span
                  className="type-label"
                  style={{ color: getTypeColor(ioc.iocType) }}
                >
                  {ioc.iocType?.toUpperCase()}
                </span>
              </td>

              {/* Indicator */}
              <td className="col-indicator">
                <div className="indicator-cell">
                  <span className="indicator-value mono">
                    {ioc.indicator?.length > 50
                      ? ioc.indicator.slice(0, 50) + '…'
                      : ioc.indicator}
                  </span>
                  {ioc.isFP && (
                    <span className="fp-badge">FALSE POSITIVE</span>
                  )}
                </div>
              </td>

              {/* Severity */}
              <td className="col-severity">
                <span className={`badge ${getSeverityClass(ioc.severity)}`}>
                  {ioc.severity}
                </span>
              </td>

              {/* Score Bar */}
              <td className="col-score">
                <ScoreBar score={ioc.threatScore || 0} />
              </td>

              {/* Source */}
              <td className="col-source">
                <span className="source-label">{ioc.source || 'manual'}</span>
              </td>

              {/* First Seen */}
              <td className="col-seen">
                <span className="time-label">{timeAgo(ioc.createdAt)}</span>
              </td>

              {/* Actions */}
              <td className="col-actions" onClick={(e) => e.stopPropagation()}>
                <div className="action-btns">
                  <button
                    className={`action-btn flag ${ioc.isFP ? 'active' : ''}`}
                    onClick={(e) => handleFlag(e, ioc._id)}
                    title={ioc.isFP ? 'Unmark False Positive' : 'Mark False Positive'}
                  >
                    FP
                  </button>
                  {isAdmin && (
                    <button
                      className="action-btn delete"
                      onClick={(e) => handleDelete(e, ioc._id)}
                      title="Archive IOC"
                    >
                      ✕
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* ── Pagination ── */}
      {pagination && pagination.totalPages > 1 && (
        <div className="table-pagination">
          <span className="pagination-info">
            Showing {((pagination.page - 1) * pagination.limit) + 1}–
            {Math.min(pagination.page * pagination.limit, pagination.total)} of{' '}
            {pagination.total} IOCs
          </span>
          <div className="pagination-controls">
            <button
              className="page-btn"
              onClick={() => onPageChange(pagination.page - 1)}
              disabled={pagination.page <= 1}
            >
              ◀ PREV
            </button>
            {Array.from({ length: Math.min(pagination.totalPages, 7) }, (_, i) => i + 1).map(p => (
              <button
                key={p}
                className={`page-btn ${p === pagination.page ? 'active' : ''}`}
                onClick={() => onPageChange(p)}
              >
                {p}
              </button>
            ))}
            <button
              className="page-btn"
              onClick={() => onPageChange(pagination.page + 1)}
              disabled={pagination.page >= pagination.totalPages}
            >
              NEXT ▶
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatTable;
