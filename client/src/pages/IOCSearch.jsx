// ============================================================
// pages/IOCSearch.jsx (rendered at /search route)
// ============================================================
// The search page combines IOCSearch bar + result ThreatCard
// + the full paginated IOC table below.
// ============================================================

import { useEffect, useState } from 'react';
import { useIOC }       from '../hooks/useIOC';
import IOCSearch        from '../components/IOCSearch/IOCSearch';
import ThreatCard       from '../components/ThreatCard/ThreatCard';
import ThreatTable      from '../components/ThreatTable/ThreatTable';
import Loader           from '../components/Loader/Loader';
import BulkUpload       from '../components/BulkUpload/BulkUpload';
import axios            from '../api/axios';
import './SearchPage.css';

// Filter bar component
const FilterBar = ({ filters, onChange }) => (
  <div className="filter-bar">
    <select
      className="filter-select"
      value={filters.severity}
      onChange={e => onChange({ ...filters, severity: e.target.value, page: 1 })}
    >
      <option value="">ALL SEVERITIES</option>
      <option value="Critical">CRITICAL</option>
      <option value="High">HIGH</option>
      <option value="Medium">MEDIUM</option>
      <option value="Low">LOW</option>
    </select>

    <select
      className="filter-select"
      value={filters.iocType}
      onChange={e => onChange({ ...filters, iocType: e.target.value, page: 1 })}
    >
      <option value="">ALL TYPES</option>
      <option value="ip">IP ADDRESS</option>
      <option value="domain">DOMAIN</option>
      <option value="url">URL</option>
      <option value="hash">HASH</option>
    </select>

    <input
      type="text"
      className="filter-input input"
      placeholder="Search indicators..."
      value={filters.search}
      onChange={e => onChange({ ...filters, search: e.target.value, page: 1 })}
    />

    <button
      className="btn"
      onClick={() => onChange({ severity: '', iocType: '', search: '', page: 1 })}
    >
      CLEAR
    </button>
  </div>
);

const IOCSearchPage = () => {
  const { searchResult, iocs, pagination, isFetching, fetchIOCs, clearSearch } = useIOC();

  const [filters, setFilters] = useState({
    severity: '', iocType: '', search: '', page: 1,
    sortBy: 'createdAt', sortOrder: 'desc',
  });

  const [showBulkUpload, setShowBulkUpload] = useState(false);
  const [exporting, setExporting] = useState(false);

  // Re-fetch whenever filters change (with 300ms debounce on search text)
  useEffect(() => {
    const delay = filters.search ? 300 : 0;
    const timer = setTimeout(() => {
      fetchIOCs(filters);
    }, delay);
    return () => clearTimeout(timer);
  }, [filters, fetchIOCs]);

  const handleSort = (field) => {
    setFilters(prev => ({
      ...prev,
      sortBy:    field,
      sortOrder: prev.sortBy === field && prev.sortOrder === 'desc' ? 'asc' : 'desc',
    }));
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const token = localStorage.getItem('token');
      const queryParams = new URLSearchParams({
        severity: filters.severity || '',
        iocType: filters.iocType || '',
        search: filters.search || '',
        isActive: 'true'
      });

      const response = await axios.get(`/api/ioc/export?${queryParams}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `ioc-export-${Date.now()}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
      alert('Export failed. Please try again.');
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="search-page animate-in">

      {/* ── Page Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">IOC SEARCH & ANALYSIS</h1>
          <p className="page-subtitle">Enrich indicators against multiple threat intelligence sources</p>
        </div>
        <div className="header-actions">
          <button
            className="btn btn-secondary"
            onClick={() => setShowBulkUpload(true)}
          >
            Bulk Import
          </button>
          <button
            className="btn btn-primary"
            onClick={handleExport}
            disabled={exporting || !iocs.length}
          >
            {exporting ? 'Exporting...' : 'Export CSV'}
          </button>
        </div>
      </div>

      {/* ── Search Bar ── */}
      <IOCSearch onResult={() => {}} />

      {/* ── Search Result Card ── */}
      {searchResult && (
        <div className="search-result-section animate-in">
          <div className="result-header">
            <span className="result-label">◈ ENRICHMENT RESULT</span>
            <button className="btn" onClick={clearSearch}>CLEAR</button>
          </div>
          <ThreatCard ioc={searchResult} />
        </div>
      )}

      {/* ── IOC Table Section ── */}
      <div className="card table-section">
        <div className="table-header">
          <span className="chart-panel-title" style={{ margin: 0 }}>
            ALL IOCs {pagination && `(${pagination.total})`}
          </span>
          <FilterBar filters={filters} onChange={setFilters} />
        </div>

        {isFetching && !iocs.length ? (
          <Loader message="LOADING IOCs..." />
        ) : (
          <ThreatTable
            iocs={iocs}
            pagination={pagination}
            onPageChange={(p) => setFilters(f => ({ ...f, page: p }))}
            onSort={handleSort}
            sortBy={filters.sortBy}
            sortOrder={filters.sortOrder}
          />
        )}
      </div>

      {/* ── Bulk Upload Modal ── */}
      <BulkUpload
        isOpen={showBulkUpload}
        onClose={() => setShowBulkUpload(false)}
        onSuccess={() => fetchIOCs(filters)}
      />

    </div>
  );
};

export default IOCSearchPage;
