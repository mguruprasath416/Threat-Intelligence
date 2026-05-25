// ============================================================
// pages/Reports.jsx — ANALYST REPORTS PAGE
// ============================================================
// Lists all saved reports + allows creating new ones.
// Reports bundle IOC investigations into shareable documents.
// ============================================================

import { useEffect, useState } from 'react';
import api    from '../api/axios';
import Loader from '../components/Loader/Loader';
import { formatDateTime } from '../utils/formatDate';
import './Reports.css';

const STATUS_COLORS = {
  draft:     'var(--yellow)',
  published: 'var(--green)',
  archived:  'var(--text-dim)',
};

const Reports = () => {
  const [reports,  setReports]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form,     setForm]     = useState({ title: '', description: '', reportType: 'custom' });
  const [creating, setCreating] = useState(false);

  useEffect(() => { fetchReports(); }, []);

  const fetchReports = async () => {
    try {
      const res = await api.get('/reports');
      setReports(res.data.data.reports);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!form.title.trim()) return;
    setCreating(true);
    try {
      await api.post('/reports', form);
      setShowForm(false);
      setForm({ title: '', description: '', reportType: 'custom' });
      fetchReports();
    } catch (err) {
      console.error(err);
    } finally {
      setCreating(false);
    }
  };

  const handlePublish = async (id) => {
    try {
      await api.post(`/reports/${id}/publish`);
      fetchReports();
    } catch (err) { console.error(err); }
  };

  return (
    <div className="reports-page animate-in">

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">THREAT REPORTS</h1>
          <p className="page-subtitle">Analyst investigation reports and threat summaries</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowForm(p => !p)}>
          + NEW REPORT
        </button>
      </div>

      {/* ── Create Form ── */}
      {showForm && (
        <div className="card report-form animate-in">
          <div className="chart-panel-title">CREATE NEW REPORT</div>
          <div className="form-fields">
            <input
              className="input"
              placeholder="Report title..."
              value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
            />
            <textarea
              className="input report-textarea"
              placeholder="Description (optional)..."
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            />
            <select
              className="input"
              value={form.reportType}
              onChange={e => setForm(f => ({ ...f, reportType: e.target.value }))}
            >
              <option value="custom">Custom</option>
              <option value="incident">Incident Report</option>
              <option value="campaign">Campaign Analysis</option>
              <option value="daily_summary">Daily Summary</option>
              <option value="threat_actor">Threat Actor</option>
            </select>
          </div>
          <div className="form-actions">
            <button className="btn" onClick={() => setShowForm(false)}>CANCEL</button>
            <button
              className="btn btn-primary"
              onClick={handleCreate}
              disabled={creating || !form.title.trim()}
            >
              {creating ? 'CREATING...' : 'CREATE REPORT'}
            </button>
          </div>
        </div>
      )}

      {/* ── Reports List ── */}
      {loading ? (
        <Loader message="LOADING REPORTS..." />
      ) : reports.length === 0 ? (
        <div className="card reports-empty">
          <div className="empty-icon">📋</div>
          <div className="empty-title">NO REPORTS YET</div>
          <div className="empty-sub">Create your first threat intelligence report</div>
        </div>
      ) : (
        <div className="reports-grid">
          {reports.map(report => (
            <div key={report._id} className="report-card card">
              <div className="report-card-header">
                <span className="report-type">{report.reportType?.toUpperCase()}</span>
                <span
                  className="report-status"
                  style={{ color: STATUS_COLORS[report.status] }}
                >
                  ● {report.status?.toUpperCase()}
                </span>
              </div>

              <h3 className="report-title">{report.title}</h3>

              {report.description && (
                <p className="report-desc">{report.description}</p>
              )}

              <div className="report-summary">
                <span className="summary-item critical">
                  {report.summary?.criticalCount || 0} Critical
                </span>
                <span className="summary-item high">
                  {report.summary?.highCount || 0} High
                </span>
                <span className="summary-item">
                  {report.summary?.totalIOCs || 0} Total IOCs
                </span>
              </div>

              <div className="report-footer">
                <span className="report-author">
                  by {report.createdBy?.username || 'Unknown'}
                </span>
                <span className="report-date">{formatDateTime(report.createdAt)}</span>
              </div>

              {report.status === 'draft' && (
                <div className="report-actions">
                  <button
                    className="btn"
                    onClick={() => handlePublish(report._id)}
                  >
                    PUBLISH
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Reports;
