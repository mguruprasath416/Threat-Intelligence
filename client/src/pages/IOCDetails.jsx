// ============================================================
// pages/IOCDetails.jsx — SINGLE IOC DETAILS PAGE
// ============================================================
// Full detail view for one IOC — accessed by clicking a row
// in ThreatTable or by navigating to /ioc/:id directly.
// Shows the full ThreatCard with all enrichment data,
// plus raw JSON for analysts who need it.
// ============================================================

import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api        from '../api/axios';
import ThreatCard from '../components/ThreatCard/ThreatCard';
import Loader     from '../components/Loader/Loader';
import './IOCDetails.css';

const IOCDetails = () => {
  const { id }     = useParams();   // /ioc/:id
  const navigate   = useNavigate();
  const [ioc,      setIOC]      = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [showRaw,  setShowRaw]  = useState(false);

  useEffect(() => {
    const fetchIOC = async () => {
      try {
        setLoading(true);
        const response = await api.get(`/ioc/${id}`);
        setIOC(response.data.data);
      } catch (err) {
        setError(err.userMessage || 'IOC not found');
      } finally {
        setLoading(false);
      }
    };
    fetchIOC();
  }, [id]);

  if (loading) return <div className="page-center"><Loader message="FETCHING IOC DATA..." /></div>;

  if (error) {
    return (
      <div className="ioc-details-page animate-in">
        <div className="details-error">
          <div className="error-code">404</div>
          <div className="error-msg">{error}</div>
          <button className="btn" onClick={() => navigate(-1)}>← GO BACK</button>
        </div>
      </div>
    );
  }

  return (
    <div className="ioc-details-page animate-in">

      {/* ── Breadcrumb ── */}
      <div className="breadcrumb">
        <button className="breadcrumb-back" onClick={() => navigate(-1)}>← BACK</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current mono">{ioc?.indicator}</span>
      </div>

      {/* ── Main Card ── */}
      <ThreatCard ioc={ioc} />

      {/* ── Raw JSON Toggle ── */}
      <div className="raw-section card">
        <div className="raw-header" onClick={() => setShowRaw(p => !p)}>
          <span className="chart-panel-title" style={{ margin: 0 }}>RAW ENRICHMENT DATA</span>
          <span className="raw-toggle">{showRaw ? '▲ COLLAPSE' : '▼ EXPAND'}</span>
        </div>
        {showRaw && (
          <pre className="raw-json">
            {JSON.stringify(ioc?.enrichment, null, 2)}
          </pre>
        )}
      </div>

    </div>
  );
};

export default IOCDetails;
