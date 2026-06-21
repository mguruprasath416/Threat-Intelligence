// ============================================================
// pages/ThreatActorPage.jsx — THREAT ACTOR TRACKING MODULE
// ============================================================
// Two views:
//   LIST  — paginated actor cards with search/filter sidebar
//   DETAIL — full actor profile with linked IOCs + MITRE heatmap
// ============================================================

import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useParams, useLocation } from 'react-router-dom';
import api from '../api/axios';
import MitreHeatmap from '../components/MitreHeatmap/MitreHeatmap';
import './ThreatActorPage.css';

// ─── Constants ───────────────────────────────────────────────
const MOTIVATION_COLORS = {
  financial:   { bg: '#1A2F1A', text: '#4ADE80', border: '#166534' },
  espionage:   { bg: '#1A1A2E', text: '#818CF8', border: '#312E81' },
  hacktivism:  { bg: '#2D1B1B', text: '#F87171', border: '#7F1D1D' },
  sabotage:    { bg: '#2D1A0A', text: '#FB923C', border: '#7C2D12' },
  disruption:  { bg: '#1F1A2D', text: '#C084FC', border: '#4C1D95' },
  unknown:     { bg: '#1A2435', text: '#8A9BB0', border: '#1E2D40' },
};

const ACTOR_TYPE_ICONS = {
  apt:        '🎯',
  criminal:   '💰',
  hacktivist: '✊',
  insider:    '👤',
  unknown:    '❓',
};

const CONFIDENCE_LABEL = (v) =>
  v >= 80 ? 'High' : v >= 50 ? 'Medium' : 'Low';

const CONFIDENCE_COLOR = (v) =>
  v >= 80 ? '#4ADE80' : v >= 50 ? '#F5A623' : '#8A9BB0';

// ─── Actor Card (list view) ───────────────────────────────
const ActorCard = ({ actor, onClick }) => {
  const mc = MOTIVATION_COLORS[actor.motivation] || MOTIVATION_COLORS.unknown;
  return (
    <div className="actor-card" onClick={() => onClick(actor._id)} role="button" tabIndex={0}
         onKeyDown={e => e.key === 'Enter' && onClick(actor._id)}>

      <div className="actor-card-header">
        <div className="actor-type-icon">{ACTOR_TYPE_ICONS[actor.actorType] || '❓'}</div>
        <div className="actor-card-title">
          <h3 className="actor-name">{actor.name}</h3>
          {actor.aliases?.length > 0 && (
            <p className="actor-aliases">
              aka {actor.aliases.slice(0, 3).join(' · ')}
              {actor.aliases.length > 3 && ` +${actor.aliases.length - 3}`}
            </p>
          )}
        </div>
        {actor.isActive && <span className="active-indicator" title="Active threat" />}
      </div>

      <div className="actor-card-meta">
        <div className="meta-row">
          <span className="meta-flag">{actor.countryCode || '🌍'}</span>
          <span className="meta-country">{actor.country || 'Unknown'}</span>
        </div>
        <div className="meta-badge" style={{
          background: mc.bg,
          color: mc.text,
          borderColor: mc.border,
        }}>
          {actor.motivation?.toUpperCase()}
        </div>
      </div>

      {actor.targetSectors?.length > 0 && (
        <div className="actor-sectors">
          {actor.targetSectors.slice(0, 4).map(s => (
            <span key={s} className="sector-tag">{s}</span>
          ))}
          {actor.targetSectors.length > 4 && (
            <span className="sector-more">+{actor.targetSectors.length - 4}</span>
          )}
        </div>
      )}

      <div className="actor-card-footer">
        <div className="footer-stat">
          <span className="fs-val">{actor.iocCount || 0}</span>
          <span className="fs-label">IOCs</span>
        </div>
        <div className="footer-stat">
          <span className="fs-val">{actor.ttps?.length || 0}</span>
          <span className="fs-label">TTPs</span>
        </div>
        <div className="footer-stat">
          <span className="fs-val" style={{ color: CONFIDENCE_COLOR(actor.confidence) }}>
            {actor.confidence || 0}%
          </span>
          <span className="fs-label">Conf.</span>
        </div>
        <div className="actor-chevron">›</div>
      </div>
    </div>
  );
};

// ─── Create Actor Modal ───────────────────────────────────
const CreateActorModal = ({ onClose, onCreated }) => {
  const [form, setForm] = useState({
    name: '', aliases: '', country: '', motivation: 'unknown',
    actorType: 'unknown', confidence: 50, description: '', targetSectors: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const payload = {
        ...form,
        aliases: form.aliases.split(',').map(s => s.trim()).filter(Boolean),
        targetSectors: form.targetSectors.split(',').map(s => s.trim()).filter(Boolean),
      };
      const { data } = await api.post('/actors', payload);
      onCreated(data.data);
    } catch (err) {
      setError(err.userMessage || 'Failed to create actor');
    } finally {
      setLoading(false);
    }
  };

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-panel">
        <div className="modal-header">
          <h2>New Threat Actor Profile</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <form className="modal-form" onSubmit={handleSubmit}>
          <div className="form-row">
            <div className="form-group">
              <label>Actor Name *</label>
              <input required value={form.name} onChange={e => set('name', e.target.value)}
                     placeholder="e.g. APT29, Lazarus Group" />
            </div>
            <div className="form-group">
              <label>Aliases <span className="form-hint">(comma-separated)</span></label>
              <input value={form.aliases} onChange={e => set('aliases', e.target.value)}
                     placeholder="Cozy Bear, The Dukes" />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Country / Attribution</label>
              <input value={form.country} onChange={e => set('country', e.target.value)}
                     placeholder="Russia, China, Unknown..." />
            </div>
            <div className="form-group">
              <label>Actor Type</label>
              <select value={form.actorType} onChange={e => set('actorType', e.target.value)}>
                <option value="apt">APT Group</option>
                <option value="criminal">Criminal</option>
                <option value="hacktivist">Hacktivist</option>
                <option value="insider">Insider</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Motivation</label>
              <select value={form.motivation} onChange={e => set('motivation', e.target.value)}>
                <option value="financial">Financial</option>
                <option value="espionage">Espionage</option>
                <option value="hacktivism">Hacktivism</option>
                <option value="sabotage">Sabotage</option>
                <option value="disruption">Disruption</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>
            <div className="form-group">
              <label>Confidence: {form.confidence}%</label>
              <input type="range" min="0" max="100" value={form.confidence}
                     onChange={e => set('confidence', Number(e.target.value))}
                     className="confidence-slider" />
            </div>
          </div>
          <div className="form-group">
            <label>Target Sectors <span className="form-hint">(comma-separated)</span></label>
            <input value={form.targetSectors} onChange={e => set('targetSectors', e.target.value)}
                   placeholder="Finance, Healthcare, Government..." />
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea value={form.description} onChange={e => set('description', e.target.value)}
                      rows={3} placeholder="Brief threat actor profile..." />
          </div>

          {error && <div className="form-error">{error}</div>}

          <div className="form-actions">
            <button type="button" className="btn-cancel" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-create" disabled={loading}>
              {loading ? 'Creating…' : 'Create Actor'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// ─── Detail View ──────────────────────────────────────────
const ActorDetail = ({ actorId, onBack }) => {
  const [actor, setActor] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const { data } = await api.get(`/actors/${actorId}`);
        setActor(data.data);
      } catch (e) {
        setError(e.userMessage || 'Failed to load actor');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [actorId]);

  if (loading) return (
    <div className="detail-loading">
      <div className="pulse-ring" />
      <span>LOADING ACTOR PROFILE…</span>
    </div>
  );

  if (error) return (
    <div className="detail-error">
      <span>⚠ {error}</span>
      <button onClick={onBack}>← Back</button>
    </div>
  );

  if (!actor) return null;

  const mc = MOTIVATION_COLORS[actor.motivation] || MOTIVATION_COLORS.unknown;

  // Collect all MITRE techniques from the actor's TTPs + linked IOCs
  const allTechniques = [
    ...(actor.ttps || []),
    ...(actor.linkedIOCs || []).flatMap(ioc => ioc.mitreTechniques || []),
  ];

  return (
    <div className="actor-detail">
      {/* Back button */}
      <button className="back-btn" onClick={onBack}>
        <span>‹</span> All Actors
      </button>

      {/* Hero banner */}
      <div className="actor-hero">
        <div className="hero-left">
          <div className="hero-icon">{ACTOR_TYPE_ICONS[actor.actorType]}</div>
          <div>
            <h1 className="hero-name">{actor.name}</h1>
            {actor.aliases?.length > 0 && (
              <p className="hero-aliases">
                {actor.aliases.join(' · ')}
              </p>
            )}
          </div>
        </div>

        <div className="hero-stats">
          <div className="hstat">
            <span className="hstat-v">{actor.linkedIOCs?.length || 0}</span>
            <span className="hstat-l">Linked IOCs</span>
          </div>
          <div className="hstat">
            <span className="hstat-v">{actor.ttps?.length || 0}</span>
            <span className="hstat-l">TTPs</span>
          </div>
          <div className="hstat">
            <span className="hstat-v">{actor.campaigns?.length || 0}</span>
            <span className="hstat-l">Campaigns</span>
          </div>
          <div className="hstat">
            <span className="hstat-v" style={{ color: CONFIDENCE_COLOR(actor.confidence) }}>
              {actor.confidence}%
            </span>
            <span className="hstat-l">{CONFIDENCE_LABEL(actor.confidence)} Confidence</span>
          </div>
        </div>
      </div>

      {/* Profile cards */}
      <div className="profile-cards">
        <div className="profile-card">
          <span className="pcard-label">COUNTRY</span>
          <span className="pcard-val">{actor.country || 'Unknown'}</span>
        </div>
        <div className="profile-card">
          <span className="pcard-label">TYPE</span>
          <span className="pcard-val">{actor.actorType?.toUpperCase()}</span>
        </div>
        <div className="profile-card motivation-card" style={{
          borderColor: mc.border,
          background: mc.bg,
        }}>
          <span className="pcard-label">MOTIVATION</span>
          <span className="pcard-val" style={{ color: mc.text }}>
            {actor.motivation?.toUpperCase()}
          </span>
        </div>
        <div className="profile-card">
          <span className="pcard-label">STATUS</span>
          <span className={`pcard-val ${actor.isActive ? 'active-text' : 'inactive-text'}`}>
            {actor.isActive ? '● ACTIVE' : '○ INACTIVE'}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="detail-tabs">
        {['overview', 'iocs', 'mitre', 'campaigns'].map(tab => (
          <button
            key={tab}
            className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'overview'   && '📋 Overview'}
            {tab === 'iocs'       && `🔗 Linked IOCs (${actor.linkedIOCs?.length || 0})`}
            {tab === 'mitre'      && `⚔️ ATT&CK (${allTechniques.length})`}
            {tab === 'campaigns'  && `🎯 Campaigns (${actor.campaigns?.length || 0})`}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="tab-content">
        {/* OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="tab-overview">
            {actor.description && (
              <div className="overview-desc">
                <h4>Profile</h4>
                <p>{actor.description}</p>
              </div>
            )}
            {actor.targetSectors?.length > 0 && (
              <div className="overview-sectors">
                <h4>Target Sectors</h4>
                <div className="sectors-list">
                  {actor.targetSectors.map(s => (
                    <span key={s} className="sector-tag large">{s}</span>
                  ))}
                </div>
              </div>
            )}
            {actor.ttps?.length > 0 && (
              <div className="overview-ttps">
                <h4>Known TTPs</h4>
                <div className="ttps-list">
                  {actor.ttps.map((t, i) => (
                    <div key={i} className="ttp-row">
                      <span className="ttp-id">{t.techniqueId}</span>
                      <span className="ttp-name">{t.techniqueName}</span>
                      <span className="ttp-tactic">{t.tactic}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* LINKED IOCS */}
        {activeTab === 'iocs' && (
          <div className="tab-iocs">
            {!actor.linkedIOCs?.length ? (
              <div className="empty-tab">
                <span>🔗</span>
                <p>No IOCs linked to this actor yet</p>
              </div>
            ) : (
              <div className="ioc-table-wrap">
                <table className="ioc-table">
                  <thead>
                    <tr>
                      <th>Indicator</th>
                      <th>Type</th>
                      <th>Severity</th>
                      <th>Score</th>
                      <th>Tags</th>
                      <th>Added</th>
                    </tr>
                  </thead>
                  <tbody>
                    {actor.linkedIOCs.map(ioc => (
                      <tr key={ioc._id} className={`sev-row sev-${ioc.severity?.toLowerCase()}`}>
                        <td className="ioc-indicator">
                          <span className="ind-mono">{ioc.indicator}</span>
                        </td>
                        <td>
                          <span className={`type-badge type-${ioc.iocType}`}>
                            {ioc.iocType?.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <span className={`sev-badge sev-${ioc.severity?.toLowerCase()}`}>
                            {ioc.severity}
                          </span>
                        </td>
                        <td className="score-cell">
                          <div className="score-bar">
                            <div className="score-fill" style={{ width: `${ioc.threatScore}%` }} />
                          </div>
                          <span>{ioc.threatScore}</span>
                        </td>
                        <td>
                          <div className="ioc-tags">
                            {ioc.tags?.slice(0, 3).map(t => (
                              <span key={t} className="ioc-tag">{t}</span>
                            ))}
                          </div>
                        </td>
                        <td className="date-cell">
                          {new Date(ioc.createdAt).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* MITRE ATT&CK */}
        {activeTab === 'mitre' && (
          <div className="tab-mitre">
            <MitreHeatmap techniques={allTechniques} />
          </div>
        )}

        {/* CAMPAIGNS */}
        {activeTab === 'campaigns' && (
          <div className="tab-campaigns">
            {!actor.campaigns?.length ? (
              <div className="empty-tab">
                <span>🎯</span>
                <p>No campaigns documented for this actor</p>
              </div>
            ) : (
              <div className="campaigns-list">
                {actor.campaigns.map(c => (
                  <div key={c._id} className={`campaign-card status-${c.status}`}>
                    <div className="campaign-header">
                      <h4>{c.name}</h4>
                      <span className={`campaign-status status-${c.status}`}>
                        {c.status?.toUpperCase()}
                      </span>
                    </div>
                    {c.description && <p className="campaign-desc">{c.description}</p>}
                    {c.targets?.length > 0 && (
                      <div className="campaign-targets">
                        {c.targets.map(t => <span key={t} className="target-tag">{t}</span>)}
                      </div>
                    )}
                    {(c.startDate || c.endDate) && (
                      <div className="campaign-dates">
                        {c.startDate && <span>Start: {new Date(c.startDate).toLocaleDateString()}</span>}
                        {c.endDate   && <span>End: {new Date(c.endDate).toLocaleDateString()}</span>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// ─── Main Page ────────────────────────────────────────────
const ThreatActorPage = () => {
  const navigate = useNavigate();
  const { id }   = useParams();

  const [actors, setActors]       = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [search, setSearch]       = useState('');
  const [filters, setFilters]     = useState({ motivation: '', actorType: '' });
  const [pagination, setPagination] = useState({ page: 1, pages: 1, total: 0 });

  const loadActors = useCallback(async (page = 1) => {
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams({
        page,
        limit: 12,
        ...(search && { search }),
        ...(filters.motivation && { motivation: filters.motivation }),
        ...(filters.actorType  && { actorType: filters.actorType }),
      });
      const { data } = await api.get(`/actors?${params}`);
      setActors(data.data);
      setPagination(data.pagination);
    } catch (e) {
      setError(e.userMessage || 'Failed to load threat actors');
    } finally {
      setLoading(false);
    }
  }, [search, filters]);

  useEffect(() => {
    if (!id) loadActors();
  }, [id, loadActors]);

  const handleActorCreated = (actor) => {
    setShowCreate(false);
    navigate(`/threat-actors/${actor._id}`);
  };

  // Detail view
  if (id) {
    return (
      <div className="threat-actor-page">
        <ActorDetail actorId={id} onBack={() => navigate('/threat-actors')} />
      </div>
    );
  }

  // List view
  return (
    <div className="threat-actor-page">
      {/* Page header */}
      <div className="page-header">
        <div className="page-title-group">
          <h1 className="page-title">
            <span className="title-icon">🕵️</span>
            Threat Actors
          </h1>
          <p className="page-subtitle">
            Track APT groups, criminal organizations, and campaign attribution
          </p>
        </div>
        <button className="btn-new-actor" onClick={() => setShowCreate(true)}>
          + New Actor
        </button>
      </div>

      {/* Search + filter bar */}
      <div className="filter-bar">
        <div className="search-wrap">
          <svg className="search-ico" width="14" height="14" viewBox="0 0 16 16" fill="none">
            <circle cx="6.5" cy="6.5" r="4.5" stroke="currentColor" strokeWidth="1.5"/>
            <line x1="10.5" y1="10.5" x2="15" y2="15" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          <input
            className="search-input"
            placeholder="Search actors, aliases…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && loadActors(1)}
          />
          {search && (
            <button className="search-clear" onClick={() => setSearch('')}>✕</button>
          )}
        </div>
        <select className="filter-select"
          value={filters.motivation}
          onChange={e => setFilters(f => ({ ...f, motivation: e.target.value }))}>
          <option value="">All Motivations</option>
          <option value="financial">Financial</option>
          <option value="espionage">Espionage</option>
          <option value="hacktivism">Hacktivism</option>
          <option value="sabotage">Sabotage</option>
          <option value="disruption">Disruption</option>
        </select>
        <select className="filter-select"
          value={filters.actorType}
          onChange={e => setFilters(f => ({ ...f, actorType: e.target.value }))}>
          <option value="">All Types</option>
          <option value="apt">APT</option>
          <option value="criminal">Criminal</option>
          <option value="hacktivist">Hacktivist</option>
          <option value="insider">Insider</option>
        </select>
        <button className="btn-search" onClick={() => loadActors(1)}>Apply</button>
      </div>

      {/* Count */}
      <div className="results-info">
        {!loading && (
          <span>{pagination.total} actor{pagination.total !== 1 ? 's' : ''} tracked</span>
        )}
      </div>

      {/* Error */}
      {error && <div className="page-error">{error}</div>}

      {/* Grid */}
      {loading ? (
        <div className="actors-loading">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="actor-skeleton" />
          ))}
        </div>
      ) : actors.length === 0 ? (
        <div className="actors-empty">
          <div className="empty-icon">🕵️</div>
          <h3>No Threat Actors Found</h3>
          <p>Start tracking threat actors by creating your first profile.</p>
          <button className="btn-new-actor" onClick={() => setShowCreate(true)}>
            + Create First Actor
          </button>
        </div>
      ) : (
        <div className="actors-grid">
          {actors.map(actor => (
            <ActorCard
              key={actor._id}
              actor={actor}
              onClick={(id) => navigate(`/threat-actors/${id}`)}
            />
          ))}
        </div>
      )}

      {/* Pagination */}
      {pagination.pages > 1 && (
        <div className="pagination">
          <button
            className="page-btn"
            disabled={pagination.page <= 1}
            onClick={() => loadActors(pagination.page - 1)}
          >‹ Prev</button>
          <span className="page-info">
            Page {pagination.page} of {pagination.pages}
          </span>
          <button
            className="page-btn"
            disabled={pagination.page >= pagination.pages}
            onClick={() => loadActors(pagination.page + 1)}
          >Next ›</button>
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <CreateActorModal
          onClose={() => setShowCreate(false)}
          onCreated={handleActorCreated}
        />
      )}
    </div>
  );
};

export default ThreatActorPage;
