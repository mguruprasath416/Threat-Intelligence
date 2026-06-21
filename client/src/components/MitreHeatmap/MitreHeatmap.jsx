// ============================================================
// components/MitreHeatmap/MitreHeatmap.jsx
// ============================================================
// Displays ATT&CK technique coverage as an interactive heatmap.
// Groups techniques by tactic column, coloring cells by frequency.
//
// Props:
//   techniques — array of { techniqueId, techniqueName, tactic, killChainStage }
//   compact    — bool: show compact version (for IOC details)
// ============================================================

import { useMemo, useState } from 'react';
import './MitreHeatmap.css';

// Full ATT&CK Enterprise tactic order (left→right = kill chain order)
const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

const TACTIC_SHORT = {
  'Reconnaissance':       'RECON',
  'Resource Development': 'RESDEV',
  'Initial Access':       'INIT',
  'Execution':            'EXEC',
  'Persistence':          'PERS',
  'Privilege Escalation': 'PRIVESC',
  'Defense Evasion':      'DEFEVAS',
  'Credential Access':    'CREDACC',
  'Discovery':            'DISC',
  'Lateral Movement':     'LATMOV',
  'Collection':           'COLL',
  'Command and Control':  'C2',
  'Exfiltration':         'EXFIL',
  'Impact':               'IMPACT',
};

const getHeatColor = (count, maxCount) => {
  if (count === 0) return null;
  const ratio = count / Math.max(maxCount, 1);
  if (ratio >= 0.8) return '#FF3B5C'; // critical — threat red
  if (ratio >= 0.5) return '#F5A623'; // high — amber
  if (ratio >= 0.25) return '#00D4B4'; // medium — teal
  return '#1E7A68';                    // low — muted teal
};

const MitreHeatmap = ({ techniques = [], compact = false }) => {
  const [hoveredCell, setHoveredCell] = useState(null);

  // Group techniques by tactic
  const { byTactic, maxCount, totalUnique } = useMemo(() => {
    const map = {};
    TACTIC_ORDER.forEach(t => { map[t] = {}; });

    techniques.forEach(({ techniqueId, techniqueName, tactic }) => {
      if (!tactic) return;
      // Normalize tactic name
      const normalizedTactic = TACTIC_ORDER.find(
        t => t.toLowerCase() === tactic?.toLowerCase()
      ) || tactic;

      if (!map[normalizedTactic]) map[normalizedTactic] = {};
      const key = techniqueId || techniqueName || 'unknown';
      if (!map[normalizedTactic][key]) {
        map[normalizedTactic][key] = { techniqueId, techniqueName, count: 0 };
      }
      map[normalizedTactic][key].count += 1;
    });

    let maxCount = 0;
    let totalUnique = 0;
    Object.values(map).forEach(tacticTechs => {
      const techCount = Object.keys(tacticTechs).length;
      totalUnique += techCount;
      Object.values(tacticTechs).forEach(({ count }) => {
        maxCount = Math.max(maxCount, count);
      });
    });

    return { byTactic: map, maxCount, totalUnique };
  }, [techniques]);

  const tacticCoverage = TACTIC_ORDER.filter(t => Object.keys(byTactic[t] || {}).length > 0);
  const coveragePercent = Math.round((tacticCoverage.length / TACTIC_ORDER.length) * 100);

  if (techniques.length === 0) {
    return (
      <div className="mitre-empty">
        <div className="mitre-empty-icon">⬡</div>
        <p>No MITRE ATT&CK techniques mapped</p>
        <span>Add technique IDs when submitting IOCs</span>
      </div>
    );
  }

  return (
    <div className={`mitre-heatmap ${compact ? 'compact' : ''}`}>
      {/* Header */}
      <div className="mitre-header">
        <div className="mitre-title">
          <span className="mitre-badge">ATT&CK</span>
          <h3>MITRE ATT&CK Coverage</h3>
        </div>
        <div className="mitre-meta">
          <div className="mitre-stat">
            <span className="mstat-val">{totalUnique}</span>
            <span className="mstat-label">Techniques</span>
          </div>
          <div className="mitre-stat">
            <span className="mstat-val">{tacticCoverage.length}</span>
            <span className="mstat-label">Tactics</span>
          </div>
          <div className="mitre-stat">
            <span className="mstat-val">{coveragePercent}%</span>
            <span className="mstat-label">Coverage</span>
          </div>
        </div>
      </div>

      {/* Coverage bar */}
      <div className="mitre-coverage-bar-wrap">
        <div className="mitre-coverage-bar">
          <div
            className="mitre-coverage-fill"
            style={{ width: `${coveragePercent}%` }}
          />
        </div>
        <span className="mitre-coverage-label">Kill Chain Coverage</span>
      </div>

      {/* Grid */}
      <div className="mitre-grid-scroll">
        <div className="mitre-grid">
          {TACTIC_ORDER.map(tactic => {
            const techs = byTactic[tactic] || {};
            const techList = Object.values(techs);
            const tacticTotal = techList.reduce((s, t) => s + t.count, 0);

            return (
              <div key={tactic} className="mitre-column">
                <div className={`mitre-tactic-header ${tacticTotal > 0 ? 'has-hits' : ''}`}>
                  <span className="tactic-short">{TACTIC_SHORT[tactic] || tactic.toUpperCase()}</span>
                  {tacticTotal > 0 && <span className="tactic-count">{techList.length}</span>}
                </div>

                <div className="mitre-cells">
                  {techList.length === 0 ? (
                    <div className="mitre-cell empty" />
                  ) : (
                    techList.map(({ techniqueId, techniqueName, count }) => {
                      const color = getHeatColor(count, maxCount);
                      const cellKey = `${tactic}-${techniqueId}`;
                      return (
                        <div
                          key={cellKey}
                          className={`mitre-cell filled ${hoveredCell === cellKey ? 'hovered' : ''}`}
                          style={{ '--cell-color': color }}
                          onMouseEnter={() => setHoveredCell(cellKey)}
                          onMouseLeave={() => setHoveredCell(null)}
                        >
                          <span className="cell-id">{techniqueId || '?'}</span>

                          {/* Tooltip */}
                          <div className="cell-tooltip">
                            <div className="tooltip-id">{techniqueId}</div>
                            <div className="tooltip-name">{techniqueName}</div>
                            <div className="tooltip-tactic">{tactic}</div>
                            <div className="tooltip-count">{count} IOC{count !== 1 ? 's' : ''}</div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="mitre-legend">
        <span className="legend-label">Frequency:</span>
        {[
          { color: '#1E7A68', label: 'Low' },
          { color: '#00D4B4', label: 'Medium' },
          { color: '#F5A623', label: 'High' },
          { color: '#FF3B5C', label: 'Critical' },
        ].map(({ color, label }) => (
          <div key={label} className="legend-item">
            <div className="legend-dot" style={{ background: color }} />
            <span>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default MitreHeatmap;
