// ============================================================
// components/ThreatCard/ThreatCard.jsx — ENRICHED IOC CARD
// ============================================================
// Displays the full enrichment result for one IOC.
// Shows:
//   - Indicator value + type badge + severity badge
//   - Threat score gauge (0-100)
//   - API scores from VT / AbuseIPDB / OTX
//   - MITRE ATT&CK techniques
//   - Geolocation (for IPs)
//   - Tags
//   - Timestamps
//
// Used on:
//   - /search page after a search result returns
//   - /ioc/:id details page
// ============================================================

import { getSeverityClass, getTypeColor, getSeverityColor } from '../../utils/formatDate';
import { timeAgo, formatDateTime }                          from '../../utils/formatDate';
import './ThreatCard.css';

// Circular threat score gauge
const ThreatGauge = ({ score }) => {
  const radius      = 36;
  const circumference = 2 * Math.PI * radius;
  // progress: how much of the circle to fill
  const progress    = (score / 100) * circumference;
  const color = score >= 76 ? '#ff3355'
              : score >= 51 ? '#ff8800'
              : score >= 26 ? '#ffcc00'
              : '#00ff88';

  return (
    <div className="threat-gauge">
      <svg width="96" height="96" viewBox="0 0 96 96">
        {/* Background circle */}
        <circle cx="48" cy="48" r={radius}
          fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
        {/* Score arc */}
        <circle cx="48" cy="48" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          strokeDashoffset={circumference * 0.25}  /* start from top */
          style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: 'stroke-dasharray 1s ease' }}
        />
      </svg>
      {/* Score number overlaid */}
      <div className="gauge-score" style={{ color }}>
        <span className="score-number">{score}</span>
        <span className="score-label">/100</span>
      </div>
    </div>
  );
};

const ThreatCard = ({ ioc }) => {
  if (!ioc) return null;

  const {
    indicator, iocType, severity, threatScore,
    enrichment, mitreTechniques, geoLocation,
    tags, source, cached, createdAt, lastEnriched,
  } = ioc;

  const vt    = enrichment?.virustotal;
  const abuse = enrichment?.abuseipdb;
  const otx   = enrichment?.otx;

  return (
    <div className={`threat-card severity-${severity?.toLowerCase()}`}>

      {/* ── Header Row ── */}
      <div className="tc-header">
        <div className="tc-indicator-block">
          <div
            className="tc-type-tag"
            style={{ color: getTypeColor(iocType), borderColor: getTypeColor(iocType) + '44' }}
          >
            {iocType?.toUpperCase()}
          </div>
          <div className="tc-indicator mono">{indicator}</div>
          {cached && <span className="cached-label">CACHED</span>}
        </div>

        <div className="tc-header-right">
          <span className={`badge ${getSeverityClass(severity)}`}>{severity}</span>
          <ThreatGauge score={threatScore || 0} />
        </div>
      </div>

      {/* ── API Scores Grid ── */}
      <div className="tc-section">
        <div className="tc-section-title">INTELLIGENCE SOURCES</div>
        <div className="api-scores-grid">

          {/* VirusTotal */}
          <div className="api-score-card">
            <div className="api-name">VIRUSTOTAL</div>
            {vt ? (
              <>
                <div className="api-detection">
                  <span className="detect-bad">{vt.maliciousVotes || 0}</span>
                  <span className="detect-sep"> / </span>
                  <span className="detect-total">
                    {(vt.maliciousVotes || 0) + (vt.suspiciousVotes || 0) +
                     (vt.harmlessVotes  || 0) + (vt.undetectedVotes || 0)}
                  </span>
                </div>
                <div className="api-sublabel">engines detected</div>
                {vt.country && <div className="api-meta">Country: {vt.country}</div>}
              </>
            ) : (
              <div className="api-na">NO DATA</div>
            )}
          </div>

          {/* AbuseIPDB */}
          <div className="api-score-card">
            <div className="api-name">ABUSEIPDB</div>
            {abuse ? (
              <>
                <div className="api-detection">
                  <span
                    className="detect-bad"
                    style={{ color: abuse.abuseConfidenceScore >= 75 ? 'var(--red)' : 'var(--orange)' }}
                  >
                    {abuse.abuseConfidenceScore}%
                  </span>
                </div>
                <div className="api-sublabel">abuse confidence</div>
                <div className="api-meta">{abuse.totalReports || 0} reports</div>
              </>
            ) : (
              <div className="api-na">IP ONLY</div>
            )}
          </div>

          {/* OTX */}
          <div className="api-score-card">
            <div className="api-name">ALIENVAULT OTX</div>
            {otx ? (
              <>
                <div className="api-detection">
                  <span className="detect-bad">{otx.pulseCount || 0}</span>
                </div>
                <div className="api-sublabel">threat pulses</div>
                {otx.country && <div className="api-meta">{otx.country}</div>}
              </>
            ) : (
              <div className="api-na">NO DATA</div>
            )}
          </div>

        </div>
      </div>

      {/* ── Geolocation (IPs only) ── */}
      {geoLocation && (geoLocation.country || geoLocation.countryCode) && (
        <div className="tc-section">
          <div className="tc-section-title">GEOLOCATION</div>
          <div className="geo-grid">
            {geoLocation.country     && <div className="geo-item"><span className="geo-label">Country</span><span className="geo-value">{geoLocation.country}</span></div>}
            {geoLocation.countryCode && <div className="geo-item"><span className="geo-label">Code</span><span className="geo-value">{geoLocation.countryCode}</span></div>}
            {geoLocation.city        && <div className="geo-item"><span className="geo-label">City</span><span className="geo-value">{geoLocation.city}</span></div>}
            {geoLocation.isp         && <div className="geo-item"><span className="geo-label">ISP</span><span className="geo-value">{geoLocation.isp}</span></div>}
            {geoLocation.asn         && <div className="geo-item"><span className="geo-label">ASN</span><span className="geo-value mono">{geoLocation.asn}</span></div>}
          </div>
        </div>
      )}

      {/* ── MITRE ATT&CK ── */}
      {mitreTechniques?.length > 0 && (
        <div className="tc-section">
          <div className="tc-section-title">MITRE ATT&CK MAPPING</div>
          <div className="mitre-list">
            {mitreTechniques.map((t) => (
              <div key={t.techniqueId} className="mitre-item">
                <span className="mitre-id">{t.techniqueId}</span>
                <span className="mitre-name">{t.techniqueName}</span>
                <span className="mitre-tactic">{t.tactic}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Tags ── */}
      {tags?.length > 0 && (
        <div className="tc-section">
          <div className="tc-section-title">TAGS</div>
          <div className="tags-list">
            {tags.map(tag => (
              <span key={tag} className="tag">{tag}</span>
            ))}
          </div>
        </div>
      )}

      {/* ── Footer Meta ── */}
      <div className="tc-footer">
        <span>Source: <strong>{source}</strong></span>
        <span>First seen: {timeAgo(createdAt)}</span>
        <span>Enriched: {timeAgo(lastEnriched)}</span>
      </div>

    </div>
  );
};

export default ThreatCard;
