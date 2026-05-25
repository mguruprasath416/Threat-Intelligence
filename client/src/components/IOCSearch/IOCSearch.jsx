// ============================================================
// components/IOCSearch/IOCSearch.jsx — IOC SEARCH BAR
// ============================================================
// The main input component for submitting indicators.
// Features:
//   - Auto-detects IOC type as user types (shows type badge)
//   - Client-side validation before API call
//   - Submit on Enter key OR button click
//   - Quick example buttons for testing
//   - Shows animated scanning state while enriching
// ============================================================

import { useState, useRef } from 'react';
import { useIOC } from '../../hooks/useIOC';
import { validateIndicator, detectType } from '../../utils/formatDate';
import './IOCSearch.css';

// Quick-fill example IOCs for demo/testing
const EXAMPLES = [
  { label: 'Malicious IP',  value: '185.220.101.45',       type: 'ip' },
  { label: 'Bad Domain',    value: 'malware-c2.example.com', type: 'domain' },
  { label: 'Phish URL',     value: 'https://phish.example.com/login', type: 'url' },
  { label: 'Hash',          value: '44d88612fea8a8f36de82e1278abb02f', type: 'hash' },
];

const IOCSearch = ({ onResult }) => {
  const { searchIOC, isSearching, error } = useIOC();
  const [inputValue,    setInputValue]    = useState('');
  const [detectedType,  setDetectedType]  = useState(null);
  const [validationErr, setValidationErr] = useState(null);
  const inputRef = useRef(null);

  // Detect type on every keystroke for real-time feedback
  const handleChange = (e) => {
    const val = e.target.value;
    setInputValue(val);
    setValidationErr(null);

    if (val.trim()) {
      setDetectedType(detectType(val.trim()));
    } else {
      setDetectedType(null);
    }
  };

  const handleSubmit = async (e) => {
    e?.preventDefault();

    const validation = validateIndicator(inputValue);
    if (!validation.valid) {
      setValidationErr(validation.error);
      inputRef.current?.focus();
      return;
    }

    try {
      const result = await searchIOC(inputValue);
      if (result && onResult) onResult(result);
    } catch {
      // Error is handled in IOCContext
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleSubmit();
  };

  const handleExample = (val) => {
    setInputValue(val);
    setDetectedType(detectType(val));
    setValidationErr(null);
    inputRef.current?.focus();
  };

  const TYPE_LABELS = {
    ip:     { label: 'IPv4 ADDRESS', color: '#00d4ff' },
    domain: { label: 'DOMAIN',       color: '#7c6af7' },
    url:    { label: 'URL',          color: '#ff8800' },
    hash:   { label: 'FILE HASH',    color: '#00ff88' },
    email:  { label: 'EMAIL',        color: '#ff3355' },
  };

  return (
    <div className="ioc-search">
      {/* ── Header ── */}
      <div className="search-header">
        <h2 className="search-title cursor">INDICATOR LOOKUP</h2>
        <p className="search-subtitle">
          Submit an IP address, domain, URL, or file hash for threat intelligence enrichment
        </p>
      </div>

      {/* ── Search Input ── */}
      <div className="search-input-wrapper">
        <div className="search-prefix">
          <span className="prefix-symbol">&gt;_</span>
        </div>

        <input
          ref={inputRef}
          type="text"
          className={`search-input ${validationErr ? 'error' : ''}`}
          value={inputValue}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          placeholder="Enter IP / domain / URL / hash..."
          disabled={isSearching}
          autoComplete="off"
          spellCheck="false"
        />

        {/* Type badge — appears as user types */}
        {detectedType && TYPE_LABELS[detectedType] && (
          <div
            className="type-badge"
            style={{ color: TYPE_LABELS[detectedType].color,
                     borderColor: TYPE_LABELS[detectedType].color + '55',
                     background:  TYPE_LABELS[detectedType].color + '12' }}
          >
            {TYPE_LABELS[detectedType].label}
          </div>
        )}

        <button
          className={`search-btn ${isSearching ? 'scanning' : ''}`}
          onClick={handleSubmit}
          disabled={isSearching || !inputValue.trim()}
        >
          {isSearching ? (
            <span className="scanning-text">SCANNING...</span>
          ) : (
            'ANALYZE'
          )}
        </button>
      </div>

      {/* ── Validation / API Error ── */}
      {(validationErr || error) && (
        <div className="search-error">
          <span className="error-icon">⚠</span>
          {validationErr || error}
        </div>
      )}

      {/* ── Scanning Progress Bar ── */}
      {isSearching && (
        <div className="scan-progress">
          <div className="scan-bar" />
          <div className="scan-sources">
            <span className="scan-source active">VirusTotal</span>
            <span className="scan-source active">AbuseIPDB</span>
            <span className="scan-source active">AlienVault OTX</span>
            <span className="scan-source active">OpenPhish</span>
          </div>
        </div>
      )}

      {/* ── Quick Examples ── */}
      <div className="search-examples">
        <span className="examples-label">QUICK TEST:</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.value}
            className="example-btn"
            onClick={() => handleExample(ex.value)}
            disabled={isSearching}
          >
            {ex.label}
          </button>
        ))}
      </div>
    </div>
  );
};

export default IOCSearch;
