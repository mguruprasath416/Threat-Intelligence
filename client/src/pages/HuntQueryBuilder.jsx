// ============================================================
// pages/HuntQueryBuilder.jsx — THREAT HUNTING QUERY BUILDER
// ============================================================
// Allows analysts to select IOCs and generate hunting rules
// in various formats (YARA, Sigma, KQL, SPL) with syntax highlighting
// ============================================================

import { useState, useEffect } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import axios from '../api/axios';
import Loader from '../components/Loader/Loader';
import './HuntQueryBuilder.css';

const HuntQueryBuilder = () => {
  const [iocs, setIOCs] = useState([]);
  const [selectedIOCs, setSelectedIOCs] = useState([]);
  const [format, setFormat] = useState('yara');
  const [generatedRule, setGeneratedRule] = useState('');
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  // Fetch all IOCs on component mount
  useEffect(() => {
    const fetchIOCs = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get('/ioc?limit=100', {
          headers: { Authorization: `Bearer ${token}` }
        });
        // Backend returns { success: true, data: { iocs: [], pagination: {} } }
        setIOCs(response.data.data?.iocs || []);
        setLoading(false);
      } catch (err) {
        console.error('Failed to load IOCs:', err.response?.status, err.response?.data);
        console.error('Full error:', err);
        setError(`Failed to load IOCs: ${err.response?.data?.message || err.message}`);
        setLoading(false);
      }
    };

    fetchIOCs();
  }, []);

  // Handle IOC selection
  const handleIOCToggle = (iocId) => {
    setSelectedIOCs(prev => {
      if (prev.includes(iocId)) {
        return prev.filter(id => id !== iocId);
      } else {
        return [...prev, iocId];
      }
    });
  };

  // Handle select all
  const handleSelectAll = () => {
    if (selectedIOCs.length === iocs.length) {
      setSelectedIOCs([]);
    } else {
      setSelectedIOCs(iocs.map(ioc => ioc._id));
    }
  };

  // Handle format change
  const handleFormatChange = (newFormat) => {
    setFormat(newFormat);
    setGeneratedRule(''); // Clear previous rule when format changes
  };

  // Generate hunting rule
  const handleGenerate = async () => {
    if (selectedIOCs.length === 0) {
      setError('Please select at least one IOC');
      return;
    }

    setGenerating(true);
    setError(null);

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('/hunt/generate', {
        iocIds: selectedIOCs,
        format: format
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setGeneratedRule(response.data.data.rule);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to generate rule');
    } finally {
      setGenerating(false);
    }
  };

  // Copy rule to clipboard
  const handleCopy = () => {
    navigator.clipboard.writeText(generatedRule);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Get syntax highlighter language based on format
  const getLanguage = () => {
    switch (format) {
      case 'yara':
        return 'yara';
      case 'sigma':
        return 'yaml';
      case 'kql':
        return 'sql';
      case 'spl':
        return 'sql';
      default:
        return 'text';
    }
  };

  if (loading) {
    return (
      <div className="hunt-query-builder-page">
        <div className="page-header">
          <h1 className="page-title">THREAT HUNTING QUERY BUILDER</h1>
          <p className="page-subtitle">Generate detection rules from selected IOCs</p>
        </div>
        <Loader message="Loading IOCs..." />
      </div>
    );
  }

  return (
    <div className="hunt-query-builder-page">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">THREAT HUNTING QUERY BUILDER</h1>
          <p className="page-subtitle">Generate detection rules from selected IOCs</p>
        </div>
      </div>

      {/* Main Content */}
      <div className="hunt-builder-content">
        {/* IOC Selection Panel */}
        <div className="ioc-selection-panel">
          <div className="panel-header">
            <h2>Select IOCs</h2>
            <div className="selection-controls">
              <button
                className="btn btn-secondary"
                onClick={handleSelectAll}
              >
                {selectedIOCs.length === iocs.length ? 'Deselect All' : 'Select All'}
              </button>
              <span className="selected-count">
                {selectedIOCs.length} of {iocs.length} selected
              </span>
            </div>
          </div>

          <div className="ioc-list">
            {iocs.length === 0 ? (
              <div className="empty-state">
                <p>No IOCs available</p>
              </div>
            ) : (
              iocs.map(ioc => (
                <div
                  key={ioc._id}
                  className={`ioc-item ${selectedIOCs.includes(ioc._id) ? 'selected' : ''}`}
                  onClick={() => handleIOCToggle(ioc._id)}
                >
                  <input
                    type="checkbox"
                    checked={selectedIOCs.includes(ioc._id)}
                    onChange={() => handleIOCToggle(ioc._id)}
                  />
                  <div className="ioc-info">
                    <span className="ioc-indicator">{ioc.indicator}</span>
                    <span className="ioc-type">{ioc.iocType}</span>
                    <span className={`ioc-severity severity-${ioc.severity.toLowerCase()}`}>
                      {ioc.severity}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Rule Generation Panel */}
        <div className="rule-generation-panel">
          <div className="panel-header">
            <h2>Generate Rule</h2>
          </div>

          {/* Format Selection */}
          <div className="format-selection">
            <label className="format-label">Output Format:</label>
            <div className="format-buttons">
              {['yara', 'sigma', 'kql', 'spl'].map(fmt => (
                <button
                  key={fmt}
                  className={`format-btn ${format === fmt ? 'active' : ''}`}
                  onClick={() => handleFormatChange(fmt)}
                >
                  {fmt.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Generate Button */}
          <button
            className="btn btn-primary generate-btn"
            onClick={handleGenerate}
            disabled={generating || selectedIOCs.length === 0}
          >
            {generating ? 'Generating...' : 'Generate Rule'}
          </button>

          {/* Error Message */}
          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          {/* Generated Rule Output */}
          {generatedRule && (
            <div className="rule-output">
              <div className="rule-output-header">
                <h3>Generated {format.toUpperCase()} Rule</h3>
                <button
                  className="btn btn-secondary copy-btn"
                  onClick={handleCopy}
                >
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div className="rule-code">
                <SyntaxHighlighter
                  language={getLanguage()}
                  style={vscDarkPlus}
                  customStyle={{
                    margin: 0,
                    borderRadius: '8px',
                    fontSize: '13px',
                    lineHeight: '1.5'
                  }}
                  showLineNumbers
                  wrapLines
                >
                  {generatedRule}
                </SyntaxHighlighter>
              </div>
            </div>
          )}

          {/* Format Info */}
          <div className="format-info">
            <div className="info-title">Format Descriptions:</div>
            <div className="info-item">
              <strong>YARA:</strong> File-based malware detection rules
            </div>
            <div className="info-item">
              <strong>Sigma:</strong> Generic SIEM detection rules (YAML format)
            </div>
            <div className="info-item">
              <strong>KQL:</strong> Kibana Query Language for Elasticsearch
            </div>
            <div className="info-item">
              <strong>SPL:</strong> Splunk Search Processing Language
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HuntQueryBuilder;
