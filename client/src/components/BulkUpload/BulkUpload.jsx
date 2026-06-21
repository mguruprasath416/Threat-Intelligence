// ============================================================
// components/BulkUpload/BulkUpload.jsx — BULK IOC IMPORT MODAL
// ============================================================
// Modal component for bulk importing IOCs from CSV or JSON files
// Features drag-and-drop file upload and import results summary
// ============================================================

import { useState, useRef } from 'react';
import axios from 'axios';
import './BulkUpload.css';

const BulkUpload = ({ isOpen, onClose, onSuccess }) => {
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const inputRef = useRef(null);

  // Handle drag events
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  // Handle file drop
  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  // Handle file selection via input
  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  // Validate and set file
  const handleFile = (selectedFile) => {
    const validTypes = ['text/csv', 'application/json', 'application/vnd.ms-excel'];
    const validExtensions = ['.csv', '.json'];
    const fileExtension = '.' + selectedFile.name.split('.').pop().toLowerCase();

    if (!validExtensions.includes(fileExtension)) {
      setError('Invalid file type. Please upload a CSV or JSON file.');
      setFile(null);
      return;
    }

    if (selectedFile.size > 10 * 1024 * 1024) { // 10MB limit
      setError('File size exceeds 10MB limit.');
      setFile(null);
      return;
    }

    setFile(selectedFile);
    setError(null);
    setResults(null);
  };

  // Handle file upload
  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('/api/ioc/bulk-import', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Authorization': `Bearer ${token}`
        }
      });

      setResults(response.data.data);
      setFile(null);
      if (inputRef.current) {
        inputRef.current.value = '';
      }

      if (onSuccess) {
        onSuccess();
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  // Handle modal close
  const handleClose = () => {
    setFile(null);
    setResults(null);
    setError(null);
    if (inputRef.current) {
      inputRef.current.value = '';
    }
    onClose();
  };

  // Download sample CSV template
  const downloadSampleCSV = () => {
    const csvContent = 'indicator,tags,severity\n192.168.1.1,malware,High\nexample.com,phishing,Critical\nhttps://evil.com/malware.exe,botnet,Medium\n5d41402abc4b2a76b9719d911017c592,,Low';
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ioc-sample.csv';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  // Download sample JSON template
  const downloadSampleJSON = () => {
    const jsonContent = [
      { indicator: '192.168.1.1', tags: 'malware', severity: 'High' },
      { indicator: 'example.com', tags: 'phishing', severity: 'Critical' },
      { indicator: 'https://evil.com/malware.exe', tags: 'botnet', severity: 'Medium' },
      { indicator: '5d41402abc4b2a76b9719d911017c592', tags: '', severity: 'Low' }
    ];
    const blob = new Blob([JSON.stringify(jsonContent, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ioc-sample.json';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  if (!isOpen) return null;

  return (
    <div className="bulk-upload-overlay">
      <div className="bulk-upload-modal">
        <div className="bulk-upload-header">
          <h2>BULK IOC IMPORT</h2>
          <button className="close-btn" onClick={handleClose}>✕</button>
        </div>

        <div className="bulk-upload-content">
          {!results ? (
            <>
              {/* File Upload Area */}
              <div
                className={`drop-zone ${dragActive ? 'active' : ''} ${file ? 'has-file' : ''}`}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => inputRef.current?.click()}
              >
                <input
                  ref={inputRef}
                  type="file"
                  accept=".csv,.json"
                  onChange={handleChange}
                  style={{ display: 'none' }}
                />
                <div className="drop-zone-content">
                  {file ? (
                    <>
                      <div className="file-icon">📄</div>
                      <div className="file-name">{file.name}</div>
                      <div className="file-size">{(file.size / 1024).toFixed(2)} KB</div>
                    </>
                  ) : (
                    <>
                      <div className="upload-icon">📤</div>
                      <div className="upload-text">
                        Drag & drop your CSV or JSON file here
                      </div>
                      <div className="upload-subtext">or click to browse</div>
                    </>
                  )}
                </div>
              </div>

              {/* Error Message */}
              {error && (
                <div className="error-message">
                  <span className="error-icon">⚠️</span>
                  {error}
                </div>
              )}

              {/* Sample Templates */}
              <div className="template-section">
                <div className="template-title">Don't have a file?</div>
                <div className="template-buttons">
                  <button className="btn btn-secondary" onClick={downloadSampleCSV}>
                    Download CSV Template
                  </button>
                  <button className="btn btn-secondary" onClick={downloadSampleJSON}>
                    Download JSON Template
                  </button>
                </div>
              </div>

              {/* Upload Button */}
              <div className="upload-actions">
                <button
                  className="btn btn-secondary"
                  onClick={handleClose}
                  disabled={uploading}
                >
                  Cancel
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleUpload}
                  disabled={!file || uploading}
                >
                  {uploading ? 'Uploading...' : 'Import IOCs'}
                </button>
              </div>
            </>
          ) : (
            <>
              {/* Results Summary */}
              <div className="results-summary">
                <div className="results-title">IMPORT RESULTS</div>
                <div className="results-stats">
                  <div className="stat-card success">
                    <div className="stat-value">{results.successful}</div>
                    <div className="stat-label">Successfully Imported</div>
                  </div>
                  <div className="stat-card skipped">
                    <div className="stat-value">{results.skipped}</div>
                    <div className="stat-label">Skipped (Duplicates)</div>
                  </div>
                  <div className="stat-card failed">
                    <div className="stat-value">{results.failed}</div>
                    <div className="stat-label">Failed</div>
                  </div>
                  <div className="stat-card total">
                    <div className="stat-value">{results.total}</div>
                    <div className="stat-label">Total Processed</div>
                  </div>
                </div>
              </div>

              {/* Error Details */}
              {results.errors && results.errors.length > 0 && (
                <div className="error-details">
                  <div className="error-details-title">
                    FAILED ROWS ({results.errors.length})
                  </div>
                  <div className="error-table-container">
                    <table className="error-table">
                      <thead>
                        <tr>
                          <th>Row</th>
                          <th>Indicator</th>
                          <th>Error</th>
                        </tr>
                      </thead>
                      <tbody>
                        {results.errors.slice(0, 10).map((err, index) => (
                          <tr key={index}>
                            <td>{err.row}</td>
                            <td className="mono">{err.indicator}</td>
                            <td className="error-text">{err.error}</td>
                          </tr>
                        ))}
                        {results.errors.length > 10 && (
                          <tr>
                            <td colSpan="3" className="more-errors">
                              ... and {results.errors.length - 10} more errors
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Close Button */}
              <div className="results-actions">
                <button className="btn btn-primary" onClick={handleClose}>
                  Done
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default BulkUpload;
