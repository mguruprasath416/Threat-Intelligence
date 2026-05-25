// ============================================================
// components/Alerts/Alerts.jsx — NOTIFICATION ALERTS
// ============================================================
// Stackable toast-style alert notifications.
// Types: success | error | warning | info
// Auto-dismisses after 5 seconds.
// ============================================================

import { useState, useEffect } from 'react';
import './Alerts.css';

const ICONS = {
  success: '✓',
  error:   '✕',
  warning: '⚠',
  info:    'ℹ',
};

export const Alert = ({ type = 'info', message, onDismiss }) => {
  useEffect(() => {
    const timer = setTimeout(() => onDismiss?.(), 5000);
    return () => clearTimeout(timer);
  }, [onDismiss]);

  return (
    <div className={`alert alert-${type}`}>
      <span className="alert-icon">{ICONS[type]}</span>
      <span className="alert-message">{message}</span>
      <button className="alert-close" onClick={onDismiss}>✕</button>
      <div className="alert-progress" />
    </div>
  );
};

export const AlertContainer = ({ alerts, onDismiss }) => (
  <div className="alert-container">
    {alerts.map((alert) => (
      <Alert
        key={alert.id}
        type={alert.type}
        message={alert.message}
        onDismiss={() => onDismiss(alert.id)}
      />
    ))}
  </div>
);

export default Alert;
