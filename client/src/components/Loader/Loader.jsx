// ============================================================
// components/Loader/Loader.jsx — LOADING SPINNER
// ============================================================
// Cyber-themed loading indicator used during data fetches.
// ============================================================

import './Loader.css';

const Loader = ({ message = 'LOADING...' }) => (
  <div className="loader-wrapper">
    <div className="loader-ring">
      <div className="loader-inner" />
    </div>
    <div className="loader-text">{message}</div>
  </div>
);

export default Loader;
