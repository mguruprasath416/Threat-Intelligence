// ============================================================
// pages/NotFound.jsx — 404 PAGE
// ============================================================

import { useNavigate } from 'react-router-dom';
import './NotFound.css';

const NotFound = () => {
  const navigate = useNavigate();
  return (
    <div className="notfound-page">
      <div className="notfound-code">404</div>
      <div className="notfound-title cursor">PAGE NOT FOUND</div>
      <p className="notfound-msg">
        The route you requested does not exist in this system.
      </p>
      <div className="notfound-actions">
        <button className="btn btn-primary" onClick={() => navigate('/dashboard')}>
          ← RETURN TO DASHBOARD
        </button>
        <button className="btn" onClick={() => navigate(-1)}>
          GO BACK
        </button>
      </div>
    </div>
  );
};

export default NotFound;
