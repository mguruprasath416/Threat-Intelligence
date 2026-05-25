// ============================================================
// pages/Login.jsx — AUTHENTICATION PAGE
// ============================================================
// Full-screen login/register form with cyber aesthetic.
// Switches between Login and Register modes.
// On success: saves JWT + user, redirects to /dashboard.
// ============================================================

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth }     from '../hooks/useAuth';
import api             from '../api/axios';
import './Login.css';

const Login = () => {
  const navigate        = useNavigate();
  const { login }       = useAuth();
  const [mode,     setMode]     = useState('login'); // 'login' | 'register'
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState(null);

  const [form, setForm] = useState({
    email: '', password: '', username: '', confirmPassword: '',
  });

  const handleChange = (e) => {
    setForm(f => ({ ...f, [e.target.name]: e.target.value }));
    setError(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    // Client-side validation
    if (mode === 'register') {
      if (!form.username.trim()) return setError('Username is required');
      if (form.password !== form.confirmPassword) return setError('Passwords do not match');
      if (form.password.length < 8) return setError('Password must be at least 8 characters');
    }

    setLoading(true);

    try {
      const endpoint = mode === 'login' ? '/auth/login' : '/auth/register';
      const payload  = mode === 'login'
        ? { email: form.email, password: form.password }
        : { email: form.email, password: form.password, username: form.username };

      const response = await api.post(endpoint, payload);
      const { token, user } = response.data;

      login(user, token);
      navigate('/dashboard', { replace: true });

    } catch (err) {
      setError(err.userMessage || 'Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">

      {/* ── Background Grid ── */}
      <div className="login-bg">
        <div className="bg-grid" />
        <div className="bg-glow" />
      </div>

      {/* ── Login Card ── */}
      <div className="login-card">

        {/* Logo */}
        <div className="login-logo">
          <div className="logo-hex">
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
              <polygon points="24,4 44,14 44,34 24,44 4,34 4,14"
                stroke="#00d4ff" strokeWidth="1.5" fill="rgba(0,212,255,0.05)" />
              <polygon points="24,12 36,19 36,29 24,36 12,29 12,19"
                stroke="#00d4ff" strokeWidth="1" fill="rgba(0,212,255,0.08)" opacity="0.6" />
              <circle cx="24" cy="24" r="4" fill="#00d4ff"
                style={{ filter: 'drop-shadow(0 0 6px #00d4ff)' }} />
            </svg>
          </div>
          <div className="logo-text">
            <div className="logo-name">IOC SENTINEL</div>
            <div className="logo-tagline">Threat Intelligence Platform</div>
          </div>
        </div>

        {/* Mode Tabs */}
        <div className="login-tabs">
          <button
            className={`tab-btn ${mode === 'login' ? 'active' : ''}`}
            onClick={() => { setMode('login'); setError(null); }}
          >
            SIGN IN
          </button>
          <button
            className={`tab-btn ${mode === 'register' ? 'active' : ''}`}
            onClick={() => { setMode('register'); setError(null); }}
          >
            REGISTER
          </button>
        </div>

        {/* Form */}
        <form className="login-form" onSubmit={handleSubmit}>

          {mode === 'register' && (
            <div className="field-group">
              <label className="field-label">USERNAME</label>
              <input
                type="text"
                name="username"
                className="input"
                placeholder="analyst_zero"
                value={form.username}
                onChange={handleChange}
                autoComplete="username"
                required
              />
            </div>
          )}

          <div className="field-group">
            <label className="field-label">EMAIL ADDRESS</label>
            <input
              type="email"
              name="email"
              className="input"
              placeholder="analyst@soc.org"
              value={form.email}
              onChange={handleChange}
              autoComplete="email"
              required
            />
          </div>

          <div className="field-group">
            <label className="field-label">PASSWORD</label>
            <input
              type="password"
              name="password"
              className="input"
              placeholder="••••••••"
              value={form.password}
              onChange={handleChange}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              required
            />
          </div>

          {mode === 'register' && (
            <div className="field-group">
              <label className="field-label">CONFIRM PASSWORD</label>
              <input
                type="password"
                name="confirmPassword"
                className="input"
                placeholder="••••••••"
                value={form.confirmPassword}
                onChange={handleChange}
                autoComplete="new-password"
                required
              />
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="login-error">
              <span>⚠</span> {error}
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            className="btn btn-primary login-submit"
            disabled={loading}
          >
            {loading
              ? (mode === 'login' ? 'AUTHENTICATING...' : 'CREATING ACCOUNT...')
              : (mode === 'login' ? 'ACCESS SYSTEM' : 'CREATE ACCOUNT')
            }
          </button>

        </form>

        {/* Footer */}
        <div className="login-footer">
          <span className="status-dot online" />
          SYSTEM ONLINE — AUTHORIZED ACCESS ONLY
        </div>

      </div>
    </div>
  );
};

export default Login;
