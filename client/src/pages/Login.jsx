// ============================================================
// pages/Login.jsx — LOGIN & REGISTER PAGE
// ============================================================
// After successful register → immediately logged in
// After successful login   → goes to /dashboard
// Already logged in        → PublicRoute redirects to /dashboard
// ============================================================

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth }     from '../hooks/useAuth';
import api             from '../api/axios';
import './Login.css';

const Login = () => {
  const navigate        = useNavigate();
  const { login }       = useAuth();
  const [mode,     setMode]     = useState('login');
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState(null);
  const [success,  setSuccess]  = useState(null);

  const [form, setForm] = useState({
    identifier: '', email: '', password: '', username: '', confirmPassword: '',
  });

  const handleChange = (e) => {
    setForm(f => ({ ...f, [e.target.name]: e.target.value }));
    setError(null);
    setSuccess(null);
  };

  const switchMode = (newMode) => {
    setMode(newMode);
    setError(null);
    setSuccess(null);
    setForm({ identifier: '', email: '', password: '', username: '', confirmPassword: '' });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    // Client-side validation
    if (mode === 'login') {
      if (!form.identifier.trim()) return setError('Username or Email is required');
      if (!form.password)          return setError('Password is required');
    }

    if (mode === 'register') {
      if (!form.username.trim()) {
        return setError('Username is required');
      }
      if (form.username.trim().length < 3) {
        return setError('Username must be at least 3 characters');
      }
      if (!form.email.trim()) {
        return setError('Email is required');
      }
      if (form.password.length < 8) {
        return setError('Password must be at least 8 characters');
      }
      if (form.password !== form.confirmPassword) {
        return setError('Passwords do not match');
      }
    }

    setLoading(true);

    try {
      const endpoint = mode === 'login' ? '/auth/login' : '/auth/register';
      const payload  = mode === 'login'
        ? { identifier: form.identifier.trim(), password: form.password }
        : { email: form.email, password: form.password, username: form.username };

      const response = await api.post(endpoint, payload);
      
      if (mode === 'register') {
        setSuccess('Account created! Please sign in with your credentials.');
        setForm({ identifier: '', email: '', password: '', username: '', confirmPassword: '' });

        // Switch to login mode after 2.5 seconds
        setTimeout(() => {
          setMode('login');
          setSuccess(null);
        }, 2500);

        setLoading(false);
        return;
      }

      // Login mode logic
      const { token, user } = response.data;

      // Save session
      login(user, token);

      // Show success briefly then redirect
      setSuccess(`Welcome back, ${user.username}!`);

      // Redirect to dashboard after short delay
      setTimeout(() => {
        navigate('/dashboard', { replace: true });
      }, 800);

    } catch (err) {
      setError(err.userMessage || 'Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">

      {/* Background */}
      <div className="login-bg">
        <div className="bg-grid" />
        <div className="bg-glow" />
      </div>

      {/* Card */}
      <div className="login-card">

        {/* Logo */}
        <div className="login-logo">
          <div className="logo-hex">
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
              <polygon
                points="24,4 44,14 44,34 24,44 4,34 4,14"
                stroke="#00d4ff" strokeWidth="1.5"
                fill="rgba(0,212,255,0.05)"
              />
              <polygon
                points="24,12 36,19 36,29 24,36 12,29 12,19"
                stroke="#00d4ff" strokeWidth="1"
                fill="rgba(0,212,255,0.08)" opacity="0.6"
              />
              <circle
                cx="24" cy="24" r="4" fill="#00d4ff"
                style={{ filter: 'drop-shadow(0 0 6px #00d4ff)' }}
              />
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
            onClick={() => switchMode('login')}
            type="button"
          >
            SIGN IN
          </button>
          <button
            className={`tab-btn ${mode === 'register' ? 'active' : ''}`}
            onClick={() => switchMode('register')}
            type="button"
          >
            REGISTER
          </button>
        </div>

        {/* Form */}
        <form className="login-form" onSubmit={handleSubmit}>

          {/* LOGIN: identifier field (username OR email) */}
          {mode === 'login' && (
            <div className="field-group">
              <label className="field-label">USERNAME OR EMAIL</label>
              <input
                type="text"
                name="identifier"
                className="input"
                placeholder="analyst_zero  or  analyst@soc.org"
                value={form.identifier}
                onChange={handleChange}
                autoComplete="username"
                autoFocus
                disabled={loading}
              />
            </div>
          )}

          {/* REGISTER: separate username + email fields */}
          {mode === 'register' && (
            <>
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
                  autoFocus
                  disabled={loading}
                />
              </div>
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
                  disabled={loading}
                />
              </div>
            </>
          )}

          {/* Password */}
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
              disabled={loading}
            />
          </div>

          {/* Confirm Password (register only) */}
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
                disabled={loading}
              />
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="login-error">
              <span>⚠</span> {error}
            </div>
          )}

          {/* Success Message */}
          {success && (
            <div className="login-success">
              <span>✓</span> {success}
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            className="btn btn-primary login-submit"
            disabled={loading}
          >
            {loading
              ? (mode === 'login' ? 'AUTHENTICATING...' : 'CREATING ACCOUNT...')
              : (mode === 'login' ? 'ACCESS SYSTEM'    : 'CREATE ACCOUNT')
            }
          </button>

        </form>

        {/* Switch mode hint */}
        <div className="login-switch">
          {mode === 'login' ? (
            <span>
              No account?{' '}
              <button
                className="switch-link"
                onClick={() => switchMode('register')}
                type="button"
              >
                Register here
              </button>
            </span>
          ) : (
            <span>
              Already registered?{' '}
              <button
                className="switch-link"
                onClick={() => switchMode('login')}
                type="button"
              >
                Sign in
              </button>
            </span>
          )}
        </div>

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