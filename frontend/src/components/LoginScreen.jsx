import React, { useState } from 'react';
import { useAuth } from '../hooks/useAuth.js';

const LoginScreen = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-primary, #0a0a0f)',
      fontFamily: 'Fira Code, monospace',
    }}>
      <div className="glass-card fade-in" style={{
        padding: '3rem',
        width: '100%',
        maxWidth: '420px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '2rem',
      }}>
        <div style={{ textAlign: 'center' }}>
          <h1 className="accent-text" style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>MOONKEEP v2</h1>
          <p style={{ fontSize: '0.6rem', letterSpacing: '4px', fontWeight: 900, color: 'var(--text-secondary)' }}>SOVEREIGN ELITE</p>
        </div>

        <form onSubmit={handleSubmit} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>USERNAME</label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              style={{
                background: 'rgba(0,0,0,0.5)',
                border: '1px solid var(--glass-border)',
                borderRadius: '6px',
                padding: '0.7rem 1rem',
                color: 'var(--neo-cyan)',
                fontFamily: 'Fira Code, monospace',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>PASSWORD</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="current-password"
              style={{
                background: 'rgba(0,0,0,0.5)',
                border: '1px solid var(--glass-border)',
                borderRadius: '6px',
                padding: '0.7rem 1rem',
                color: 'var(--neo-cyan)',
                fontFamily: 'Fira Code, monospace',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            />
          </div>

          {error && (
            <div style={{
              background: 'rgba(244, 63, 94, 0.1)',
              border: '1px solid rgba(244, 63, 94, 0.4)',
              borderRadius: '6px',
              padding: '0.6rem 1rem',
              fontSize: '0.75rem',
              color: '#f43f5e',
            }}>
              {error}
            </div>
          )}

          <button
            className="btn-primary"
            type="submit"
            disabled={loading}
            style={{
              marginTop: '0.5rem',
              padding: '0.8rem',
              fontSize: '0.85rem',
              letterSpacing: '2px',
            }}
          >
            {loading ? 'AUTHENTICATING...' : 'ACCESS SYSTEM'}
          </button>
        </form>

        <p style={{ fontSize: '0.55rem', color: 'var(--text-secondary)', textAlign: 'center' }}>
          SECURE AUTHENTICATION REQUIRED
        </p>
      </div>
    </div>
  );
};

export default LoginScreen;
