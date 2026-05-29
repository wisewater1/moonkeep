import React, { useState } from 'react';
import { API_BASE } from '../config.js';
import { useAuth } from '../hooks/useAuth.js';

export default function AccountMenu({ open, onClose, currentUser }) {
  const { authFetch, logout } = useAuth();
  const [oldPw, setOldPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);

  if (!open) return null;

  const submit = async (e) => {
    e.preventDefault();
    setStatus(null);
    if (!oldPw || !newPw) {
      setStatus({ ok: false, msg: 'Both current and new password are required.' });
      return;
    }
    if (newPw !== confirmPw) {
      setStatus({ ok: false, msg: 'New password and confirmation do not match.' });
      return;
    }
    if (newPw.length < 8) {
      setStatus({ ok: false, msg: 'New password must be at least 8 characters.' });
      return;
    }
    setBusy(true);
    try {
      const res = await authFetch(`${API_BASE}/auth/change_password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: oldPw, new_password: newPw }),
      });
      if (res.ok) {
        setStatus({ ok: true, msg: 'Password changed. Re-login required.' });
        setOldPw(''); setNewPw(''); setConfirmPw('');
      } else {
        const err = await res.json().catch(() => ({}));
        setStatus({ ok: false, msg: err.detail || `Request failed (${res.status}).` });
      }
    } catch (err) {
      setStatus({ ok: false, msg: err.message || 'Network error.' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999,
      }}>
      <div
        onClick={e => e.stopPropagation()}
        className="glass-card"
        style={{ width: '420px', maxWidth: '92vw', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ margin: 0 }}>Account</h3>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', fontSize: '1.2rem', cursor: 'pointer' }}>×</button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', letterSpacing: '1px' }}>SIGNED IN AS</div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ color: 'var(--neo-cyan)', fontWeight: 800 }}>{currentUser?.username || '—'}</span>
            {currentUser?.role && (
              <span style={{ fontSize: '0.6rem', padding: '0.1rem 0.4rem', borderRadius: '3px', background: currentUser.role === 'admin' ? 'rgba(236,72,153,0.15)' : 'rgba(168,85,247,0.1)', color: currentUser.role === 'admin' ? '#ec4899' : '#a78bfa' }}>{currentUser.role}</span>
            )}
          </div>
        </div>

        <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', letterSpacing: '1px' }}>CHANGE PASSWORD</div>
          <input type="password" autoComplete="current-password" placeholder="Current password" value={oldPw} onChange={e => setOldPw(e.target.value)}
            style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.5rem 0.7rem', borderRadius: '4px', fontSize: '0.8rem' }} />
          <input type="password" autoComplete="new-password" placeholder="New password (min 8 chars)" value={newPw} onChange={e => setNewPw(e.target.value)}
            style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.5rem 0.7rem', borderRadius: '4px', fontSize: '0.8rem' }} />
          <input type="password" autoComplete="new-password" placeholder="Confirm new password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)}
            style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.5rem 0.7rem', borderRadius: '4px', fontSize: '0.8rem' }} />
          {status && (
            <div style={{ fontSize: '0.7rem', color: status.ok ? '#4ade80' : '#f87171', padding: '0.3rem 0' }}>{status.msg}</div>
          )}
          <button type="submit" className="btn-primary" disabled={busy} style={{ opacity: busy ? 0.5 : 1 }}>
            {busy ? 'CHANGING…' : 'CHANGE PASSWORD'}
          </button>
        </form>

        <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '0.75rem', display: 'flex', justifyContent: 'flex-end' }}>
          <button onClick={() => { logout(); onClose(); }} className="btn-primary" style={{ background: 'rgba(239,68,68,0.15)', borderColor: 'rgba(239,68,68,0.5)', color: '#f87171' }}>
            LOG OUT
          </button>
        </div>
      </div>
    </div>
  );
}
