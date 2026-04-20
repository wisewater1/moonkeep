import { useState } from 'react';

export default function CredSprayPanel({ apiCall, activeTarget }) {
  const [credSprayResults, setCredSprayResults] = useState([]);
  const [credSprayTarget, setCredSprayTarget] = useState('');
  const [credSprayCred, setCredSprayCred] = useState('');

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Credential Spray</h3>
        <span className={`status-badge ${credSprayResults.filter(r => r.success).length > 0 ? 'active' : ''}`}>
          {credSprayResults.filter(r => r.success).length} HITS / {credSprayResults.length} TOTAL
        </span>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <input value={credSprayTarget} onChange={e => setCredSprayTarget(e.target.value)} placeholder="Target IP"
          style={{ flex: 1, minWidth: '120px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <input value={credSprayCred} onChange={e => setCredSprayCred(e.target.value)} placeholder="user:pass"
          style={{ flex: 1, minWidth: '120px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
          const r = await apiCall('/cred_spray/run', 'POST', { target_ip: credSprayTarget || activeTarget?.ip, credential: credSprayCred || undefined });
          if (r) setCredSprayResults(r.results || credSprayResults);
        }}>SPRAY</button>
        <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.7 }} onClick={async () => {
          const r = await apiCall('/cred_spray/results');
          if (r) setCredSprayResults(r.results || []);
        }}>REFRESH</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table style={{ width: '100%', fontSize: '0.72rem', borderCollapse: 'collapse' }}>
          <thead><tr style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--glass-border)' }}>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>TARGET</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>PORT</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>PROTOCOL</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>CREDENTIAL</th>
          </tr></thead>
          <tbody>
            {credSprayResults.filter(r => r.success).map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                <td style={{ padding: '0.4rem', color: 'var(--neo-cyan)' }}>{r.ip}</td>
                <td style={{ padding: '0.4rem' }}>{r.port}</td>
                <td style={{ padding: '0.4rem', color: '#f59e0b' }}>{r.protocol}</td>
                <td style={{ padding: '0.4rem', fontFamily: 'monospace', color: '#4ade80' }}>{r.user}:{r.password}</td>
              </tr>
            ))}
            {credSprayResults.filter(r => r.success).length === 0 && (
              <tr><td colSpan="4" style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>No successful logins yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
