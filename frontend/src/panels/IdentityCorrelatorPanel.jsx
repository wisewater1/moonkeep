import { useState } from 'react';

export default function IdentityCorrelatorPanel({ apiCall }) {
  const [identities, setIdentities] = useState([]);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Cross-Protocol Identity Engine</h3>
        <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
          const r = await apiCall('/identity/correlate', 'POST');
          if (r?.identities) setIdentities(r.identities);
        }}>CORRELATE IDENTITIES</button>
      </div>
      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        Fuses RADIUS AD usernames, portal harvests, sniffer credentials, and device hostnames into ranked human profiles.
      </p>
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {identities.map((id, i) => (
          <div key={i} className="glass-card" style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '0.4rem' }}>
                <span style={{ color: 'var(--neo-cyan)', fontWeight: 800, fontSize: '0.8rem' }}>{id.username}</span>
                {id.domain && <span style={{ fontSize: '0.6rem', color: '#a78bfa', background: 'rgba(168,85,247,0.1)', padding: '0.1rem 0.35rem', borderRadius: '3px' }}>{id.domain}</span>}
                {(id.sources || []).map(s => (
                  <span key={s} style={{ fontSize: '0.55rem', color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '0.1rem 0.35rem', borderRadius: '3px' }}>{s}</span>
                ))}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.15rem', fontSize: '0.65rem', color: 'var(--text-secondary)' }}>
                {id.email && <span><span style={{ color: '#f59e0b' }}>EMAIL</span> {id.email}</span>}
                {id.device_ip && <span><span style={{ color: '#f59e0b' }}>IP</span> {id.device_ip}</span>}
                {id.hostname && <span><span style={{ color: '#f59e0b' }}>HOST</span> {id.hostname}</span>}
                {id.device_vendor && <span><span style={{ color: '#f59e0b' }}>VENDOR</span> {id.device_vendor}</span>}
              </div>
              {id.ntlm_hash && <p style={{ fontSize: '0.6rem', fontFamily: 'monospace', color: '#6b7280', marginTop: '0.3rem', wordBreak: 'break-all' }}>{id.ntlm_hash}</p>}
            </div>
            <div style={{ textAlign: 'right', flexShrink: 0 }}>
              <div style={{ fontSize: '1.2rem', fontWeight: 900, color: id.confidence >= 0.7 ? '#4ade80' : id.confidence >= 0.4 ? '#f59e0b' : '#6b7280' }}>
                {Math.round((id.confidence || 0) * 100)}%
              </div>
              <div style={{ fontSize: '0.55rem', color: 'var(--text-secondary)' }}>CONFIDENCE</div>
            </div>
          </div>
        ))}
        {identities.length === 0 && <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Run Rogue-AP, Rogue-RADIUS, or Sniffer to collect data, then click CORRELATE IDENTITIES.</p>}
      </div>
    </div>
  );
}
