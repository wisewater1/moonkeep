import { useState } from 'react';

export default function WiFiFingerprintPanel({ apiCall, networks }) {
  const [fpProfiles, setFpProfiles] = useState([]);
  const [fpTargetBssid, setFpTargetBssid] = useState('');

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>OS Behavioral Fingerprinter</h3>
        <span className={`status-badge ${fpProfiles.length > 0 ? 'active' : ''}`}>{fpProfiles.length} PROFILES</span>
      </div>
      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        Deauths clients, measures reconnect latency, probe patterns, and EAPOL spacing to fingerprint device OS without sending identifying packets.
      </p>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input value={fpTargetBssid} onChange={e => setFpTargetBssid(e.target.value)} placeholder="AP BSSID (e.g. aa:bb:cc:dd:ee:ff)"
          style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }} />
        <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
          await apiCall('/wifi_fingerprint/start', 'POST', {});
          await apiCall('/wifi_fingerprint/fingerprint', 'POST', { bssid: fpTargetBssid || (networks[0]?.mac || 'ff:ff:ff:ff:ff:ff') });
          setTimeout(async () => {
            const r = await apiCall('/wifi_fingerprint/profiles');
            if (r?.profiles) setFpProfiles(r.profiles);
          }, 5000);
        }}>FINGERPRINT AP</button>
        <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.7 }} onClick={async () => {
          const r = await apiCall('/wifi_fingerprint/profiles');
          if (r?.profiles) setFpProfiles(r.profiles);
        }}>REFRESH</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table style={{ width: '100%', fontSize: '0.7rem', borderCollapse: 'collapse' }}>
          <thead><tr style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--glass-border)' }}>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>MAC</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>OS GUESS</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>CONF</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>RECONNECT</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>SSID HISTORY</th>
          </tr></thead>
          <tbody>
            {fpProfiles.map((p, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                <td style={{ padding: '0.4rem', fontFamily: 'monospace', color: 'var(--neo-cyan)' }}>{p.mac}</td>
                <td style={{ padding: '0.4rem', color: '#f59e0b', fontWeight: 700 }}>{p.os_guess}</td>
                <td style={{ padding: '0.4rem', color: p.confidence >= 0.7 ? '#4ade80' : p.confidence >= 0.4 ? '#f59e0b' : '#6b7280' }}>{Math.round((p.confidence || 0) * 100)}%</td>
                <td style={{ padding: '0.4rem' }}>{p.reconnect_ms != null ? `${p.reconnect_ms}ms` : '—'}</td>
                <td style={{ padding: '0.4rem', fontSize: '0.65rem', color: 'var(--text-secondary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {(p.ssid_history || []).join(', ') || '—'}
                </td>
              </tr>
            ))}
            {fpProfiles.length === 0 && <tr><td colSpan="5" style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>No profiles yet. Enter a BSSID and fingerprint.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
