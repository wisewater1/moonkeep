import { useState } from 'react';

export default function SnifferPanel({ apiCall, packets, capturedCreds, setCapturedCreds }) {
  const [snifferActive, setSnifferActive] = useState(false);
  const [snifferIface, setSnifferIface] = useState('eth0');

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>DPI Credential Harvester</h3>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <span className={`status-badge ${snifferActive ? 'active' : ''}`}>
            <span className={snifferActive ? 'pulse' : ''}>{snifferActive ? '● LIVE' : '○ IDLE'}</span>
          </span>
          <span className="status-badge">{packets.length} PKT</span>
          {capturedCreds.length > 0 && <span className="status-badge" style={{ color: '#f87171', borderColor: 'rgba(248,113,113,0.5)' }}>{capturedCreds.length} CREDS</span>}
        </div>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <input value={snifferIface} onChange={e => setSnifferIface(e.target.value)} placeholder="Interface (eth0, wlan0)"
          style={{ width: '150px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <button className={`btn-primary ${snifferActive ? 'btn-danger' : ''}`} onClick={async () => {
          if (snifferActive) {
            await apiCall('/sniffer/stop', 'POST', {});
            setSnifferActive(false);
          } else {
            const r = await apiCall('/sniffer/start', 'POST', { iface: snifferIface });
            if (r) setSnifferActive(true);
          }
        }}>{snifferActive ? 'STOP CAPTURE' : 'START CAPTURE'}</button>
        <button className="btn-primary btn-ghost" onClick={async () => {
          const r = await apiCall('/sniffer/credentials');
          if (r?.credentials) setCapturedCreds(r.credentials);
        }}>REFRESH CREDS</button>
      </div>
      {capturedCreds.length > 0 && (
        <div className="glass-card" style={{ padding: '0.5rem 0.75rem', border: '1px solid rgba(244,63,94,0.35)', background: 'rgba(244,63,94,0.04)', maxHeight: '110px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
          {capturedCreds.map((c, i) => (
            <div key={i} style={{ fontSize: '0.72rem', fontFamily: 'Fira Code', color: '#fca5a5' }}>✦ {c}</div>
          ))}
        </div>
      )}
      {capturedCreds.length === 0 && (
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Set interface → START CAPTURE. DPI will auto-extract credentials from HTTP, FTP, SMTP, IMAP and TELNET streams.</p>
      )}
      <div style={{ flex: 1, overflowY: 'auto', background: 'rgba(0,0,0,0.4)', padding: '0.6rem', borderRadius: '8px', fontFamily: 'Fira Code', fontSize: '0.62rem' }}>
        {packets.length === 0
          ? <span style={{ color: 'var(--text-secondary)' }}>No packets yet — start capture above.</span>
          : packets.slice(-150).map((p, i) => (
            <div key={i} style={{ margin: '0.12rem 0', color: 'var(--text-secondary)' }}>{p.src} → {p.dst}</div>
          ))}
      </div>
    </div>
  );
}
