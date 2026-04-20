import { useState } from 'react';

export default function WebScannerPanel({ apiCall, activeTarget }) {
  const [webScanFindings, setWebScanFindings] = useState([]);
  const [webScanTarget, setWebScanTarget] = useState('');

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Web Application Scanner</h3>
        <span className={`status-badge ${webScanFindings.length > 0 ? 'active' : ''}`}>{webScanFindings.length} FINDINGS</span>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input value={webScanTarget} onChange={e => setWebScanTarget(e.target.value)} placeholder="https://target.example.com"
          style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
          const raw = webScanTarget || `http://${activeTarget?.ip}`;
          let host = raw, port = 80, https = false;
          try {
            const u = new URL(raw.includes('://') ? raw : 'http://' + raw);
            host = u.hostname;
            https = u.protocol === 'https:';
            port = u.port ? parseInt(u.port) : (https ? 443 : 80);
          } catch { host = raw.replace(/^https?:\/\//, '').split('/')[0].split(':')[0]; }
          await apiCall('/web_scanner/scan', 'POST', { host, port, https });
          setTimeout(async () => {
            const r = await apiCall('/web_scanner/findings');
            if (r?.findings) setWebScanFindings(r.findings);
          }, 3000);
        }}>SCAN</button>
        <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.7 }} onClick={async () => {
          const r = await apiCall('/web_scanner/findings');
          if (r) setWebScanFindings(r.findings || []);
        }}>REFRESH</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
        {webScanFindings.map((f, i) => (
          <div key={i} className="glass-card" style={{ padding: '0.6rem 0.9rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between' }}>
            <div>
              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f97316' : f.severity === 'MEDIUM' ? '#eab308' : '#6b7280' }}>
                [{f.severity}]
              </span>
              <span style={{ fontSize: '0.72rem', marginLeft: '0.5rem' }}>{f.title || f.type}</span>
              <p style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: '0.15rem', fontFamily: 'monospace' }}>{f.url}</p>
            </div>
          </div>
        ))}
        {webScanFindings.length === 0 && <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Enter a URL and click SCAN to begin OWASP detection.</p>}
      </div>
    </div>
  );
}
