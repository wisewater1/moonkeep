import { useState } from 'react';

export default function VulnScannerPanel({ apiCall, activeTarget }) {
  const [vulnCards, setVulnCards] = useState([]);
  const [vulnScanTarget, setVulnScanTarget] = useState('');
  const [vulnScanPorts, setVulnScanPorts] = useState('1-1024');
  const [vulnScanning, setVulnScanning] = useState(false);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Vulnerability Scanner</h3>
        <span className={`status-badge ${vulnScanning ? 'active' : ''}`}>
          {vulnScanning ? <span className="pulse">● SCANNING</span> : `${vulnCards.length} FINDINGS`}
        </span>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <input value={vulnScanTarget} onChange={e => setVulnScanTarget(e.target.value)} placeholder={activeTarget?.ip || 'Target IP'}
          style={{ width: '145px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <input value={vulnScanPorts} onChange={e => setVulnScanPorts(e.target.value)} placeholder="Ports (1-1024)"
          style={{ width: '120px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <button className={`btn-primary ${vulnScanning ? 'active' : ''}`} disabled={vulnScanning} onClick={async () => {
          const target = vulnScanTarget || activeTarget?.ip;
          if (!target) return;
          setVulnScanning(true);
          await apiCall(`/vuln_scan?target=${encodeURIComponent(target)}`);
          await new Promise(r => setTimeout(r, 5000));
          const res = await apiCall('/vuln_scan/results');
          if (res?.vulnerabilities) setVulnCards(res.vulnerabilities);
          setVulnScanning(false);
        }}>{vulnScanning ? 'SCANNING…' : 'DEEP SCAN'}</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '0.75rem', overflowY: 'auto', flex: 1 }}>
        {vulnCards.length === 0
          ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Enter a target IP and click DEEP SCAN — port scan, banner grab, SSL audit and CVE matching will run.</p>
          : vulnCards.map((v, i) => (
            <div key={v.cve || v.type || i} className="glass-card" style={{ padding: '1rem', borderLeft: `3px solid ${v.severity === 'CRITICAL' ? '#ef4444' : v.severity === 'HIGH' ? '#f97316' : '#eab308'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <h4 style={{ margin: 0, fontSize: '0.75rem', color: '#a78bfa' }}>{v.cve || v.type}</h4>
                <span style={{ fontSize: '0.6rem', color: v.severity === 'CRITICAL' ? '#ef4444' : v.severity === 'HIGH' ? '#f97316' : '#eab308', fontWeight: 900, flexShrink: 0, marginLeft: '0.5rem' }}>{v.severity}</span>
              </div>
              <p style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', marginTop: '0.4rem' }}>{v.desc || v.description}</p>
              {v.port && <span style={{ fontSize: '0.6rem', color: 'var(--neo-cyan)', fontFamily: 'monospace' }}>port {v.port}</span>}
            </div>
          ))}
      </div>
    </div>
  );
}
