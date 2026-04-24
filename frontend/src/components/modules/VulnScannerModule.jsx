import React from 'react';

const VulnScannerModule = ({ activeTarget, vulnCards, setStrikeLog, apiCall }) => {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <h3>Vulnerability Scanner</h3>
        <button className="btn-primary" onClick={async () => {
          const target = activeTarget?.ip || '';
          const data = await apiCall(`/vuln_scan${target ? `?target=${target}` : ''}`);
          if (data) setStrikeLog(prev => [...prev.slice(-40), `[Vuln-Scanner] Scanning ${data.target}...`]);
        }}>START DEEP ANALYSIS</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '1rem', overflowY: 'auto' }}>
        {vulnCards.map((v, i) => (
          <div key={i} className="glass-card" style={{ padding: '1rem', borderLeft: `3px solid ${v.severity === 'CRITICAL' ? '#f43f5e' : '#f59e0b'}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <h4 style={{ margin: 0 }}>{v.cve}</h4>
              <span style={{ fontSize: '0.6rem', color: v.severity === 'CRITICAL' ? '#f43f5e' : '#f59e0b', fontWeight: 900 }}>{v.severity}</span>
            </div>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>{v.desc}</p>
          </div>
        ))}
        {vulnCards.length === 0 && <p style={{ color: 'var(--text-secondary)' }}>No vulnerabilities detected.</p>}
      </div>
    </div>
  );
};

export default VulnScannerModule;
