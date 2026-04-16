import React from 'react';

const SnifferModule = ({ capturedCreds, packets, apiCall }) => {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>DPI Credential Loot</h3>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn-primary" onClick={() => apiCall('/sniffer/start', 'POST')}>START CAPTURE</button>
          <button className="btn-primary ghost" onClick={() => apiCall('/sniffer/stop', 'POST')}>STOP</button>
        </div>
      </div>
      <div className="glass-card" style={{ border: '1px solid var(--secondary-accent)', background: 'rgba(244, 63, 94, 0.05)', maxHeight: '200px', overflowY: 'auto' }}>
        {capturedCreds.length === 0 && <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', padding: '0.5rem' }}>No credentials captured yet. Start capture and generate traffic.</div>}
        {capturedCreds.map((c, i) => (
          <div key={i} style={{ fontSize: '0.8rem', margin: '0.3rem 0', fontFamily: 'Fira Code' }}>[FOUND] {c}</div>
        ))}
      </div>
      <div style={{ flex: 1, overflowY: 'auto', background: 'rgba(0,0,0,0.4)', padding: '1rem', borderRadius: '12px' }}>
        {packets.map((p, i) => (
          <div key={i} style={{ fontSize: '0.65rem', margin: '0.2rem 0', color: 'var(--text-secondary)' }}>{p.src} -&gt; {p.dst} {p.proto ? `[${p.proto}]` : ''} {p.query ? `DNS: ${p.query}` : ''}</div>
        ))}
      </div>
    </div>
  );
};

export default SnifferModule;
