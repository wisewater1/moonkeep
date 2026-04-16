import React from 'react';

const ProxyModule = ({ proxyPort, setProxyPort, proxyActive, setProxyActive, apiCall }) => {
  return (
    <div className="glass-card fade-in" style={{ flex: 1 }}>
      <h3>HTTP/HTTPS Intercept Proxy</h3>
      <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', alignItems: 'center' }}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>PORT</span>
        <input type="number" value={proxyPort} onChange={e => setProxyPort(Number(e.target.value))} style={{ width: '80px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'var(--neo-cyan)', padding: '0.4rem' }} />
        <button className={`btn-primary ${proxyActive ? 'ghost' : ''}`} onClick={() => {
          apiCall(proxyActive ? '/proxy/stop' : '/proxy/start', 'POST', proxyActive ? null : { port: proxyPort });
          setProxyActive(!proxyActive);
        }}>{proxyActive ? 'STOP PROXY' : 'START PROXY'}</button>
      </div>
      <p style={{ marginTop: '1rem', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Traffic intercepted by Bettercap will emit websocket events under the PROXY type. Setup complete proxy configs via CLI.</p>
    </div>
  );
};

export default ProxyModule;
