import React from 'react';

const SpooferModule = ({ devices, spoofing, setSpoofing, apiCall }) => {
  return (
    <div className="glass-card fade-in" style={{ flex: 1 }}>
      <h3>Sovereign MITM Proxy</h3>
      <div style={{ marginTop: '2rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
        <div className="glass-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
          <p style={{ fontSize: '0.8rem' }}>Gateway: 192.168.1.1</p>
          <p style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>Active Target: {devices[0]?.ip || "DISCOVERY REQUIRED"}</p>
        </div>
        <button
          className={`btn-primary ${spoofing ? 'active' : ''}`}
          style={{ height: '100px', fontSize: '1rem' }}
          onClick={async () => {
            const action = spoofing ? '/spoofer/stop' : '/spoofer/start';
            const res = await apiCall(action, 'POST', { targets: devices.map(d => d.ip) });
            if (res) setSpoofing(!spoofing);
          }}
        >
          {spoofing ? 'CEASE POISONING' : 'START ARP/NDP POISON'}
        </button>
      </div>
    </div>
  );
};

export default SpooferModule;
