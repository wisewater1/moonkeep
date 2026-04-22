export default function ScannerPanel({ apiCall, devices, setDevices, activeTarget, setActiveTarget, setTargetDrawerOpen, scanning, setScanning }) {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <h3>Network Topology</h3>
        <button className="btn-primary" onClick={async () => {
          setScanning(true);
          const data = await apiCall('/scan');
          if (data) setDevices(data.devices || []);
          setScanning(false);
        }}>
          {scanning ? 'SENSING...' : 'INITIATE RECON'}
        </button>
      </div>
      <div style={{ flex: 1, background: 'rgba(0,0,0,0.4)', borderRadius: '12px', border: '1px solid var(--glass-border)', display: 'flex', flexWrap: 'wrap', gap: '1rem', padding: '1.5rem', overflowY: 'auto' }}>
        {devices.length === 0 ? <p style={{ color: 'var(--text-secondary)' }}>No active nodes detected.</p> :
          devices.map((d, i) => (
            <div
              key={i}
              className={`glass-card ${activeTarget?.ip === d.ip ? 'active' : ''}`}
              style={{ padding: '1rem', minWidth: '150px', cursor: 'pointer', border: activeTarget?.ip === d.ip ? '1px solid var(--neo-cyan)' : '1px solid var(--glass-border)' }}
              onClick={() => { setActiveTarget(d); setTargetDrawerOpen(true); }}
            >
              <div style={{ color: 'var(--neo-cyan)', fontWeight: 800 }}>{d.ip}</div>
              <div style={{ fontSize: '0.65rem' }}>{d.mac}</div>
              <p style={{ fontSize: '0.6rem', color: 'var(--text-secondary)' }}>{d.vendor || 'Unknown Host'}</p>
            </div>
          ))
        }
      </div>
    </div>
  );
}
