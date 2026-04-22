import { useState } from 'react';

export default function MeshInjectorPanel({ apiCall }) {
  const [meshActive, setMeshActive] = useState(false);
  const [meshId, setMeshId] = useState('');
  const [meshDiscovered, setMeshDiscovered] = useState([]);
  const [meshStatus, setMeshStatus] = useState(null);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>802.11s Mesh Node Injector</h3>
        <span className={`status-badge ${meshActive ? 'active' : ''}`} style={{ color: meshActive ? '#4ade80' : undefined }}>
          {meshActive ? '● INJECTING' : '○ IDLE'}
        </span>
      </div>
      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        Injects a rogue 802.11s mesh node advertising a superior Airtime Link Metric. Legitimate mesh nodes route traffic through the attacker transparently — no deauth, no captive portal.
      </p>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <input value={meshId} onChange={e => setMeshId(e.target.value)} placeholder="Mesh ID (auto-detect if blank)"
          style={{ flex: 1, minWidth: '180px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.8 }} onClick={async () => {
          const r = await apiCall('/mesh/scan', 'POST', {});
          if (r?.meshes) setMeshDiscovered(r.meshes);
        }}>PASSIVE SCAN</button>
        <button className="btn-primary" style={{ fontSize: '0.7rem', background: meshActive ? 'rgba(239,68,68,0.15)' : undefined, borderColor: meshActive ? '#ef4444' : undefined }}
          onClick={async () => {
            if (meshActive) {
              await apiCall('/mesh/stop', 'POST', {});
              setMeshActive(false);
            } else {
              await apiCall('/mesh/start', 'POST', { mesh_id: meshId, scan_first: !meshId });
              setMeshActive(true);
            }
          }}>{meshActive ? 'STOP INJECTION' : 'INJECT NODE'}</button>
      </div>
      {meshDiscovered.length > 0 && (
        <div>
          <h4 style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>DISCOVERED MESHES</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {meshDiscovered.map((m, i) => (
              <div key={i} className="glass-card" style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                onClick={() => setMeshId(m.mesh_id)}>
                <div>
                  <span style={{ color: 'var(--neo-cyan)', fontWeight: 700, fontSize: '0.75rem' }}>{m.mesh_id || '(unnamed)'}</span>
                  <span style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', marginLeft: '0.5rem' }}>{m.bssid}</span>
                </div>
                <span style={{ fontSize: '0.65rem', color: '#f59e0b' }}>ch{m.channel}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {meshActive && meshStatus && (
        <div className="glass-card" style={{ padding: '0.75rem', background: 'rgba(34,197,94,0.04)', border: '1px solid rgba(34,197,94,0.2)', fontSize: '0.72rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.3rem' }}>
          <span><span style={{ color: 'var(--text-secondary)' }}>MESH ID</span> <span style={{ color: '#4ade80', fontFamily: 'monospace' }}>{meshStatus.mesh_id}</span></span>
          <span><span style={{ color: 'var(--text-secondary)' }}>CHANNEL</span> <span style={{ color: '#4ade80' }}>{meshStatus.channel}</span></span>
          <span><span style={{ color: 'var(--text-secondary)' }}>IFACE</span> <span style={{ color: '#4ade80' }}>{meshStatus.iface}</span></span>
          <span><span style={{ color: 'var(--text-secondary)' }}>BEACONS</span> <span style={{ color: '#4ade80' }}>~10/sec</span></span>
        </div>
      )}
    </div>
  );
}
