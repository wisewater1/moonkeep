export default function RogueAPPanel({ apiCall, rogueAPActive, setRogueAPActive, rogueAPMode, setRogueAPMode, rogueAPSSID, setRogueAPSSID, rogueAPCreds, setRogueAPCreds }) {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Evil Twin AP</h3>
        <span className={`status-badge ${rogueAPActive ? 'active' : ''}`}>
          <span className={rogueAPActive ? 'pulse' : ''}>{rogueAPActive ? '● LIVE' : '○ IDLE'}</span>
        </span>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <input value={rogueAPSSID} onChange={e => setRogueAPSSID(e.target.value)} placeholder="SSID to impersonate"
          style={{ flex: 1, minWidth: '160px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <select value={rogueAPMode} onChange={e => setRogueAPMode(e.target.value)}
          style={{ fontSize: '0.7rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid var(--glass-border)', borderRadius: '4px', padding: '0.4rem 0.6rem' }}>
          <option value="portal">Portal — harvest creds</option>
          <option value="bridge">Bridge — silent MITM</option>
        </select>
        <button className={`btn-primary ${rogueAPActive ? 'btn-danger' : ''}`} onClick={async () => {
          if (rogueAPActive) {
            await apiCall('/rogue_ap/stop', 'POST', {});
            setRogueAPActive(false);
          } else {
            const r = await apiCall('/rogue_ap/start', 'POST', { ssid: rogueAPSSID, mode: rogueAPMode });
            if (r) setRogueAPActive(true);
          }
        }}>{rogueAPActive ? 'STOP AP' : 'LAUNCH AP'}</button>
        {rogueAPActive && (
          <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
            const r = await apiCall('/rogue_ap/creds');
            if (r) setRogueAPCreds(r.creds || []);
          }}>REFRESH CREDS ({rogueAPCreds.length})</button>
        )}
      </div>
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
        {rogueAPCreds.length === 0
          ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>No credentials captured yet. Launch the AP and wait for clients to connect.</p>
          : rogueAPCreds.map((c, i) => (
            <div key={i} className="glass-card" style={{ padding: '0.5rem 0.8rem', background: 'rgba(255,255,255,0.02)', display: 'flex', gap: '0.5rem', fontSize: '0.7rem' }}>
              <span style={{ color: 'var(--neo-cyan)' }}>{c.src_ip}</span>
              <span style={{ color: 'var(--text-secondary)' }}>→</span>
              <span style={{ color: '#f87171', fontWeight: 700 }}>{c.user}</span>
              <span style={{ color: 'var(--text-secondary)' }}>:{c.password}</span>
            </div>
          ))}
      </div>
    </div>
  );
}
