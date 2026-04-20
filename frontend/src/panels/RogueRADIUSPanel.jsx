export default function RogueRADIUSPanel({ apiCall, rogueRADIUSActive, setRogueRADIUSActive, rogueRADIUSSSID, setRogueRADIUSSSID, rogueRADIUSHashes, setRogueRADIUSHashes }) {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>WPA-Enterprise RADIUS Trap</h3>
        <span className={`status-badge ${rogueRADIUSActive ? 'active' : ''}`}>
          <span className={rogueRADIUSActive ? 'pulse' : ''}>{rogueRADIUSActive ? '● LIVE' : '○ IDLE'}</span>
        </span>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
        <input value={rogueRADIUSSSID} onChange={e => setRogueRADIUSSSID(e.target.value)} placeholder="Corp SSID (e.g. CorpNet)"
          style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <button className={`btn-primary ${rogueRADIUSActive ? 'btn-danger' : ''}`} onClick={async () => {
          if (rogueRADIUSActive) {
            await apiCall('/rogue_radius/stop', 'POST', {});
            setRogueRADIUSActive(false);
          } else {
            const r = await apiCall('/rogue_radius/start', 'POST', { ssid: rogueRADIUSSSID });
            if (r) setRogueRADIUSActive(true);
          }
        }}>{rogueRADIUSActive ? 'STOP RADIUS' : 'LAUNCH RADIUS'}</button>
        {rogueRADIUSActive && (
          <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
            const r = await apiCall('/rogue_radius/hashes');
            if (r) setRogueRADIUSHashes(r.hashes || []);
          }}>REFRESH HASHES ({rogueRADIUSHashes.length})</button>
        )}
      </div>
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
        {rogueRADIUSHashes.length === 0
          ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>No MSCHAPv2 hashes captured yet. Launch the trap and wait for enterprise clients.</p>
          : rogueRADIUSHashes.map((h, i) => (
            <div key={i} className="glass-card" style={{ padding: '0.5rem 0.8rem', background: 'rgba(255,255,255,0.02)', fontSize: '0.65rem' }}>
              <span style={{ color: '#a855f7', fontWeight: 700 }}>{h.identity}</span>
              <span style={{ color: 'var(--text-secondary)', marginLeft: '0.5rem', wordBreak: 'break-all', fontFamily: 'monospace' }}>{h.hashcat}</span>
            </div>
          ))}
      </div>
    </div>
  );
}
