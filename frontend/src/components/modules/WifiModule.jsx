import React from 'react';

const WifiModule = ({ networks, setNetworks, setStrikeLog, apiCall }) => {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <h3>Wireless Strike Arsenal</h3>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn-primary" onClick={async () => {
            apiCall('/bettercap/command', 'POST', { cmd: 'wifi.recon on' });
            setStrikeLog(prev => [...prev.slice(-40), "[#] AUTO-WARDRIVER STARTED"]);
          }}>START WARDRIVER</button>
          <button className="btn-primary" onClick={async () => {
            const data = await apiCall('/wifi_scan');
            if (data) setNetworks(data.networks || []);
          }}>REFRESH BANDS</button>
        </div>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem', paddingRight: '0.5rem' }}>
        {networks.length === 0 ? <p style={{ color: 'var(--text-secondary)' }}>No networks found. Run a scan or start wardriving.</p> :
          networks.map((n, i) => (
            <div key={i} className="glass-card" style={{ padding: '1rem', background: 'rgba(255,255,255,0.02)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', overflow: 'hidden' }}>
                <p style={{ fontWeight: 900, whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden', paddingRight: '0.5rem' }} title={n.ssid || 'HIDDEN'}>{n.ssid || 'HIDDEN'}</p>
                <p style={{ color: 'var(--neo-cyan)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>{n.rssi} dBm</p>
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                MAC: {n.mac} <br />
                CH: {n.channel} | ENC: {n.encryption}
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
                <button className="btn-primary" style={{ flex: 1, fontSize: '0.6rem' }} onClick={() => apiCall('/wifi/deauth', 'POST', { target: 'FF:FF:FF:FF:FF:FF', ap: n.mac })}>DEAUTH</button>
                <button className="btn-primary" style={{ flex: 1, fontSize: '0.6rem' }} onClick={() => apiCall('/wifi/capture', 'POST', { bssid: n.mac })}>LISTEN (EAPOL)</button>
              </div>
            </div>
          ))}
      </div>
    </div>
  );
};

export default WifiModule;
