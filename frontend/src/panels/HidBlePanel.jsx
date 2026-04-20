import { useState } from 'react';

export default function HidBlePanel({ apiCall, activeTarget }) {
  const [bleDevices, setBleDevices] = useState([]);
  const [bleScanning, setBleScanning] = useState(false);
  const [blePayload, setBlePayload] = useState('GUI r\nDELAY 500\nSTRING cmd.exe\nENTER');

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>HID / BLE Tactical Injection</h3>
        <span className={`status-badge ${bleScanning ? 'active' : ''}`}>
          <span className={bleScanning ? 'pulse' : ''}>{bleScanning ? '● SCANNING' : `${bleDevices.length} DEVICES`}</span>
        </span>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button className="btn-primary" onClick={async () => {
          setBleScanning(true);
          const r = await apiCall('/hid_ble/scan');
          setBleDevices(Array.isArray(r) ? r : r?.devices || []);
          setBleScanning(false);
        }}>BLE RECON</button>
        {bleDevices.length > 0 && <button className="btn-primary btn-ghost" onClick={() => setBleDevices([])}>CLEAR</button>}
      </div>
      {bleDevices.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', maxHeight: '170px', overflowY: 'auto' }}>
          {bleDevices.map((d, i) => (
            <div key={d.mac || i} className="glass-card" style={{ padding: '0.5rem 0.8rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ fontWeight: 700, fontSize: '0.75rem', color: d.type === 'HID' ? '#f97316' : 'white' }}>{d.name || 'Unknown'}</span>
                <span style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', fontFamily: 'monospace', marginLeft: '0.5rem' }}>{d.mac}</span>
                <span style={{ fontSize: '0.55rem', background: 'rgba(255,255,255,0.07)', borderRadius: '3px', padding: '0.1rem 0.3rem', marginLeft: '0.4rem' }}>{d.type}</span>
              </div>
              <button className="btn-primary btn-danger" style={{ fontSize: '0.6rem', padding: '0.2rem 0.5rem' }}
                onClick={() => apiCall(`/hid_ble/inject?target_mac=${encodeURIComponent(d.mac)}`, 'POST')}>
                INJECT
              </button>
            </div>
          ))}
        </div>
      )}
      {bleDevices.length === 0 && !bleScanning && (
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Run BLE RECON to enumerate nearby HID/wireless peripherals (requires Bluetooth adapter + root).</p>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', marginTop: 'auto' }}>
        <span style={{ fontSize: '0.55rem', color: 'var(--text-secondary)', letterSpacing: '1.5px', textTransform: 'uppercase' }}>Ducky Payload</span>
        <textarea value={blePayload} onChange={e => setBlePayload(e.target.value)} rows={4}
          style={{ background: 'rgba(0,0,0,0.6)', border: '1px solid var(--glass-border)', color: '#86efac', fontFamily: 'Fira Code', fontSize: '0.7rem', borderRadius: '6px', padding: '0.5rem', resize: 'vertical', lineHeight: 1.5 }} />
        <button className="btn-primary btn-danger" style={{ alignSelf: 'flex-start' }}
          onClick={() => apiCall(`/hid_ble/inject?target_mac=${encodeURIComponent(activeTarget?.mac || 'AA:BB:CC:11:22:33')}`, 'POST')}>
          INJECT → {activeTarget?.mac || 'AA:BB:CC:11:22:33'}
        </button>
      </div>
    </div>
  );
}
