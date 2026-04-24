import React from 'react';

const HidBleModule = ({ activeTarget, apiCall }) => {
  return (
    <div className="glass-card fade-in" style={{ flex: 1 }}>
      <h3>HID / BLE Tactical Injection</h3>
      <p style={{ fontSize: '0.8rem', marginBottom: '1.5rem' }}>Active Vector: {activeTarget?.mac || "AA:BB:CC:11:22:33"}</p>
      <div style={{ display: 'flex', gap: '1rem' }}>
        <button className="btn-primary" style={{ flex: 1 }} onClick={() => apiCall('/hid_ble/scan')}>BLE RECON</button>
        <button className="btn-primary" style={{ flex: 1 }} onClick={() => apiCall('/hid_ble/inject', 'POST', { target_mac: activeTarget?.mac || 'AA:BB:CC:11:22:33' })}>MOUSEJACK INJ</button>
      </div>
    </div>
  );
};

export default HidBleModule;
