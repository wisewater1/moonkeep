import { useState } from 'react';

export default function CyberStrikePanel({ apiCall }) {
  const [cyberStrikeRole, setCyberStrikeRole] = useState('Shadow');
  const [cyberStrikeLog, setCyberStrikeLog] = useState([]);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h3>Autonomous Cyber-Strike</h3>
        <span className="status-badge active" style={{ fontSize: '0.6rem' }}>{cyberStrikeLog.length > 0 ? 'RUNNING' : 'STANDBY'}</span>
      </div>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <select value={cyberStrikeRole} onChange={e => setCyberStrikeRole(e.target.value)}
          style={{ background: 'rgba(0,0,0,0.5)', color: 'var(--neo-cyan)', padding: '0.5rem 0.75rem', border: '1px solid var(--glass-border)', borderRadius: '4px', flex: 1 }}>
          <option value="Shadow">Shadow — Stealth Recon</option>
          <option value="Phantom">Phantom — Silent Infiltration</option>
          <option value="Ghost">Ghost — WiFi Wardriving</option>
          <option value="Specter">Specter — Complete MITM</option>
          <option value="Predator">Predator — WiFi-to-Access</option>
          <option value="Reaper">Reaper — Intel + Exploit</option>
        </select>
        <button className="btn-primary" onClick={async () => {
          setCyberStrikeLog([]);
          await apiCall('/cyber_strike/start', 'POST', { role: cyberStrikeRole });
        }}>ENGAGE {cyberStrikeRole.toUpperCase()}</button>
        <button className="btn-primary btn-danger" onClick={() => apiCall('/cyber_strike/stop', 'POST')}>ABORT</button>
      </div>
      <div style={{ flex: 1, background: '#000', padding: '1rem', marginTop: '1rem', borderRadius: '6px', overflowY: 'auto', border: '1px solid var(--glass-border)', fontFamily: 'monospace', fontSize: '0.75rem' }}>
        {cyberStrikeLog.map((log, i) => (
          <div key={i} style={{ color: log.includes('ERROR') || log.includes('FAIL') ? '#f87171' : log.includes('SUCCESS') || log.includes('FOUND') ? '#4ade80' : '#22c55e', margin: '0.15rem 0' }}>
            {log}
          </div>
        ))}
        {cyberStrikeLog.length === 0 && <div style={{ color: 'var(--text-secondary)' }}>Select a role and engage to begin automated attack sequence.</div>}
      </div>
    </div>
  );
}
