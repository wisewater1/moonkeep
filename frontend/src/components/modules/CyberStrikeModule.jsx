import React from 'react';

const CyberStrikeModule = ({ cyberStrikeRole, setCyberStrikeRole, cyberStrikeLog, setCyberStrikeLog, apiCall }) => {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <h3>Autonomous Cyber-Strike</h3>
      <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
        <select value={cyberStrikeRole} onChange={e => setCyberStrikeRole(e.target.value)} style={{ background: 'rgba(0,0,0,0.5)', color: 'var(--neo-cyan)', padding: '0.5rem', border: '1px solid var(--glass-border)', borderRadius: '4px' }}>
          <option value="Shadow">Shadow (Stealth Recon)</option>
          <option value="Infiltrator">Infiltrator (MITM Strike)</option>
          <option value="Ghost">Ghost (Signal Ghost)</option>
          <option value="Reaper">Reaper (Full Killchain)</option>
        </select>
        <button className="btn-primary" onClick={async () => {
          setCyberStrikeLog(prev => [...prev, `[*] Engaging ${cyberStrikeRole} protocol...`]);
          await apiCall('/cyber_strike/start', 'POST', { role: cyberStrikeRole });
        }}>ENGAGE {cyberStrikeRole.toUpperCase()}</button>
        <button className="btn-primary ghost" onClick={async () => {
          await apiCall('/cyber_strike/stop', 'POST');
          setCyberStrikeLog(prev => [...prev, `[!] ${cyberStrikeRole} protocol ABORTED`]);
        }}>ABORT</button>
      </div>
      <div style={{ flex: 1, background: '#000', padding: '1rem', marginTop: '1rem', borderRadius: '6px', overflowY: 'auto', border: '1px solid var(--glass-border)', fontFamily: 'monospace', fontSize: '0.75rem' }}>
        {cyberStrikeLog.map((log, i) => <div key={i} style={{ color: '#22c55e', margin: '0.2rem 0' }}>{log}</div>)}
        {cyberStrikeLog.length === 0 && <div style={{ color: 'var(--text-secondary)' }}>Awaiting protocol engagement...</div>}
      </div>
    </div>
  );
};

export default CyberStrikeModule;
