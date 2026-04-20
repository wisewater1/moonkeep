import { useState } from 'react';

export default function FuzzerPanel({ apiCall, activeTarget }) {
  const [fuzzResults, setFuzzResults] = useState([]);
  const [fuzzTarget, setFuzzTarget] = useState('');
  const [fuzzingStatus, setFuzzingStatus] = useState('IDLE');

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Protocol Mutation Fuzzer</h3>
        <span className={`status-badge ${fuzzingStatus !== 'IDLE' ? 'active' : ''}`}>
          <span className={fuzzingStatus !== 'IDLE' ? 'pulse' : ''}>{fuzzingStatus}</span>
        </span>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <input value={fuzzTarget} onChange={e => setFuzzTarget(e.target.value)} placeholder={activeTarget?.ip || 'Target IP'}
          style={{ width: '150px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <button className="btn-primary" onClick={async () => {
          const ip = fuzzTarget || activeTarget?.ip || '';
          if (!ip) return;
          setFuzzingStatus('SNMP…');
          const r = await apiCall(`/fuzzer/snmp?ip=${encodeURIComponent(ip)}`, 'POST');
          if (r) setFuzzResults(prev => [{ proto: 'SNMP', ip, ...r, ts: new Date().toLocaleTimeString() }, ...prev]);
          setFuzzingStatus('IDLE');
        }}>FUZZ SNMP</button>
        <button className="btn-primary" onClick={async () => {
          const ip = fuzzTarget || activeTarget?.ip || '224.0.0.251';
          setFuzzingStatus('mDNS…');
          const r = await apiCall(`/fuzzer/mdns?ip=${encodeURIComponent(ip)}`, 'POST');
          if (r) setFuzzResults(prev => [{ proto: 'mDNS', ip, ...r, ts: new Date().toLocaleTimeString() }, ...prev]);
          setFuzzingStatus('IDLE');
        }}>FUZZ mDNS</button>
        {fuzzResults.length > 0 && <button className="btn-primary btn-ghost" onClick={() => setFuzzResults([])}>CLEAR</button>}
      </div>
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
        {fuzzResults.length === 0
          ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Enter a target IP and select a protocol to begin mutation fuzzing. Results and crash signals appear here.</p>
          : fuzzResults.map((r, i) => (
            <div key={i} className="glass-card" style={{ padding: '0.6rem 0.8rem', background: 'rgba(255,255,255,0.02)', fontSize: '0.72rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                <span style={{ color: '#f97316', fontWeight: 700 }}>{r.proto}</span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: '0.6rem' }}>{r.ts}</span>
              </div>
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <span style={{ color: 'var(--neo-cyan)', fontFamily: 'monospace' }}>{r.ip}</span>
                {r.packets_sent != null && <span style={{ color: 'var(--text-secondary)' }}>{r.packets_sent} sent</span>}
                {r.responses != null && <span style={{ color: '#22c55e' }}>{r.responses} resp</span>}
                {r.crashes > 0 && <span style={{ color: '#ef4444', fontWeight: 700 }}>⚠ {r.crashes} CRASH</span>}
                {r.status && <span style={{ color: r.status === 'ok' ? '#22c55e' : '#f59e0b' }}>{r.status}</span>}
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}
