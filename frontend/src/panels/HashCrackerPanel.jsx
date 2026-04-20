import { useState } from 'react';

export default function HashCrackerPanel({ apiCall, rogueRADIUSHashes }) {
  const [hashInput, setHashInput] = useState('');
  const [hashResults, setHashResults] = useState([]);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Hash Cracker</h3>
        <span className={`status-badge ${hashResults.filter(r => r.cracked).length > 0 ? 'active' : ''}`}>
          {hashResults.filter(r => r.cracked).length} CRACKED
        </span>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input value={hashInput} onChange={e => setHashInput(e.target.value)} placeholder="Hash or hashcat NetNTLMv1 line"
          style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.72rem', fontFamily: 'monospace' }} />
        <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
          await apiCall('/hash_cracker/crack', 'POST', { hash: hashInput });
          setTimeout(async () => {
            const r = await apiCall('/hash_cracker/results');
            if (r?.results) setHashResults(r.results);
          }, 2000);
        }}>CRACK</button>
        <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.7 }} onClick={async () => {
          const r = await apiCall('/hash_cracker/results');
          if (r) setHashResults(r.results || []);
        }}>REFRESH</button>
      </div>
      {rogueRADIUSHashes?.length > 0 && (
        <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', background: 'rgba(168,85,247,0.08)', border: '1px solid rgba(168,85,247,0.3)', borderRadius: '6px', padding: '0.5rem 0.75rem' }}>
          {rogueRADIUSHashes.length} MSCHAPv2 hash{rogueRADIUSHashes.length > 1 ? 'es' : ''} from Rogue-RADIUS —&nbsp;
          <button style={{ background: 'none', border: 'none', color: '#a855f7', cursor: 'pointer', fontSize: '0.65rem', padding: 0 }} onClick={() => {
            setHashInput(rogueRADIUSHashes[rogueRADIUSHashes.length - 1]?.hashcat || '');
          }}>load latest</button>
        </div>
      )}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table style={{ width: '100%', fontSize: '0.7rem', borderCollapse: 'collapse' }}>
          <thead><tr style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--glass-border)' }}>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>HASH</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>RESULT</th>
          </tr></thead>
          <tbody>
            {hashResults.map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                <td style={{ padding: '0.4rem', fontFamily: 'monospace', color: 'var(--text-secondary)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.hash}</td>
                <td style={{ padding: '0.4rem', fontFamily: 'monospace', color: r.cracked ? '#4ade80' : '#6b7280' }}>{r.cracked ? r.password : 'NOT FOUND'}</td>
              </tr>
            ))}
            {hashResults.length === 0 && <tr><td colSpan="2" style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>No hashes queued.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
