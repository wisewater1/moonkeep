import { useState } from 'react';

export default function CredGenomePanel({ apiCall }) {
  const [genomePolicy, setGenomePolicy] = useState(null);
  const [genomeCreds, setGenomeCreds] = useState([]);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Credential Genome</h3>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
            const r = await apiCall('/cred_genome/analyze', 'POST');
            if (r?.policy?.summary) setGenomePolicy(r.policy.summary);
          }}>ANALYZE GRAMMAR</button>
          <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
            const r = await apiCall('/cred_genome/generate', 'POST', { count: 100 });
            if (r?.credentials) setGenomeCreds(r.credentials);
          }}>GENERATE CREDS</button>
        </div>
      </div>
      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        Infers organisational password grammar from captured passwords and generates statistically targeted credential pairs.
      </p>
      {genomePolicy && (
        <div className="glass-card" style={{ padding: '0.75rem', background: 'rgba(34,197,94,0.03)', border: '1px solid rgba(34,197,94,0.2)', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: '0.35rem', fontSize: '0.68rem' }}>
          <span><span style={{ color: '#22c55e' }}>LENGTH</span> {genomePolicy.min_length}–{genomePolicy.max_length} (avg {genomePolicy.avg_length})</span>
          <span><span style={{ color: '#22c55e' }}>UPPER</span> {genomePolicy.req_upper ? 'REQUIRED' : 'optional'}</span>
          <span><span style={{ color: '#22c55e' }}>DIGIT</span> {genomePolicy.req_digit ? 'REQUIRED' : 'optional'}</span>
          <span><span style={{ color: '#22c55e' }}>SPECIAL</span> {genomePolicy.req_special ? 'REQUIRED' : 'optional'}</span>
          <span style={{ gridColumn: 'span 2' }}><span style={{ color: '#22c55e' }}>PATTERNS</span> {(genomePolicy.top_patterns || []).join(' · ')}</span>
          <span style={{ gridColumn: 'span 2' }}><span style={{ color: '#22c55e' }}>WORDS</span> {(genomePolicy.common_words || []).join(', ')}</span>
        </div>
      )}
      {genomeCreds.length > 0 && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{genomeCreds.length} targeted pairs generated</span>
          <button className="btn-primary" style={{ fontSize: '0.65rem' }} onClick={async () => {
            for (const c of genomeCreds.slice(0, 20)) {
              await apiCall('/cred_spray/run', 'POST', { credential: `${c.username}:${c.password}` });
            }
          }}>PIPE TOP-20 → SPRAY</button>
        </div>
      )}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table style={{ width: '100%', fontSize: '0.7rem', borderCollapse: 'collapse' }}>
          <thead><tr style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--glass-border)' }}>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>USERNAME</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>PASSWORD</th>
            <th style={{ padding: '0.4rem', textAlign: 'left' }}>CONFIDENCE</th>
          </tr></thead>
          <tbody>
            {genomeCreds.map((c, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                <td style={{ padding: '0.4rem', color: 'var(--neo-cyan)', fontFamily: 'monospace' }}>{c.username}</td>
                <td style={{ padding: '0.4rem', fontFamily: 'monospace', color: '#f87171' }}>{c.password}</td>
                <td style={{ padding: '0.4rem', color: c.confidence >= 0.6 ? '#4ade80' : '#f59e0b' }}>{Math.round(c.confidence * 100)}%</td>
              </tr>
            ))}
            {genomeCreds.length === 0 && <tr><td colSpan="3" style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>Analyze captured passwords first, then generate.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
