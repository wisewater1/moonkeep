import React from 'react';

const SecretHunterModule = ({ secretFindings, setSecretFindings, apiCall }) => {
  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <h3>Repository Secret Hunter</h3>
        <button className="btn-primary" onClick={async () => {
          setSecretFindings([]);
          const data = await apiCall('/secret_hunter/hunt', 'POST');
          if (data?.findings) setSecretFindings(data.findings);
        }}>HUNT SECRETS</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table style={{ width: '100%', textAlign: 'left', fontSize: '0.75rem', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--glass-border)' }}>
              <th style={{ padding: '0.5rem' }}>TYPE</th>
              <th style={{ padding: '0.5rem' }}>FILE</th>
              <th style={{ padding: '0.5rem' }}>PREVIEW</th>
            </tr>
          </thead>
          <tbody>
            {secretFindings.map((f, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <td style={{ padding: '0.5rem', color: '#f59e0b' }}>{f.type}</td>
                <td style={{ padding: '0.5rem' }}>{f.file}</td>
                <td style={{ padding: '0.5rem', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{f.preview}</td>
              </tr>
            ))}
            {secretFindings.length === 0 && <tr><td colSpan="3" style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>No secrets found yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default SecretHunterModule;
