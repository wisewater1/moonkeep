import { useState } from 'react';
import { API_URL } from '../api';

export default function ReportBuilderPanel({ apiCall, activeCampaign }) {
  const [reportHTML, setReportHTML] = useState('');

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1.5rem', alignItems: 'center', justifyContent: 'center' }}>
      <h3>Pentest Report Generator</h3>
      <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textAlign: 'center', maxWidth: '400px' }}>
        Generates a full HTML/PDF pentest report for campaign <strong style={{ color: 'var(--neo-cyan)' }}>{activeCampaign}</strong> covering all discovered devices, credentials, vulnerabilities, and findings.
      </p>
      <div style={{ display: 'flex', gap: '1rem' }}>
        <button className="btn-primary" onClick={async () => {
          const r = await apiCall('/report/generate', 'POST', { campaign_id: activeCampaign });
          if (r?.report_id || r?.status) {
            setReportHTML(`${API_URL}/report/${activeCampaign}/html`);
          }
        }}>GENERATE REPORT</button>
        {reportHTML && (
          <a href={reportHTML} target="_blank" rel="noreferrer"
            style={{ display: 'inline-block', padding: '0.5rem 1rem', background: 'rgba(6,182,212,0.1)', border: '1px solid var(--neo-cyan)', color: 'var(--neo-cyan)', borderRadius: '4px', fontSize: '0.75rem', textDecoration: 'none' }}>
            VIEW REPORT
          </a>
        )}
      </div>
      {reportHTML && (
        <div style={{ width: '100%', flex: 1, borderRadius: '8px', overflow: 'hidden', border: '1px solid var(--glass-border)' }}>
          <iframe src={reportHTML} style={{ width: '100%', height: '100%', border: 'none', background: '#fff' }} title="Pentest Report" />
        </div>
      )}
    </div>
  );
}
