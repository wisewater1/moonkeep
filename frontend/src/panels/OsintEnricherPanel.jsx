import { useState } from 'react';

export default function OsintEnricherPanel({ apiCall, activeTarget }) {
  const [osintIP, setOsintIP] = useState('');
  const [osintData, setOsintData] = useState(null);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>OSINT Enricher</h3>
        <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
          const r = await apiCall('/osint/enrich_all', 'POST');
          if (r) setOsintData(r);
        }}>ENRICH ALL TARGETS</button>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input value={osintIP} onChange={e => setOsintIP(e.target.value)} placeholder="IP or hostname"
          style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
        <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
          const r = await apiCall(`/osint/enrich?ip=${osintIP || activeTarget?.ip}`);
          if (r) setOsintData(r);
        }}>ENRICH</button>
      </div>
      {osintData && (
        <div style={{ flex: 1, overflowY: 'auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '0.75rem' }}>
          {Object.entries(osintData).map(([ip, info]) => (
            <div key={ip} className="glass-card" style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', fontSize: '0.7rem' }}>
              <p style={{ color: 'var(--neo-cyan)', fontWeight: 700, marginBottom: '0.5rem' }}>{ip}</p>
              {info.hostname && <p><span style={{ color: 'var(--text-secondary)' }}>HOST</span> {info.hostname}</p>}
              {info.org && <p><span style={{ color: 'var(--text-secondary)' }}>ORG</span> {info.org}</p>}
              {info.country && <p><span style={{ color: 'var(--text-secondary)' }}>GEO</span> {info.city || ''} {info.country}</p>}
              {info.asn && <p><span style={{ color: 'var(--text-secondary)' }}>ASN</span> {info.asn}</p>}
              {info.open_ports?.length > 0 && <p><span style={{ color: 'var(--text-secondary)' }}>PORTS</span> {info.open_ports.join(', ')}</p>}
            </div>
          ))}
        </div>
      )}
      {!osintData && <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Enter an IP or click ENRICH ALL TARGETS to run rDNS, WHOIS, GeoIP, and Shodan lookups.</p>}
    </div>
  );
}
