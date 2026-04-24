import React from 'react';

const metrics = [
  { key: 'devices', label: 'HOSTS' },
  { key: 'networks', label: 'NETWORKS' },
  { key: 'capturedCreds', label: 'CREDENTIALS' },
  { key: 'vulnCards', label: 'VULNS' },
  { key: 'secretFindings', label: 'SECRETS' },
  { key: 'strikeLog', label: 'EVENTS' },
];

const MetricsDashboard = ({ devices, networks, capturedCreds, vulnCards, secretFindings, strikeLog }) => {
  const data = { devices, networks, capturedCreds, vulnCards, secretFindings, strikeLog };

  return (
    <div style={{
      display: 'flex',
      gap: '0.6rem',
      flexWrap: 'nowrap',
    }}>
      {metrics.map(({ key, label }) => (
        <div
          key={key}
          className="glass-card"
          style={{
            flex: 1,
            padding: '0.6rem 0.8rem',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minWidth: 0,
          }}
        >
          <span style={{
            fontSize: '1.4rem',
            fontWeight: 900,
            color: 'var(--neo-cyan)',
            fontFamily: 'Fira Code, monospace',
            lineHeight: 1,
          }}>
            {(data[key] || []).length}
          </span>
          <span style={{
            fontSize: '0.5rem',
            fontWeight: 700,
            color: 'var(--text-secondary)',
            letterSpacing: '1.5px',
            marginTop: '0.3rem',
            textTransform: 'uppercase',
          }}>
            {label}
          </span>
        </div>
      ))}
    </div>
  );
};

export default MetricsDashboard;
