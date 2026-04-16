import React from 'react';

const TacticalFeed = ({ strikeLog }) => {
  return (
    <div style={{ background: 'black', borderRadius: '6px', border: '1px solid var(--glass-border)', padding: '0.5rem', overflowY: 'auto', fontFamily: 'Fira Code, monospace', fontSize: '0.6rem' }}>
      {strikeLog.map((log, i) => (
        <div key={i} style={{
          margin: '0.2rem 0',
          color: log.includes('[cap]') ? '#a78bfa' : log.includes('!') ? 'var(--secondary-accent)' : 'var(--text-secondary)'
        }}>
          {log}
        </div>
      ))}
    </div>
  );
};

export default TacticalFeed;
