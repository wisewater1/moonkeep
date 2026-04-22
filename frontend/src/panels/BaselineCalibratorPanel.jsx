import { useState } from 'react';

export default function BaselineCalibratorPanel({ apiCall }) {
  const [baselineActive, setBaselineActive] = useState(false);
  const [baselineData, setBaselineData] = useState(null);
  const [baselineSecs, setBaselineSecs] = useState(60);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Noise-Floor Baseline</h3>
        <span className={`status-badge ${baselineActive ? 'active' : ''}`}>{baselineActive ? 'OBSERVING' : baselineData ? 'READY' : 'IDLE'}</span>
      </div>
      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        Passively measures ARP, DNS, and TCP-SYN rates to compute safe injection delays that stay statistically indistinguishable from baseline traffic.
      </p>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>OBSERVE FOR</span>
        <input type="number" value={baselineSecs} onChange={e => setBaselineSecs(Number(e.target.value))} min={10} max={300}
          style={{ width: '70px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'var(--neo-cyan)', padding: '0.3rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem', textAlign: 'center' }} />
        <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>seconds</span>
        <button className="btn-primary" style={{ fontSize: '0.7rem' }} disabled={baselineActive} onClick={async () => {
          setBaselineActive(true);
          setBaselineData(null);
          await apiCall('/baseline/start', 'POST', { observe_secs: baselineSecs });
          setTimeout(async () => {
            const r = await apiCall('/baseline/status');
            if (r?.baseline) setBaselineData(r.baseline);
            setBaselineActive(false);
          }, (baselineSecs + 6) * 1000);
        }}>START OBSERVATION</button>
      </div>
      {baselineData && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
          {[
            { label: 'ARP', rate: baselineData.arp_per_min, delay: baselineData.safe_arp_delay_s, color: '#22c55e' },
            { label: 'DNS', rate: baselineData.dns_per_min, delay: baselineData.safe_dns_delay_s, color: '#22d3ee' },
            { label: 'SYN', rate: baselineData.syn_per_min, delay: baselineData.safe_syn_delay_s, color: '#a78bfa' },
          ].map(m => (
            <div key={m.label} className="glass-card" style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', textAlign: 'center' }}>
              <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', letterSpacing: '1px' }}>{m.label} / MIN</div>
              <div style={{ fontSize: '1.6rem', fontWeight: 900, color: m.color, margin: '0.25rem 0' }}>{m.rate}</div>
              <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)' }}>safe delay</div>
              <div style={{ fontSize: '0.85rem', color: m.color, fontWeight: 700 }}>{m.delay}s</div>
            </div>
          ))}
        </div>
      )}
      {!baselineData && !baselineActive && <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Start observation to calibrate safe injection timing for ARP spoof, DNS hijack, and TCP spray attacks.</p>}
    </div>
  );
}
