import { useState } from 'react';

export default function AiOrchestratorPanel({ apiCall }) {
  const [aiCmd, setAiCmd] = useState('');
  const [aiPlan, setAiPlan] = useState([]);
  const [aiInsights, setAiInsights] = useState([]);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem', alignItems: 'center' }}>
        <h3>AI Copilot War Room</h3>
        <button className="btn-primary" onClick={async () => {
          const r = await apiCall('/ai/analyze', 'GET');
          if (r?.insights) setAiInsights(r.insights);
        }}>ANALYZE TARGETS</button>
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
        <input type="text" value={aiCmd} onChange={e => setAiCmd(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') e.target.nextSibling.click(); }}
          placeholder="e.g. Pivot through 192.168 LAN seeking open databases..." style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', padding: '0.5rem', color: 'var(--neo-cyan)', fontFamily: 'Fira Code', fontSize: '0.8rem', outline: 'none' }} />
        <button className="btn-primary" onClick={async () => {
          const r = await apiCall('/ai/command', 'POST', { instruction: aiCmd });
          if (r?.plan) setAiPlan(r.plan);
        }}>PLAN ATTACK</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', flex: 1, overflow: 'hidden' }}>
        <div style={{ background: 'rgba(167,139,250,0.05)', borderRadius: '6px', border: '1px solid rgba(167,139,250,0.2)', padding: '1rem', overflowY: 'auto' }}>
          <h4 style={{ color: '#a78bfa', fontSize: '0.75rem', marginBottom: '0.5rem' }}>GENERATED PLAN</h4>
          {aiPlan.map((step, i) => (
            <div key={i} style={{ padding: '0.5rem', borderBottom: '1px solid var(--glass-border)', fontSize: '0.7rem' }}>
              <span style={{ color: '#f59e0b', fontWeight: 'bold' }}>STEP {i + 1}:</span> {step.action} via {step.plugin}
            </div>
          ))}
          {aiPlan.length === 0 && <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>No active plan.</p>}
          {aiPlan.length > 0 && <button className="btn-primary hover-glow" style={{ marginTop: '1rem', width: '100%' }} onClick={() => { apiCall('/ai/execute', 'POST', { plan: aiPlan }); setAiPlan([]); }}>EXECUTE SEQUENCE</button>}
        </div>
        <div style={{ background: 'rgba(34,197,94,0.05)', borderRadius: '6px', border: '1px solid rgba(34,197,94,0.2)', padding: '1rem', overflowY: 'auto' }}>
          <h4 style={{ color: '#22c55e', fontSize: '0.75rem', marginBottom: '0.5rem' }}>AI INSIGHTS</h4>
          {aiInsights.map((ins, i) => (
            <div key={i} style={{ padding: '0.5rem 0', borderBottom: '1px dotted rgba(34,197,94,0.3)', fontSize: '0.7rem', color: '#cbd5e1' }}>
              {ins}
            </div>
          ))}
          {aiInsights.length === 0 && <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Requires analysis.</p>}
        </div>
      </div>
    </div>
  );
}
