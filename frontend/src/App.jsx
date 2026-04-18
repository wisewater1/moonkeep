import React, { useState, useEffect, useRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from '@xterm/addon-fit';
import 'xterm/css/xterm.css';
import './index.css';
import { API_BASE, WS_BASE } from './config.js';
import { AuthProvider, useAuth } from './hooks/useAuth.js';
import LoginScreen from './components/LoginScreen.jsx';
import ModulePanel from './components/ModulePanel.jsx';
import CapTerminal from './components/CapTerminal.jsx';
import TacticalFeed from './components/TacticalFeed.jsx';
import MetricsDashboard from './components/MetricsDashboard.jsx';

const ReconTerminal = () => {
  const terminalRef = useRef(null);
  const xtermRef = useRef(null);
  const wsRef = useRef(null);
  const { token } = useAuth();

  useEffect(() => {
    const term = new Terminal({
      theme: { background: '#000000', foreground: '#22c55e', cursor: '#22c55e' },
      fontFamily: 'Fira Code, monospace',
      fontSize: 13,
      cursorBlink: true
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);

    xtermRef.current = term;
    term.open(terminalRef.current);
    setTimeout(() => fitAddon.fit(), 50);

    const wsUrl = token ? `${WS_BASE}/ws/recon?token=${token}` : `${WS_BASE}/ws/recon`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = async (e) => {
      if (e.data instanceof Blob) {
        const text = await e.data.text();
        term.write(text);
      } else {
        term.write(e.data);
      }
    };

    term.onData(data => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });

    const handleResize = () => fitAddon.fit();
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      ws.close();
      term.dispose();
    };
  }, [token]);

  return (
    <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <h3>Recon-ng Interactive Terminal</h3>
        <span className="status-badge active" style={{ fontSize: '0.6rem' }}>LIVE SOCK</span>
      </div>
      <div style={{ flex: 1, background: '#000', padding: '0.5rem', borderRadius: '8px', overflow: 'hidden' }} ref={terminalRef}></div>
    </div>
  );
};

const Dashboard = () => {
  const { authFetch, user, logout, token } = useAuth();

  const [plugins, setPlugins] = useState([]);
  const [activePlugin, setActivePlugin] = useState("");
  const [devices, setDevices] = useState([]);
  const [networks, setNetworks] = useState([]);
  const [packets, setPackets] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [capturedCreds, setCapturedCreds] = useState([]);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [activeTarget, setActiveTarget] = useState(null);
  const [strikeLog, setStrikeLog] = useState(["[#] MOONKEEP v2 CORE INITIALIZED", "[#] STANDBY..."]);
  const [toasts, setToasts] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [activeCampaign, setActiveCampaign] = useState("default");

  const [secretFindings, setSecretFindings] = useState([]);
  const [vulnCards, setVulnCards] = useState([]);
  const [cyberStrikeRole, setCyberStrikeRole] = useState("Shadow");
  const [cyberStrikeLog, setCyberStrikeLog] = useState([]);
  const [aiCmd, setAiCmd] = useState("");
  const [aiPlan, setAiPlan] = useState([]);
  const [aiInsights, setAiInsights] = useState([]);
  const [proxyPort, setProxyPort] = useState(8080);
  const [targetDrawerOpen, setTargetDrawerOpen] = useState(false);

  const [spoofing, setSpoofing] = useState(false);
  const [proxyActive, setProxyActive] = useState(false);
  const [fuzzingStatus, setFuzzingStatus] = useState("IDLE");

  const [bcapStatus, setBcapStatus] = useState({ installed: false, running: false });
  const [manualTarget, setManualTarget] = useState("");

  const ws = useRef(null);

  useEffect(() => {
    if (window.location.pathname !== "/") window.history.replaceState({}, "", "/");

    const boot = async () => {
      try {
        const res = await authFetch(`${API_BASE}/plugins`);
        const data = await res.json();
        setPlugins([...data, { name: 'Recon-Console' }]);
        if (data.length > 0) setActivePlugin(data[0].name);

        const campRes = await authFetch(`${API_BASE}/campaigns`);
        const campData = await campRes.json();
        setCampaigns(campData);

        authFetch(`${API_BASE}/scan`).then(r => r.json()).then(d => {
          if (d.devices && d.devices.length > 0) {
            setDevices(d.devices);
            setActiveTarget(d.devices[0]);
          }
        });
      } catch {
        setStrikeLog(prev => [...prev.slice(-40), "[!] BACKEND OFFLINE ON PORT 8001"]);
      }
    };
    boot();

    const wsUrl = token ? `${WS_BASE}/ws?token=${token}` : `${WS_BASE}/ws`;
    ws.current = new WebSocket(wsUrl);
    ws.current.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.plugin && data.ts) {
        const msg = data.data?.msg || (typeof data.data === 'string' ? data.data : JSON.stringify(data.data));
        setStrikeLog(prev => [...prev.slice(-40), `[${data.plugin}] ${msg}`]);
        const newToast = { id: Date.now() + Math.random(), ...data };
        setToasts(prev => [...prev.slice(-6), newToast]);
        setTimeout(() => setToasts(prev => prev.filter(t => t.id !== newToast.id)), 7000);

        if (data.type === "VULN_RESULT" && data.data?.cve) {
          setVulnCards(prev => [...prev, { cve: data.data.cve, severity: data.data.severity || "HIGH", desc: data.data.desc || "" }]);
        }
        if (data.type === "SECRET_FOUND" && data.data) {
          setSecretFindings(prev => [...prev, data.data]);
        }
        if (data.plugin === "Cyber-Strike") {
          setCyberStrikeLog(prev => [...prev.slice(-60), msg]);
        }
        if (data.plugin === "AI-Orchestrator") {
          if (data.data?.insight) setAiInsights(prev => [...prev, data.data.insight]);
        }
        if (data.type === "CREDENTIAL" && data.data) {
          setCapturedCreds(prev => [...prev, typeof data.data === 'string' ? data.data : JSON.stringify(data.data)]);
        }
      } else if (data.type === "EVENT") {
        setStrikeLog(prev => [...prev.slice(-40), data.data.msg]);
      } else {
        setPackets(prev => [data, ...prev].slice(0, 50));
      }
    };

    return () => ws.current?.close();
  }, [authFetch, token]);

  useEffect(() => {
    if (!activePlugin) return;
    const poll = setInterval(() => {
      if (activePlugin === "AI-Orchestrator") {
        authFetch(`${API_BASE}/graph`).then(r => r.json()).then(setGraphData).catch(() => {});
      }
      if (activePlugin === "Sniffer") {
        authFetch(`${API_BASE}/sniffer/credentials`).then(r => r.json()).then(d => setCapturedCreds(d.credentials || [])).catch(() => {});
      }
    }, 4000);
    return () => clearInterval(poll);
  }, [activePlugin, authFetch]);

  useEffect(() => {
    const pollBcap = setInterval(() => {
      authFetch(`${API_BASE}/bettercap/status`).then(r => r.json()).then(setBcapStatus).catch(() => {});
    }, 5000);
    authFetch(`${API_BASE}/bettercap/status`).then(r => r.json()).then(setBcapStatus).catch(() => {});
    return () => clearInterval(pollBcap);
  }, [authFetch]);

  const apiCall = async (endpoint, method = 'GET', body = null) => {
    setStrikeLog(prev => [...prev.slice(-40), `[>] INVOKE: ${endpoint}`]);
    try {
      const options = { method };
      if (body) {
        options.headers = { 'Content-Type': 'application/json' };
        options.body = JSON.stringify(body);
      }
      const res = await authFetch(`${API_BASE}${endpoint}`, options);
      const data = await res.json();
      setStrikeLog(prev => [...prev.slice(-40), `[<] SUCCESS: ${endpoint}`, `[#] DATA: ${JSON.stringify(data).slice(0, 100)}...`]);
      return data;
    } catch {
      setStrikeLog(prev => [...prev.slice(-40), `[!] FAILED: ${endpoint}`]);
      return null;
    }
  };

  const handleExportReport = async () => {
    try {
      const res = await authFetch(`${API_BASE}/campaigns/${activeCampaign}/report`);
      const data = await res.json();
      if (data.report) {
        const blob = new Blob([data.report], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `moonkeep_report_${activeCampaign}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      }
    } catch { /* ignore */ }
  };

  const moduleState = {
    devices, setDevices, networks, setNetworks, packets,
    scanning, setScanning, capturedCreds,
    activeTarget, setActiveTarget, setTargetDrawerOpen,
    secretFindings, setSecretFindings,
    vulnCards, setVulnCards, setStrikeLog,
    cyberStrikeRole, setCyberStrikeRole,
    cyberStrikeLog, setCyberStrikeLog,
    aiCmd, setAiCmd, aiPlan, setAiPlan,
    aiInsights, setAiInsights, graphData,
    proxyPort, setProxyPort, proxyActive, setProxyActive,
    spoofing, setSpoofing, fuzzingStatus, setFuzzingStatus,
  };

  return (
    <div className="dashboard-container">
      <aside className="sidebar">
        <div>
          <h1 className="accent-text" style={{ fontSize: '1.6rem' }}>MOONKEEP v2</h1>
          <p style={{ fontSize: '0.6rem', letterSpacing: '4px', fontWeight: 900, color: 'var(--text-secondary)' }}>SOVEREIGN ELITE</p>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1, overflowY: 'auto' }}>
          {plugins.map(p => (
            <button
              key={p.name}
              className={`btn-primary nav-btn ${activePlugin === p.name ? 'active' : ''}`}
              onClick={() => setActivePlugin(p.name)}
            >
              {p.name.toUpperCase()}
            </button>
          ))}
        </nav>

        <div className="glass-card" style={{ padding: '0.8rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <span style={{ fontSize: '0.55rem', color: 'var(--neo-cyan)', fontWeight: 800 }}>{user?.username?.toUpperCase()}</span>
            <span style={{ fontSize: '0.45rem', color: 'var(--text-secondary)' }}>{user?.role}</span>
          </div>
          <button className="btn-primary ghost" style={{ padding: '0.2rem 0.5rem', fontSize: '0.55rem' }} onClick={logout}>LOGOUT</button>
        </div>
      </aside>

      <main className="main-content">
        <header className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', padding: '1rem 2rem', alignItems: 'center' }}>
          <div>
            <h2 className="accent-text" style={{ fontSize: '1.1rem' }}>{activePlugin || "COMMANDER"}</h2>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Operational Surface Matrix</p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', borderLeft: '1px solid rgba(167,139,250,0.2)', borderRight: '1px solid rgba(167,139,250,0.2)', padding: '0 1rem' }}>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '0.55rem', color: 'var(--text-secondary)', letterSpacing: '1px' }}>WORKSPACE / CAMPAIGN</span>
              <select
                value={activeCampaign}
                onChange={async (e) => {
                  const newCamp = e.target.value;
                  setActiveCampaign(newCamp);
                  await apiCall(`/campaigns/${newCamp}/activate`, 'PUT');
                  const d = await apiCall('/scan');
                  if (d && d.devices) setDevices(d.devices);
                }}
                style={{ background: 'transparent', color: 'var(--neo-cyan)', border: 'none', outline: 'none', fontFamily: 'Fira Code', fontWeight: 800, fontSize: '0.8rem', cursor: 'pointer' }}
              >
                {campaigns.map(c => <option key={c.id} value={c.id} style={{ background: '#000' }}>{c.name}</option>)}
              </select>
            </div>
            <button className="btn-primary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.65rem' }} onClick={handleExportReport}>
              EXPORT .MD
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, maxWidth: '400px', margin: '0 1rem' }}>
            <span style={{ fontSize: '0.6rem', color: 'var(--neo-cyan)', fontWeight: 900, whiteSpace: 'nowrap' }}>TARGET</span>
            <input
              type="text"
              value={manualTarget || activeTarget?.ip || ""}
              onChange={e => {
                setManualTarget(e.target.value);
                setActiveTarget({ ip: e.target.value, mac: "manual" });
              }}
              placeholder="192.168.1.X or scan first"
              style={{
                flex: 1,
                background: 'rgba(0,0,0,0.5)',
                border: '1px solid var(--glass-border)',
                borderRadius: '6px',
                padding: '0.4rem 0.7rem',
                color: 'var(--neo-cyan)',
                fontFamily: 'Fira Code, monospace',
                fontSize: '0.75rem',
                outline: 'none'
              }}
            />
            <span className="status-badge active" style={{ fontSize: '0.45rem', whiteSpace: 'nowrap' }}>{activeTarget?.ip ? 'LOCKED' : 'NONE'}</span>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span className="status-badge active">{user?.role?.toUpperCase() || 'ACTIVE'}</span>
            <p style={{ fontSize: '0.6rem', marginTop: '0.3rem', color: 'var(--neo-cyan)' }}>{user?.username?.toUpperCase()}</p>
          </div>
        </header>

        <MetricsDashboard
          devices={devices}
          networks={networks}
          capturedCreds={capturedCreds}
          vulnCards={vulnCards}
          secretFindings={secretFindings}
          strikeLog={strikeLog}
        />

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 450px', gap: '1rem', flex: 1, overflow: 'hidden' }}>
          <ModulePanel
            activePlugin={activePlugin}
            reconConsole={<ReconTerminal />}
            moduleState={moduleState}
            apiCall={apiCall}
          />

          <aside className="glass-card" style={{ display: 'grid', gridTemplateRows: '28px 1fr 2fr 40px', gap: '0.5rem', overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '0.85rem', margin: 0 }}>Tactical Feed</h3>
              <span className="status-badge active" style={{ fontSize: '0.5rem' }}>ENGINE LIVE</span>
            </div>

            <TacticalFeed strikeLog={strikeLog} />

            <CapTerminal bcapStatus={bcapStatus} setStrikeLog={setStrikeLog} />

            <button className="btn-primary active" style={{ height: '100%', fontSize: '0.7rem', flexShrink: 0 }} onClick={() => apiCall('/cyber_strike/start', 'POST', { role: cyberStrikeRole })}>INVOKE {cyberStrikeRole.toUpperCase()}</button>
          </aside>
        </div>
      </main>

      {targetDrawerOpen && activeTarget && (
        <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: '400px', background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(20px)', borderLeft: '1px solid var(--glass-border)', zIndex: 9000, padding: '2rem', display: 'flex', flexDirection: 'column', animation: 'slideIn 0.3s ease-out' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
            <h2 className="accent-text" style={{ margin: 0, fontSize: '1.2rem' }}>TARGET DETAIL</h2>
            <button className="btn-primary ghost" style={{ padding: '0.2rem 0.5rem' }} onClick={() => setTargetDrawerOpen(false)}>X</button>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <div className="glass-card" style={{ padding: '1rem', marginBottom: '1rem' }}>
              <span style={{ fontSize: '0.6rem', color: 'var(--text-secondary)' }}>IP ADDRESS</span>
              <div style={{ color: 'var(--neo-cyan)', fontSize: '1.2rem', fontWeight: 900 }}>{activeTarget.ip}</div>
              <span style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', display: 'block', marginTop: '0.5rem' }}>MAC / VENDOR</span>
              <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>{activeTarget.mac}</div>
              <div style={{ color: '#cbd5e1', fontSize: '0.7rem' }}>{activeTarget.vendor || 'Unknown Hardware'}</div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '0.5rem', marginTop: '2rem' }}>
              <h4 style={{ fontSize: '0.7rem', color: '#a78bfa', margin: '0 0 0.5rem 0' }}>QUICK ACTIONS</h4>
              <button className="btn-primary" onClick={() => { setTargetDrawerOpen(false); setActivePlugin('Spoofer'); setCyberStrikeRole('Infiltrator'); apiCall('/cyber_strike/start', 'POST', { role: 'Infiltrator' }); }}>[ ARP POISON ]</button>
              <button className="btn-primary" onClick={() => { setTargetDrawerOpen(false); setActivePlugin('Post-Exploit'); apiCall('/post_exploit/pivot', 'POST', { target_ip: activeTarget.ip }); }}>[ PIVOT SCAN ]</button>
              <button className="btn-primary ghost" onClick={() => { setTargetDrawerOpen(false); setActivePlugin('Fuzzer'); }}>[ FUZZ SERVICES ]</button>
            </div>
          </div>
        </div>
      )}

      <div style={{ position: 'fixed', top: '1rem', right: '1rem', zIndex: 9999, display: 'flex', flexDirection: 'column', gap: '0.5rem', pointerEvents: 'none' }}>
        {toasts.map(t => (
          <div key={t.id} style={{
            background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(10px)',
            border: `1px solid ${t.type === 'CRITICAL' || t.type === 'ERROR' ? '#f43f5e' : t.type === 'SUCCESS' ? '#22c55e' : '#a78bfa'}`,
            padding: '1rem', borderRadius: '8px', minWidth: '300px', maxWidth: '400px',
            animation: 'fadeIn 0.3s ease-out', color: '#fff', fontSize: '0.8rem',
            boxShadow: '0 4px 20px rgba(0,0,0,0.8)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.2rem' }}>
              <span style={{ fontWeight: 'bold', letterSpacing: '1px', fontSize: '0.7rem', color: t.type === 'CRITICAL' || t.type === 'ERROR' ? '#f43f5e' : t.type === 'SUCCESS' ? '#22c55e' : '#a78bfa' }}>{t.plugin.toUpperCase()} :: {t.type}</span>
              <span style={{ fontSize: '0.65rem', color: '#94a3b8', fontFamily: 'monospace' }}>{new Date(t.ts * 1000).toLocaleTimeString()}</span>
            </div>
            <div style={{ fontFamily: 'Fira Code, monospace', fontSize: '0.75rem', color: '#cbd5e1', wordBreak: 'break-word' }}>
              {t.data?.msg || (typeof t.data === 'string' ? t.data : JSON.stringify(t.data, null, 2))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const App = () => {
  return (
    <AuthProvider>
      <AppRouter />
    </AuthProvider>
  );
};

const AppRouter = () => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <Dashboard /> : <LoginScreen />;
};

export default App;
