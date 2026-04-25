import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from '@xterm/addon-fit';
import 'xterm/css/xterm.css';
import './index.css';
import { API_BASE, WS_BASE, setApiBase, setWsBase } from './config.js';
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

    const ws = new WebSocket(WS_BASE + '/ws/recon');
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

  // WiFi Routing States
  const [rogueAPActive, setRogueAPActive] = useState(false);
  const [rogueAPMode, setRogueAPMode] = useState("portal");
  const [rogueAPSSID, setRogueAPSSID] = useState("Free_WiFi");
  const [rogueAPCreds, setRogueAPCreds] = useState([]);
  const [rogueRADIUSActive, setRogueRADIUSActive] = useState(false);
  const [rogueRADIUSSSID, setRogueRADIUSSSID] = useState("CorpNet");
  const [rogueRADIUSHashes, setRogueRADIUSHashes] = useState([]);
  const [autoAttacking, setAutoAttacking] = useState(new Set());

  // Plugin-specific States
  const [credSprayResults, setCredSprayResults] = useState([]);
  const [credSprayTarget, setCredSprayTarget] = useState('');
  const [credSprayCred, setCredSprayCred] = useState('');
  const [exploitMappings, setExploitMappings] = useState([]);
  const [webScanFindings, setWebScanFindings] = useState([]);
  const [webScanTarget, setWebScanTarget] = useState('');
  const [hashInput, setHashInput] = useState('');
  const [hashResults, setHashResults] = useState([]);
  const [osintIP, setOsintIP] = useState('');
  const [osintData, setOsintData] = useState(null);
  const [reportHTML, setReportHTML] = useState('');

  // Novel Concept Plugin States
  const [fpProfiles, setFpProfiles] = useState([]);
  const [fpTargetBssid, setFpTargetBssid] = useState('');
  const [identities, setIdentities] = useState([]);
  const [genomePolicy, setGenomePolicy] = useState(null);
  const [genomeCreds, setGenomeCreds] = useState([]);
  const [baselineActive, setBaselineActive] = useState(false);
  const [baselineData, setBaselineData] = useState(null);
  const [baselineSecs, setBaselineSecs] = useState(60);
  const [meshActive, setMeshActive] = useState(false);
  const [meshId, setMeshId] = useState('');
  const [meshDiscovered, setMeshDiscovered] = useState([]);
  const [meshStatus, setMeshStatus] = useState(null);

  // Sniffer
  const [snifferActive, setSnifferActive] = useState(false);
  const [snifferIface, setSnifferIface] = useState('eth0');
  // Post-Exploit
  const [postExploitOutput, setPostExploitOutput] = useState('');
  const [postExploitSessions, setPostExploitSessions] = useState([]);
  const [postExploitOS, setPostExploitOS] = useState('windows');
  // Fuzzer
  const [fuzzResults, setFuzzResults] = useState([]);
  const [fuzzTarget, setFuzzTarget] = useState('');
  // HID-BLE
  const [bleDevices, setBleDevices] = useState([]);
  const [bleScanning, setBleScanning] = useState(false);
  const [blePayload, setBlePayload] = useState('GUI r\nDELAY 500\nSTRING cmd.exe\nENTER');
  // Vuln-Scanner
  const [vulnScanTarget, setVulnScanTarget] = useState('');
  const [vulnScanPorts, setVulnScanPorts] = useState('1-1024');
  const [vulnScanning, setVulnScanning] = useState(false);

  // Bettercap CLI State
  const [bcapStatus, setBcapStatus] = useState({ installed: false, running: false });
  const [manualTarget, setManualTarget] = useState("");
  const [cliOutput, setCliOutput] = useState([{ text: '═══ NATIVE CAP ENGINE ═══', color: '#a78bfa' }, { text: 'Type "help" for available commands.', color: '#666' }]);
  const [suggestion, setSuggestion] = useState("");
  const [bcapCmd, setBcapCmd] = useState("");
  const [bcapHistory, setBcapHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const cliRef = useRef(null);
  const tacticalFeedRef = useRef(null);
  const inputRef = useRef(null);
  const cmdInputRef = useRef(null);

  // ── Productivity Features ──────────────────────────────────────
  const [cmdOpen, setCmdOpen]           = useState(false);
  const [cmdQuery, setCmdQuery]         = useState('');
  const [splitPanel, setSplitPanel]     = useState(null);
  const [logDrawerOpen, setLogDrawerOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const pickPlugin = (name) => { setActivePlugin(name); setMobileNavOpen(false); };
  const [redOpsMode, setRedOpsMode]     = useState(() => localStorage.getItem('moonkeep_red_ops') === '1');
  const [favPlugins, setFavPlugins]     = useState(() => { try { return JSON.parse(localStorage.getItem('moonkeep_favs') || '[]'); } catch { return []; } });
  const [pluginFindings, setPluginFindings] = useState({});

  const PLUGIN_CATEGORIES = {
    RECON:     ['Scanner', 'Wardriver', 'OSINT-Enricher', 'Recon-Console'],
    WIFI:      ['WiFi-Strike', 'Rogue-AP', 'Rogue-RADIUS', 'WiFi-Fingerprinter', 'Mesh-Injector'],
    INTERCEPT: ['Sniffer', 'Proxy', 'Spoofer'],
    EXPLOIT:   ['Post-Exploit', 'Fuzzer', 'HID-BLE-Strike', 'Cyber-Strike'],
    INTEL:     ['AI-Orchestrator', 'Secret-Hunter', 'Vuln-Scanner', 'Exploit-Mapper', 'Web-Scanner', 'Identity-Correlator'],
    CREDS:     ['Cred-Spray', 'Hash-Cracker', 'Cred-Genome', 'Baseline-Calibrator'],
    REPORT:    ['Report-Builder'],
  };
  const CAT_COLORS = {
    RECON: '#06b6d4', WIFI: '#f97316', INTERCEPT: '#a78bfa',
    EXPLOIT: '#ef4444', INTEL: '#22c55e', CREDS: '#f59e0b', REPORT: '#94a3b8',
  };

  const CLI_COMMANDS = [
    'net.probe on', 'net.probe off', 'net.recon on', 'net.recon off', 'net.show',
    'net.sniff on', 'net.sniff off',
    'arp.spoof on', 'arp.spoof off', 'arp.ban on', 'arp.ban off',
    'dns.spoof on', 'dns.spoof off',
    'wifi.recon on', 'wifi.recon off', 'wifi.show', 'wifi.deauth', 'wifi.ap on', 'wifi.ap off',
    'http.proxy on', 'http.proxy off', 'https.proxy on', 'https.proxy off',
    'tcp.proxy on', 'tcp.proxy off', 'udp.proxy on', 'udp.proxy off',
    'syn.scan', 'ble.recon on', 'ble.recon off', 'ble.show',
    'hid on', 'hid off', 'hid inject',
    'http.server on', 'http.server off',
    'mac.changer on', 'mac.changer off',
    'ticker on', 'ticker off', 'wol',
    'events.stream on', 'events.stream off', 'events.show',
    'set arp.spoof.targets', 'set dns.spoof.domains', 'set dns.spoof.address',
    'set http.proxy.port', 'set wifi.deauth.targets', 'set syn.scan.ports',
    'set ticker.commands', 'set wifi.ap.ssid',
    'get *', 'get arp.*', 'get dns.*', 'get wifi.*', 'get http.*',
    'show', 'active', 'help', 'clear', 'alias'
  ];

  const ws = useRef(null);

  // ── Red-ops theme ──────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.dataset.theme = redOpsMode ? 'red' : 'dark';
    localStorage.setItem('moonkeep_red_ops', redOpsMode ? '1' : '0');
  }, [redOpsMode]);

  // ── Session persistence ────────────────────────────────────────
  useEffect(() => {
    try { const t = localStorage.getItem('moonkeep_target'); if (t) setActiveTarget(JSON.parse(t)); } catch {}
    try { const p = localStorage.getItem('moonkeep_plugin'); if (p) setActivePlugin(p); } catch {}
    try { const v = localStorage.getItem('moonkeep_vulns');  if (v) setVulnCards(JSON.parse(v)); } catch {}
    try { const c = localStorage.getItem('moonkeep_creds');  if (c) setCapturedCreds(JSON.parse(c)); } catch {}
  }, []);
  useEffect(() => { try { localStorage.setItem('moonkeep_target', JSON.stringify(activeTarget)); } catch {} }, [activeTarget]);
  useEffect(() => { try { localStorage.setItem('moonkeep_plugin', activePlugin); } catch {} }, [activePlugin]);
  useEffect(() => { try { localStorage.setItem('moonkeep_vulns', JSON.stringify(vulnCards.slice(-100))); } catch {} }, [vulnCards]);
  useEffect(() => { try { localStorage.setItem('moonkeep_creds', JSON.stringify(capturedCreds.slice(-100))); } catch {} }, [capturedCreds]);
  useEffect(() => { try { localStorage.setItem('moonkeep_favs', JSON.stringify(favPlugins)); } catch {} }, [favPlugins]);

  // ── Ctrl+K command palette ─────────────────────────────────────
  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); setCmdOpen(o => !o); setCmdQuery(''); }
      if (e.key === 'Escape') { setCmdOpen(false); setSplitPanel(null); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => { if (cmdOpen) setTimeout(() => cmdInputRef.current?.focus(), 30); }, [cmdOpen]);

  const toggleFav = useCallback((name) => {
    setFavPlugins(prev => prev.includes(name) ? prev.filter(n => n !== name) : [...prev, name]);
  }, []);

  useEffect(() => {
    if (window.location.pathname !== "/") window.history.replaceState({}, "", "/");

    const boot = async () => {
      try {
        const res = await fetch(API_BASE + '/plugins');
        const data = await res.json();
        setPlugins([...data, { name: 'Recon-Console' }]);
        const savedPlugin = localStorage.getItem('moonkeep_plugin');
        if (!savedPlugin && data.length > 0) setActivePlugin(data[0].name);

        const campRes = await fetch(API_BASE + '/campaigns');
        const campData = await campRes.json();
        setCampaigns(campData);

        // Hydrate targets from backend store
        fetch(API_BASE + '/scan').then(r => r.json()).then(d => {
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

    ws.current = new WebSocket(WS_BASE + '/ws');
    ws.current.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.plugin && data.ts) {
          const msg = data.data?.msg || (typeof data.data === 'string' ? data.data : JSON.stringify(data.data));
          setStrikeLog(prev => [...prev.slice(-40), `[${data.plugin}] ${msg}`]);

          // Route events to the correct module state
          if (data.plugin === 'Cyber-Strike') {
            setCyberStrikeLog(prev => [...prev.slice(-100), `[${data.type}] ${msg}`]);
          }
          if (data.type === 'CREDENTIAL_FOUND' || data.type === 'HARVEST') {
            setCapturedCreds(prev => [...prev.slice(-200), msg]);
            setPluginFindings(prev => ({ ...prev, Sniffer: (prev.Sniffer || 0) + 1, 'Cred-Spray': (prev['Cred-Spray'] || 0) + 1 }));
          }
          if (data.type === 'SECRET_FOUND' && data.data?.type) {
            setSecretFindings(prev => [...prev, data.data]);
            setPluginFindings(prev => ({ ...prev, 'Secret-Hunter': (prev['Secret-Hunter'] || 0) + 1 }));
          }
          if (data.type === 'PACKET' && data.data) {
            setPackets(prev => [data.data, ...prev].slice(0, 150));
          }
          if (data.type === 'VULN_RESULT' && data.data?.findings) {
            setVulnCards(prev => {
              const existing = new Set(prev.map(v => `${v.ip}-${v.cve}-${v.port}`));
              const fresh = data.data.findings.filter(v => !existing.has(`${v.ip}-${v.cve}-${v.port}`));
              return [...prev, ...fresh];
            });
            setPluginFindings(prev => ({ ...prev, 'Vuln-Scanner': (prev['Vuln-Scanner'] || 0) + (data.data.findings?.length || 0) }));
          }

          const newToast = { id: Date.now() + Math.random(), ...data };
          setToasts(prev => [...prev.slice(-4), newToast]);
          setTimeout(() => setToasts(prev => prev.filter(t => t.id !== newToast.id)), 5000);
        } else if (data.type === "EVENT") {
          setStrikeLog(prev => [...prev.slice(-40), data.data?.msg || '']);
        } else {
          setPackets(prev => [data, ...prev].slice(0, 30));
        }
      } catch { /* malformed frame — ignore */ }
    };

    return () => ws.current?.close();
  }, [authFetch, token]);

  useEffect(() => {
    if (!activePlugin) return;
    const poll = setInterval(() => {
      if (activePlugin === "AI-Orchestrator") {
        fetch(API_BASE + '/graph').then(r => r.json()).then(setGraphData).catch(() => { });
      }
      if (activePlugin === "Sniffer") {
        fetch(API_BASE + '/sniffer/credentials').then(r => r.json()).then(d => setCapturedCreds(d.credentials || [])).catch(() => { });
      }
      if (activePlugin === "Cred-Spray") {
        fetch(API_BASE + '/cred_spray/results').then(r => r.json()).then(d => setCredSprayResults(d.results || [])).catch(() => { });
      }
      if ((activePlugin === "WiFi-Strike" || activePlugin === "Wardriver") && rogueAPActive) {
        fetch(API_BASE + '/rogue_ap/creds').then(r => r.json()).then(d => setRogueAPCreds(d.creds || [])).catch(() => { });
      }
      if ((activePlugin === "WiFi-Strike" || activePlugin === "Wardriver") && rogueRADIUSActive) {
        fetch(API_BASE + '/rogue_radius/hashes').then(r => r.json()).then(d => setRogueRADIUSHashes(d.hashes || [])).catch(() => { });
      }
      if (activePlugin === "WiFi-Fingerprinter") {
        fetch(API_BASE + '/wifi_fingerprint/profiles').then(r => r.json()).then(d => setFpProfiles(d.profiles || [])).catch(() => { });
      }
      if (activePlugin === "Baseline-Calibrator" && baselineActive) {
        fetch(API_BASE + '/baseline/status').then(r => r.json()).then(d => { if (d.baseline && d.baseline.arp_per_min !== undefined) setBaselineData(d.baseline); }).catch(() => { });
      }
      if (activePlugin === "Mesh-Injector" && meshActive) {
        fetch(API_BASE + '/mesh/status').then(r => r.json()).then(d => setMeshStatus(d)).catch(() => { });
      }
    }, 4000);
    return () => clearInterval(poll);
  }, [activePlugin, rogueAPActive, rogueRADIUSActive]);

  // Auto-scroll tactical feed on new entries
  useEffect(() => {
    if (tacticalFeedRef.current) {
      tacticalFeedRef.current.scrollTop = tacticalFeedRef.current.scrollHeight;
    }
  }, [strikeLog]);

  useEffect(() => {
    const pollBcap = setInterval(() => {
      fetch(API_BASE + '/bettercap/status').then(r => r.json()).then(setBcapStatus).catch(() => { });
    }, 5000);
    // Initial check
    fetch(API_BASE + '/bettercap/status').then(r => r.json()).then(setBcapStatus).catch(() => { });
    return () => clearInterval(pollBcap);
  }, [authFetch]);

  const sendBcapCommand = async (cmd) => {
    if (!cmd.trim()) return;
    const newHistory = [cmd, ...bcapHistory.filter(h => h !== cmd)].slice(0, 100);
    setBcapHistory(newHistory);
    try { localStorage.setItem('moonkeep_cli_history', JSON.stringify(newHistory)); } catch { }
    setHistoryIndex(-1);
    setBcapCmd("");
    setSuggestion("");
    setCliOutput(prev => [...prev, { text: `❯ ${cmd}`, color: '#a78bfa', bold: true }]);
    setStrikeLog(prev => [...prev.slice(-40), `[cap] > ${cmd}`]);
    try {
      const res = await fetch(API_BASE + '/bettercap/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cmd })
      });
      const data = await res.json();
      if (data.output === '__CLEAR__') {
        setCliOutput([{ text: '═══ CLEARED ═══', color: '#a78bfa' }]);
      } else if (data.output) {
        const lines = data.output.split('\n').filter(l => l.trim());
        setCliOutput(prev => [...prev.slice(-200), ...lines.map(l => ({
          text: l,
          color: l.includes('→') ? '#22d3ee' : l.includes('error') ? '#f43f5e' : l.includes('═') ? '#a78bfa' : '#94a3b8'
        }))]);
      }
    } catch (err) {
      setCliOutput(prev => [...prev, { text: '[!] Engine connection failed', color: '#f43f5e' }]);
      setStrikeLog(prev => [...prev.slice(-40), `[!] CAP: Connection failed`]);
    }
    setTimeout(() => cliRef.current?.scrollTo(0, cliRef.current.scrollHeight), 50);
  };

  const handleCliInput = (val) => {
    setBcapCmd(val);
    if (val.length > 1) {
      const match = CLI_COMMANDS.find(c => c.startsWith(val) && c !== val);
      setSuggestion(match ? match.slice(val.length) : "");
    } else {
      setSuggestion("");
    }
  };

  // ACTIONS
  const apiCall = async (endpoint, method = 'GET', body = null) => {
    setStrikeLog(prev => [...prev.slice(-40), `[>] INVOKE: ${endpoint}`]);
    try {
      const options = { method };
      if (body) {
        options.headers = { 'Content-Type': 'application/json' };
        options.body = JSON.stringify(body);
      }
      const res = await fetch(`${API_BASE}${endpoint}`, options);
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
      const res = await fetch(`${API_BASE}/campaigns/${activeCampaign}/report`);
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

  const renderModuleUI = (plugin = activePlugin) => {
    if (!plugin) return <div className="glass-card">INITIALIZING VECTORS...</div>;

    switch (plugin) {
      case "Scanner":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
              <h3>Network Topology</h3>
              <button className="btn-primary" onClick={async () => {
                setScanning(true);
                const data = await apiCall('/scan');
                if (data) setDevices(data.devices || []);
                setScanning(false);
              }}>
                {scanning ? 'SENSING...' : 'INITIATE RECON'}
              </button>
            </div>
            <div style={{ flex: 1, background: 'rgba(0,0,0,0.4)', borderRadius: '12px', border: '1px solid var(--glass-border)', display: 'flex', flexWrap: 'wrap', gap: '1rem', padding: '1.5rem', overflowY: 'auto' }}>
              {devices.length === 0 ? <p style={{ color: 'var(--text-secondary)' }}>No active nodes detected.</p> :
                devices.map((d, i) => (
                  <div
                    key={i}
                    className={`glass-card ${activeTarget?.ip === d.ip ? 'active' : ''}`}
                    style={{ padding: '1rem', minWidth: '150px', cursor: 'pointer', border: activeTarget?.ip === d.ip ? '1px solid var(--neo-cyan)' : '1px solid var(--glass-border)' }}
                    onClick={() => { setActiveTarget(d); setTargetDrawerOpen(true); }}
                  >
                    <div style={{ color: 'var(--neo-cyan)', fontWeight: 800 }}>{d.ip}</div>
                    <div style={{ fontSize: '0.65rem' }}>{d.mac}</div>
                    <p style={{ fontSize: '0.6rem', color: 'var(--text-secondary)' }}>{d.vendor || 'Unknown Host'}</p>
                  </div>
                ))
              }
            </div>
          </div>
        );

      case "WiFi-Strike":
      case "Wardriver":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem', overflowY: 'auto' }}>
            {/* ── Header ── */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Wireless Strike Arsenal</h3>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn-primary" onClick={() => {
                  apiCall('/bettercap/command', 'POST', { cmd: 'wifi.recon on' });
                  setStrikeLog(prev => [...prev.slice(-40), "[#] AUTO-WARDRIVER STARTED"]);
                }}>START WARDRIVER</button>
                <button className="btn-primary" onClick={async () => {
                  const data = await apiCall('/wifi_scan');
                  if (data) setNetworks(data.networks || []);
                }}>REFRESH BANDS</button>
              </div>
            </div>

            {/* ── Network Cards ── */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(270px, 1fr))', gap: '1rem' }}>
              {networks.length === 0
                ? <p style={{ color: 'var(--text-secondary)' }}>No networks found. Run a scan or start wardriving.</p>
                : networks.map((n) => (
                  <div key={n.mac} className="glass-card" style={{ padding: '1rem', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', overflow: 'hidden' }}>
                      <p style={{ fontWeight: 900, whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden', paddingRight: '0.5rem' }} title={n.ssid || 'HIDDEN'}>{n.ssid || 'HIDDEN'}</p>
                      <p style={{ color: 'var(--neo-cyan)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>{n.rssi} dBm</p>
                    </div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                      MAC: {n.mac}<br />CH: {n.channel} | ENC: {n.encryption}
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.35rem', marginTop: '0.9rem' }}>
                      <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem' }}
                        onClick={() => apiCall('/wifi/deauth', 'POST', { target: 'FF:FF:FF:FF:FF:FF', ap: n.mac })}>
                        DEAUTH
                      </button>
                      <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem' }}
                        onClick={() => apiCall(`/wifi/capture?bssid=${encodeURIComponent(n.mac)}`, 'POST')}>
                        LISTEN (EAPOL)
                      </button>
                      <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem', gridColumn: 'span 2', background: autoAttacking.has(n.mac) ? 'rgba(239,68,68,0.25)' : undefined, borderColor: autoAttacking.has(n.mac) ? '#ef4444' : undefined }}
                        disabled={autoAttacking.has(n.mac)}
                        onClick={async () => {
                          setAutoAttacking(prev => new Set([...prev, n.mac]));
                          await apiCall('/wifi/auto_attack', 'POST', { bssid: n.mac });
                          setAutoAttacking(prev => { const s = new Set(prev); s.delete(n.mac); return s; });
                        }}>
                        {autoAttacking.has(n.mac) ? 'AUTO-ATTACKING…' : 'AUTO-ATTACK (DEAUTH+CRACK)'}
                      </button>
                      <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem' }}
                        onClick={() => {
                          setRogueAPSSID(n.ssid || 'Free_WiFi');
                          apiCall('/rogue_ap/start', 'POST', { ssid: n.ssid || 'Free_WiFi', channel: n.channel || 6, mode: rogueAPMode })
                            .then(r => { if (r) setRogueAPActive(true); });
                        }}>
                        EVIL TWIN
                      </button>
                      <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.35rem' }}
                        onClick={() => {
                          setRogueRADIUSSSID(n.ssid || 'CorpNet');
                          apiCall('/rogue_radius/start', 'POST', { ssid: n.ssid || 'CorpNet', channel: n.channel || 6 })
                            .then(r => { if (r) setRogueRADIUSActive(true); });
                        }}>
                        ENT TRAP
                      </button>
                    </div>
                  </div>
                ))}
            </div>

            {/* ── Rogue AP Panel (Options A + B) ── */}
            <div className="glass-card" style={{ padding: '1rem', border: '1px solid rgba(239,68,68,0.35)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                <span style={{ fontWeight: 700, fontSize: '0.8rem', color: '#f87171' }}>
                  EVIL TWIN AP&nbsp;&nbsp;<span className={rogueAPActive ? 'pulse' : ''} style={{ color: rogueAPActive ? '#4ade80' : '#6b7280' }}>{rogueAPActive ? '● LIVE' : '○ IDLE'}</span>
                </span>
                <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <select value={rogueAPMode} onChange={e => setRogueAPMode(e.target.value)}
                    style={{ fontSize: '0.65rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '4px', padding: '0.25rem 0.4rem' }}>
                    <option value="portal">Portal — harvest creds</option>
                    <option value="bridge">Bridge — silent MITM</option>
                  </select>
                  <input value={rogueAPSSID} onChange={e => setRogueAPSSID(e.target.value)} placeholder="SSID"
                    style={{ width: '90px', fontSize: '0.65rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '4px', padding: '0.25rem 0.4rem' }} />
                  <button className={`btn-primary ${rogueAPActive ? 'btn-danger' : ''}`} style={{ fontSize: '0.6rem' }} onClick={async () => {
                    if (rogueAPActive) {
                      await apiCall('/rogue_ap/stop', 'POST', {});
                      setRogueAPActive(false);
                    } else {
                      const r = await apiCall('/rogue_ap/start', 'POST', { ssid: rogueAPSSID, mode: rogueAPMode });
                      if (r) setRogueAPActive(true);
                    }
                  }}>{rogueAPActive ? 'STOP AP' : 'LAUNCH AP'}</button>
                  {rogueAPActive && (
                    <button className="btn-primary" style={{ fontSize: '0.6rem' }} onClick={async () => {
                      const r = await apiCall('/rogue_ap/creds');
                      if (r) setRogueAPCreds(r.creds || []);
                    }}>REFRESH CREDS ({rogueAPCreds.length})</button>
                  )}
                </div>
              </div>
              {rogueAPCreds.length > 0 && (
                <div style={{ marginTop: '0.75rem', maxHeight: '130px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                  {rogueAPCreds.map((c, i) => (
                    <div key={i} style={{ fontSize: '0.65rem', padding: '0.25rem 0.4rem', background: 'rgba(0,0,0,0.3)', borderRadius: '4px' }}>
                      <span style={{ color: 'var(--neo-cyan)' }}>{c.src_ip}</span>
                      <span style={{ color: 'var(--text-secondary)', margin: '0 0.4rem' }}>→</span>
                      <span style={{ color: '#f87171' }}>{c.user}</span>
                      <span style={{ color: 'var(--text-secondary)' }}>:{c.password}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* ── Rogue RADIUS Panel (Option D) ── */}
            <div className="glass-card" style={{ padding: '1rem', border: '1px solid rgba(168,85,247,0.35)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                <span style={{ fontWeight: 700, fontSize: '0.8rem', color: '#a855f7' }}>
                  WPA-ENTERPRISE TRAP&nbsp;&nbsp;<span className={rogueRADIUSActive ? 'pulse' : ''} style={{ color: rogueRADIUSActive ? '#4ade80' : '#6b7280' }}>{rogueRADIUSActive ? '● LIVE' : '○ IDLE'}</span>
                </span>
                <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <input value={rogueRADIUSSSID} onChange={e => setRogueRADIUSSSID(e.target.value)} placeholder="Corp SSID"
                    style={{ width: '100px', fontSize: '0.65rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '4px', padding: '0.25rem 0.4rem' }} />
                  <button className={`btn-primary ${rogueRADIUSActive ? 'btn-danger' : ''}`} style={{ fontSize: '0.6rem' }} onClick={async () => {
                    if (rogueRADIUSActive) {
                      await apiCall('/rogue_radius/stop', 'POST', {});
                      setRogueRADIUSActive(false);
                    } else {
                      const r = await apiCall('/rogue_radius/start', 'POST', { ssid: rogueRADIUSSSID });
                      if (r) setRogueRADIUSActive(true);
                    }
                  }}>{rogueRADIUSActive ? 'STOP RADIUS' : 'LAUNCH RADIUS'}</button>
                  {rogueRADIUSActive && (
                    <button className="btn-primary" style={{ fontSize: '0.6rem' }} onClick={async () => {
                      const r = await apiCall('/rogue_radius/hashes');
                      if (r) setRogueRADIUSHashes(r.hashes || []);
                    }}>REFRESH HASHES ({rogueRADIUSHashes.length})</button>
                  )}
                </div>
              </div>
              {rogueRADIUSHashes.length > 0 && (
                <div style={{ marginTop: '0.75rem', maxHeight: '130px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                  {rogueRADIUSHashes.map((h, i) => (
                    <div key={i} style={{ fontSize: '0.6rem', padding: '0.25rem 0.4rem', background: 'rgba(0,0,0,0.3)', borderRadius: '4px' }}>
                      <span style={{ color: '#a855f7', fontWeight: 700 }}>{h.identity}</span>
                      <span style={{ color: 'var(--text-secondary)', marginLeft: '0.5rem', wordBreak: 'break-all', fontFamily: 'monospace' }}>{h.hashcat}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        );

      case "Spoofer":
        return (
          <div className="glass-card fade-in" style={{ flex: 1 }}>
            <h3>Sovereign MITM Proxy</h3>
            <div style={{ marginTop: '2rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
              <div className="glass-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
                <p style={{ fontSize: '0.8rem' }}>Gateway: 192.168.1.1</p>
                <p style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>Active Target: {devices[0]?.ip || "DISCOVERY REQUIRED"}</p>
              </div>
              <button
                className={`btn-primary ${spoofing ? 'btn-danger' : ''}`}
                style={{ height: '100px', fontSize: '1rem' }}
                onClick={async () => {
                  const action = spoofing ? '/spoofer/stop' : '/spoofer/start';
                  const res = await apiCall(action, 'POST', { targets: devices.map(d => d.ip) });
                  if (res) setSpoofing(!spoofing);
                }}
              >
                {spoofing ? 'CEASE POISONING' : 'START ARP/NDP POISON'}
              </button>
            </div>
          </div>
        );

      case "Sniffer":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>DPI Credential Harvester</h3>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <span className={`status-badge ${snifferActive ? 'active' : ''}`}>
                  <span className={snifferActive ? 'pulse' : ''}>{snifferActive ? '● LIVE' : '○ IDLE'}</span>
                </span>
                <span className="status-badge">{packets.length} PKT</span>
                {capturedCreds.length > 0 && <span className="status-badge" style={{ color: '#f87171', borderColor: 'rgba(248,113,113,0.5)' }}>{capturedCreds.length} CREDS</span>}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <input value={snifferIface} onChange={e => setSnifferIface(e.target.value)} placeholder="Interface (eth0, wlan0)"
                style={{ width: '150px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <button className={`btn-primary ${snifferActive ? 'btn-danger' : ''}`} onClick={async () => {
                if (snifferActive) {
                  await apiCall('/sniffer/stop', 'POST', {});
                  setSnifferActive(false);
                } else {
                  const r = await apiCall('/sniffer/start', 'POST', { iface: snifferIface });
                  if (r) setSnifferActive(true);
                }
              }}>{snifferActive ? 'STOP CAPTURE' : 'START CAPTURE'}</button>
              <button className="btn-primary btn-ghost" onClick={async () => {
                const r = await apiCall('/sniffer/credentials');
                if (r?.credentials) setCapturedCreds(r.credentials);
              }}>REFRESH CREDS</button>
            </div>
            {capturedCreds.length > 0 && (
              <div className="glass-card" style={{ padding: '0.5rem 0.75rem', border: '1px solid rgba(244,63,94,0.35)', background: 'rgba(244,63,94,0.04)', maxHeight: '110px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                {capturedCreds.map((c, i) => (
                  <div key={i} style={{ fontSize: '0.72rem', fontFamily: 'Fira Code', color: '#fca5a5' }}>✦ {c}</div>
                ))}
              </div>
            )}
            {capturedCreds.length === 0 && (
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Set interface → START CAPTURE. DPI will auto-extract credentials from HTTP, FTP, SMTP, IMAP and TELNET streams.</p>
            )}
            <div style={{ flex: 1, overflowY: 'auto', background: 'rgba(0,0,0,0.4)', padding: '0.6rem', borderRadius: '8px', fontFamily: 'Fira Code', fontSize: '0.62rem' }}>
              {packets.length === 0
                ? <span style={{ color: 'var(--text-secondary)' }}>No packets yet — start capture above.</span>
                : packets.slice(-150).map((p, i) => (
                  <div key={i} style={{ margin: '0.12rem 0', color: 'var(--text-secondary)' }}>{p.src} → {p.dst}</div>
                ))}
            </div>
          </div>
        );

      case "Post-Exploit":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Post-Exploit C2</h3>
              <span className="status-badge">{postExploitSessions.length} SESSIONS</span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <select value={postExploitOS} onChange={e => setPostExploitOS(e.target.value)}
                style={{ fontSize: '0.7rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid var(--glass-border)', borderRadius: '4px', padding: '0.4rem 0.6rem' }}>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="macos">macOS</option>
              </select>
              <button className="btn-primary" onClick={async () => {
                const r = await apiCall('/post_exploit/pivot', 'POST', { target_ip: activeTarget?.ip || '192.168.1.1' });
                if (r) setPostExploitOutput(JSON.stringify(r, null, 2));
              }}>SCAN PIVOT: {activeTarget?.ip || 'AUTO'}</button>
              <button className="btn-primary btn-ghost" onClick={async () => {
                const r = await apiCall(`/post_exploit/persistence?os=${postExploitOS}`);
                if (r?.methods) {
                  const fmt = Object.entries(r.methods).map(([name, cmd]) => `## ${name}\n${cmd}`).join('\n\n');
                  setPostExploitOutput(`# ${(r.os || postExploitOS).toUpperCase()} Persistence Payloads\n\n${fmt}`);
                } else if (r?.script) setPostExploitOutput(r.script);
                else if (r?.payload) setPostExploitOutput(r.payload);
                else if (r) setPostExploitOutput(JSON.stringify(r, null, 2));
              }}>GEN PERSISTENCE</button>
              <button className="btn-primary btn-ghost" onClick={async () => {
                const r = await apiCall('/post_exploit/exfiltrate', 'POST', { target_session_id: activeTarget?.ip });
                if (r?.files) setPostExploitOutput(r.files.join('\n'));
                else if (r?.secrets) setPostExploitOutput(r.secrets.join('\n'));
                else if (r) setPostExploitOutput(JSON.stringify(r, null, 2));
              }}>HARVEST DATA</button>
              {postExploitOutput && <button className="btn-primary btn-ghost" style={{ marginLeft: 'auto' }} onClick={() => setPostExploitOutput('')}>CLEAR</button>}
            </div>
            {postExploitSessions.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', maxHeight: '90px', overflowY: 'auto' }}>
                {postExploitSessions.map((s, i) => (
                  <div key={s.id || i} className="glass-card" style={{ padding: '0.35rem 0.7rem', background: 'rgba(255,255,255,0.02)', fontSize: '0.7rem', display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                    <span style={{ color: '#22c55e', fontWeight: 700, fontFamily: 'monospace' }}>#{s.id}</span>
                    <span style={{ color: 'var(--neo-cyan)' }}>{s.target_ip}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{s.os}</span>
                    <span style={{ color: '#f59e0b', marginLeft: 'auto' }}>{s.privileges}</span>
                  </div>
                ))}
              </div>
            )}
            <div style={{ flex: 1, background: 'rgba(0,0,0,0.5)', borderRadius: '8px', padding: '0.75rem', fontFamily: 'Fira Code', fontSize: '0.65rem', overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', border: `1px solid ${postExploitOutput ? 'rgba(34,197,94,0.25)' : 'var(--glass-border)'}`, color: postExploitOutput ? '#86efac' : 'var(--text-secondary)' }}>
              {postExploitOutput || 'Select a target then:\n• SCAN PIVOT → enumerate lateral movement paths via SMB/WinRM/SSH\n• GEN PERSISTENCE → deployable payload for selected OS\n• HARVEST DATA → enumerate secrets, .env files, credentials'}
            </div>
          </div>
        );

      case "Fuzzer":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Protocol Mutation Fuzzer</h3>
              <span className={`status-badge ${fuzzingStatus !== 'IDLE' ? 'active' : ''}`}>
                <span className={fuzzingStatus !== 'IDLE' ? 'pulse' : ''}>{fuzzingStatus}</span>
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <input value={fuzzTarget} onChange={e => setFuzzTarget(e.target.value)} placeholder={activeTarget?.ip || 'Target IP'}
                style={{ width: '150px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <button className="btn-primary" onClick={async () => {
                const ip = fuzzTarget || activeTarget?.ip || '';
                if (!ip) return;
                setFuzzingStatus('SNMP…');
                const r = await apiCall(`/fuzzer/snmp?ip=${encodeURIComponent(ip)}`, 'POST');
                if (r) setFuzzResults(prev => [{ proto: 'SNMP', ip, ...r, ts: new Date().toLocaleTimeString() }, ...prev]);
                setFuzzingStatus('IDLE');
              }}>FUZZ SNMP</button>
              <button className="btn-primary" onClick={async () => {
                const ip = fuzzTarget || activeTarget?.ip || '224.0.0.251';
                setFuzzingStatus('mDNS…');
                const r = await apiCall(`/fuzzer/mdns?ip=${encodeURIComponent(ip)}`, 'POST');
                if (r) setFuzzResults(prev => [{ proto: 'mDNS', ip, ...r, ts: new Date().toLocaleTimeString() }, ...prev]);
                setFuzzingStatus('IDLE');
              }}>FUZZ mDNS</button>
              {fuzzResults.length > 0 && <button className="btn-primary btn-ghost" onClick={() => setFuzzResults([])}>CLEAR</button>}
            </div>
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              {fuzzResults.length === 0
                ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Enter a target IP and select a protocol to begin mutation fuzzing. Results and crash signals appear here.</p>
                : fuzzResults.map((r, i) => (
                  <div key={i} className="glass-card" style={{ padding: '0.6rem 0.8rem', background: 'rgba(255,255,255,0.02)', fontSize: '0.72rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                      <span style={{ color: '#f97316', fontWeight: 700 }}>{r.proto}</span>
                      <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: '0.6rem' }}>{r.ts}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                      <span style={{ color: 'var(--neo-cyan)', fontFamily: 'monospace' }}>{r.ip}</span>
                      {r.packets_sent != null && <span style={{ color: 'var(--text-secondary)' }}>{r.packets_sent} sent</span>}
                      {r.responses != null && <span style={{ color: '#22c55e' }}>{r.responses} resp</span>}
                      {r.crashes > 0 && <span style={{ color: '#ef4444', fontWeight: 700 }}>⚠ {r.crashes} CRASH</span>}
                      {r.status && <span style={{ color: r.status === 'ok' ? '#22c55e' : '#f59e0b' }}>{r.status}</span>}
                    </div>
                  </div>
                ))}
            </div>
          </div>
        );

      case "HID-BLE-Strike":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>HID / BLE Tactical Injection</h3>
              <span className={`status-badge ${bleScanning ? 'active' : ''}`}>
                <span className={bleScanning ? 'pulse' : ''}>{bleScanning ? '● SCANNING' : `${bleDevices.length} DEVICES`}</span>
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button className="btn-primary" onClick={async () => {
                setBleScanning(true);
                const r = await apiCall('/hid_ble/scan');
                setBleDevices(Array.isArray(r) ? r : r?.devices || []);
                setBleScanning(false);
              }}>BLE RECON</button>
              {bleDevices.length > 0 && <button className="btn-primary btn-ghost" onClick={() => setBleDevices([])}>CLEAR</button>}
            </div>
            {bleDevices.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', maxHeight: '170px', overflowY: 'auto' }}>
                {bleDevices.map((d, i) => (
                  <div key={d.mac || i} className="glass-card" style={{ padding: '0.5rem 0.8rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <span style={{ fontWeight: 700, fontSize: '0.75rem', color: d.type === 'HID' ? '#f97316' : 'white' }}>{d.name || 'Unknown'}</span>
                      <span style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', fontFamily: 'monospace', marginLeft: '0.5rem' }}>{d.mac}</span>
                      <span style={{ fontSize: '0.55rem', background: 'rgba(255,255,255,0.07)', borderRadius: '3px', padding: '0.1rem 0.3rem', marginLeft: '0.4rem' }}>{d.type}</span>
                    </div>
                    <button className="btn-primary btn-danger" style={{ fontSize: '0.6rem', padding: '0.2rem 0.5rem' }}
                      onClick={() => apiCall(`/hid_ble/inject?target_mac=${encodeURIComponent(d.mac)}`, 'POST')}>
                      INJECT
                    </button>
                  </div>
                ))}
              </div>
            )}
            {bleDevices.length === 0 && !bleScanning && (
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Run BLE RECON to enumerate nearby HID/wireless peripherals (requires Bluetooth adapter + root).</p>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', marginTop: 'auto' }}>
              <span style={{ fontSize: '0.55rem', color: 'var(--text-secondary)', letterSpacing: '1.5px', textTransform: 'uppercase' }}>Ducky Payload</span>
              <textarea value={blePayload} onChange={e => setBlePayload(e.target.value)} rows={4}
                style={{ background: 'rgba(0,0,0,0.6)', border: '1px solid var(--glass-border)', color: '#86efac', fontFamily: 'Fira Code', fontSize: '0.7rem', borderRadius: '6px', padding: '0.5rem', resize: 'vertical', lineHeight: 1.5 }} />
              <button className="btn-primary btn-danger" style={{ alignSelf: 'flex-start' }}
                onClick={() => apiCall(`/hid_ble/inject?target_mac=${encodeURIComponent(activeTarget?.mac || 'AA:BB:CC:11:22:33')}`, 'POST')}>
                INJECT → {activeTarget?.mac || 'AA:BB:CC:11:22:33'}
              </button>
            </div>
          </div>
        );

      case "Secret-Hunter":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
              <h3>Repository Secret Hunter</h3>
              <button className="btn-primary" onClick={() => apiCall('/secret_hunter/hunt', 'POST')}>HUNT SECRETS</button>
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
                    <tr key={`${f.file}-${f.type}-${i}`} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
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

      case "Vuln-Scanner":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Vulnerability Scanner</h3>
              <span className={`status-badge ${vulnScanning ? 'active' : ''}`}>
                {vulnScanning ? <span className="pulse">● SCANNING</span> : `${vulnCards.length} FINDINGS`}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <input value={vulnScanTarget} onChange={e => setVulnScanTarget(e.target.value)} placeholder={activeTarget?.ip || 'Target IP'}
                style={{ width: '145px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <input value={vulnScanPorts} onChange={e => setVulnScanPorts(e.target.value)} placeholder="Ports (1-1024)"
                style={{ width: '120px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <button className={`btn-primary ${vulnScanning ? 'active' : ''}`} disabled={vulnScanning} onClick={async () => {
                const target = vulnScanTarget || activeTarget?.ip;
                if (!target) return;
                setVulnScanning(true);
                await apiCall(`/vuln_scan?target=${encodeURIComponent(target)}`);
                await new Promise(r => setTimeout(r, 5000));
                const res = await apiCall('/vuln_scan/results');
                if (res?.vulnerabilities) setVulnCards(res.vulnerabilities);
                setVulnScanning(false);
              }}>{vulnScanning ? 'SCANNING…' : 'DEEP SCAN'}</button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '0.75rem', overflowY: 'auto', flex: 1 }}>
              {vulnCards.length === 0
                ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Enter a target IP and click DEEP SCAN — port scan, banner grab, SSL audit and CVE matching will run.</p>
                : vulnCards.map((v, i) => (
                  <div key={v.cve || v.type || i} className="glass-card" style={{ padding: '1rem', borderLeft: `3px solid ${v.severity === 'CRITICAL' ? '#ef4444' : v.severity === 'HIGH' ? '#f97316' : '#eab308'}` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <h4 style={{ margin: 0, fontSize: '0.75rem', color: '#a78bfa' }}>{v.cve || v.type}</h4>
                      <span style={{ fontSize: '0.6rem', color: v.severity === 'CRITICAL' ? '#ef4444' : v.severity === 'HIGH' ? '#f97316' : '#eab308', fontWeight: 900, flexShrink: 0, marginLeft: '0.5rem' }}>{v.severity}</span>
                    </div>
                    <p style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', marginTop: '0.4rem' }}>{v.desc || v.description}</p>
                    {v.port && <span style={{ fontSize: '0.6rem', color: 'var(--neo-cyan)', fontFamily: 'monospace' }}>port {v.port}</span>}
                  </div>
                ))}
            </div>
          </div>
        );

      case "Cyber-Strike":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3>Autonomous Cyber-Strike</h3>
              <span className="status-badge active" style={{ fontSize: '0.6rem' }}>{cyberStrikeLog.length > 0 ? 'RUNNING' : 'STANDBY'}</span>
            </div>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <select value={cyberStrikeRole} onChange={e => setCyberStrikeRole(e.target.value)}
                style={{ background: 'rgba(0,0,0,0.5)', color: 'var(--neo-cyan)', padding: '0.5rem 0.75rem', border: '1px solid var(--glass-border)', borderRadius: '4px', flex: 1 }}>
                <option value="Shadow">Shadow — Stealth Recon</option>
                <option value="Phantom">Phantom — Silent Infiltration</option>
                <option value="Ghost">Ghost — WiFi Wardriving</option>
                <option value="Specter">Specter — Complete MITM</option>
                <option value="Predator">Predator — WiFi-to-Access</option>
                <option value="Reaper">Reaper — Intel + Exploit</option>
              </select>
              <button className="btn-primary" onClick={async () => {
                setCyberStrikeLog([]);
                await apiCall('/cyber_strike/start', 'POST', { role: cyberStrikeRole });
              }}>ENGAGE {cyberStrikeRole.toUpperCase()}</button>
              <button className="btn-primary btn-danger" onClick={() => apiCall('/cyber_strike/stop', 'POST')}>ABORT</button>
            </div>
            <div style={{ flex: 1, background: '#000', padding: '1rem', marginTop: '1rem', borderRadius: '6px', overflowY: 'auto', border: '1px solid var(--glass-border)', fontFamily: 'monospace', fontSize: '0.75rem' }}>
              {cyberStrikeLog.map((log, i) => (
                <div key={i} style={{ color: log.includes('ERROR') || log.includes('FAIL') ? '#f87171' : log.includes('SUCCESS') || log.includes('FOUND') ? '#4ade80' : '#22c55e', margin: '0.15rem 0' }}>
                  {log}
                </div>
              ))}
              {cyberStrikeLog.length === 0 && <div style={{ color: 'var(--text-secondary)' }}>Select a role and engage to begin automated attack sequence.</div>}
            </div>
          </div>
        );

      case "AI-Orchestrator":
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

      case "Proxy":
        return (
          <div className="glass-card fade-in" style={{ flex: 1 }}>
            <h3>HTTP/HTTPS Intercept Proxy</h3>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>PORT</span>
              <input type="number" value={proxyPort} onChange={e => setProxyPort(Number(e.target.value))} style={{ width: '80px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'var(--neo-cyan)', padding: '0.4rem' }} />
              <button className={`btn-primary ${proxyActive ? 'btn-danger' : ''}`} onClick={() => {
                apiCall(proxyActive ? '/proxy/stop' : '/proxy/start', 'POST', proxyActive ? null : { port: proxyPort });
                setProxyActive(!proxyActive);
              }}>{proxyActive ? 'STOP PROXY' : 'START PROXY'}</button>
            </div>
            <p style={{ marginTop: '1rem', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Traffic intercepted by Bettercap will emit websocket events under the PROXY type. Setup complete proxy configs via CLI.</p>
          </div>
        );

      case "Recon-Console":
        return <ReconTerminal />;

      case "Cred-Spray":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Credential Spray</h3>
              <span className={`status-badge ${credSprayResults.filter(r => r.success).length > 0 ? 'active' : ''}`}>
                {credSprayResults.filter(r => r.success).length} HITS / {credSprayResults.length} TOTAL
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <input value={credSprayTarget} onChange={e => setCredSprayTarget(e.target.value)} placeholder="Target IP"
                style={{ flex: 1, minWidth: '120px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <input value={credSprayCred} onChange={e => setCredSprayCred(e.target.value)} placeholder="user:pass"
                style={{ flex: 1, minWidth: '120px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
                const r = await apiCall('/cred_spray/run', 'POST', { target_ip: credSprayTarget || activeTarget?.ip, credential: credSprayCred || undefined });
                if (r) setCredSprayResults(r.results || credSprayResults);
              }}>SPRAY</button>
              <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.7 }} onClick={async () => {
                const r = await apiCall('/cred_spray/results');
                if (r) setCredSprayResults(r.results || []);
              }}>REFRESH</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto' }}>
              <table style={{ width: '100%', fontSize: '0.72rem', borderCollapse: 'collapse' }}>
                <thead><tr style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--glass-border)' }}>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>TARGET</th>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>PORT</th>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>PROTOCOL</th>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>CREDENTIAL</th>
                </tr></thead>
                <tbody>
                  {credSprayResults.filter(r => r.success).map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <td style={{ padding: '0.4rem', color: 'var(--neo-cyan)' }}>{r.ip}</td>
                      <td style={{ padding: '0.4rem' }}>{r.port}</td>
                      <td style={{ padding: '0.4rem', color: '#f59e0b' }}>{r.protocol}</td>
                      <td style={{ padding: '0.4rem', fontFamily: 'monospace', color: '#4ade80' }}>{r.user}:{r.password}</td>
                    </tr>
                  ))}
                  {credSprayResults.filter(r => r.success).length === 0 && (
                    <tr><td colSpan="4" style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>No successful logins yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        );

      case "Exploit-Mapper":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>CVE → Exploit Mapper</h3>
              <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
                const r = await apiCall(`/exploit_mapper/map?target=${encodeURIComponent(activeTarget?.ip || '')}`, 'POST');
                if (r?.suggestions) setExploitMappings(r.suggestions);
              }}>MAP EXPLOITS FOR {activeTarget?.ip || 'ALL'}</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {exploitMappings.length === 0
                ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Select a target device and click MAP EXPLOITS to query the CVE database.</p>
                : exploitMappings.map((m, i) => (
                  <div key={i} className="glass-card" style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <span style={{ color: '#f59e0b', fontWeight: 700, fontSize: '0.75rem' }}>{m.cve}</span>
                      <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>{m.description || m.module}</p>
                    </div>
                    <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: '1rem' }}>
                      <span style={{ fontSize: '0.65rem', color: m.cvss >= 9 ? '#ef4444' : m.cvss >= 7 ? '#f97316' : '#eab308', fontWeight: 700 }}>CVSS {m.cvss}</span>
                      {m.msf_module && <p style={{ fontSize: '0.6rem', color: '#a78bfa', fontFamily: 'monospace', marginTop: '0.2rem' }}>{m.msf_module}</p>}
                    </div>
                  </div>
                ))}
            </div>
          </div>
        );

      case "Web-Scanner":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Web Application Scanner</h3>
              <span className={`status-badge ${webScanFindings.length > 0 ? 'active' : ''}`}>{webScanFindings.length} FINDINGS</span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input value={webScanTarget} onChange={e => setWebScanTarget(e.target.value)} placeholder="https://target.example.com"
                style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
                const raw = webScanTarget || `http://${activeTarget?.ip}`;
                let host = raw, port = 80, https = false;
                try {
                  const u = new URL(raw.includes('://') ? raw : 'http://' + raw);
                  host = u.hostname;
                  https = u.protocol === 'https:';
                  port = u.port ? parseInt(u.port) : (https ? 443 : 80);
                } catch { host = raw.replace(/^https?:\/\//, '').split('/')[0].split(':')[0]; }
                await apiCall('/web_scanner/scan', 'POST', { host, port, https });
                setTimeout(async () => {
                  const r = await apiCall('/web_scanner/findings');
                  if (r?.findings) setWebScanFindings(r.findings);
                }, 3000);
              }}>SCAN</button>
              <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.7 }} onClick={async () => {
                const r = await apiCall('/web_scanner/findings');
                if (r) setWebScanFindings(r.findings || []);
              }}>REFRESH</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {webScanFindings.map((f, i) => (
                <div key={i} className="glass-card" style={{ padding: '0.6rem 0.9rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between' }}>
                  <div>
                    <span style={{ fontSize: '0.7rem', fontWeight: 700, color: f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f97316' : f.severity === 'MEDIUM' ? '#eab308' : '#6b7280' }}>
                      [{f.severity}]
                    </span>
                    <span style={{ fontSize: '0.72rem', marginLeft: '0.5rem' }}>{f.title || f.type}</span>
                    <p style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: '0.15rem', fontFamily: 'monospace' }}>{f.url}</p>
                  </div>
                </div>
              ))}
              {webScanFindings.length === 0 && <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Enter a URL and click SCAN to begin OWASP detection.</p>}
            </div>
          </div>
        );

      case "Hash-Cracker":
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
            {rogueRADIUSHashes.length > 0 && (
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

      case "OSINT-Enricher":
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

      case "Report-Builder":
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
                  setReportHTML(`${API_BASE}/report/${activeCampaign}/html`);
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

      case "WiFi-Fingerprinter":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>OS Behavioral Fingerprinter</h3>
              <span className={`status-badge ${fpProfiles.length > 0 ? 'active' : ''}`}>{fpProfiles.length} PROFILES</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Deauths clients, measures reconnect latency, probe patterns, and EAPOL spacing to fingerprint device OS without sending identifying packets.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input value={fpTargetBssid} onChange={e => setFpTargetBssid(e.target.value)} placeholder="AP BSSID (e.g. aa:bb:cc:dd:ee:ff)"
                style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }} />
              <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
                await apiCall('/wifi_fingerprint/start', 'POST', {});
                await apiCall('/wifi_fingerprint/fingerprint', 'POST', { bssid: fpTargetBssid || (networks[0]?.mac || 'ff:ff:ff:ff:ff:ff') });
                setTimeout(async () => {
                  const r = await apiCall('/wifi_fingerprint/profiles');
                  if (r?.profiles) setFpProfiles(r.profiles);
                }, 5000);
              }}>FINGERPRINT AP</button>
              <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.7 }} onClick={async () => {
                const r = await apiCall('/wifi_fingerprint/profiles');
                if (r?.profiles) setFpProfiles(r.profiles);
              }}>REFRESH</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto' }}>
              <table style={{ width: '100%', fontSize: '0.7rem', borderCollapse: 'collapse' }}>
                <thead><tr style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--glass-border)' }}>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>MAC</th>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>OS GUESS</th>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>CONF</th>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>RECONNECT</th>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>PROBES</th>
                  <th style={{ padding: '0.4rem', textAlign: 'left' }}>SSID HISTORY</th>
                </tr></thead>
                <tbody>
                  {fpProfiles.map((p, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <td style={{ padding: '0.4rem', fontFamily: 'monospace', color: 'var(--neo-cyan)' }}>{p.mac}</td>
                      <td style={{ padding: '0.4rem', color: '#f59e0b', fontWeight: 700 }}>{p.os_guess}</td>
                      <td style={{ padding: '0.4rem', color: p.confidence >= 0.7 ? '#4ade80' : p.confidence >= 0.4 ? '#f59e0b' : '#6b7280' }}>{Math.round((p.confidence || 0) * 100)}%</td>
                      <td style={{ padding: '0.4rem' }}>{p.reconnect_ms != null ? `${p.reconnect_ms}ms` : '—'}</td>
                      <td style={{ padding: '0.4rem', color: 'var(--text-secondary)' }}>{p.probe_pattern}</td>
                      <td style={{ padding: '0.4rem', fontSize: '0.65rem', color: 'var(--text-secondary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {(p.ssid_history || []).join(', ') || '—'}
                      </td>
                    </tr>
                  ))}
                  {fpProfiles.length === 0 && <tr><td colSpan="6" style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>No profiles yet. Enter a BSSID and fingerprint.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        );

      case "Identity-Correlator":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Cross-Protocol Identity Engine</h3>
              <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
                const r = await apiCall('/identity/correlate', 'POST');
                if (r?.identities) setIdentities(r.identities);
              }}>CORRELATE IDENTITIES</button>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Fuses RADIUS AD usernames, portal harvests, sniffer credentials, and device hostnames into ranked human profiles.
            </p>
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {identities.map((id, i) => (
                <div key={i} className="glass-card" style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '0.4rem' }}>
                      <span style={{ color: 'var(--neo-cyan)', fontWeight: 800, fontSize: '0.8rem' }}>{id.username}</span>
                      {id.domain && <span style={{ fontSize: '0.6rem', color: '#a78bfa', background: 'rgba(168,85,247,0.1)', padding: '0.1rem 0.35rem', borderRadius: '3px' }}>{id.domain}</span>}
                      {(id.sources || []).map(s => (
                        <span key={s} style={{ fontSize: '0.55rem', color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '0.1rem 0.35rem', borderRadius: '3px' }}>{s}</span>
                      ))}
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.15rem', fontSize: '0.65rem', color: 'var(--text-secondary)' }}>
                      {id.email && <span><span style={{ color: '#f59e0b' }}>EMAIL</span> {id.email}</span>}
                      {id.device_ip && <span><span style={{ color: '#f59e0b' }}>IP</span> {id.device_ip}</span>}
                      {id.hostname && <span><span style={{ color: '#f59e0b' }}>HOST</span> {id.hostname}</span>}
                      {id.device_vendor && <span><span style={{ color: '#f59e0b' }}>VENDOR</span> {id.device_vendor}</span>}
                    </div>
                    {id.ntlm_hash && <p style={{ fontSize: '0.6rem', fontFamily: 'monospace', color: '#6b7280', marginTop: '0.3rem', wordBreak: 'break-all' }}>{id.ntlm_hash}</p>}
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ fontSize: '1.2rem', fontWeight: 900, color: id.confidence >= 0.7 ? '#4ade80' : id.confidence >= 0.4 ? '#f59e0b' : '#6b7280' }}>
                      {Math.round((id.confidence || 0) * 100)}%
                    </div>
                    <div style={{ fontSize: '0.55rem', color: 'var(--text-secondary)' }}>CONFIDENCE</div>
                  </div>
                </div>
              ))}
              {identities.length === 0 && <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Run Rogue-AP, Rogue-RADIUS, or Sniffer to collect data, then click CORRELATE IDENTITIES.</p>}
            </div>
          </div>
        );

      case "Cred-Genome":
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

      case "Baseline-Calibrator":
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
            {baselineData && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.7rem' }}>
                <div className="glass-card" style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.02)' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>AVG PACKET SIZE</span>
                  <span style={{ float: 'right', color: 'var(--neo-cyan)', fontWeight: 700 }}>{baselineData.avg_packet_bytes} B</span>
                </div>
                <div className="glass-card" style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.02)' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>OBSERVED</span>
                  <span style={{ float: 'right', color: 'var(--neo-cyan)', fontWeight: 700 }}>{baselineData.observed_seconds}s</span>
                </div>
              </div>
            )}
            {!baselineData && !baselineActive && <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Start observation to calibrate safe injection timing for ARP spoof, DNS hijack, and TCP spray attacks.</p>}
          </div>
        );

      case "Mesh-Injector":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>802.11s Mesh Node Injector</h3>
              <span className={`status-badge ${meshActive ? 'active' : ''}`} style={{ color: meshActive ? '#4ade80' : undefined }}>
                {meshActive ? '● INJECTING' : '○ IDLE'}
              </span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Injects a rogue 802.11s mesh node advertising a superior Airtime Link Metric. Legitimate mesh nodes route traffic through the attacker transparently — no deauth, no captive portal.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <input value={meshId} onChange={e => setMeshId(e.target.value)} placeholder="Mesh ID (auto-detect if blank)"
                style={{ flex: 1, minWidth: '180px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <button className="btn-primary" style={{ fontSize: '0.7rem', opacity: 0.8 }} onClick={async () => {
                const r = await apiCall('/mesh/scan', 'POST', {});
                if (r?.meshes) setMeshDiscovered(r.meshes);
              }}>PASSIVE SCAN</button>
              <button className="btn-primary" style={{ fontSize: '0.7rem', background: meshActive ? 'rgba(239,68,68,0.15)' : undefined, borderColor: meshActive ? '#ef4444' : undefined }}
                onClick={async () => {
                  if (meshActive) {
                    await apiCall('/mesh/stop', 'POST', {});
                    setMeshActive(false);
                  } else {
                    await apiCall('/mesh/start', 'POST', { mesh_id: meshId, scan_first: !meshId });
                    setMeshActive(true);
                  }
                }}>{meshActive ? 'STOP INJECTION' : 'INJECT NODE'}</button>
            </div>
            {meshDiscovered.length > 0 && (
              <div>
                <h4 style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>DISCOVERED MESHES</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                  {meshDiscovered.map((m, i) => (
                    <div key={i} className="glass-card" style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                      onClick={() => setMeshId(m.mesh_id)}>
                      <div>
                        <span style={{ color: 'var(--neo-cyan)', fontWeight: 700, fontSize: '0.75rem' }}>{m.mesh_id || '(unnamed)'}</span>
                        <span style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', marginLeft: '0.5rem' }}>{m.bssid}</span>
                      </div>
                      <span style={{ fontSize: '0.65rem', color: '#f59e0b' }}>ch{m.channel}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {meshActive && meshStatus && (
              <div className="glass-card" style={{ padding: '0.75rem', background: 'rgba(34,197,94,0.04)', border: '1px solid rgba(34,197,94,0.2)', fontSize: '0.72rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.3rem' }}>
                <span><span style={{ color: 'var(--text-secondary)' }}>MESH ID</span> <span style={{ color: '#4ade80', fontFamily: 'monospace' }}>{meshStatus.mesh_id}</span></span>
                <span><span style={{ color: 'var(--text-secondary)' }}>CHANNEL</span> <span style={{ color: '#4ade80' }}>{meshStatus.channel}</span></span>
                <span><span style={{ color: 'var(--text-secondary)' }}>IFACE</span> <span style={{ color: '#4ade80' }}>{meshStatus.iface}</span></span>
                <span><span style={{ color: 'var(--text-secondary)' }}>BEACONS</span> <span style={{ color: '#4ade80' }}>~10/sec</span></span>
              </div>
            )}
          </div>
        );

      case "Rogue-AP":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Evil Twin AP</h3>
              <span className={`status-badge ${rogueAPActive ? 'active' : ''}`}>
                <span className={rogueAPActive ? 'pulse' : ''}>{rogueAPActive ? '● LIVE' : '○ IDLE'}</span>
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <input value={rogueAPSSID} onChange={e => setRogueAPSSID(e.target.value)} placeholder="SSID to impersonate"
                style={{ flex: 1, minWidth: '160px', background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <select value={rogueAPMode} onChange={e => setRogueAPMode(e.target.value)}
                style={{ fontSize: '0.7rem', background: 'rgba(0,0,0,0.6)', color: 'white', border: '1px solid var(--glass-border)', borderRadius: '4px', padding: '0.4rem 0.6rem' }}>
                <option value="portal">Portal — harvest creds</option>
                <option value="bridge">Bridge — silent MITM</option>
              </select>
              <button className={`btn-primary ${rogueAPActive ? 'btn-danger' : ''}`} onClick={async () => {
                if (rogueAPActive) {
                  await apiCall('/rogue_ap/stop', 'POST', {});
                  setRogueAPActive(false);
                } else {
                  const r = await apiCall('/rogue_ap/start', 'POST', { ssid: rogueAPSSID, mode: rogueAPMode });
                  if (r) setRogueAPActive(true);
                }
              }}>{rogueAPActive ? 'STOP AP' : 'LAUNCH AP'}</button>
              {rogueAPActive && (
                <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
                  const r = await apiCall('/rogue_ap/creds');
                  if (r) setRogueAPCreds(r.creds || []);
                }}>REFRESH CREDS ({rogueAPCreds.length})</button>
              )}
            </div>
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              {rogueAPCreds.length === 0
                ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>No credentials captured yet. Launch the AP and wait for clients to connect.</p>
                : rogueAPCreds.map((c, i) => (
                  <div key={i} className="glass-card" style={{ padding: '0.5rem 0.8rem', background: 'rgba(255,255,255,0.02)', display: 'flex', gap: '0.5rem', fontSize: '0.7rem' }}>
                    <span style={{ color: 'var(--neo-cyan)' }}>{c.src_ip}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>→</span>
                    <span style={{ color: '#f87171', fontWeight: 700 }}>{c.user}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>:{c.password}</span>
                  </div>
                ))}
            </div>
          </div>
        );

      case "Rogue-RADIUS":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>WPA-Enterprise RADIUS Trap</h3>
              <span className={`status-badge ${rogueRADIUSActive ? 'active' : ''}`}>
                <span className={rogueRADIUSActive ? 'pulse' : ''}>{rogueRADIUSActive ? '● LIVE' : '○ IDLE'}</span>
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <input value={rogueRADIUSSSID} onChange={e => setRogueRADIUSSSID(e.target.value)} placeholder="Corp SSID (e.g. CorpNet)"
                style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', color: 'white', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem' }} />
              <button className={`btn-primary ${rogueRADIUSActive ? 'btn-danger' : ''}`} onClick={async () => {
                if (rogueRADIUSActive) {
                  await apiCall('/rogue_radius/stop', 'POST', {});
                  setRogueRADIUSActive(false);
                } else {
                  const r = await apiCall('/rogue_radius/start', 'POST', { ssid: rogueRADIUSSSID });
                  if (r) setRogueRADIUSActive(true);
                }
              }}>{rogueRADIUSActive ? 'STOP RADIUS' : 'LAUNCH RADIUS'}</button>
              {rogueRADIUSActive && (
                <button className="btn-primary" style={{ fontSize: '0.7rem' }} onClick={async () => {
                  const r = await apiCall('/rogue_radius/hashes');
                  if (r) setRogueRADIUSHashes(r.hashes || []);
                }}>REFRESH HASHES ({rogueRADIUSHashes.length})</button>
              )}
            </div>
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              {rogueRADIUSHashes.length === 0
                ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>No MSCHAPv2 hashes captured yet. Launch the trap and wait for enterprise clients.</p>
                : rogueRADIUSHashes.map((h, i) => (
                  <div key={i} className="glass-card" style={{ padding: '0.5rem 0.8rem', background: 'rgba(255,255,255,0.02)', fontSize: '0.65rem' }}>
                    <span style={{ color: '#a855f7', fontWeight: 700 }}>{h.identity}</span>
                    <span style={{ color: 'var(--text-secondary)', marginLeft: '0.5rem', wordBreak: 'break-all', fontFamily: 'monospace' }}>{h.hashcat}</span>
                  </div>
                ))}
            </div>
          </div>
        );

      default:
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ textAlign: 'center' }}>
              <h3 style={{ color: 'var(--text-secondary)' }}>{plugin.toUpperCase()}</h3>
              <p style={{ marginTop: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Module loaded. No dedicated interface — use the CLI panel or API directly.</p>
              <button className="btn-primary" style={{ marginTop: '2rem', width: '220px' }} onClick={() => {
                const slug = plugin.toLowerCase().replace(/[^a-z0-9]+/g, '_');
                apiCall(`/${slug}/start`, 'POST', {});
              }}>START {plugin.toUpperCase()}</button>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="dashboard-container">
      <div
        className={`mobile-drawer-backdrop${mobileNavOpen ? ' mobile-open' : ''}`}
        onClick={() => setMobileNavOpen(false)}
      />
      <aside className={`sidebar${mobileNavOpen ? ' mobile-open' : ''}`}>
        {/* Logo + Ctrl+K hint */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <h1 className="accent-text" style={{ fontSize: '1.6rem' }}>MOONKEEP</h1>
            <button className="cmd-palette-trigger" onClick={() => { setCmdOpen(true); setCmdQuery(''); }} title="Ctrl+K">
              <span style={{ fontSize: '0.5rem', color: 'var(--text-secondary)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '4px', padding: '0.15rem 0.35rem', fontFamily: 'Fira Code', letterSpacing: '1px' }}>⌘K</span>
            </button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.15rem' }}>
            <span style={{ fontSize: '0.55rem', letterSpacing: '3px', fontWeight: 900, color: 'var(--text-secondary)' }}>SOVEREIGN ELITE</span>
            <span style={{ fontSize: '0.45rem', background: 'rgba(99,102,241,0.2)', border: '1px solid rgba(99,102,241,0.4)', color: '#a78bfa', padding: '0.1rem 0.3rem', borderRadius: '3px', fontWeight: 900, letterSpacing: '1px' }}>v2</span>
          </div>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: 0, flex: 1, overflowY: 'auto', paddingRight: '0.1rem' }}>
          {/* ── Favorites strip ── */}
          {favPlugins.length > 0 && (
            <div>
              <div className="nav-category" style={{ color: '#f59e0b' }}>★ PINNED</div>
              {favPlugins.map(name => {
                const badge = pluginFindings[name];
                return (
                  <button key={name} className={`btn-primary nav-btn ${activePlugin === name ? 'active' : ''}`}
                    style={{ marginBottom: '0.15rem', paddingLeft: '0.6rem', justifyContent: 'space-between' }}
                    onClick={() => pickPlugin(name)}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#f59e0b', flexShrink: 0 }} />
                      {name.toUpperCase()}
                    </span>
                    {badge > 0 && <span className="nav-badge">{badge}</span>}
                  </button>
                );
              })}
            </div>
          )}

          {/* ── Category nav ── */}
          {Object.entries(PLUGIN_CATEGORIES).map(([cat, catNames]) => {
            const available = plugins.filter(p => catNames.includes(p.name));
            if (available.length === 0) return null;
            return (
              <div key={cat}>
                <div className="nav-category" style={{ color: CAT_COLORS[cat] }}>{cat}</div>
                {available.map(p => {
                  const badge = pluginFindings[p.name];
                  const isLive = (p.name === 'Sniffer' && snifferActive) ||
                    (p.name === 'Rogue-AP' && rogueAPActive) ||
                    (p.name === 'Rogue-RADIUS' && rogueRADIUSActive) ||
                    (p.name === 'Mesh-Injector' && meshActive) ||
                    (p.name === 'Baseline-Calibrator' && baselineActive) ||
                    (p.name === 'Spoofer' && spoofing) ||
                    (p.name === 'Proxy' && proxyActive);
                  const isFav = favPlugins.includes(p.name);
                  return (
                    <div key={p.name} className="nav-item-row">
                      <button
                        className={`btn-primary nav-btn ${activePlugin === p.name ? 'active' : ''}`}
                        style={{ flex: 1, marginBottom: '0.15rem', paddingLeft: '0.6rem', justifyContent: 'space-between' }}
                        onClick={() => pickPlugin(p.name)}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <span style={{
                            width: 5, height: 5, borderRadius: '50%', flexShrink: 0,
                            background: isLive ? '#22c55e' : activePlugin === p.name ? CAT_COLORS[cat] : 'rgba(255,255,255,0.15)',
                            boxShadow: isLive ? '0 0 5px #22c55e' : 'none',
                            animation: isLive ? 'pulse 2s ease-in-out infinite' : 'none',
                          }} />
                          {p.name.toUpperCase()}
                        </span>
                        {badge > 0 && <span className="nav-badge">{badge}</span>}
                      </button>
                      <button className="nav-pin-btn" onClick={() => toggleFav(p.name)} title={isFav ? 'Unpin' : 'Pin'} style={{ opacity: isFav ? 1 : 0 }}>
                        {isFav ? '★' : '☆'}
                      </button>
                    </div>
                  );
                })}
              </div>
            );
          })}
          {plugins.filter(p => !Object.values(PLUGIN_CATEGORIES).flat().includes(p.name)).map(p => (
            <button key={p.name} className={`btn-primary nav-btn ${activePlugin === p.name ? 'active' : ''}`}
              style={{ marginBottom: '0.15rem' }} onClick={() => pickPlugin(p.name)}>
              {p.name.toUpperCase()}
            </button>
          ))}
        </nav>

        {/* Engine status + theme toggle */}
        <div className="glass-card" style={{ padding: '0.6rem 0.8rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.15rem' }}>
            <span className={`status-badge ${bcapStatus.running ? 'active' : ''}`} style={{ fontSize: '0.45rem' }}>
              {bcapStatus.running ? 'ENGINE LIVE' : 'ENGINE IDLE'}
            </span>
            <span style={{ fontSize: '0.55rem', color: 'var(--text-secondary)' }}>{plugins.length} modules</span>
          </div>
          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
            <button
              onClick={() => setRedOpsMode(m => !m)}
              title="Toggle Red Ops / Dark mode"
              style={{
                background: redOpsMode ? 'rgba(239,68,68,0.15)' : 'transparent',
                border: `1px solid ${redOpsMode ? 'rgba(239,68,68,0.5)' : 'rgba(255,255,255,0.1)'}`,
                borderRadius: '4px', padding: '0.2rem 0.4rem', cursor: 'pointer',
                fontSize: '0.6rem', color: redOpsMode ? '#f87171' : 'var(--text-secondary)',
                fontWeight: 700, letterSpacing: '1px',
              }}>
              {redOpsMode ? '◉ RED' : '○ DRK'}
            </button>
            <div style={{ textAlign: 'right' }}>
              <button
                type="button"
                title="Tap to point this app at a different backend (Tailscale / Cloudflare Tunnel / LAN IP). Blank = same origin."
                onClick={() => {
                  const current = API_BASE || '';
                  const next = window.prompt(
                    'Backend URL (leave blank = same origin):\n' +
                    'e.g. https://moonkeep.mytunnel.ts.net',
                    current
                  );
                  if (next === null) return;
                  const trimmed = next.trim().replace(/\/+$/, '');
                  setApiBase(trimmed);
                  if (trimmed.startsWith('https://'))      setWsBase('wss://' + trimmed.slice(8));
                  else if (trimmed.startsWith('http://'))  setWsBase('ws://' + trimmed.slice(7));
                  else                                     setWsBase('');
                  window.location.reload();
                }}
                style={{
                  background: 'transparent', border: 'none', padding: 0, cursor: 'pointer',
                  fontSize: '0.65rem', color: 'var(--neo-cyan)', fontWeight: 700,
                  fontFamily: 'Fira Code, monospace',
                }}>
                {API_BASE ? (API_BASE.replace(/^https?:\/\//, '').slice(0, 22) || 'same origin') : 'same origin'}
              </button>
              {bcapStatus.active_modules?.length > 0 && (
                <div style={{ fontSize: '0.5rem', color: '#f59e0b', marginTop: '0.1rem' }}>{bcapStatus.active_modules.length} active</div>
              )}
            </div>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1.5rem', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', minWidth: 0 }}>
            <button
              className="mobile-menu-btn"
              aria-label="Open navigation"
              onClick={() => setMobileNavOpen(o => !o)}
            >
              ☰
            </button>
            <div style={{ minWidth: 0 }}>
              <h2 className="accent-text" style={{ fontSize: '1.1rem', whiteSpace: 'nowrap' }}>{activePlugin || "COMMANDER"}</h2>
              <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Operational Surface Matrix</p>
            </div>
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
          {/* View controls */}
          <div style={{ display: 'flex', gap: '0.4rem', flexShrink: 0 }}>
            <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.3rem 0.6rem', background: splitPanel ? 'rgba(99,102,241,0.2)' : undefined, borderColor: splitPanel ? '#6366f1' : undefined }}
              onClick={() => { if (splitPanel) { setSplitPanel(null); } else { const others = plugins.filter(p => p.name !== activePlugin); setSplitPanel(others[0]?.name || null); } }}
              title="Split pane (show two modules side-by-side)">
              {splitPanel ? '▣ SPLIT ON' : '▤ SPLIT'}
            </button>
            <button className="btn-primary" style={{ fontSize: '0.55rem', padding: '0.3rem 0.6rem', background: logDrawerOpen ? 'rgba(99,102,241,0.2)' : undefined, borderColor: logDrawerOpen ? '#6366f1' : undefined }}
              onClick={() => setLogDrawerOpen(o => !o)}
              title="Toggle strike log drawer">
              {logDrawerOpen ? '▲ LOG' : '▽ LOG'}
            </button>
            <span className="status-badge active" style={{ alignSelf: 'center' }}>ADMIN_ACTIVE</span>
          </div>
        </header>

        {/* ── Target Context Toolbar ── */}
        {activeTarget && (
          <div className="target-toolbar">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 }}>
              <span style={{ fontSize: '0.5rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>TARGET</span>
              <span style={{ color: 'var(--neo-cyan)', fontFamily: 'Fira Code', fontWeight: 800, fontSize: '0.85rem' }}>{activeTarget.ip}</span>
              {activeTarget.vendor && <span style={{ fontSize: '0.6rem', color: 'var(--text-secondary)' }}>{activeTarget.vendor}</span>}
              {activeTarget.mac && activeTarget.mac !== 'manual' && <span style={{ fontSize: '0.55rem', color: '#71717a', fontFamily: 'Fira Code' }}>{activeTarget.mac}</span>}
              {vulnCards.filter(v => v.ip === activeTarget.ip).length > 0 && (
                <span style={{ fontSize: '0.5rem', background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.4)', color: '#f87171', borderRadius: '4px', padding: '0.1rem 0.3rem', fontWeight: 700 }}>
                  {vulnCards.filter(v => v.ip === activeTarget.ip).length} VULNS
                </span>
              )}
            </div>
            <div style={{ display: 'flex', gap: '0.35rem', flexShrink: 0 }}>
              <button className="btn-primary" style={{ fontSize: '0.5rem', padding: '0.2rem 0.5rem' }}
                onClick={() => apiCall('/vuln_scan', 'GET', null)}>VULN SCAN</button>
              <button className="btn-primary" style={{ fontSize: '0.5rem', padding: '0.2rem 0.5rem' }}
                onClick={() => apiCall('/osint/enrich_all', 'POST', {})}>OSINT</button>
              <button className="btn-primary" style={{ fontSize: '0.5rem', padding: '0.2rem 0.5rem' }}
                onClick={() => apiCall('/wifi/deauth', 'POST', { target: 'FF:FF:FF:FF:FF:FF', ap: activeTarget.ip })}>DEAUTH</button>
              <button className="btn-primary btn-danger" style={{ fontSize: '0.5rem', padding: '0.2rem 0.5rem' }}
                onClick={() => apiCall('/wifi/auto_attack', 'POST', { bssid: activeTarget.ip })}>AUTO-ATTACK</button>
              <button className="btn-ghost btn-primary" style={{ fontSize: '0.5rem', padding: '0.2rem 0.5rem' }}
                onClick={() => setActiveTarget(null)}>✕ CLEAR</button>
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: '1rem', flex: 1, overflow: 'hidden', flexDirection: 'column' }}>
          <div style={{ display: 'grid', gridTemplateColumns: splitPanel ? `1fr 1fr 420px` : `1fr 420px`, gap: '1rem', flex: 1, overflow: 'hidden' }}>
            <div key={activePlugin} style={{ display: 'contents' }}>{renderModuleUI()}</div>
            {splitPanel && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', overflow: 'hidden' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 0.25rem' }}>
                  <select value={splitPanel} onChange={e => setSplitPanel(e.target.value)}
                    style={{ background: 'rgba(0,0,0,0.6)', color: 'var(--neo-cyan)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: '4px', padding: '0.2rem 0.4rem', fontSize: '0.6rem', fontWeight: 700, cursor: 'pointer' }}>
                    {plugins.map(p => <option key={p.name} value={p.name} style={{ background: '#000' }}>{p.name.toUpperCase()}</option>)}
                  </select>
                  <button className="btn-primary" style={{ fontSize: '0.5rem', padding: '0.2rem 0.4rem' }} onClick={() => setSplitPanel(null)}>✕</button>
                </div>
                <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>{renderModuleUI(splitPanel)}</div>
              </div>
            )}

          <aside className="glass-card" style={{ display: 'grid', gridTemplateRows: '28px 1fr 2fr 40px', gap: '0.5rem', overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '0.85rem', margin: 0 }}>Tactical Feed</h3>
              <span className="status-badge active" style={{ fontSize: '0.5rem' }}>ENGINE LIVE</span>
            </div>

            {/* Row 2: Tactical Feed — fixed height, scrollable */}
            <div ref={tacticalFeedRef} style={{ background: 'black', borderRadius: '6px', border: '1px solid var(--glass-border)', padding: '0.5rem', overflowY: 'auto', fontFamily: 'Fira Code, monospace', fontSize: '0.6rem' }}>
              {strikeLog.map((log, i) => (
                <div key={i} style={{
                  margin: '0.2rem 0',
                  color: log.includes('[cap]') ? '#a78bfa' : log.includes('!') ? 'var(--secondary-accent)' : 'var(--text-secondary)'
                }}>
                  {log}
                </div>
              ))}
            </div>

            <CapTerminal bcapStatus={bcapStatus} setStrikeLog={setStrikeLog} />

            <div style={{ display: 'flex', flexDirection: 'column', background: '#000', border: '1px solid rgba(167,139,250,0.15)', borderRadius: '6px', overflow: 'hidden' }}>
              {/* Terminal Output */}
              <div
                ref={cliRef}
                onClick={() => inputRef.current?.focus()}
                style={{ flex: 1, overflowY: 'auto', padding: '6px 8px', fontFamily: 'Fira Code, Menlo, monospace', fontSize: '0.68rem', lineHeight: '1.45', cursor: 'text' }}
              >
                {cliOutput.map((line, i) => (
                  <div key={i} style={{ color: line.color || '#94a3b8', fontWeight: line.bold ? 700 : 400, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {line.text}
                  </div>
                ))}
              </div>

              {/* Terminal Input */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', padding: '5px 8px', borderTop: '1px solid rgba(167,139,250,0.15)', flexShrink: 0, background: 'rgba(0,0,0,0.3)' }}>
                <span style={{ color: '#22c55e', fontSize: '0.75rem', fontFamily: 'Fira Code, monospace', fontWeight: 700 }}>❯</span>
                <div style={{ flex: 1, position: 'relative' }}>
                  <span style={{ position: 'absolute', left: 0, top: '50%', transform: 'translateY(-50%)', fontFamily: 'Fira Code, monospace', fontSize: '0.75rem', color: 'rgba(167,139,250,0.2)', pointerEvents: 'none', whiteSpace: 'nowrap' }}>
                    {bcapCmd}{suggestion}
                  </span>
                  <input
                    ref={inputRef}
                    type="text"
                    value={bcapCmd}
                    onChange={e => handleCliInput(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter') {
                        sendBcapCommand(bcapCmd);
                      } else if (e.key === 'Tab') {
                        e.preventDefault();
                        if (suggestion) { setBcapCmd(bcapCmd + suggestion); setSuggestion(""); }
                      } else if (e.key === 'ArrowUp') {
                        e.preventDefault();
                        const newIdx = Math.min(historyIndex + 1, bcapHistory.length - 1);
                        setHistoryIndex(newIdx);
                        if (bcapHistory[newIdx]) { setBcapCmd(bcapHistory[newIdx]); setSuggestion(""); }
                      } else if (e.key === 'ArrowDown') {
                        e.preventDefault();
                        const newIdx = Math.max(historyIndex - 1, -1);
                        setHistoryIndex(newIdx);
                        setBcapCmd(newIdx >= 0 ? bcapHistory[newIdx] : ""); setSuggestion("");
                      } else if (e.key === 'l' && e.ctrlKey) {
                        e.preventDefault(); setCliOutput([]);
                      }
                    }}
                    placeholder=""
                    autoComplete="off"
                    spellCheck={false}
                    style={{ width: '100%', background: 'transparent', border: 'none', outline: 'none', color: '#a78bfa', fontFamily: 'Fira Code, Menlo, monospace', fontSize: '0.75rem', padding: 0, caretColor: '#a78bfa', position: 'relative', zIndex: 1 }}
                  />
                </div>
              </div>
            </div>

            {/* Row 4: Action Button — always pinned at bottom */}
            <button className="btn-primary active" style={{ height: '100%', fontSize: '0.7rem', flexShrink: 0 }} onClick={() => apiCall('/cyber_strike/start', 'POST', { role: cyberStrikeRole })}>INVOKE PROTOCOL</button>
          </aside>
          </div>

          {/* ── Bottom Log Drawer ── */}
          {logDrawerOpen && (
            <div className="log-drawer">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.4rem 0.75rem', borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.55rem', fontWeight: 900, letterSpacing: '2px', color: '#a78bfa' }}>STRIKE LOG</span>
                  <span className="status-badge active" style={{ fontSize: '0.4rem' }}>{strikeLog.length} ENTRIES</span>
                </div>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  <button className="btn-primary" style={{ fontSize: '0.5rem', padding: '0.15rem 0.4rem' }} onClick={() => setStrikeLog(["[#] LOG CLEARED"])}>CLEAR</button>
                  <button className="btn-primary" style={{ fontSize: '0.5rem', padding: '0.15rem 0.4rem' }} onClick={() => setLogDrawerOpen(false)}>✕</button>
                </div>
              </div>
              <div ref={tacticalFeedRef} style={{ flex: 1, overflowY: 'auto', padding: '0.4rem 0.75rem', fontFamily: 'Fira Code, monospace', fontSize: '0.6rem', display: 'flex', flexDirection: 'column', gap: '0.1rem' }}>
                {strikeLog.map((log, i) => (
                  <div key={i} style={{
                    color: log.includes('[!]') ? '#f43f5e' : log.includes('[<]') ? '#22c55e' : log.includes('[>]') ? '#06b6d4' : log.includes('[cap]') ? '#a78bfa' : 'var(--text-secondary)',
                    padding: '0.05rem 0',
                  }}>
                    {log}
                  </div>
                ))}
              </div>
            </div>
          )}
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

      {/* ── Command Palette (Ctrl+K) ── */}
      {cmdOpen && (
        <div className="cmd-overlay" onClick={() => setCmdOpen(false)}>
          <div className="cmd-palette" onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1rem', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>⌘</span>
              <input
                ref={cmdInputRef}
                value={cmdQuery}
                onChange={e => setCmdQuery(e.target.value)}
                placeholder="Search modules, actions…"
                style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', color: 'white', fontFamily: 'Fira Code, monospace', fontSize: '0.85rem' }}
                onKeyDown={e => {
                  if (e.key === 'Escape') setCmdOpen(false);
                  if (e.key === 'Enter') {
                    const filtered = [...plugins.map(p => p.name), 'Split', 'Log Drawer', 'Red Ops', 'Clear Log']
                      .filter(n => n.toLowerCase().includes(cmdQuery.toLowerCase()));
                    if (filtered[0]) {
                      if (filtered[0] === 'Split') { setSplitPanel(plugins.find(p => p.name !== activePlugin)?.name); }
                      else if (filtered[0] === 'Log Drawer') { setLogDrawerOpen(o => !o); }
                      else if (filtered[0] === 'Red Ops') { setRedOpsMode(m => !m); }
                      else if (filtered[0] === 'Clear Log') { setStrikeLog(["[#] LOG CLEARED"]); }
                      else { setActivePlugin(filtered[0]); }
                      setCmdOpen(false);
                    }
                  }
                }}
              />
              <span style={{ fontSize: '0.55rem', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>ESC to close</span>
            </div>
            <div style={{ maxHeight: '360px', overflowY: 'auto', padding: '0.4rem 0' }}>
              {/* Action shortcuts */}
              {[{ label: '▣ Toggle Split Pane', action: () => { setSplitPanel(s => s ? null : plugins.find(p => p.name !== activePlugin)?.name); setCmdOpen(false); } },
                { label: '▽ Toggle Log Drawer', action: () => { setLogDrawerOpen(o => !o); setCmdOpen(false); } },
                { label: `${redOpsMode ? '○' : '◉'} Toggle Red Ops Mode`, action: () => { setRedOpsMode(m => !m); setCmdOpen(false); } },
                { label: '⎚ Clear Strike Log', action: () => { setStrikeLog(["[#] LOG CLEARED"]); setCmdOpen(false); } },
              ].filter(a => !cmdQuery || a.label.toLowerCase().includes(cmdQuery.toLowerCase())).map(a => (
                <div key={a.label} className="cmd-item cmd-action" onClick={a.action}>
                  <span style={{ color: '#a78bfa', fontSize: '0.65rem', marginRight: '0.5rem' }}>⚡</span>
                  {a.label}
                </div>
              ))}
              {/* Module results */}
              {plugins
                .filter(p => !cmdQuery || p.name.toLowerCase().includes(cmdQuery.toLowerCase()))
                .map(p => {
                  const cat = Object.entries(PLUGIN_CATEGORIES).find(([, names]) => names.includes(p.name))?.[0];
                  const badge = pluginFindings[p.name];
                  const isFav = favPlugins.includes(p.name);
                  return (
                    <div key={p.name} className={`cmd-item ${activePlugin === p.name ? 'cmd-item-active' : ''}`}
                      onClick={() => { setActivePlugin(p.name); setCmdOpen(false); }}>
                      <span style={{ width: 7, height: 7, borderRadius: '50%', background: CAT_COLORS[cat] || '#6366f1', flexShrink: 0, marginRight: '0.5rem' }} />
                      <span style={{ flex: 1 }}>{p.name.toUpperCase()}</span>
                      {badge > 0 && <span className="nav-badge" style={{ marginRight: '0.5rem' }}>{badge}</span>}
                      <span style={{ fontSize: '0.5rem', color: 'var(--text-secondary)', marginRight: '0.5rem' }}>{cat}</span>
                      <button style={{ background: 'none', border: 'none', cursor: 'pointer', color: isFav ? '#f59e0b' : '#444', fontSize: '0.7rem', padding: 0 }}
                        onClick={e => { e.stopPropagation(); toggleFav(p.name); }}>
                        {isFav ? '★' : '☆'}
                      </button>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>
      )}

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
