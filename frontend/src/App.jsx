import React, { useState, useEffect, useRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from '@xterm/addon-fit';
import 'xterm/css/xterm.css';
import './index.css';

const ReconTerminal = () => {
  const terminalRef = useRef(null);
  const xtermRef = useRef(null);
  const wsRef = useRef(null);

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
    // Slight delay to ensure DOM is ready before fitting
    setTimeout(() => fitAddon.fit(), 50);

    const ws = new WebSocket('ws://localhost:8001/ws/recon');
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
  }, []);

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

  // Pillar 3 UI States
  const [secretFindings, setSecretFindings] = useState([]);
  const [vulnCards, setVulnCards] = useState([]);
  const [cyberStrikeRole, setCyberStrikeRole] = useState("Shadow");
  const [cyberStrikeLog, setCyberStrikeLog] = useState([]);
  const [aiCmd, setAiCmd] = useState("");
  const [aiPlan, setAiPlan] = useState([]);
  const [aiInsights, setAiInsights] = useState([]);
  const [proxyPort, setProxyPort] = useState(8080);
  const [targetDrawerOpen, setTargetDrawerOpen] = useState(false);

  // Specific Module States
  const [spoofing, setSpoofing] = useState(false);
  const [proxyActive, setProxyActive] = useState(false);
  const [fuzzingStatus, setFuzzingStatus] = useState("IDLE");

  // Bettercap CLI State
  const [bcapStatus, setBcapStatus] = useState({ installed: false, running: false });
  const [bcapCmd, setBcapCmd] = useState("");
  const [bcapHistory, setBcapHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('moonkeep_cli_history') || '[]'); } catch { return []; }
  });
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [manualTarget, setManualTarget] = useState("");
  const [cliOutput, setCliOutput] = useState([{ text: '═══ NATIVE CAP ENGINE ═══', color: '#a78bfa' }, { text: 'Type "help" for available commands.', color: '#666' }]);
  const [suggestion, setSuggestion] = useState("");
  const cliRef = useRef(null);
  const inputRef = useRef(null);

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

  useEffect(() => {
    // Force path sync
    if (window.location.pathname !== "/") window.history.replaceState({}, "", "/");

    const boot = async () => {
      try {
        const res = await fetch('http://localhost:8001/plugins');
        const data = await res.json();
        setPlugins([...data, { name: 'Recon-Console' }]);
        if (data.length > 0) setActivePlugin(data[0].name);

        const campRes = await fetch('http://localhost:8001/campaigns');
        const campData = await campRes.json();
        setCampaigns(campData);

        // Hydrate targets from backend store
        fetch('http://localhost:8001/scan').then(r => r.json()).then(d => {
          if (d.devices && d.devices.length > 0) {
            setDevices(d.devices);
            setActiveTarget(d.devices[0]);
          }
        });
      } catch (err) {
        setStrikeLog(prev => [...prev.slice(-40), "[!] BACKEND OFFLINE ON PORT 8001"]);
      }
    };
    boot();

    ws.current = new WebSocket('ws://localhost:8001/ws');
    ws.current.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.plugin && data.ts) {
        const msg = data.data?.msg || (typeof data.data === 'string' ? data.data : JSON.stringify(data.data));
        setStrikeLog(prev => [...prev.slice(-40), `[${data.plugin}] ${msg}`]);
        const newToast = { id: Date.now() + Math.random(), ...data };
        setToasts(prev => [...prev.slice(-6), newToast]);
        setTimeout(() => setToasts(prev => prev.filter(t => t.id !== newToast.id)), 7000);

        // Route events to module-specific state
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
  }, []);

  useEffect(() => {
    if (!activePlugin) return;
    const poll = setInterval(() => {
      if (activePlugin === "AI-Orchestrator") {
        fetch('http://localhost:8001/graph').then(r => r.json()).then(setGraphData).catch(() => { });
      }
      if (activePlugin === "Sniffer") {
        fetch('http://localhost:8001/sniffer/credentials').then(r => r.json()).then(d => setCapturedCreds(d.credentials || [])).catch(() => { });
      }
    }, 4000);
    return () => clearInterval(poll);
  }, [activePlugin]);

  // Bettercap status polling
  useEffect(() => {
    const pollBcap = setInterval(() => {
      fetch('http://localhost:8001/bettercap/status').then(r => r.json()).then(setBcapStatus).catch(() => { });
    }, 5000);
    // Initial check
    fetch('http://localhost:8001/bettercap/status').then(r => r.json()).then(setBcapStatus).catch(() => { });
    return () => clearInterval(pollBcap);
  }, []);

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
      const res = await fetch('http://localhost:8001/bettercap/command', {
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
      const res = await fetch(`http://localhost:8001${endpoint}`, options);
      const data = await res.json();
      setStrikeLog(prev => [...prev.slice(-40), `[<] SUCCESS: ${endpoint}`, `[#] DATA: ${JSON.stringify(data).slice(0, 100)}...`]);
      return data;
    } catch (err) {
      setStrikeLog(prev => [...prev.slice(-40), `[!] FAILED: ${endpoint}`]);
      return null;
    }
  };

  const handleExportReport = async () => {
    try {
      const res = await fetch(`http://localhost:8001/campaigns/${activeCampaign}/report`);
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
    } catch (err) { }
  };

  const renderModuleUI = () => {
    if (!activePlugin) return <div className="glass-card">INITIALIZING VECTORS...</div>;

    switch (activePlugin) {
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
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
              <h3>Wireless Strike Arsenal</h3>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn-primary" onClick={async () => {
                  apiCall('/bettercap/command', 'POST', { cmd: 'wifi.recon on' });
                  setStrikeLog(prev => [...prev.slice(-40), "[#] AUTO-WARDRIVER STARTED"]);
                }}>START WARDRIVER</button>
                <button className="btn-primary" onClick={async () => {
                  const data = await apiCall('/wifi_scan');
                  if (data) setNetworks(data.networks || []);
                }}>REFRESH BANDS</button>
              </div>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem', paddingRight: '0.5rem' }}>
              {networks.length === 0 ? <p style={{ color: 'var(--text-secondary)' }}>No networks found. Run a scan or start wardriving.</p> :
                networks.map((n, i) => (
                  <div key={i} className="glass-card" style={{ padding: '1rem', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', overflow: 'hidden' }}>
                      <p style={{ fontWeight: 900, whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden', paddingRight: '0.5rem' }} title={n.ssid || 'HIDDEN'}>{n.ssid || 'HIDDEN'}</p>
                      <p style={{ color: 'var(--neo-cyan)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>{n.rssi} dBm</p>
                    </div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                      MAC: {n.mac} <br />
                      CH: {n.channel} | ENC: {n.encryption}
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
                      <button className="btn-primary" style={{ flex: 1, fontSize: '0.6rem' }} onClick={() => apiCall('/wifi/deauth', 'POST', { target: 'FF:FF:FF:FF:FF:FF', ap: n.mac })}>DEAUTH</button>
                      <button className="btn-primary" style={{ flex: 1, fontSize: '0.6rem' }} onClick={() => apiCall('/wifi/capture', 'POST', { bssid: n.mac })}>LISTEN (EAPOL)</button>
                    </div>
                  </div>
                ))}
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
                className={`btn-primary ${spoofing ? 'active' : ''}`}
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
              <h3>DPI Credential Loot</h3>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn-primary" onClick={() => apiCall('/sniffer/start', 'POST')}>START CAPTURE</button>
                <button className="btn-primary ghost" onClick={() => apiCall('/sniffer/stop', 'POST')}>STOP</button>
              </div>
            </div>
            <div className="glass-card" style={{ border: '1px solid var(--secondary-accent)', background: 'rgba(244, 63, 94, 0.05)', maxHeight: '200px', overflowY: 'auto' }}>
              {capturedCreds.length === 0 && <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', padding: '0.5rem' }}>No credentials captured yet. Start capture and generate traffic.</div>}
              {capturedCreds.map((c, i) => (
                <div key={i} style={{ fontSize: '0.8rem', margin: '0.3rem 0', fontFamily: 'Fira Code' }}>[FOUND] {c}</div>
              ))}
            </div>
            <div style={{ flex: 1, overflowY: 'auto', background: 'rgba(0,0,0,0.4)', padding: '1rem', borderRadius: '12px' }}>
              {packets.map((p, i) => (
                <div key={i} style={{ fontSize: '0.65rem', margin: '0.2rem 0', color: 'var(--text-secondary)' }}>{p.src} -&gt; {p.dst} {p.proto ? `[${p.proto}]` : ''} {p.query ? `DNS: ${p.query}` : ''}</div>
              ))}
            </div>
          </div>
        );

      case "Post-Exploit":
        return (
          <div className="glass-card fade-in" style={{ flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2rem' }}>
              <h3>Post-Exploit C2</h3>
              <button className="btn-primary" onClick={() => apiCall('/post_exploit/pivot', 'POST', { target_ip: activeTarget?.ip || '192.168.1.1' })}>
                SCAN PIVOT: {activeTarget?.ip || "AUTO"}
              </button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <button className="btn-primary ghost" onClick={() => apiCall('/post_exploit/persistence?os_type=windows')}>GENERATE PERSISTENCE</button>
              <button className="btn-primary ghost" onClick={() => apiCall('/post_exploit/exfiltrate', 'POST', { target_session_id: activeTarget?.ip })}>HARVEST DATA</button>
            </div>
          </div>
        );

      case "Fuzzer":
        return (
          <div className="glass-card fade-in" style={{ flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2rem' }}>
              <h3>Protocol Mutation Fuzzer</h3>
              <span className="status-badge active">{fuzzingStatus}</span>
            </div>
            <p style={{ fontSize: '0.8rem', marginBottom: '1rem' }}>Targeting: {activeTarget?.ip || "None Selected"}</p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
              <button className="btn-primary" onClick={async () => { setFuzzingStatus("FUZZING SNMP"); const d = await apiCall('/fuzzer/snmp', 'POST', { ip: activeTarget?.ip }); setFuzzingStatus(d ? "COMPLETE" : "ERROR"); }}>FUZZ SNMP</button>
              <button className="btn-primary" onClick={async () => { setFuzzingStatus("FUZZING MDNS"); const d = await apiCall('/fuzzer/mdns', 'POST', { ip: activeTarget?.ip }); setFuzzingStatus(d ? "COMPLETE" : "ERROR"); }}>FUZZ MDNS</button>
              <button className="btn-primary" onClick={async () => { setFuzzingStatus("FUZZING UPnP"); const d = await apiCall('/fuzzer/upnp', 'POST', { ip: activeTarget?.ip }); setFuzzingStatus(d ? "COMPLETE" : "ERROR"); }}>FUZZ UPnP</button>
            </div>
          </div>
        );

      case "HID-BLE-Strike":
        return (
          <div className="glass-card fade-in" style={{ flex: 1 }}>
            <h3>HID / BLE Tactical Injection</h3>
            <p style={{ fontSize: '0.8rem', marginBottom: '1.5rem' }}>Active Vector: {activeTarget?.mac || "AA:BB:CC:11:22:33"}</p>
            <div style={{ display: 'flex', gap: '1rem' }}>
              <button className="btn-primary" style={{ flex: 1 }} onClick={() => apiCall('/hid_ble/scan')}>BLE RECON</button>
              <button className="btn-primary" style={{ flex: 1 }} onClick={() => apiCall('/hid_ble/inject', 'POST', { target_mac: activeTarget?.mac || 'AA:BB:CC:11:22:33' })}>MOUSEJACK INJ</button>
            </div>
          </div>
        );

      case "Secret-Hunter":
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

      case "Vuln-Scanner":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
              <h3>Vulnerability Scanner</h3>
              <button className="btn-primary" onClick={async () => {
                const target = activeTarget?.ip || '';
                const data = await apiCall(`/vuln_scan${target ? `?target=${target}` : ''}`);
                if (data) setStrikeLog(prev => [...prev.slice(-40), `[Vuln-Scanner] Scanning ${data.target}...`]);
              }}>START DEEP ANALYSIS</button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '1rem', overflowY: 'auto' }}>
              {vulnCards.map((v, i) => (
                <div key={i} className="glass-card" style={{ padding: '1rem', borderLeft: `3px solid ${v.severity === 'CRITICAL' ? '#f43f5e' : '#f59e0b'}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <h4 style={{ margin: 0 }}>{v.cve}</h4>
                    <span style={{ fontSize: '0.6rem', color: v.severity === 'CRITICAL' ? '#f43f5e' : '#f59e0b', fontWeight: 900 }}>{v.severity}</span>
                  </div>
                  <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>{v.desc}</p>
                </div>
              ))}
              {vulnCards.length === 0 && <p style={{ color: 'var(--text-secondary)' }}>No vulnerabilities detected.</p>}
            </div>
          </div>
        );

      case "Cyber-Strike":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <h3>Autonomous Cyber-Strike</h3>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
              <select value={cyberStrikeRole} onChange={e => setCyberStrikeRole(e.target.value)} style={{ background: 'rgba(0,0,0,0.5)', color: 'var(--neo-cyan)', padding: '0.5rem', border: '1px solid var(--glass-border)', borderRadius: '4px' }}>
                <option value="Shadow">Shadow (Stealth Recon)</option>
                <option value="Infiltrator">Infiltrator (MITM Strike)</option>
                <option value="Ghost">Ghost (Signal Ghost)</option>
                <option value="Reaper">Reaper (Full Killchain)</option>
              </select>
              <button className="btn-primary" onClick={async () => {
                setCyberStrikeLog(prev => [...prev, `[*] Engaging ${cyberStrikeRole} protocol...`]);
                await apiCall('/cyber_strike/start', 'POST', { role: cyberStrikeRole });
              }}>ENGAGE {cyberStrikeRole.toUpperCase()}</button>
              <button className="btn-primary ghost" onClick={async () => {
                await apiCall('/cyber_strike/stop', 'POST');
                setCyberStrikeLog(prev => [...prev, `[!] ${cyberStrikeRole} protocol ABORTED`]);
              }}>ABORT</button>
            </div>
            <div style={{ flex: 1, background: '#000', padding: '1rem', marginTop: '1rem', borderRadius: '6px', overflowY: 'auto', border: '1px solid var(--glass-border)', fontFamily: 'monospace', fontSize: '0.75rem' }}>
              {cyberStrikeLog.map((log, i) => <div key={i} style={{ color: '#22c55e', margin: '0.2rem 0' }}>{log}</div>)}
              {cyberStrikeLog.length === 0 && <div style={{ color: 'var(--text-secondary)' }}>Awaiting protocol engagement...</div>}
            </div>
          </div>
        );

      case "AI-Orchestrator":
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <h3>AI Copilot War Room</h3>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <span className="status-badge active">BRAIN ONLINE</span>
                <button className="btn-primary flex items-center gap-2" onClick={async () => {
                  const data = await apiCall('/ai/analyze', 'POST');
                  if (data?.insights) setAiInsights(data.insights);
                }}>
                  ANALYZE SECRETS & VULNS
                </button>
              </div>
            </div>
            {/* Knowledge Graph */}
            <div style={{ height: '80px', background: 'rgba(0,0,0,0.5)', borderRadius: '8px', border: '1px solid var(--glass-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '0.5rem', flexShrink: 0 }}>
              <svg width="100%" height="60">
                {graphData.nodes.map((n, i) => <circle key={i} cx={50 + i * 70} cy="30" r="8" fill="var(--neo-cyan)" stroke="white" strokeWidth="1" />)}
                {graphData.nodes.length === 0 && <text x="50%" y="30" textAnchor="middle" fill="#666" fontSize="11">Run analysis to populate graph</text>}
              </svg>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
              <input type="text" value={aiCmd} onChange={e => setAiCmd(e.target.value)} placeholder="e.g. Pivot through the 192 LAN seeking open databases..." style={{ flex: 1, background: 'rgba(0,0,0,0.5)', border: '1px solid var(--glass-border)', padding: '0.5rem', color: 'var(--neo-cyan)', fontFamily: 'Fira Code', fontSize: '0.8rem', outline: 'none' }} />
              <button className="btn-primary" onClick={async () => {
                const data = await apiCall('/ai/command', 'POST', { instruction: aiCmd });
                if (data?.plan) setAiPlan(data.plan);
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
              <button className={`btn-primary ${proxyActive ? 'ghost' : ''}`} onClick={() => {
                apiCall(proxyActive ? '/proxy/stop' : '/proxy/start', 'POST', proxyActive ? null : { port: proxyPort });
                setProxyActive(!proxyActive);
              }}>{proxyActive ? 'STOP PROXY' : 'START PROXY'}</button>
            </div>
            <p style={{ marginTop: '1rem', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Traffic intercepted by Bettercap will emit websocket events under the PROXY type. Setup complete proxy configs via CLI.</p>
          </div>
        );

      case "Recon-Console":
        return <ReconTerminal />;

      default:
        return (
          <div className="glass-card fade-in" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ textAlign: 'center' }}>
              <h3 style={{ color: 'var(--text-secondary)' }}>{activePlugin.toUpperCase()}</h3>
              <p style={{ marginTop: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Operational module ready. Proceed to command.</p>
              <button className="btn-primary" style={{ marginTop: '2rem', width: '200px' }} onClick={() => apiCall('/cyber_strike/start', 'POST', { role: 'Shadow' })}>INVOKE</button>
            </div>
          </div>
        );
    }
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
          <span className="status-badge active" style={{ fontSize: '0.5rem' }}>EPIC.SYSTEM</span>
          <span style={{ fontSize: '0.6rem', color: 'var(--text-secondary)' }}>8001</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', padding: '1rem 2rem', alignItems: 'center' }}>
          <div>
            <h2 className="accent-text" style={{ fontSize: '1.1rem' }}>{activePlugin || "COMMANDER"}</h2>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Operational Surface Matrix</p>
          </div>

          {/* CAMPAIGN WORKSPACE UI */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', borderLeft: '1px solid rgba(167,139,250,0.2)', borderRight: '1px solid rgba(167,139,250,0.2)', padding: '0 1rem' }}>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '0.55rem', color: 'var(--text-secondary)', letterSpacing: '1px' }}>WORKSPACE / CAMPAIGN</span>
              <select
                value={activeCampaign}
                onChange={async (e) => {
                  const newCamp = e.target.value;
                  setActiveCampaign(newCamp);
                  await apiCall(`/campaigns/${newCamp}/activate`, 'PUT');
                  // Re-hydrate UI
                  const d = await apiCall('/scan');
                  if (d && d.devices) setDevices(d.devices);
                }}
                style={{ background: 'transparent', color: 'var(--neo-cyan)', border: 'none', outline: 'none', fontFamily: 'Fira Code', fontWeight: 800, fontSize: '0.8rem', cursor: 'pointer' }}
              >
                {campaigns.map(c => <option key={c.id} value={c.id} style={{ background: '#000' }}>{c.name}</option>)}
              </select>
            </div>
            <button className="btn-primary flex items-center gap-2" style={{ padding: '0.4rem 0.8rem', fontSize: '0.65rem' }} onClick={handleExportReport}>
              EXPORT .MD
            </button>
          </div>

          {/* GLOBAL TARGET INPUT */}
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
            <span className="status-badge active">ADMIN_ACTIVE</span>
            <p style={{ fontSize: '0.6rem', marginTop: '0.3rem', color: 'var(--neo-cyan)' }}>ROOT_SESSION</p>
          </div>
        </header>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 450px', gap: '1rem', flex: 1, overflow: 'hidden' }}>
          {renderModuleUI()}

          <aside className="glass-card" style={{ display: 'grid', gridTemplateRows: '28px 1fr 2fr 40px', gap: '0.5rem', overflow: 'hidden' }}>
            {/* Row 1: Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '0.85rem', margin: 0 }}>Tactical Feed</h3>
              <span className="status-badge active" style={{ fontSize: '0.5rem' }}>ENGINE LIVE</span>
            </div>

            {/* Row 2: Tactical Feed — fixed height, scrollable */}
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

            {/* Row 3: MOONKEEP CAP Terminal — takes remaining space */}
            <div style={{ background: 'rgba(0,0,0,0.95)', borderRadius: '6px', border: '1px solid rgba(167, 139, 250, 0.25)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              {/* Terminal Title Bar */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 8px', background: 'rgba(167,139,250,0.08)', borderBottom: '1px solid rgba(167,139,250,0.15)', flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#f43f5e', display: 'inline-block' }} />
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#f59e0b', display: 'inline-block' }} />
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} />
                  <span style={{ fontSize: '0.55rem', color: '#a78bfa', fontWeight: 800, letterSpacing: '1.5px', marginLeft: '4px' }}>MOONKEEP CAP</span>
                </div>
                <span style={{ fontSize: '0.45rem', color: 'rgba(167,139,250,0.6)' }}>{bcapStatus.active_modules?.length || 0} active</span>
              </div>

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
            <button className="btn-primary active" style={{ height: '100%', fontSize: '0.7rem', flexShrink: 0 }} onClick={() => apiCall('/cyber_strike/start', 'POST', { role: cyberStrikeRole })}>INVOKE {cyberStrikeRole.toUpperCase()}</button>
          </aside>
        </div>
      </main>

      {/* Target Detail Drawer Overlay */}
      {targetDrawerOpen && activeTarget && (
        <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: '400px', background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(20px)', borderLeft: '1px solid var(--glass-border)', zIndex: 9000, padding: '2rem', display: 'flex', flexDirection: 'column', animation: 'slideIn 0.3s ease-out' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
            <h2 className="accent-text" style={{ margin: 0, fontSize: '1.2rem' }}>TARGET DETAIL</h2>
            <button className="btn-primary ghost" style={{ padding: '0.2rem 0.5rem' }} onClick={() => setTargetDrawerOpen(false)}>✕</button>
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

      {/* Toast Notifications */}
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

export default Dashboard;
