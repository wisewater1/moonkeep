import React, { useState, useRef, useEffect } from 'react';
import { API_BASE } from '../config.js';
import { useAuth } from '../hooks/useAuth.js';

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

const CapTerminal = ({ bcapStatus, setStrikeLog }) => {
  const { authFetch } = useAuth();
  const [bcapCmd, setBcapCmd] = useState("");
  const [bcapHistory, setBcapHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('moonkeep_cli_history') || '[]'); } catch { return []; }
  });
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [cliOutput, setCliOutput] = useState([{ text: '\u2550\u2550\u2550 NATIVE CAP ENGINE \u2550\u2550\u2550', color: '#a78bfa' }, { text: 'Type "help" for available commands.', color: '#666' }]);
  const [suggestion, setSuggestion] = useState("");
  const cliRef = useRef(null);
  const inputRef = useRef(null);

  const sendBcapCommand = async (cmd) => {
    if (!cmd.trim()) return;
    const newHistory = [cmd, ...bcapHistory.filter(h => h !== cmd)].slice(0, 100);
    setBcapHistory(newHistory);
    try { localStorage.setItem('moonkeep_cli_history', JSON.stringify(newHistory)); } catch { /* ignore */ }
    setHistoryIndex(-1);
    setBcapCmd("");
    setSuggestion("");
    setCliOutput(prev => [...prev, { text: `\u276F ${cmd}`, color: '#a78bfa', bold: true }]);
    setStrikeLog(prev => [...prev.slice(-40), `[cap] > ${cmd}`]);
    try {
      const res = await authFetch(`${API_BASE}/bettercap/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cmd })
      });
      const data = await res.json();
      if (data.output === '__CLEAR__') {
        setCliOutput([{ text: '\u2550\u2550\u2550 CLEARED \u2550\u2550\u2550', color: '#a78bfa' }]);
      } else if (data.output) {
        const lines = data.output.split('\n').filter(l => l.trim());
        setCliOutput(prev => [...prev.slice(-200), ...lines.map(l => ({
          text: l,
          color: l.includes('\u2192') ? '#22d3ee' : l.includes('error') ? '#f43f5e' : l.includes('\u2550') ? '#a78bfa' : '#94a3b8'
        }))]);
      }
    } catch {
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

  // Ensure we use current bcapHistory in key handler via ref
  const bcapHistoryRef = useRef(bcapHistory);
  useEffect(() => { bcapHistoryRef.current = bcapHistory; }, [bcapHistory]);

  return (
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
        <span style={{ color: '#22c55e', fontSize: '0.75rem', fontFamily: 'Fira Code, monospace', fontWeight: 700 }}>{'\u276F'}</span>
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
                const newIdx = Math.min(historyIndex + 1, bcapHistoryRef.current.length - 1);
                setHistoryIndex(newIdx);
                if (bcapHistoryRef.current[newIdx]) { setBcapCmd(bcapHistoryRef.current[newIdx]); setSuggestion(""); }
              } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                const newIdx = Math.max(historyIndex - 1, -1);
                setHistoryIndex(newIdx);
                setBcapCmd(newIdx >= 0 ? bcapHistoryRef.current[newIdx] : ""); setSuggestion("");
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
  );
};

export default CapTerminal;
