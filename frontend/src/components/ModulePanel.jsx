import React from 'react';
import ScannerModule from './modules/ScannerModule.jsx';
import WifiModule from './modules/WifiModule.jsx';
import SpooferModule from './modules/SpooferModule.jsx';
import SnifferModule from './modules/SnifferModule.jsx';
import PostExploitModule from './modules/PostExploitModule.jsx';
import FuzzerModule from './modules/FuzzerModule.jsx';
import HidBleModule from './modules/HidBleModule.jsx';
import SecretHunterModule from './modules/SecretHunterModule.jsx';
import VulnScannerModule from './modules/VulnScannerModule.jsx';
import CyberStrikeModule from './modules/CyberStrikeModule.jsx';
import AIModule from './modules/AIModule.jsx';
import ProxyModule from './modules/ProxyModule.jsx';

const ModulePanel = ({ activePlugin, reconConsole, moduleState, apiCall }) => {
  if (!activePlugin) return <div className="glass-card">INITIALIZING VECTORS...</div>;

  switch (activePlugin) {
    case "Scanner":
      return (
        <ScannerModule
          devices={moduleState.devices}
          setDevices={moduleState.setDevices}
          scanning={moduleState.scanning}
          setScanning={moduleState.setScanning}
          activeTarget={moduleState.activeTarget}
          setActiveTarget={moduleState.setActiveTarget}
          setTargetDrawerOpen={moduleState.setTargetDrawerOpen}
          apiCall={apiCall}
        />
      );

    case "WiFi-Strike":
    case "Wardriver":
      return (
        <WifiModule
          networks={moduleState.networks}
          setNetworks={moduleState.setNetworks}
          setStrikeLog={moduleState.setStrikeLog}
          apiCall={apiCall}
        />
      );

    case "Spoofer":
      return (
        <SpooferModule
          devices={moduleState.devices}
          spoofing={moduleState.spoofing}
          setSpoofing={moduleState.setSpoofing}
          apiCall={apiCall}
        />
      );

    case "Sniffer":
      return (
        <SnifferModule
          capturedCreds={moduleState.capturedCreds}
          packets={moduleState.packets}
          apiCall={apiCall}
        />
      );

    case "Post-Exploit":
      return (
        <PostExploitModule
          activeTarget={moduleState.activeTarget}
          apiCall={apiCall}
        />
      );

    case "Fuzzer":
      return (
        <FuzzerModule
          activeTarget={moduleState.activeTarget}
          fuzzingStatus={moduleState.fuzzingStatus}
          setFuzzingStatus={moduleState.setFuzzingStatus}
          apiCall={apiCall}
        />
      );

    case "HID-BLE-Strike":
      return (
        <HidBleModule
          activeTarget={moduleState.activeTarget}
          apiCall={apiCall}
        />
      );

    case "Secret-Hunter":
      return (
        <SecretHunterModule
          secretFindings={moduleState.secretFindings}
          setSecretFindings={moduleState.setSecretFindings}
          apiCall={apiCall}
        />
      );

    case "Vuln-Scanner":
      return (
        <VulnScannerModule
          activeTarget={moduleState.activeTarget}
          vulnCards={moduleState.vulnCards}
          setStrikeLog={moduleState.setStrikeLog}
          apiCall={apiCall}
        />
      );

    case "Cyber-Strike":
      return (
        <CyberStrikeModule
          cyberStrikeRole={moduleState.cyberStrikeRole}
          setCyberStrikeRole={moduleState.setCyberStrikeRole}
          cyberStrikeLog={moduleState.cyberStrikeLog}
          setCyberStrikeLog={moduleState.setCyberStrikeLog}
          apiCall={apiCall}
        />
      );

    case "AI-Orchestrator":
      return (
        <AIModule
          aiCmd={moduleState.aiCmd}
          setAiCmd={moduleState.setAiCmd}
          aiPlan={moduleState.aiPlan}
          setAiPlan={moduleState.setAiPlan}
          aiInsights={moduleState.aiInsights}
          setAiInsights={moduleState.setAiInsights}
          graphData={moduleState.graphData}
          apiCall={apiCall}
        />
      );

    case "Proxy":
      return (
        <ProxyModule
          proxyPort={moduleState.proxyPort}
          setProxyPort={moduleState.setProxyPort}
          proxyActive={moduleState.proxyActive}
          setProxyActive={moduleState.setProxyActive}
          apiCall={apiCall}
        />
      );

    case "Recon-Console":
      return reconConsole;

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

export default ModulePanel;
