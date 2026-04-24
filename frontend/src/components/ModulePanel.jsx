import React, { Suspense, lazy } from 'react';

const ScannerModule = lazy(() => import('./modules/ScannerModule.jsx'));
const WifiModule = lazy(() => import('./modules/WifiModule.jsx'));
const SpooferModule = lazy(() => import('./modules/SpooferModule.jsx'));
const SnifferModule = lazy(() => import('./modules/SnifferModule.jsx'));
const PostExploitModule = lazy(() => import('./modules/PostExploitModule.jsx'));
const FuzzerModule = lazy(() => import('./modules/FuzzerModule.jsx'));
const HidBleModule = lazy(() => import('./modules/HidBleModule.jsx'));
const SecretHunterModule = lazy(() => import('./modules/SecretHunterModule.jsx'));
const VulnScannerModule = lazy(() => import('./modules/VulnScannerModule.jsx'));
const CyberStrikeModule = lazy(() => import('./modules/CyberStrikeModule.jsx'));
const AIModule = lazy(() => import('./modules/AIModule.jsx'));
const ProxyModule = lazy(() => import('./modules/ProxyModule.jsx'));

const fallback = (
  <div className="glass-card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.85rem', letterSpacing: '3px', color: 'var(--neo-cyan)' }}>
    LOADING MODULE...
  </div>
);

const ModulePanel = ({ activePlugin, reconConsole, moduleState, apiCall }) => {
  if (!activePlugin) return <div className="glass-card">INITIALIZING VECTORS...</div>;

  const content = (() => {
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
  })();

  return <Suspense fallback={fallback}>{content}</Suspense>;
};

export default ModulePanel;
