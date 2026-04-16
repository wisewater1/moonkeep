import React from 'react';

const FuzzerModule = ({ activeTarget, fuzzingStatus, setFuzzingStatus, apiCall }) => {
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
};

export default FuzzerModule;
