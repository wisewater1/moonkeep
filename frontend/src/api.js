export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';
export const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8001';

export function makeApiCall(setStrikeLog) {
  return async function apiCall(endpoint, method = 'GET', body = null) {
    setStrikeLog(prev => [...prev.slice(-40), `[>] INVOKE: ${endpoint}`]);
    try {
      const options = { method };
      if (body) {
        options.headers = { 'Content-Type': 'application/json' };
        options.body = JSON.stringify(body);
      }
      const res = await fetch(`${API_URL}${endpoint}`, options);
      const data = await res.json();
      setStrikeLog(prev => [
        ...prev.slice(-40),
        `[<] SUCCESS: ${endpoint}`,
        `[#] DATA: ${JSON.stringify(data).slice(0, 100)}...`,
      ]);
      return data;
    } catch {
      setStrikeLog(prev => [...prev.slice(-40), `[!] FAILED: ${endpoint}`]);
      return null;
    }
  };
}
