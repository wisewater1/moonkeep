// Share the same runtime-resolved bases as config.js so a localStorage
// override (used by the mobile Settings panel) applies everywhere.
import { API_BASE, WS_BASE } from './config.js';
export const API_URL = API_BASE;
export const WS_URL = WS_BASE;

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
