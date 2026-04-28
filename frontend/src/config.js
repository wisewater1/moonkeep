// Runtime-overridable API/WS base URLs.
//
// Resolution order (first hit wins):
//   1. localStorage.moonkeep_api_base / moonkeep_ws_base
//        — lets an admin retarget the PWA at a Tailscale / tunnel URL
//        from the phone without rebuilding.
//   2. VITE_API_URL / VITE_WS_URL (build-time env)
//   3. Same origin as the page (empty string API base; derived WS base).
//
// Same-origin default is critical on mobile: a hardcoded `localhost:8001`
// fallback resolves to the *phone* when the PWA is installed to the home
// screen, and breaks every call.

const LS_API = 'moonkeep_api_base';
const LS_WS  = 'moonkeep_ws_base';

const safeGet = (key) => {
  try { return typeof localStorage !== 'undefined' ? localStorage.getItem(key) : null; }
  catch { return null; }
};

const derivedWs = () => {
  if (typeof window === 'undefined') return '';
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}`;
};

export const API_BASE = (
  safeGet(LS_API) ||
  import.meta.env.VITE_API_URL ||
  ''
);

export const WS_BASE = (
  safeGet(LS_WS) ||
  import.meta.env.VITE_WS_URL ||
  derivedWs()
);

export const setApiBase = (url) => {
  try {
    if (url) localStorage.setItem(LS_API, url);
    else     localStorage.removeItem(LS_API);
  } catch { /* ignore */ }
};

export const setWsBase = (url) => {
  try {
    if (url) localStorage.setItem(LS_WS, url);
    else     localStorage.removeItem(LS_WS);
  } catch { /* ignore */ }
};
