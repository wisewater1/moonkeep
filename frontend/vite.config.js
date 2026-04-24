import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/auth': { target: 'http://localhost:8001', changeOrigin: true },
      '/admin': { target: 'http://localhost:8001', changeOrigin: true },
      '/plugins': { target: 'http://localhost:8001', changeOrigin: true },
      '/campaigns': { target: 'http://localhost:8001', changeOrigin: true },
      '/scan': { target: 'http://localhost:8001', changeOrigin: true },
      '/wifi_scan': { target: 'http://localhost:8001', changeOrigin: true },
      '/wifi': { target: 'http://localhost:8001', changeOrigin: true },
      '/bettercap': { target: 'http://localhost:8001', changeOrigin: true },
      '/graph': { target: 'http://localhost:8001', changeOrigin: true },
      '/interfaces': { target: 'http://localhost:8001', changeOrigin: true },
      '/vuln_scan': { target: 'http://localhost:8001', changeOrigin: true },
      '/secret_hunter': { target: 'http://localhost:8001', changeOrigin: true },
      '/cyber_strike': { target: 'http://localhost:8001', changeOrigin: true },
      '/ai': { target: 'http://localhost:8001', changeOrigin: true },
      '/post_exploit': { target: 'http://localhost:8001', changeOrigin: true },
      '/fuzzer': { target: 'http://localhost:8001', changeOrigin: true },
      '/sniffer': { target: 'http://localhost:8001', changeOrigin: true },
      '/hid_ble': { target: 'http://localhost:8001', changeOrigin: true },
      '/proxy': { target: 'http://localhost:8001', changeOrigin: true },
      '/spoofer': { target: 'http://localhost:8001', changeOrigin: true },
      '/docs': { target: 'http://localhost:8001', changeOrigin: true },
      '/openapi.json': { target: 'http://localhost:8001', changeOrigin: true },
      '/ws': {
        target: 'ws://localhost:8001',
        ws: true,
      },
    },
  },
})
