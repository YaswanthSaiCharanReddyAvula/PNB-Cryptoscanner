import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// Backend origin — the Kali VM running FastAPI/Uvicorn.
// Override with VITE_BACKEND_ORIGIN env var if the IP changes.
const BACKEND = process.env.VITE_BACKEND_ORIGIN || "http://192.168.56.102:8000";

// https://vitejs.dev/config/
// ELECTRON=true: relative asset paths so packaged app can load dist/index.html via file://
export default defineConfig(({ mode }) => ({
  base: process.env.ELECTRON === "true" ? "./" : "/",
  server: {
    host: "::",
    port: 8080,
    hmr: {
      overlay: false,
    },
    // ── Dev proxy ─────────────────────────────────────────────────
    // Forward /api/* and /health to the backend so the browser never
    // makes cross-origin requests — eliminates CORS issues entirely.
    proxy: {
      "/api": {
        target: BACKEND,
        changeOrigin: true,
        secure: false,
      },
      "/health": {
        target: BACKEND,
        changeOrigin: true,
        secure: false,
      },
      "/ws": {
        target: BACKEND,
        changeOrigin: true,
        ws: true,
        secure: false,
      },
    },
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
