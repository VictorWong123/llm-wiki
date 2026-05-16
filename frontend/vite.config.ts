import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/accept-rewrite": "http://127.0.0.1:8000",
      "/agent": "http://127.0.0.1:8000",
      "/demo-data": "http://127.0.0.1:8000",
      "/demo-evidence": "http://127.0.0.1:8000",
      "/events": "http://127.0.0.1:8000",
      "/feedback": "http://127.0.0.1:8000",
      "/health": "http://127.0.0.1:8000",
      "/ingest": "http://127.0.0.1:8000",
      "/lint": "http://127.0.0.1:8000",
      "/memory": "http://127.0.0.1:8000",
      "/preflight": "http://127.0.0.1:8000",
      "/wiki": "http://127.0.0.1:8000"
    }
  }
});
