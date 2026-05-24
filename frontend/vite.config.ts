/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backendTarget = (process.env.VITE_BACKEND_HTTP ?? "http://localhost:8000").replace(
  /\/$/,
  "",
);

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/recharts") || id.includes("node_modules/d3-")) {
            return "recharts";
          }
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
  },
  server: {
    port: 3000,
    host: true,
    proxy: {
      "/health": { target: backendTarget, changeOrigin: true },
      "/metrics": { target: backendTarget, changeOrigin: true },
      "/alerts": { target: backendTarget, changeOrigin: true },
      "/events": { target: backendTarget, changeOrigin: true, ws: true },
      "/analyze": { target: backendTarget, changeOrigin: true },
      "/scan": { target: backendTarget, changeOrigin: true },
      "/config": { target: backendTarget, changeOrigin: true },
      "/kernel": { target: backendTarget, changeOrigin: true },
    },
  },
});
