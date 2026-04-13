/**
 * Preload — keep minimal; renderer stays a normal web app (no Node in UI).
 * Packaged apps: optional quantumshield.config.json next to the .exe (or in resources/) with:
 *   { "VITE_API_BASE_URL": "https://your-api.example.com/api/v1" }
 */
const { contextBridge } = require("electron");
const fs = require("fs");
const path = require("path");

function readPackagedApiBase() {
  try {
    // Preload runs in renderer context; Electron `app` is not available here.
    const isPackaged = typeof process !== "undefined" && !String(process.execPath || "").toLowerCase().includes("\\electron\\");
    if (!isPackaged) return "";
    const exePath = String(process.execPath || "");
    const exeDir = exePath ? path.dirname(exePath) : "";
    const candidates = [
      exeDir ? path.join(exeDir, "quantumshield.config.json") : "",
    ];
    if (process.resourcesPath) {
      candidates.push(path.join(process.resourcesPath, "quantumshield.config.json"));
    }
    for (const p of candidates) {
      if (!p || !fs.existsSync(p)) continue;
      const j = JSON.parse(fs.readFileSync(p, "utf8"));
      const v = j.VITE_API_BASE_URL;
      if (typeof v === "string" && v.trim()) return v.trim();
    }
  } catch (e) {
    const msg = e && typeof e.message === "string" ? e.message : String(e);
    console.warn("[QuantumShield] runtime config:", msg);
  }
  return "";
}

const apiBaseUrl = readPackagedApiBase();

contextBridge.exposeInMainWorld("electronAPI", {
  platform: process.platform,
  apiBaseUrl: apiBaseUrl || null,
});
