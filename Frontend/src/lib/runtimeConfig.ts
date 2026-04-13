/**
 * REST API base path (must end with /api/v1).
 * Electron packaged builds can override via quantumshield.config.json → preload bridge.
 */
export function getViteApiBaseUrl(): string {
  if (typeof window !== "undefined") {
    const fromElectron = window.electronAPI?.apiBaseUrl?.trim();
    if (fromElectron) return fromElectron;
  }
  return import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";
}
