/** Domain from the last Overview scan — used by Security Roadmap (no separate domain entry). */
const KEY = "quantumshield:lastScanDomain";

export function setLastScannedDomain(domain: string): void {
  const d = domain.trim().toLowerCase();
  if (!d) return;
  try {
    sessionStorage.setItem(KEY, d);
  } catch {
    /* ignore quota / private mode */
  }
}

export function getLastScannedDomain(): string | null {
  try {
    const v = sessionStorage.getItem(KEY);
    return v?.trim() || null;
  } catch {
    return null;
  }
}
