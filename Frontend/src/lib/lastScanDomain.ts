/** Domain from the last Overview scan — used by Security Roadmap (no separate domain entry).
 * Notes:
 * - `sessionStorage` is per-tab, which can break demos or automated browser checks.
 * - We also mirror to `localStorage` as a fallback so the roadmap can still load.
 */
const KEY = "quantumshield:lastScanDomain";

function safeSet(storage: Storage, value: string) {
  try {
    storage.setItem(KEY, value);
  } catch {
    /* ignore quota / private mode */
  }
}

function safeGet(storage: Storage): string | null {
  try {
    const v = storage.getItem(KEY);
    return v?.trim() || null;
  } catch {
    return null;
  }
}

export function setLastScannedDomain(domain: string): void {
  const d = domain.trim().toLowerCase();
  if (!d) return;
  safeSet(sessionStorage, d);
  safeSet(localStorage, d);
}

export function getLastScannedDomain(): string | null {
  // Prefer session storage (most “correct” for tab-specific user intent), then local storage.
  return safeGet(sessionStorage) ?? safeGet(localStorage);
}
