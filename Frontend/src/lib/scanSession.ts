/**
 * Persist active Overview scan + WebSocket log buffer across route changes (sessionStorage).
 */

const ACTIVE_KEY = "quantumshield_active_scan_v1";
const LOG_PREFIX = "quantumshield_scan_logs_v1:";
const MAX_LOG_MESSAGES = 250;

export type ActiveScanPayload = {
  scanId: string;
  domain: string;
};

function safeParse<T>(raw: string | null): T | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function saveActiveScan(scanId: string, domain: string): void {
  try {
    const d = domain.trim().toLowerCase();
    if (!scanId || !d) return;
    sessionStorage.setItem(
      ACTIVE_KEY,
      JSON.stringify({ scanId, domain: d } satisfies ActiveScanPayload),
    );
  } catch {
    /* quota / private mode */
  }
}

export function loadActiveScan(): ActiveScanPayload | null {
  try {
    const o = safeParse<ActiveScanPayload>(sessionStorage.getItem(ACTIVE_KEY));
    if (!o?.scanId || !o?.domain) return null;
    return { scanId: o.scanId, domain: o.domain.trim().toLowerCase() };
  } catch {
    return null;
  }
}

export function clearActiveScan(): void {
  try {
    sessionStorage.removeItem(ACTIVE_KEY);
  } catch {
    /* ignore */
  }
}

function logKey(scanId: string): string {
  return `${LOG_PREFIX}${scanId}`;
}

/** Replace full log array (bounded). */
export function saveScanLogs(scanId: string, messages: unknown[]): void {
  try {
    const slice = messages.slice(-MAX_LOG_MESSAGES);
    sessionStorage.setItem(logKey(scanId), JSON.stringify(slice));
  } catch {
    /* ignore */
  }
}

export function loadScanLogs(scanId: string): unknown[] {
  try {
    const arr = safeParse<unknown[]>(sessionStorage.getItem(logKey(scanId)));
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

export function clearScanLogs(scanId: string): void {
  try {
    sessionStorage.removeItem(logKey(scanId));
  } catch {
    /* ignore */
  }
}

/** Remove all persisted WS log buffers (e.g. when starting a fresh scan). */
export function clearAllScanLogStorage(): void {
  try {
    const toRemove: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k?.startsWith(LOG_PREFIX)) toRemove.push(k);
    }
    toRemove.forEach((k) => sessionStorage.removeItem(k));
  } catch {
    /* ignore */
  }
}
