import { useState, useCallback, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { scanService, type ScanControllerPayload } from "@/services/api";
import {
  saveActiveScan,
  loadActiveScan,
  clearActiveScan,
  clearAllScanLogStorage,
  clearScanLogs,
} from "@/lib/scanSession";

const STAGES = [
  { label: "Discovering assets", progress: 15 },
  { label: "Scanning TLS configurations", progress: 35 },
  { label: "Analyzing crypto", progress: 60 },
  { label: "Evaluating quantum risk", progress: 80 },
  { label: "Generating CBOM", progress: 90 },
  { label: "Complete", progress: 100 },
];

/** Map MongoDB `current_stage` (and similar labels) to ScanProgressBar step 0–4; 5 = all done. */
export function backendStageToStep(currentStage: string | undefined): number {
  if (!currentStage) return 0;
  const s = currentStage.toLowerCase();
  if (s.includes("asset") || s.includes("initialis")) return 0;
  if (s.includes("tls")) return 1;
  if (s.includes("crypto")) return 2;
  if (s.includes("quantum")) return 3;
  if (s.includes("cbom")) return 4;
  if (s.includes("recommendation") || s.includes("http header") || s.includes("cve")) return 4;
  return 0;
}

export function useScan() {
  const hydrated = typeof window !== "undefined" ? loadActiveScan() : null;
  const [isScanning, setIsScanning] = useState(() => !!hydrated);
  const [targetDomain, setTargetDomain] = useState<string | null>(
    () => hydrated?.domain ?? null,
  );
  const [scanId, setScanId] = useState<string | null>(() => hydrated?.scanId ?? null);

  const [stageIndex, setStageIndex] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  /** Reconcile sessionStorage with backend after navigation remount. */
  useEffect(() => {
    const saved = loadActiveScan();
    if (!saved) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await scanService.getResults(saved.domain);
        const doc = res.data as {
          status?: string;
          current_stage?: string;
          scan_id?: string;
        };
        if (cancelled) return;
        if (doc.scan_id !== saved.scanId) {
          clearActiveScan();
          setIsScanning(false);
          setTargetDomain(null);
          setScanId(null);
          return;
        }
        if (doc.status === "completed" || doc.status === "failed") {
          clearActiveScan();
          setIsScanning(false);
          setTargetDomain(null);
          setScanId(null);
          return;
        }
        if (doc.status === "running" || doc.status === "pending") {
          setTargetDomain(saved.domain);
          setScanId(saved.scanId);
          setIsScanning(true);
          setStageIndex(backendStageToStep(doc.current_stage));
        }
      } catch {
        if (!cancelled) {
          clearActiveScan();
          setIsScanning(false);
          setTargetDomain(null);
          setScanId(null);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const startScan = useCallback(async (domain: string, controller?: ScanControllerPayload) => {
    try {
      clearActiveScan();
      clearAllScanLogStorage();

      setTargetDomain(domain);
      setStageIndex(0);
      setErrorMsg(null);
      setScanId(null);
      setIsScanning(true);

      const res = await scanService.startScan(domain, controller);
      const id = (res.data as { scan_id?: string })?.scan_id ?? null;
      if (id) {
        setScanId(id);
        saveActiveScan(id, domain);
      } else {
        console.warn("startScan: API did not return scan_id — live console WebSocket will not connect.");
      }
    } catch (err: unknown) {
      console.error(err);
      const ax = err as { response?: { data?: { detail?: string } } };
      setErrorMsg(ax.response?.data?.detail || "Failed to start scan");
      setIsScanning(false);
      setScanId(null);
      clearActiveScan();
    }
  }, []);

  const { data: results, error, isError } = useQuery({
    queryKey: ["scanResults", targetDomain, scanId],
    queryFn: async () => {
      if (!targetDomain) return null;
      try {
        const res = await scanService.getResults(targetDomain);
        return res.data;
      } catch (err: unknown) {
        const status = (err as { response?: { status?: number } })?.response?.status;
        if (status === 404) {
          return { status: "pending", _simulated: true };
        }
        throw err;
      }
    },
    enabled: isScanning && !!targetDomain,
    refetchInterval: (query) => {
      if (!isScanning) return false;
      const data = query.state.data as { status?: string } | null;
      if (!data) return 2000;
      if (data.status === "completed" || data.status === "failed") return false;
      return 2000;
    },
    retry: false,
  });

  useEffect(() => {
    if (!results || (results as { _simulated?: boolean })._simulated) return;

    const r = results as {
      status?: string;
      current_stage?: string;
      scan_id?: string;
    };

    if (r.status === "completed") {
      setStageIndex(5);
      setIsScanning(false);
      if (r.scan_id) clearScanLogs(r.scan_id);
      clearActiveScan();
      return;
    }
    if (r.status === "failed") {
      setIsScanning(false);
      setErrorMsg("Scan failed on backend.");
      if (r.scan_id) clearScanLogs(r.scan_id);
      clearActiveScan();
      return;
    }

    if (r.status === "running" || r.status === "pending") {
      setStageIndex(backendStageToStep(r.current_stage));
    }
  }, [results]);

  useEffect(() => {
    if (isError && error) {
      setIsScanning(false);
      setErrorMsg(error.message || "An unexpected error occurred during polling.");
      clearActiveScan();
    }
  }, [isError, error]);

  return {
    isScanning,
    scanId,
    targetDomain,
    progress: STAGES[Math.min(stageIndex, 5)]?.progress ?? 0,
    currentStage: STAGES[Math.min(stageIndex, 5)]?.label ?? "",
    stageIndex,
    results: results && !(results as { _simulated?: boolean })._simulated ? results : null,
    error: errorMsg,
    startScan,
  };
}
