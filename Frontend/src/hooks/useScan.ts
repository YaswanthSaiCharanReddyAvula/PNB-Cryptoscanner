import { useState, useCallback, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { scanService, type ScanControllerPayload } from "@/services/api";

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
  const [isScanning, setIsScanning] = useState(false);
  const [targetDomain, setTargetDomain] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);

  const [stageIndex, setStageIndex] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const startScan = useCallback(async (domain: string, controller?: ScanControllerPayload) => {
    try {
      setTargetDomain(domain);
      setStageIndex(0);
      setErrorMsg(null);
      setScanId(null);
      setIsScanning(true);

      const res = await scanService.startScan(domain, controller);
      const id = (res.data as { scan_id?: string })?.scan_id ?? null;
      if (id) setScanId(id);
      else console.warn("startScan: API did not return scan_id — live console WebSocket will not connect.");
    } catch (err: unknown) {
      console.error(err);
      const ax = err as { response?: { data?: { detail?: string } } };
      setErrorMsg(ax.response?.data?.detail || "Failed to start scan");
      setIsScanning(false);
      setScanId(null);
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
      return;
    }
    if (r.status === "failed") {
      setIsScanning(false);
      setErrorMsg("Scan failed on backend.");
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
    }
  }, [isError, error]);

  return {
    isScanning,
    scanId,
    progress: STAGES[Math.min(stageIndex, 5)]?.progress ?? 0,
    currentStage: STAGES[Math.min(stageIndex, 5)]?.label ?? "",
    stageIndex,
    results: results && !(results as { _simulated?: boolean })._simulated ? results : null,
    error: errorMsg,
    startScan,
  };
}
