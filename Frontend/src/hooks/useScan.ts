import { useState, useCallback, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { scanService } from "@/services/api";

const STAGES = [
  { label: "Discovering assets", progress: 15 },
  { label: "Scanning TLS configurations", progress: 35 },
  { label: "Analyzing crypto", progress: 60 },
  { label: "Evaluating quantum risk", progress: 80 },
  { label: "Generating CBOM", progress: 90 },
  { label: "Complete", progress: 100 }
];

export function useScan() {
  const [isScanning, setIsScanning] = useState(false);
  const [targetDomain, setTargetDomain] = useState<string | null>(null);
  
  const [stageIndex, setStageIndex] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const startScan = useCallback(async (domain: string) => {
    try {
      setTargetDomain(domain);
      setStageIndex(0);
      setErrorMsg(null);
      setIsScanning(true);
      
      // Fire the POST endpoint
      await scanService.startScan(domain);
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.response?.data?.detail || "Failed to start scan");
      setIsScanning(false);
    }
  }, []);

  // Progressive simulated stages via elapsed time
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isScanning && stageIndex < 4) {
      interval = setInterval(() => {
        setStageIndex(prev => Math.min(prev + 1, 4));
      }, 4500); // advance every 4.5s automatically up to stage 4
    }
    return () => clearInterval(interval);
  }, [isScanning, stageIndex]);

  // Polling with React Query
  const { data: results, error, isError } = useQuery({
    queryKey: ['scanResults', targetDomain],
    queryFn: async () => {
      if (!targetDomain) return null;
      try {
        const res = await scanService.getResults(targetDomain);
        return res.data;
      } catch (err: any) {
        if (err.response?.status === 404) {
          // If 404, it means the background job hasn't persisted the first stage yet
          return { status: "pending", _simulated: true };
        }
        throw err;
      }
    },
    enabled: isScanning && !!targetDomain,
    // Provide a function to refetchInterval: return number (ms) or false to stop
    refetchInterval: (query) => {
      if (!isScanning) return false;
      const data = query.state.data;
      if (!data) return 3000;
      if (data.status === "completed" || data.status === "failed") return false;
      return 3000;
    },
    retry: false 
  });

  // Watch for completion / failure from polling
  useEffect(() => {
    if (results && !results._simulated) {
      if (results.status === "completed") {
        setStageIndex(5); // Complete
        setIsScanning(false);
      } else if (results.status === "failed") {
        setIsScanning(false);
        setErrorMsg("Scan failed on backend.");
      }
    }
    if (isError && error) {
      setIsScanning(false);
      setErrorMsg(error.message || "An unexpected error occurred during polling.");
    }
  }, [results, isError, error]);

  return {
    isScanning,
    progress: STAGES[stageIndex].progress,
    currentStage: STAGES[stageIndex].label,
    stageIndex, // Exposing for ScanProgressBar
    results: results && !results._simulated ? results : null,
    error: errorMsg,
    startScan
  };
}
