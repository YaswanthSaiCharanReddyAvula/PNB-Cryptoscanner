import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Check, Clock, Loader2, Target } from "lucide-react";

export const SCAN_STAGES = [
  "Asset Discovery",
  "TLS Scanning",
  "Crypto Analysis",
  "Quantum Risk",
  "CBOM Generation"
];

interface ScanProgressBarProps {
  isScanning: boolean;
  stageIndex: number;
  targetDomain?: string | null;
  /** Backend `current_stage` for accurate sub-label while polling */
  pipelineStageLabel?: string | null;
}

export function ScanProgressBar({
  isScanning,
  stageIndex,
  targetDomain,
  pipelineStageLabel,
}: ScanProgressBarProps) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!isScanning) {
      if (stageIndex === 0) setElapsed(0);
      return;
    }
    // Reset on every new scan start
    setElapsed(0);
    const interval = setInterval(() => setElapsed(e => e + 1), 1000);
    return () => clearInterval(interval);
  }, [isScanning]);

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60).toString().padStart(2, "0");
    const s = (seconds % 60).toString().padStart(2, "0");
    return `${m}:${s}`;
  };

  return (
    <AnimatePresence>
      {(isScanning || stageIndex > 0) && (
        <motion.div 
          initial={{ opacity: 0, height: 0, y: -20 }}
          animate={{ opacity: 1, height: "auto", y: 0 }}
          exit={{ opacity: 0, height: 0 }}
          className="relative mb-6 w-full overflow-hidden rounded-xl border border-primary/25 bg-card p-5 shadow-lg"
        >
          {/* Subtle glow background */}
          <div className="absolute -z-10 right-1/4 top-0 h-96 w-96 rounded-full bg-primary/5 blur-3xl" />

          <div className="relative z-10 mb-8 flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
            <div>
              <h3 className="mb-1 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-foreground">
                <Target className="h-4 w-4 text-primary" />
                Scan Pipeline Active
              </h3>
              <p className="text-sm text-muted-foreground">
                {isScanning ? (
                  <span className="flex flex-col gap-0.5 sm:flex-row sm:items-center sm:gap-2">
                    <span>
                      Analyzing <strong className="text-foreground">{targetDomain}</strong>
                      …
                    </span>
                    {pipelineStageLabel ? (
                      <span className="text-xs font-medium text-primary/90 sm:text-sm">
                        {pipelineStageLabel}
                      </span>
                    ) : null}
                  </span>
                ) : stageIndex >= 5 ? (
                  <span className="font-medium text-success">Scan completed successfully.</span>
                ) : (
                  "Preparation..."
                )}
              </p>
            </div>
            {isScanning && (
              <div className="flex shrink-0 items-center gap-2 rounded-md border border-primary/20 bg-primary/10 px-3 py-1.5 font-mono text-primary shadow-sm">
                <Clock className="w-4 h-4" />
                {formatTime(elapsed)}
              </div>
            )}
          </div>

          <div className="relative flex justify-between z-10">
            {/* Track Background */}
            <div className="absolute top-4 left-0 w-full h-[3px] bg-secondary/80 rounded-full -z-10" />
            
            {/* Track Fill */}
            <motion.div 
              className="absolute top-4 left-0 h-[3px] rounded-full bg-primary -z-10"
              initial={{ width: "0%" }}
              animate={{ width: `${Math.min((stageIndex / (SCAN_STAGES.length - 1)) * 100, 100)}%` }}
              transition={{ duration: 0.6, ease: "easeInOut" }}
            />

            {/* Stages */}
            {SCAN_STAGES.map((stage, i) => {
              const isActive = i === Math.min(stageIndex, 4) && isScanning;
              const isComplete = i < stageIndex || stageIndex >= 5;

              return (
                <div key={stage} className="flex flex-col items-center gap-2 relative z-10">
                  <motion.div 
                    initial={false}
                    animate={{ 
                      scale: isActive ? 1.2 : 1,
                      backgroundColor: isComplete ? "#2563eb" : isActive ? "hsl(220, 14%, 20%)" : "hsl(220, 14%, 10%)",
                      borderColor: isComplete || isActive ? "#2563eb" : "hsl(220, 14%, 30%)",
                      color: isComplete ? "hsl(210, 40%, 98%)" : isActive ? "#60a5fa" : "hsl(215, 15%, 55%)"
                    }}
                    className={`w-8 h-8 rounded-full border-2 flex items-center justify-center shadow-sm transition-colors duration-300`}
                  >
                    {isComplete ? (
                      <Check className="w-4 h-4 stroke-[3]" />
                    ) : isActive ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <span className="text-xs font-semibold">{i + 1}</span>
                    )}
                  </motion.div>
                  <span className={`hidden sm:block text-[10px] font-medium uppercase tracking-wider transition-colors duration-300 ${
                    isActive || isComplete ? "text-foreground" : "text-muted-foreground"
                  }`}>
                    {stage}
                  </span>
                </div>
              );
            })}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
