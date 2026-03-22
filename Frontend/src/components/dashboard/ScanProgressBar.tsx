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
}

export function ScanProgressBar({ isScanning, stageIndex, targetDomain }: ScanProgressBarProps) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isScanning) {
      interval = setInterval(() => setElapsed(e => e + 1), 1000);
    } else if (stageIndex === 0) {
      setElapsed(0);
    }
    return () => clearInterval(interval);
  }, [isScanning, stageIndex]);

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
          className="w-full bg-card border border-[#FBBC09]/30 rounded-xl p-5 shadow-lg relative overflow-hidden mb-6"
        >
          {/* Subtle glow background */}
          <div className="absolute top-0 right-1/4 w-96 h-96 bg-[#FBBC09]/5 rounded-full blur-3xl -z-10" />

          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8 relative z-10">
            <div>
              <h3 className="text-sm font-bold text-foreground uppercase tracking-wider mb-1 flex items-center gap-2">
                <Target className="w-4 h-4 text-[#FBBC09]" />
                Scan Pipeline Active
              </h3>
              <p className="text-sm text-muted-foreground">
                {isScanning 
                  ? <span className="flex items-center gap-2">Analyzing <strong className="text-foreground">{targetDomain}</strong>...</span>
                  : stageIndex >= 5 ? <span className="text-success font-medium">Scan completed successfully.</span> : "Preparation..."}
              </p>
            </div>
            {isScanning && (
              <div className="flex items-center gap-2 text-[#FBBC09] font-mono bg-[#FBBC09]/10 px-3 py-1.5 rounded-md border border-[#FBBC09]/20 shadow-sm shrink-0">
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
              className="absolute top-4 left-0 h-[3px] bg-[#FBBC09] rounded-full -z-10"
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
                      backgroundColor: isComplete ? "#FBBC09" : isActive ? "hsl(220, 14%, 20%)" : "hsl(220, 14%, 10%)",
                      borderColor: isComplete || isActive ? "#FBBC09" : "hsl(220, 14%, 30%)",
                      color: isComplete ? "hsl(220, 14%, 10%)" : isActive ? "#FBBC09" : "hsl(215, 15%, 55%)"
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
