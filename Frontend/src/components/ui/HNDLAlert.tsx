import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, X, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

interface HNDLAlertProps {
  title?: string;
  description?: React.ReactNode;
}

export function HNDLAlert({ 
  title = "HNDL Vulnerability Detected", 
  description = "This asset uses vulnerable algorithms (RSA / ECDH) for key exchange. Adversaries may be harvesting encrypted traffic today for future quantum decryption. Immediate migration to CRYSTALS-Kyber is recommended."
}: HNDLAlertProps) {
  const [isVisible, setIsVisible] = useState(true);

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0, y: -20, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, scale: 0.98, height: 0, marginTop: 0, marginBottom: 0, overflow: "hidden" }}
          transition={{ duration: 0.3, ease: "easeInOut" }}
          className="relative mb-6 w-full overflow-hidden rounded-xl border border-destructive/25 bg-destructive/10 p-4 shadow-lg"
        >
          {/* Background glow effect */}
          <div className="absolute right-1/4 top-0 h-64 w-64 rounded-full bg-destructive/10 blur-3xl" />
          
          <div className="relative flex items-start gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-destructive/25 bg-destructive/15 text-destructive">
              <AlertTriangle className="h-5 w-5" />
            </div>
            
            <div className="flex-1 pt-1">
              <h3 className="mb-1 text-sm font-bold uppercase tracking-wide text-destructive">
                {title}
              </h3>
              <div className="text-sm text-foreground/90 max-w-4xl leading-relaxed mb-4">
                {description}
              </div>
              
              <div className="flex items-center gap-3">
                <Link to="/pqc-posture">
                  <Button variant="outline" size="sm" className="border-destructive/30 bg-destructive/15 font-semibold text-destructive transition-colors hover:bg-destructive/25">
                    View Migration Guide
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                </Link>
              </div>
            </div>

            <button
              onClick={() => setIsVisible(false)}
              className="absolute top-0 right-0 p-2 text-muted-foreground hover:text-foreground transition-colors rounded-lg hover:bg-secondary/50"
              aria-label="Dismiss"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
