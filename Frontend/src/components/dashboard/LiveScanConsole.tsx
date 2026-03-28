import React, { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, X, CheckCircle2, Loader2, Info } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { WSMessage } from '@/hooks/useWebSocket';

interface LiveScanConsoleProps {
  messages: WSMessage[];
  isOpen: boolean;
  onClose: () => void;
  scanId: string | null;
  wsStatus?: 'connecting' | 'open' | 'closed';
}

export const LiveScanConsole: React.FC<LiveScanConsoleProps> = ({
  messages,
  isOpen,
  onClose,
  scanId,
  wsStatus = 'closed',
}) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95, y: 20 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95, y: 20 }}
      className="fixed bottom-6 right-6 w-[450px] max-h-[500px] z-50 rounded-xl border border-border bg-card shadow-2xl overflow-hidden flex flex-col"
    >
      {/* Header */}
      <div className="p-3 border-b border-border bg-muted/30 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          <span className="text-sm font-semibold text-foreground tracking-tight">Live Scan Console</span>
          <Badge
            variant="outline"
            className="max-w-[140px] truncate text-[10px] font-mono opacity-80"
            title={scanId ? `${scanId} · ${wsStatus}` : wsStatus}
          >
            {!scanId
              ? wsStatus === 'connecting'
                ? 'connecting…'
                : 'no scan id'
              : `${scanId.slice(0, 8)}…`}
          </Badge>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-md hover:bg-muted text-muted-foreground transition-colors"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Terminal Content */}
      <ScrollArea className="flex-1 p-4 bg-secondary/20 font-mono text-[11px] leading-relaxed">
        <div ref={scrollRef} className="space-y-1.5">
          <div className="text-zinc-500 mb-2">Initialize secure connection to scan pipeline...</div>
          
          {messages.length === 0 && (
            <div className="flex items-center gap-2 text-zinc-400">
              <Loader2 className="h-3 w-3 animate-spin" />
              <span>Waiting for tool output...</span>
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-zinc-600">[{new Date().toLocaleTimeString([], { hour12: false })}]</span>
              
              {msg.type === 'status' && (
                <span className="text-primary font-bold">
                   {msg.status === 'completed' ? (
                     <CheckCircle2 className="inline h-3 w-3 mr-1 text-success" />
                   ) : (
                     <Info className="inline h-3 w-3 mr-1" />
                   )}
                   {msg.message}
                </span>
              )}
              
              {msg.type === 'log' && (
                <span className="text-zinc-300">
                  <span className="text-info/80 mr-1.5">➔</span>
                  {msg.message}
                </span>
              )}

              {msg.type === 'data' && (
                <span className="text-warning-foreground font-medium bg-warning/10 px-1 rounded">
                  {msg.message}
                </span>
              )}

              {msg.type === 'metrics' && msg.data && (
                <span className="text-emerald-700">
                  <span className="mr-1.5 text-emerald-600/80">◆</span>
                  Metrics: {JSON.stringify(msg.data)}
                </span>
              )}
            </div>
          ))}
          
          {messages.some(m => m.status === 'completed') && (
            <div className="pt-2 text-success/80 font-bold border-t border-border mt-2">
              Pipeline verification complete. Updating dashboard...
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Footer */}
      <div className="p-2 px-4 border-t border-border bg-muted/10 text-[10px] text-muted-foreground flex justify-between items-center">
        <div className="flex items-center gap-1.5">
          <div
            className={`h-1.5 w-1.5 rounded-full ${
              wsStatus === 'open' ? 'animate-pulse bg-emerald-500' : wsStatus === 'connecting' ? 'animate-pulse bg-amber-500' : 'bg-zinc-400'
            }`}
          />
          <span>
            {wsStatus === 'open'
              ? 'WebSocket connected'
              : wsStatus === 'connecting'
                ? 'Connecting…'
                : 'Stream idle'}
          </span>
        </div>
        <span>{messages.length} log entries</span>
      </div>
    </motion.div>
  );
};
