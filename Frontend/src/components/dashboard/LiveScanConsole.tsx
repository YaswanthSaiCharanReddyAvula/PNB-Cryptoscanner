import React, { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Terminal, X, CheckCircle2, Loader2, AlertCircle,
  Search, Shield, Brain, FileText, Globe, Zap, Network, Info
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { WSMessage } from '@/hooks/useWebSocket';

interface LiveScanConsoleProps {
  messages: WSMessage[];
  isOpen: boolean;
  onClose: () => void;
  scanId: string | null;
  wsStatus?: 'connecting' | 'open' | 'closed';
  onCancel?: () => void;
}

// Stage meta — icon + label for each numbered stage
const STAGE_META: Record<number, { label: string; Icon: React.ElementType; color: string }> = {
  1: { label: 'Asset Discovery', Icon: Search, color: 'text-sky-400' },
  2: { label: 'TLS Scanning', Icon: Shield, color: 'text-violet-400' },
  3: { label: 'Crypto Analysis', Icon: Brain, color: 'text-amber-400' },
  4: { label: 'Quantum Risk Scoring', Icon: Zap, color: 'text-rose-400' },
  5: { label: 'CVE Mapping', Icon: AlertCircle, color: 'text-orange-400' },
  6: { label: 'CBOM Generation', Icon: FileText, color: 'text-teal-400' },
  7: { label: 'Security Roadmap', Icon: Network, color: 'text-indigo-400' },
  8: { label: 'Finalizing Report', Icon: Globe, color: 'text-emerald-400' },
};

function formatMetrics(data: Record<string, unknown>): string {
  return Object.entries(data)
    .map(([k, v]) => {
      const label = k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      return `${label}: ${v}`;
    })
    .join('  ·  ');
}

/** Reformat a raw tool log string into something human-readable */
function formatLogMessage(msg: string): string {
  if (!msg) return msg;
  // Nmap progress — already human readable
  if (msg.startsWith('[Nmap Progress]')) return msg.replace('[Nmap Progress]', '').trim();
  // Strip internal prefixes like [12a3bc...]
  return msg.replace(/^\[[a-f0-9]{8,}\]\s*/i, '').trim();
}

/** Parse timestamp from message if present, else use current time */
function getTimestamp(): string {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export const LiveScanConsole: React.FC<LiveScanConsoleProps> = ({
  messages,
  isOpen,
  onClose,
  scanId,
  wsStatus = 'closed',
  onCancel,
}) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  if (!isOpen) return null;

  const isCompleted = messages.some(m => m.status === 'completed');
  const isFailed = messages.some(m => m.status === 'failed');

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97, y: 16 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.97, y: 16 }}
      transition={{ duration: 0.18 }}
      className="fixed bottom-6 right-6 w-[520px] max-h-[560px] z-50 rounded-2xl border border-zinc-700/60 bg-[#0d1117] shadow-2xl overflow-hidden flex flex-col"
      style={{ fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace" }}
    >
      {/* ── Header ── */}
      <div className="px-4 py-2.5 border-b border-zinc-700/60 bg-zinc-900/80 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2.5">
          <Terminal className="h-4 w-4 text-emerald-400" />
          <span className="text-sm font-semibold text-zinc-100 tracking-tight">Live Scan Console</span>
          <Badge
            variant="outline"
            className="max-w-[130px] truncate text-[10px] font-mono border-zinc-600 text-zinc-400"
            title={scanId ?? ''}
          >
            {scanId ? `${scanId.slice(0, 8)}…` : wsStatus === 'connecting' ? 'connecting…' : 'no scan id'}
          </Badge>
          {/* Connection dot */}
          <span className="flex items-center gap-1 text-[10px]">
            <span className={`h-1.5 w-1.5 rounded-full ${wsStatus === 'open' ? 'bg-emerald-400 animate-pulse' :
                wsStatus === 'connecting' ? 'bg-amber-400 animate-pulse' : 'bg-zinc-500'
              }`} />
            <span className="text-zinc-500">
              {wsStatus === 'open' ? 'Connected' : wsStatus === 'connecting' ? 'Connecting…' : 'Idle'}
            </span>
          </span>
        </div>
        <div className="flex items-center gap-1">
          {onCancel && scanId && !isCompleted && !isFailed && (
            <button
              onClick={onCancel}
              className="text-[11px] px-2.5 py-1 rounded-md bg-rose-900/40 text-rose-400 hover:bg-rose-600 hover:text-white transition-colors border border-rose-700/40"
            >
              Cancel Scan
            </button>
          )}
          <button
            onClick={onClose}
            className="p-1.5 rounded-md hover:bg-zinc-700 text-zinc-500 hover:text-zinc-200 transition-colors"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* ── Console Body ── */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-3 space-y-0.5 text-[11.5px] leading-relaxed"
        style={{ scrollbarWidth: 'thin', scrollbarColor: '#374151 transparent' }}
      >
        {/* Init line */}
        <div className="text-zinc-600 mb-2 text-[11px]">
          ▸ Secure scan pipeline initialized — streaming live output…
        </div>

        {messages.length === 0 && (
          <div className="flex items-center gap-2 text-zinc-500 py-2">
            <Loader2 className="h-3 w-3 animate-spin" />
            <span>Waiting for scan to start…</span>
          </div>
        )}

        {messages.map((msg, i) => {
          const ts = getTimestamp();

          /* ── Stage status message ── */
          if (msg.type === 'status') {
            const stageNum = typeof msg.stage === 'number' ? msg.stage : parseInt(String(msg.stage || '0'), 10);
            const meta = STAGE_META[stageNum];
            const Icon = meta?.Icon ?? Info;
            const color = meta?.color ?? 'text-zinc-400';
            const isRunning = msg.status === 'running';
            const isDone = msg.status === 'completed';
            const isFail = msg.status === 'failed';

            return (
              <div key={i} className="flex items-start gap-2 py-0.5">
                <span className="text-zinc-600 shrink-0 w-[56px] text-right">{ts}</span>
                <span className="shrink-0">
                  {isDone ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 mt-0.5" /> :
                    isFail ? <AlertCircle className="h-3.5 w-3.5 text-rose-400 mt-0.5" /> :
                      isRunning ? <Loader2 className={`h-3.5 w-3.5 ${color} animate-spin mt-0.5`} /> :
                        <Icon className={`h-3.5 w-3.5 ${color} mt-0.5`} />}
                </span>
                <div className="flex flex-col">
                  {meta && (
                    <span className={`text-[10px] font-bold uppercase tracking-wider ${color} opacity-70`}>
                      Stage {stageNum} · {meta.label}
                    </span>
                  )}
                  <span className={isDone ? 'text-emerald-300' : isFail ? 'text-rose-300' : 'text-zinc-200'}>
                    {msg.message}
                  </span>
                </div>
              </div>
            );
          }

          /* ── Tool log message ── */
          if (msg.type === 'log') {
            const text = formatLogMessage(msg.message || '');
            // Categorize log visually
            const isProgress = text.includes('%') || text.toLowerCase().includes('scanning') || text.toLowerCase().includes('progress');
            const isDiscovery = text.toLowerCase().includes('found') || text.toLowerCase().includes('discovered') || text.toLowerCase().includes('live');
            const isWarning = text.toLowerCase().includes('warn') || text.toLowerCase().includes('timed out') || text.toLowerCase().includes('failed');

            const textColor = isWarning ? 'text-amber-400' : isDiscovery ? 'text-sky-300' : isProgress ? 'text-violet-300' : 'text-zinc-400';
            const prefix = isWarning ? '⚠' : isDiscovery ? '✔' : isProgress ? '↺' : '›';

            return (
              <div key={i} className="flex items-start gap-2 py-0.5">
                <span className="text-zinc-600 shrink-0 w-[56px] text-right">{ts}</span>
                <span className={`shrink-0 font-bold ${textColor}`}>{prefix}</span>
                <span className={`${textColor} break-all`}>{text}</span>
              </div>
            );
          }

          /* ── Metrics update ── */
          if (msg.type === 'metrics' && msg.data) {
            const formatted = formatMetrics(msg.data);
            return (
              <div key={i} className="flex items-start gap-2 py-0.5">
                <span className="text-zinc-600 shrink-0 w-[56px] text-right">{ts}</span>
                <span className="shrink-0 text-teal-400 font-bold">◆</span>
                <span className="text-teal-300 bg-teal-900/20 px-1.5 rounded">{formatted}</span>
              </div>
            );
          }

          /* ── Error ── */
          if (msg.type === 'error') {
            return (
              <div key={i} className="flex items-start gap-2 py-0.5">
                <span className="text-zinc-600 shrink-0 w-[56px] text-right">{ts}</span>
                <AlertCircle className="h-3.5 w-3.5 text-rose-400 mt-0.5 shrink-0" />
                <span className="text-rose-300">{msg.message}</span>
              </div>
            );
          }

          return null;
        })}

        {/* Final banner */}
        {isCompleted && (
          <div className="mt-3 pt-2 border-t border-zinc-700/50 flex items-center gap-2 text-emerald-400 font-bold text-[11px]">
            <CheckCircle2 className="h-4 w-4" />
            Scan completed — Dashboard is updating…
          </div>
        )}
        {isFailed && (
          <div className="mt-3 pt-2 border-t border-zinc-700/50 flex items-center gap-2 text-rose-400 font-bold text-[11px]">
            <AlertCircle className="h-4 w-4" />
            Scan failed — check backend logs for details.
          </div>
        )}
      </div>

      {/* ── Footer ── */}
      <div className="px-4 py-1.5 border-t border-zinc-700/60 bg-zinc-900/60 text-[10px] text-zinc-500 flex justify-between items-center shrink-0">
        <span>{messages.length} log entries</span>
        <span className="text-zinc-600">QuantumShield Scanner</span>
      </div>
    </motion.div>
  );
};
