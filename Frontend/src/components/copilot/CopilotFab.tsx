import { useState, useRef, useEffect } from "react";
import { Loader2, Send, X, Sparkles } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { aiService } from "@/services/api";
import { getLastScannedDomain } from "@/lib/lastScanDomain";
import { formatCopilotRequestError } from "@/lib/copilotError";
import { cn } from "@/lib/utils";
import { CopilotMarkdown } from "@/components/copilot/CopilotMarkdown";

type Msg = { role: "user" | "assistant"; text: string };

export function CopilotFab() {
  const [open, setOpen] = useState(false);
  const [domain, setDomain] = useState("");
  const [input, setInput] = useState("");
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  /** Read on send so the API always gets the current input value (avoids stale React state). */
  const domainInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const d = getLastScannedDomain();
    if (d) setDomain(d);
  }, []);

  useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs, loading, open]);

  const send = async () => {
    const text = input.trim();
    if (!text) return;
    setInput("");
    setMsgs((m) => [...m, { role: "user", text }]);
    setLoading(true);
    try {
      const raw =
        (domainInputRef.current?.value ?? domain).trim().toLowerCase() || "";
      const dom = raw || undefined;
      const res = await aiService.copilotChat({ message: text, domain: dom ?? null });
      const reply = String((res.data as { reply?: string })?.reply ?? "").trim() || "No reply.";
      setMsgs((m) => [...m, { role: "assistant", text: reply }]);
    } catch (err: unknown) {
      const msg = formatCopilotRequestError(err);
      toast.error(msg);
      setMsgs((m) => [
        ...m,
        {
          role: "assistant",
          text: msg,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex flex-col items-end gap-3 md:bottom-6 md:right-6">
      <AnimatePresence>
        {open && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="pointer-events-auto fixed inset-0 z-0 bg-background/60 backdrop-blur-[2px]"
              aria-hidden
              onClick={() => setOpen(false)}
            />
            <motion.div
              initial={{ opacity: 0, y: 16, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 16, scale: 0.96 }}
              transition={{ type: "spring", stiffness: 420, damping: 32 }}
              className="pointer-events-auto relative z-10 flex w-[min(100vw-2rem,400px)] max-h-[min(72vh,560px)] flex-col overflow-hidden rounded-2xl border border-border bg-card shadow-2xl ring-1 ring-black/5 dark:ring-white/10"
            >
              <div className="flex items-start justify-between gap-2 border-b border-border bg-gradient-to-r from-primary/10 via-card to-card px-4 py-3">
                <div className="min-w-0">
                  <p className="text-xs font-bold uppercase tracking-wide text-primary">Copilot</p>
                  <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
                    QuantumShield scan context only. Off-topic questions are declined.
                  </p>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 shrink-0 rounded-full"
                  onClick={() => setOpen(false)}
                  aria-label="Close copilot"
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>

              <div className="border-b border-border/80 bg-amber-500/8 px-4 py-2.5 dark:bg-amber-500/12">
                <p className="text-[11px] leading-relaxed text-amber-950/90 dark:text-amber-100/90">
                  Answers use aggregated workspace scan data. Missing scans may limit responses.
                </p>
              </div>

              <div className="space-y-1.5 border-b border-border/60 px-4 py-3">
                <Label className="text-[11px]">Domain (optional)</Label>
                <Input
                  ref={domainInputRef}
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="Blank = latest completed scan (any domain)"
                  className="h-9 font-mono text-xs bg-secondary"
                />
              </div>

              <div className="min-h-0 flex-1 overflow-y-auto p-3 space-y-2.5">
                {msgs.length === 0 && (
                  <p className="text-xs text-muted-foreground px-1">
                    Ask about TLS, findings, or cyber rating from your scans.
                  </p>
                )}
                {msgs.map((m, i) => (
                  <div
                    key={i}
                    className={cn(
                      "rounded-xl px-3 py-2 text-sm max-w-[94%]",
                      m.role === "user"
                        ? "ml-auto bg-primary text-primary-foreground"
                        : "mr-auto bg-secondary text-foreground border border-border/60",
                    )}
                  >
                    <span className="text-[9px] font-semibold uppercase opacity-70 block mb-0.5">
                      {m.role === "user" ? "You" : "Copilot"}
                    </span>
                    {m.role === "user" ? (
                      <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>
                    ) : (
                      <CopilotMarkdown content={m.text} />
                    )}
                  </div>
                ))}
                {loading && (
                  <div className="flex items-center gap-2 text-[11px] text-muted-foreground px-1">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Thinking…
                  </div>
                )}
                <div ref={bottomRef} />
              </div>

              <form
                className="border-t border-border p-3 flex gap-2 bg-secondary/30"
                onSubmit={(e) => {
                  e.preventDefault();
                  void send();
                }}
              >
                <Input
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Message…"
                  className="h-10 bg-background text-sm"
                  disabled={loading}
                  maxLength={4000}
                />
                <Button type="submit" size="sm" disabled={loading || !input.trim()} className="h-10 shrink-0 gap-1.5 px-3">
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                  Send
                </Button>
              </form>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      <motion.button
        type="button"
        layout
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "pointer-events-auto flex h-14 w-14 items-center justify-center rounded-2xl shadow-lg transition-all md:h-[3.75rem] md:w-[3.75rem]",
          "bg-gradient-to-br from-primary to-primary/85 text-primary-foreground",
          "ring-2 ring-primary/30 hover:ring-primary/50 hover:shadow-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          open && "ring-primary",
        )}
        aria-label={open ? "Close QuantumShield Copilot" : "Open QuantumShield Copilot"}
        title="Copilot"
      >
        <span className="relative flex flex-col items-center justify-center gap-0.5">
          <Sparkles className="h-6 w-6 md:h-7 md:w-7" strokeWidth={2} />
          <span className="text-[9px] font-extrabold uppercase tracking-[0.12em] leading-none">AI</span>
        </span>
      </motion.button>
    </div>
  );
}
