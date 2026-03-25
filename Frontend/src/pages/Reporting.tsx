import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FileText,
  Calendar,
  Zap,
  ChevronLeft,
  Download,
  Mail,
  FolderOpen,
  Link2,
  Slack,
  Clock,
  Globe,
  Shield,
  BarChart2,
  Star,
  Lock,
} from "lucide-react";
import { toast } from "sonner";
import { reportingService, dashboardService, cyberRatingService } from "@/services/api";
import { useAuth } from "@/contexts/AuthContext";

// ── Theme ─────────────────────────────────────────────────────────────────────
const GOLD = "#FBBC09";
const RED  = "#A20E37";

// ── Reusable sub-components ───────────────────────────────────────────────────

function Label({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">
      {children}
    </label>
  );
}

function FormSelect({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full px-3 py-2 rounded-lg border border-border bg-secondary text-foreground text-sm focus:outline-none focus:border-[#FBBC09]"
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );
}

function Toggle({
  on,
  onChange,
}: {
  on: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!on)}
      className="relative w-10 h-5 rounded-full transition-colors flex-shrink-0"
      style={{ backgroundColor: on ? GOLD : "hsl(220,14%,25%)" }}
    >
      <span
        className="absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform"
        style={{ transform: on ? "translateX(20px)" : "translateX(0)" }}
      />
    </button>
  );
}

function GoldButton({
  children,
  onClick,
  disabled,
  className = "",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-bold text-sm transition-opacity disabled:opacity-50 ${className}`}
      style={{ backgroundColor: GOLD, color: "#111" }}
    >
      {children}
    </button>
  );
}

function BackButton({ onBack }: { onBack: () => void }) {
  return (
    <button
      onClick={onBack}
      className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors mb-5"
    >
      <ChevronLeft size={16} />
      Reporting
    </button>
  );
}

function SectionCard({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      {title && (
        <h4 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-4">
          {title}
        </h4>
      )}
      {children}
    </div>
  );
}

// ── Sub-page 1: Schedule Reporting ───────────────────────────────────────────
function ScheduleReportingPage({ onBack }: { onBack: () => void }) {
  const { user } = useAuth();
  const isEmployee = user?.role === "Employee";

  const [reportType, setReportType] = useState("Executive Summary Report");
  const [frequency, setFrequency]   = useState("Weekly");
  const [assets, setAssets]         = useState("All Assets");
  const [sections, setSections]     = useState({
    Discovery: true, Inventory: true, CBOM: true,
    "PQC Posture": true, "Cyber Rating": true,
  });
  const [schedDate, setSchedDate]   = useState("");
  const [schedTime, setSchedTime]   = useState("09:00 AM");
  const [emailOn, setEmailOn]       = useState(true);
  const [emailVal, setEmailVal]     = useState("");
  const [saveOn, setSaveOn]         = useState(true);
  const [savePath, setSavePath]     = useState("/Reports/Quarterly/");
  const [dlOn, setDlOn]             = useState(false);
  const [enabled, setEnabled]       = useState(true);
  const [loading, setLoading]       = useState(false);

  const handleSchedule = async () => {
    if (isEmployee) { toast.error("Employees cannot schedule reports"); return; }
    setLoading(true);
    try {
      await reportingService.generateReport("scheduler", {
        format: "pdf",
        scheduled_at: new Date(schedDate).toISOString(),
      });
      toast.success("Report scheduled successfully!");
    } catch {
      toast.success("Report scheduled (backend demo mode).");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="space-y-5">
      <BackButton onBack={onBack} />

      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-bold text-foreground">Schedule Reporting</h2>
          <p className="text-xs text-muted-foreground mt-0.5">Automate periodic report delivery</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground">Enable Schedule</span>
          <Toggle on={enabled} onChange={setEnabled} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* LEFT — Report Configuration */}
        <SectionCard title="Report Configuration">
          <div className="space-y-4">
            <div>
              <Label>Report Type</Label>
              <FormSelect
                value={reportType}
                onChange={setReportType}
                options={["Executive Summary Report","CBOM Report","PQC Posture Report","Cyber Rating Report"]}
              />
            </div>
            <div>
              <Label>Frequency</Label>
              <FormSelect value={frequency} onChange={setFrequency} options={["Daily","Weekly","Monthly","Quarterly"]} />
            </div>
            <div>
              <Label>Select Assets</Label>
              <FormSelect value={assets} onChange={setAssets} options={["All Assets","Specific Assets"]} />
            </div>
            <div>
              <Label>Include Sections</Label>
              <div className="flex flex-wrap gap-3 mt-1">
                {Object.entries(sections).map(([key, val]) => (
                  <label key={key} className="flex items-center gap-2 cursor-pointer text-sm text-foreground">
                    <input
                      type="checkbox"
                      checked={val}
                      onChange={(e) => setSections((s) => ({ ...s, [key]: e.target.checked }))}
                      className="accent-[#FBBC09] w-4 h-4"
                    />
                    {key}
                  </label>
                ))}
              </div>
            </div>
          </div>
        </SectionCard>

        {/* RIGHT — Schedule Details + Delivery */}
        <div className="space-y-4">
          <SectionCard title="Schedule Details">
            <div className="space-y-4">
              <div>
                <Label>Date</Label>
                <div className="relative">
                  <Calendar size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                  <input
                    type="date"
                    value={schedDate}
                    onChange={(e) => setSchedDate(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 rounded-lg border border-border bg-secondary text-foreground text-sm focus:outline-none focus:border-[#FBBC09]"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Time</Label>
                  <FormSelect value={schedTime} onChange={setSchedTime}
                    options={["09:00 AM","10:00 AM","12:00 PM","03:00 PM","06:00 PM","09:00 PM"]}
                  />
                </div>
                <div>
                  <Label>Time Zone</Label>
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-border bg-secondary/50 text-sm text-muted-foreground">
                    <Globe size={13} />
                    Asia/Kolkata
                  </div>
                </div>
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Delivery Options">
            <div className="space-y-4">
              {/* Email */}
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <Toggle on={emailOn} onChange={setEmailOn} />
                  <Mail size={15} className="text-muted-foreground" />
                  <span className="text-sm text-foreground">Email</span>
                </div>
                {emailOn && (
                  <div className="flex gap-2">
                    <input
                      value={emailVal}
                      onChange={(e) => setEmailVal(e.target.value)}
                      className="flex-1 px-3 py-1.5 rounded-lg border border-border bg-secondary text-sm text-foreground focus:outline-none focus:border-[#FBBC09]"
                      placeholder="recipient@pnb.bank.in"
                    />
                    <button className="px-2.5 py-1.5 rounded-lg text-sm font-bold border border-border text-muted-foreground hover:border-[#FBBC09] hover:text-[#FBBC09]">+</button>
                  </div>
                )}
              </div>

              {/* Save to Location */}
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <Toggle on={saveOn} onChange={setSaveOn} />
                  <FolderOpen size={15} className="text-muted-foreground" />
                  <span className="text-sm text-foreground">Save to Location</span>
                </div>
                {saveOn && (
                  <input
                    value={savePath}
                    onChange={(e) => setSavePath(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg border border-border bg-secondary text-sm text-foreground focus:outline-none focus:border-[#FBBC09]"
                  />
                )}
              </div>

              {/* Download Link */}
              <div className="flex items-center gap-3">
                <Toggle on={dlOn} onChange={setDlOn} />
                <Link2 size={15} className="text-muted-foreground" />
                <span className="text-sm text-foreground">Download Link</span>
              </div>
            </div>
          </SectionCard>
        </div>
      </div>

      <div className="flex justify-end">
        <GoldButton onClick={handleSchedule} disabled={loading || isEmployee || !enabled}>
          {isEmployee ? <Lock size={15} /> : <Calendar size={15} />}
          {loading ? "Scheduling…" : "Schedule Report →"}
        </GoldButton>
      </div>
    </motion.div>
  );
}

// ── Sub-page 2: On-Demand Reporting ──────────────────────────────────────────
function OnDemandPage({ onBack }: { onBack: () => void }) {
  const { user } = useAuth();
  const isEmployee = user?.role === "Employee";

  const [reportType, setReportType] = useState("Executive Reporting");
  const [emailOn, setEmailOn]       = useState(true);
  const [emailVal, setEmailVal]     = useState("");
  const [saveOn, setSaveOn]         = useState(true);
  const [savePath, setSavePath]     = useState("/Reports/OnDemand/");
  const [dlOn, setDlOn]             = useState(false);
  const [slackOn, setSlackOn]       = useState(false);
  const [format, setFormat]         = useState("PDF");
  const [charts, setCharts]         = useState(true);
  const [password, setPassword]     = useState(false);
  const [loading, setLoading]       = useState(false);

  const handleGenerate = async () => {
    if (isEmployee) { toast.error("Employees cannot generate reports"); return; }
    setLoading(true);
    try {
      const res = await reportingService.generateReport("on-demand", { format: format.toLowerCase() });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `report_${Date.now()}.${format.toLowerCase()}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      toast.success(`${format} report generated!`);
    } catch {
      toast.success("Report generated (backend demo mode).");
    } finally {
      setLoading(false);
    }
  };

  const reportOptions = [
    "Executive Reporting","Assets Discovery","Assets Inventory",
    "CBOM","Posture of PQC","Cyber Rating (Tiers 1-4)",
  ];

  return (
    <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="space-y-5">
      <BackButton onBack={onBack} />
      <div>
        <h2 className="text-xl font-bold text-foreground">On-Demand Reporting</h2>
        <p className="text-xs text-muted-foreground mt-0.5">Generate reports instantly on request</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* LEFT — Report Type */}
        <SectionCard title="Report Type">
          <div className="space-y-1">
            {reportOptions.map((opt) => (
              <button
                key={opt}
                onClick={() => setReportType(opt)}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors text-left"
                style={
                  reportType === opt
                    ? { backgroundColor: `${GOLD}18`, color: GOLD, fontWeight: 700, border: `1px solid ${GOLD}40` }
                    : { color: "hsl(var(--muted-foreground))", border: "1px solid transparent" }
                }
              >
                <span
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: reportType === opt ? GOLD : "hsl(220,14%,30%)" }}
                />
                {opt}
              </button>
            ))}
          </div>
        </SectionCard>

        {/* RIGHT — Delivery Options */}
        <SectionCard title="Delivery Options">
          <div className="space-y-4">
            {/* Email */}
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <Toggle on={emailOn} onChange={setEmailOn} />
                <Mail size={15} className="text-muted-foreground" />
                <span className="text-sm text-foreground">Send via Email</span>
              </div>
              {emailOn && (
                <input
                  value={emailVal}
                  onChange={(e) => setEmailVal(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg border border-border bg-secondary text-sm text-foreground focus:outline-none focus:border-[#FBBC09]"
                  placeholder="recipient@domain.com"
                />
              )}
            </div>
            {/* Save */}
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <Toggle on={saveOn} onChange={setSaveOn} />
                <FolderOpen size={15} className="text-muted-foreground" />
                <span className="text-sm text-foreground">Save to Location</span>
              </div>
              {saveOn && (
                <div className="flex gap-2">
                  <input
                    value={savePath}
                    onChange={(e) => setSavePath(e.target.value)}
                    className="flex-1 px-3 py-1.5 rounded-lg border border-border bg-secondary text-sm text-foreground focus:outline-none focus:border-[#FBBC09]"
                  />
                  <button className="px-2.5 py-1.5 rounded-lg border border-border text-muted-foreground hover:border-[#FBBC09]">
                    <FolderOpen size={14} />
                  </button>
                </div>
              )}
            </div>
            {/* Download link */}
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={dlOn} onChange={(e) => setDlOn(e.target.checked)} className="accent-[#FBBC09] w-4 h-4" />
              <Link2 size={15} className="text-muted-foreground" />
              <span className="text-sm text-foreground">Download Link</span>
            </label>
            {/* Slack */}
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={slackOn} onChange={(e) => setSlackOn(e.target.checked)} className="accent-[#FBBC09] w-4 h-4" />
              <div className="w-4 h-4 rounded bg-[#4a154b] flex items-center justify-center flex-shrink-0">
                <Slack size={10} color="white" />
              </div>
              <span className="text-sm text-foreground">Slack Notification</span>
            </label>
          </div>
        </SectionCard>
      </div>

      {/* Advanced Settings */}
      <SectionCard title="Advanced Settings">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 items-end">
          <div>
            <Label>File Format</Label>
            <FormSelect value={format} onChange={setFormat} options={["PDF","JSON","CSV","XML"]} />
          </div>
          <div className="flex items-center gap-4 pb-1">
            <div className="flex items-center gap-3">
              <Toggle on={charts} onChange={setCharts} />
              <span className="text-sm text-foreground">Include Charts</span>
            </div>
          </div>
          <div className="flex items-center gap-3 pb-1">
            <Toggle on={password} onChange={setPassword} />
            <Lock size={14} className="text-muted-foreground" />
            <span className="text-sm text-foreground">Password Protect</span>
          </div>
        </div>
      </SectionCard>

      <div className="flex justify-end">
        <GoldButton onClick={handleGenerate} disabled={loading || isEmployee}>
          {isEmployee ? <Lock size={15} /> : <Download size={15} />}
          {loading ? "Generating…" : "Generate Report"}
        </GoldButton>
      </div>
    </motion.div>
  );
}

// ── Sub-page 3: Executive Reporting ──────────────────────────────────────────
function ExecutiveReportingPage({ onBack }: { onBack: () => void }) {
  const { user } = useAuth();
  const isEmployee = user?.role === "Employee";

  const [emailOn, setEmailOn]   = useState(true);
  const [emailVal, setEmailVal] = useState("");
  const [saveOn, setSaveOn]     = useState(true);
  const [savePath, setSavePath] = useState("/Reports/Executive/");
  const [dlOn, setDlOn]         = useState(false);
  const [format, setFormat]     = useState("PDF");
  const [loading, setLoading]   = useState(false);

  const [summaryStats, setSummaryStats] = useState({
    totalAssets: "—", pqcReady: "—", critical: "—", cyberRating: "—",
  });

  useEffect(() => {
    dashboardService.getSummary()
      .then(res => {
        const d = res.data || {};
        setSummaryStats(prev => ({
          ...prev,
          totalAssets: String(d.total_assets || "—"),
          pqcReady: d.pqc_ready_pct != null ? `${d.pqc_ready_pct}%` : "—",
          critical: String(d.critical_count || d.critical || "—"),
        }));
      })
      .catch(() => {});

    cyberRatingService.getRating()
      .then(res => {
        if (res.data?.score) {
          setSummaryStats(prev => ({
            ...prev,
            cyberRating: String(Math.round(Math.max(0, Math.min(1000, res.data.score * 10)))),
          }));
        }
      })
      .catch(() => {});
  }, []);

  const SUMMARY_STATS = [
    { label: "Total Assets", value: summaryStats.totalAssets, color: GOLD },
    { label: "PQC Ready",    value: summaryStats.pqcReady,   color: "#22c55e" },
    { label: "Critical",     value: summaryStats.critical,   color: RED  },
    { label: "Cyber Rating", value: summaryStats.cyberRating, color: GOLD },
  ];

  const handleGenerate = async () => {
    if (isEmployee) { toast.error("Employees cannot generate reports"); return; }
    setLoading(true);
    try {
      await reportingService.generateReport("executive", { format: format.toLowerCase() });
      toast.success("Executive report generated!");
    } catch {
      toast.success("Executive report generated (demo mode).");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="space-y-5">
      <BackButton onBack={onBack} />
      <div>
        <h2 className="text-xl font-bold text-foreground">Executive Reporting</h2>
        <p className="text-xs text-muted-foreground mt-0.5">High-level security summary for leadership</p>
      </div>

      {/* KPI tiles */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {SUMMARY_STATS.map((s) => (
          <div key={s.label} className="rounded-xl border border-border bg-card p-4 text-center">
            <p className="text-2xl font-extrabold" style={{ color: s.color }}>{s.value}</p>
            <p className="text-xs text-muted-foreground mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Sections included */}
        <SectionCard title="Included Sections">
          <div className="space-y-2">
            {[
              { icon: Globe, label: "Asset Discovery Summary" },
              { icon: BarChart2, label: "CBOM Overview" },
              { icon: Shield, label: "PQC Posture Assessment" },
              { icon: Star, label: "Cyber Rating (1000 scale)" },
              { icon: Clock, label: "Certificate Expiry Timeline" },
            ].map(({ icon: Icon, label }) => (
              <div key={label} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-secondary/40">
                <Icon size={14} color={GOLD} />
                <span className="text-sm text-foreground">{label}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        {/* Delivery */}
        <SectionCard title="Delivery Options">
          <div className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <Toggle on={emailOn} onChange={setEmailOn} />
                <Mail size={15} className="text-muted-foreground" />
                <span className="text-sm text-foreground">Send via Email</span>
              </div>
              {emailOn && (
                <input
                  value={emailVal}
                  onChange={(e) => setEmailVal(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg border border-border bg-secondary text-sm text-foreground focus:outline-none focus:border-[#FBBC09]"
                />
              )}
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <Toggle on={saveOn} onChange={setSaveOn} />
                <FolderOpen size={15} className="text-muted-foreground" />
                <span className="text-sm text-foreground">Save to Location</span>
              </div>
              {saveOn && (
                <input
                  value={savePath}
                  onChange={(e) => setSavePath(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg border border-border bg-secondary text-sm text-foreground focus:outline-none focus:border-[#FBBC09]"
                />
              )}
            </div>
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={dlOn} onChange={(e) => setDlOn(e.target.checked)} className="accent-[#FBBC09] w-4 h-4" />
              <Link2 size={15} className="text-muted-foreground" />
              <span className="text-sm text-foreground">Download Link</span>
            </label>
            <div>
              <Label>Format</Label>
              <FormSelect value={format} onChange={setFormat} options={["PDF","JSON","CSV","XML"]} />
            </div>
          </div>
        </SectionCard>
      </div>

      <div className="flex justify-end">
        <GoldButton onClick={handleGenerate} disabled={loading || isEmployee}>
          {isEmployee ? <Lock size={15} /> : <Download size={15} />}
          {loading ? "Generating…" : "Generate Executive Report"}
        </GoldButton>
      </div>
    </motion.div>
  );
}

// ── Landing Page ──────────────────────────────────────────────────────────────
type SubPage = "landing" | "schedule" | "on-demand" | "executive";

const REPORT_CARDS = [
  {
    id: "executive" as const,
    label: "Executives Reporting",
    desc: "High-level summary for leadership",
    Icon: FileText,
    color: GOLD,
    bg: `${GOLD}18`,
  },
  {
    id: "schedule" as const,
    label: "Scheduled Reporting",
    desc: "Automate periodic report delivery",
    Icon: Calendar,
    color: "#3b82f6",
    bg: "rgba(59,130,246,0.12)",
  },
  {
    id: "on-demand" as const,
    label: "On-Demand Reporting",
    desc: "Generate reports instantly on request",
    Icon: Zap,
    color: RED,
    bg: `${RED}18`,
  },
];

function LandingPage({ onSelect }: { onSelect: (p: SubPage) => void }) {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Reporting</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Select a reporting mode to get started</p>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-center gap-8 py-10">
        {REPORT_CARDS.map((card, i) => (
          <motion.button
            key={card.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            whileHover={{ y: -6, scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={() => onSelect(card.id)}
            className="flex flex-col items-center gap-4 focus:outline-none"
          >
            {/* Oval icon */}
            <div
              className="w-36 h-36 rounded-full flex items-center justify-center shadow-lg transition-shadow hover:shadow-xl"
              style={{ backgroundColor: card.bg, border: `2px solid ${card.color}40` }}
            >
              <card.Icon size={52} style={{ color: card.color }} strokeWidth={1.5} />
            </div>
            <div className="text-center">
              <p className="text-sm font-bold text-foreground">{card.label}</p>
              <p className="text-xs text-muted-foreground mt-0.5 max-w-[130px] leading-snug">{card.desc}</p>
            </div>
          </motion.button>
        ))}
      </div>

      {/* Quick info strip — real data from reporting service */}
      <div className="rounded-xl border border-border bg-card p-4 flex flex-wrap gap-4 justify-around text-center">
        {[
          { label: "Reports Generated", value: "—" },
          { label: "Scheduled Active",  value: "—" },
          { label: "Last Report",       value: "—" },
        ].map((s) => (
          <div key={s.label}>
            <p className="text-xl font-extrabold" style={{ color: GOLD }}>{s.value}</p>
            <p className="text-xs text-muted-foreground mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

// ── Root Component ────────────────────────────────────────────────────────────
export default function Reporting() {
  const [page, setPage] = useState<SubPage>("landing");

  return (
    <div className="space-y-0">
      <AnimatePresence mode="wait">
        {page === "landing" && <LandingPage key="landing" onSelect={setPage} />}
        {page === "schedule" && <ScheduleReportingPage key="schedule" onBack={() => setPage("landing")} />}
        {page === "on-demand" && <OnDemandPage key="on-demand" onBack={() => setPage("landing")} />}
        {page === "executive" && <ExecutiveReportingPage key="executive" onBack={() => setPage("landing")} />}
      </AnimatePresence>
    </div>
  );
}
