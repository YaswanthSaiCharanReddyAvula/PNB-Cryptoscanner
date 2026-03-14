import { useState } from "react";
import { motion } from "framer-motion";
import { FileText, Download, Calendar, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";

const domains = [
  "bank.com",
  "api.bank.com",
  "portal.bank.com",
  "pay.bank.com",
  "auth.bank.com",
  "internal.bank.com",
];

const reportTypes = [
  { id: "executive", label: "Executive Reporting", icon: FileText, description: "High-level summary for leadership" },
  { id: "scheduler", label: "Scheduler Reporting", icon: Calendar, description: "Automated periodic reports" },
  { id: "on-demand", label: "On-Demand Reporting", icon: Zap, description: "Generate reports instantly" },
];

const formats = ["JSON", "XML", "CSV", "PDF"];

export default function Reporting() {
  const [selectedDomain, setSelectedDomain] = useState("");
  const [selectedType, setSelectedType] = useState("executive");
  const [selectedFormat, setSelectedFormat] = useState("PDF");
  const [generating, setGenerating] = useState(false);

  const handleGenerate = async () => {
    if (!selectedDomain) {
      toast.error("Please select a domain");
      return;
    }
    setGenerating(true);
    // Simulate generation
    await new Promise((r) => setTimeout(r, 2000));
    toast.success(`${selectedFormat} report generated for ${selectedDomain}`);
    setGenerating(false);
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">Reporting</h1>
        <p className="text-sm text-muted-foreground">Generate and download security reports</p>
      </motion.div>

      {/* Report Types */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {reportTypes.map((rt) => (
          <motion.button
            key={rt.id}
            whileHover={{ y: -2 }}
            onClick={() => setSelectedType(rt.id)}
            className={`rounded-xl border p-5 text-left transition-all duration-300 ${
              selectedType === rt.id
                ? "border-primary bg-primary/10 card-glow-gold"
                : "border-border bg-card hover:border-border/80"
            }`}
          >
            <div className={`inline-flex rounded-lg p-2.5 mb-3 ${
              selectedType === rt.id ? "bg-primary/20 text-primary" : "bg-secondary text-muted-foreground"
            }`}>
              <rt.icon className="h-5 w-5" />
            </div>
            <h3 className="text-sm font-semibold text-foreground">{rt.label}</h3>
            <p className="text-xs text-muted-foreground mt-1">{rt.description}</p>
          </motion.button>
        ))}
      </div>

      {/* Configuration */}
      <div className="rounded-xl border border-border bg-card p-6">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-5">Report Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="space-y-2">
            <label className="text-xs text-muted-foreground uppercase tracking-wider">Domain</label>
            <Select value={selectedDomain} onValueChange={setSelectedDomain}>
              <SelectTrigger className="bg-secondary border-border">
                <SelectValue placeholder="Select domain" />
              </SelectTrigger>
              <SelectContent>
                {domains.map((d) => (
                  <SelectItem key={d} value={d}>{d}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <label className="text-xs text-muted-foreground uppercase tracking-wider">Format</label>
            <Select value={selectedFormat} onValueChange={setSelectedFormat}>
              <SelectTrigger className="bg-secondary border-border">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {formats.map((f) => (
                  <SelectItem key={f} value={f}>{f}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-end">
            <Button
              onClick={handleGenerate}
              disabled={generating}
              className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-semibold"
            >
              <Download className="mr-2 h-4 w-4" />
              {generating ? "Generating..." : "Generate Report"}
            </Button>
          </div>
        </div>
      </div>

      {/* Recent Reports */}
      <div className="rounded-xl border border-border bg-card p-6">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Recent Reports</h3>
        <div className="space-y-3">
          {[
            { domain: "bank.com", type: "Executive", format: "PDF", date: "2026-03-12", size: "2.4 MB" },
            { domain: "api.bank.com", type: "On-Demand", format: "JSON", date: "2026-03-11", size: "1.1 MB" },
            { domain: "portal.bank.com", type: "Scheduler", format: "CSV", date: "2026-03-10", size: "856 KB" },
          ].map((report, i) => (
            <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-secondary/50 hover:bg-secondary transition-colors">
              <div className="flex items-center gap-3">
                <div className="h-8 w-8 rounded-lg bg-primary/15 flex items-center justify-center">
                  <FileText className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">{report.domain}</p>
                  <p className="text-xs text-muted-foreground">{report.type} • {report.format} • {report.date}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground">{report.size}</span>
                <Button variant="ghost" size="sm" className="text-primary hover:text-primary/80">
                  <Download className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
