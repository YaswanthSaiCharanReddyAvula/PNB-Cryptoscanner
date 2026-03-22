import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { FileText, Download, Calendar, Zap, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { reportingService, assetService } from "@/services/api";
import { useAuth } from "@/contexts/AuthContext";

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
  const [domains, setDomains] = useState<string[]>([]);
  const { user } = useAuth();
  const isEmployee = user?.role === "Employee";

  useEffect(() => {
    // Try to dynamically load domains from asset discovery or inventory
    assetService.getAll()
      .then((res) => {
        const items = Array.isArray(res.data) ? res.data : (res.data?.items ?? []);
        const uniqueDomains = Array.from(
          new Set(items.map((a: any) => a.url).filter(Boolean))
        ) as string[];
        if (uniqueDomains.length > 0) {
          setDomains(uniqueDomains);
        } else {
          setDomains(["All Domains"]);
        }
      })
      .catch((err) => {
        console.error("Could not fetch available domains", err);
        setDomains(["All Domains"]);
      });
  }, []);

  const handleGenerate = async () => {
    if (!selectedDomain) {
      toast.error("Please select a domain");
      return;
    }
    setGenerating(true);

    try {
      const payload: any = {
        format: selectedFormat.toLowerCase(),
        filters: selectedDomain !== "All Domains" ? { domain: selectedDomain } : undefined
      };

      if (selectedType === "scheduler") {
        // Schedule for 24 hours from now as a default
        payload.scheduled_at = new Date(Date.now() + 86400000).toISOString();
      }

      const res = await reportingService.generateReport(selectedType, payload);

      if (selectedType === "scheduler") {
        toast.success(`Report scheduled successfully for ${selectedDomain}`);
      } else {
        // Handle Blob download
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const link = document.createElement('a');
        link.href = url;
        
        // Try to extract filename from response headers
        const contentDisposition = res.headers['content-disposition'];
        let filename = `report_${new Date().toISOString()}.${selectedFormat.toLowerCase()}`;
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename="?(.+)"?/);
            if (filenameMatch && filenameMatch.length === 2) {
                filename = filenameMatch[1];
            }
        }
        
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();
        link.remove();
        toast.success(`${selectedFormat} report generated for ${selectedDomain}`);
      }

    } catch (error) {
      console.error("Report generation failed", error);
      toast.error("Failed to generate report");
    } finally {
      setGenerating(false);
    }
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
              disabled={generating || isEmployee}
              className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-semibold disabled:cursor-not-allowed"
            >
              {isEmployee ? <Lock className="mr-2 h-4 w-4" /> : <Download className="mr-2 h-4 w-4" />}
              {generating ? "Generating..." : "Generate Report"}
            </Button>
          </div>
        </div>
      </div>

      {/* Recent Reports */}
      <div className="rounded-xl border border-border bg-card p-6">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Recent Reports</h3>
        <div className="flex flex-col items-center justify-center py-8 text-center bg-secondary/20 rounded-lg border border-dashed border-border">
          <FileText className="h-8 w-8 text-muted-foreground mb-3 opacity-50" />
          <p className="text-sm font-medium text-foreground">No recent reports</p>
          <p className="text-xs text-muted-foreground mt-1">Generate a report above to see it here.</p>
        </div>
      </div>
    </div>
  );
}
